-- ---------------------------------------------------------------------------
-- 0011 — credential recovery
--
-- Recovery codes have been generated, hashed and shown to users since the first commit,
-- and nothing anywhere could redeem one. The Security screen told people those codes were
-- "the only routes back in"; they did nothing at all. Combined with there being no password
-- reset for anybody — not self-service, not administrative — a user who forgot their
-- password was locked out permanently, recoverable only by hand-editing the database.
--
-- Spec §11 requires recovery through an existing recovery credential OR controlled
-- administrative recovery, and forbids the weak paths outright: no SMS, no email OTP, no
-- "forgot password" link that mails a reset. This table is the narrow channel both routes
-- travel down.
--
-- A ticket is deliberately NOT a session. It authorises exactly one act — setting a new
-- password — and is spent doing it. Keeping it in its own table rather than reusing
-- `sessions` is the point: a bug that mistook a recovery ticket for a session would hand
-- out an authenticated session to somebody who has not authenticated.
-- ---------------------------------------------------------------------------

CREATE TABLE recovery_tickets (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- SHA-256 of the ticket, hex. The ticket itself is returned once and is not
    -- recoverable from here, exactly as a session token is not.
    ticket_hash         text NOT NULL UNIQUE,

    -- How the holder proved who they are. Recorded because the two routes carry different
    -- weight in an investigation: one is the user's own spare credential, the other is an
    -- administrator vouching for them.
    origin              text NOT NULL CHECK (origin IN ('RECOVERY_CODE', 'ADMINISTRATIVE')),

    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    consumed_at         timestamptz,
    issued_by_user_id   uuid REFERENCES users (id),
    issued_ip           inet,

    CONSTRAINT recovery_ticket_expires_after_issue CHECK (expires_at > issued_at),
    CONSTRAINT recovery_ticket_consumed_after_issue
        CHECK (consumed_at IS NULL OR consumed_at >= issued_at),
    -- An administrative ticket must name the administrator who vouched. A self-service one
    -- must not claim anybody vouched for it.
    CONSTRAINT recovery_ticket_origin_matches_issuer CHECK (
        (origin = 'ADMINISTRATIVE' AND issued_by_user_id IS NOT NULL) OR
        (origin = 'RECOVERY_CODE' AND issued_by_user_id IS NULL)
    )
);

-- One live ticket per user. A second request invalidates nothing silently; it is refused,
-- so a ticket read over somebody's shoulder and a ticket issued later cannot both be live.
CREATE UNIQUE INDEX recovery_tickets_one_live_per_user
    ON recovery_tickets (user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX recovery_tickets_user ON recovery_tickets (user_id);

-- A spent ticket is spent. Un-consuming one would make a single proof of identity reusable.
CREATE OR REPLACE FUNCTION guard_recovery_ticket_update() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: recovery ticket % is already spent and cannot be modified.',
            OLD.id;
    END IF;
    IF NEW.ticket_hash <> OLD.ticket_hash OR NEW.user_id <> OLD.user_id
       OR NEW.origin <> OLD.origin OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION
            'SOLVAREN immutability: the identity and issue of recovery ticket % cannot be rewritten.',
            OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER recovery_tickets_guard BEFORE UPDATE ON recovery_tickets
    FOR EACH ROW EXECUTE FUNCTION guard_recovery_ticket_update();

COMMENT ON TABLE recovery_tickets IS
    'Single-use authority to set a new password, issued either by redeeming a recovery code or by an executive performing controlled administrative recovery (§11). Never a session: it cannot read or move money, and it is spent by the one act it permits.';
