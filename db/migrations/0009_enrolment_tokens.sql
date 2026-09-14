-- 0009 — First-authenticator enrolment tokens.
--
-- THE GAP THIS CLOSES
--
-- L2 and L3 cannot hold a session without a verified WebAuthn assertion (spec 7.3), and the
-- only endpoint that enrols an authenticator requires a session. So the first privileged
-- account in an organisation could never sign in, and L3 is the only level that can release
-- a payment. The system could be deployed, migrated and seeded, and still not do the one
-- thing it exists to do.
--
-- WHY A TOKEN AND NOT JUST THE PASSWORD
--
-- The obvious fix — let a correct password enrol the first key — would make a stolen
-- password sufficient to become an L3 who can release money. That is exactly the bypass
-- spec 7.3 forbids, rebuilt under a different name.
--
-- So enrolment needs two independent things: the account password, and a single-use token
-- issued out of band by someone with database access. Neither alone is enough. This mirrors
-- how the first password itself is delivered (scripts/create-user.mjs prints it once and
-- never stores it).
--
-- WHAT IS STORED
--
-- Only a SHA-256 hash of the token, never the token. A database leak therefore yields no
-- usable enrolment tokens, and there is nothing for an operator to read out of a row and
-- reuse. This matches sessions, which store token hashes for the same reason.

CREATE TABLE enrolment_tokens (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- SHA-256 of the token, hex encoded. The token itself is shown once, by the issuing
    -- script, and is not recoverable from here.
    token_hash      text NOT NULL UNIQUE,

    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,

    -- Recorded so a token that is used can be traced to the authenticator it produced.
    credential_id   text,

    CONSTRAINT enrolment_token_expires_after_issue CHECK (expires_at > issued_at),
    CONSTRAINT enrolment_token_consumed_after_issue CHECK (consumed_at IS NULL OR consumed_at >= issued_at),
    -- A consumed token must say what it produced, so "was this token used to enrol that
    -- key?" is answerable from the row rather than by correlating timestamps.
    CONSTRAINT enrolment_token_consumed_records_credential
        CHECK ((consumed_at IS NULL) = (credential_id IS NULL))
);

-- Only one token may be outstanding per user. Issuing a second invalidates the first
-- (the script deletes unconsumed rows first), so a token read over someone's shoulder and
-- a token issued later cannot both be live.
CREATE UNIQUE INDEX enrolment_tokens_one_live_per_user
    ON enrolment_tokens (user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX enrolment_tokens_user ON enrolment_tokens (user_id);

-- A consumed token is evidence. Like audit_events, it must not be quietly rewritten to
-- point at a different credential or to look unused again.
CREATE OR REPLACE FUNCTION guard_enrolment_token_update() RETURNS trigger AS $$
BEGIN
    IF OLD.consumed_at IS NOT NULL THEN
        RAISE EXCEPTION 'enrolment token % is already consumed and cannot be modified', OLD.id;
    END IF;
    IF NEW.user_id <> OLD.user_id OR NEW.organization_id <> OLD.organization_id
       OR NEW.token_hash <> OLD.token_hash OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION 'enrolment token % is immutable except for consumption', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enrolment_tokens_guard_update
    BEFORE UPDATE ON enrolment_tokens
    FOR EACH ROW EXECUTE FUNCTION guard_enrolment_token_update();

COMMENT ON TABLE enrolment_tokens IS
    'Single-use, out-of-band tokens permitting exactly one action: registering the FIRST '
    'authenticator on an account that has none. Never grants a session, never applies to an '
    'account that already has a working key.';
