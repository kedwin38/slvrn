-- ---------------------------------------------------------------------------
-- 0010 — allow a deliberate retry to claim its own idempotency fingerprint
--
-- `idempotency_one_per_instruction` was UNIQUE (instruction_id): one claim per
-- instruction, for all time. Its comment says what it is actually defending against —
-- "this stops two different fingerprints (e.g. after an edit) racing for the same
-- instruction" — and that is a statement about *concurrent* claims, not about a second
-- attempt made deliberately, hours later, after the first one has settled as FAILED.
--
-- Written as an unconditional unique constraint it forbade both, so an operator retrying a
-- failed payment hit a constraint violation from an endpoint that had already told them the
-- payment was being re-sent.
--
-- The partial index below says what was meant: one LIVE claim per instruction. Two
-- fingerprints still cannot both be in flight, which is the whole anti-race property. And
-- it makes "you may not retry while an attempt is still outstanding" a database guarantee
-- rather than only an application check — the stronger place for it, because a payment
-- re-sent while the first is still unresolved is how somebody gets paid twice.
-- ---------------------------------------------------------------------------

ALTER TABLE idempotency_claims
    DROP CONSTRAINT idempotency_one_per_instruction;

CREATE UNIQUE INDEX idempotency_one_live_per_instruction
    ON idempotency_claims (instruction_id)
    WHERE state IN ('CLAIMED', 'SUBMITTED');

COMMENT ON INDEX idempotency_one_live_per_instruction IS
    'One outstanding attempt per instruction. A CLAIMED or SUBMITTED claim blocks any further claim for that instruction; a SETTLED or ABANDONED one does not, which is what lets an operator retry a payment that has definitively failed.';
