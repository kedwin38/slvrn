-- ============================================================================
-- SOLVAREN Payment Solutions — 0007 Backup retention marker
--
-- Fixes a real integrity bug found by the backup/restore round-trip test.
--
-- Retention previously recorded the removal of an object by setting
-- `backup_attempts.object_key = NULL`. That UPDATE is refused by the
-- `backup_success_requires_object` CHECK constraint, which — correctly — insists that a
-- backup recorded as SUCCESS must name an object. The delete from storage succeeded, the
-- UPDATE was rejected, the error was swallowed as a retention failure, and the attempt
-- record went on claiming an object that no longer existed. An operator reading the
-- backup history would have counted backups they did not have.
--
-- The fix keeps both properties instead of trading one for the other: the object key stays
-- on the record as historical evidence of what was written, and a separate timestamp
-- records when retention removed it. "This backup existed, and its object was retired on
-- 14 September" is both true and more useful than a null key.
-- ============================================================================

ALTER TABLE backup_attempts
    ADD COLUMN IF NOT EXISTS object_retired_at TIMESTAMPTZ;

COMMENT ON COLUMN backup_attempts.object_retired_at IS
    'Set when the retention worker removed the stored object. The attempt record and its object key are retained as evidence that the backup existed; this timestamp says it is no longer restorable.';

-- Only a SUCCESS attempt can have an object to retire.
ALTER TABLE backup_attempts
    ADD CONSTRAINT backup_retired_requires_success
    CHECK (object_retired_at IS NULL OR status = 'SUCCESS');

-- The retention worker's working set: successful backups whose object is still present.
CREATE INDEX IF NOT EXISTS backup_attempts_live_objects_idx
    ON backup_attempts (organization_id, started_at DESC)
    WHERE status = 'SUCCESS' AND object_retired_at IS NULL;

-- Allow the retention worker to set the marker on an already-terminal SUCCESS row. The
-- guard trigger blocks a *status* change, which this is not.
