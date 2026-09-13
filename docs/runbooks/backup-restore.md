# Runbook: backup restoration and disaster-recovery test

**Applies to:** spec §13.7, §27
**Cadence:** at least quarterly, and after any schema migration
**Rule:** a backup that has never been restored is not a backup. It is a file.

---

## Why this runbook exists

The Backups screen shows a green tick when an object lands in storage with a non-zero size
and a matching checksum. That proves the upload worked. It does not prove the contents can
be restored into a working database, and the only way to know that is to do it.

---

## Restore into a scratch database

**Never restore into production.** The procedure below creates a separate database.

### 1. Retrieve the snapshot

Backups → attempt history → note the object key of the backup you are validating. Retrieve
it from your storage target:

```bash
aws s3 cp --endpoint-url "$S3_ENDPOINT" "s3://$S3_BUCKET/<object-key>" /tmp/snapshot.json
```

### 2. Verify integrity before trusting it

```bash
# The checksum recorded on the attempt must match the file you just downloaded.
sha256sum /tmp/snapshot.json
# Compare with the checksum shown on the attempt record.

# And the metadata should describe what you expect.
jq '.metadata | {takenAt, totalRows, organizationId, tables: (.tables | length)}' /tmp/snapshot.json
```

A checksum mismatch means the object was corrupted in storage or in transit. Stop, and
treat the backup as unusable.

### 3. Create the scratch database and apply the schema

```bash
createdb solvaren_restore_test
for migration in db/migrations/*.sql; do
  psql solvaren_restore_test -v ON_ERROR_STOP=1 -f "$migration"
done
```

### 4. Load the snapshot

```bash
node --experimental-strip-types scripts/restore-snapshot.mjs \
  --snapshot /tmp/snapshot.json \
  --database postgres://localhost/solvaren_restore_test
```

The loader inserts in dependency order and **disables the immutability triggers for the
duration of the load** — a restore is the one legitimate reason to do so, because the
triggers exist to stop the _application_ rewriting history, not to stop a recovery. It
re-enables them before exiting, and fails loudly if it cannot.

### 5. Verify the restore is usable, not merely loaded

Row counts are not sufficient. Check the properties that matter:

```sql
-- The audit chain must still verify. If it does not, the snapshot captured a torn read.
SELECT organization_id, COUNT(*), MIN(sequence), MAX(sequence)
  FROM audit_events GROUP BY organization_id;
-- Sequences must be contiguous from 1 with no gaps.

-- Batch totals must match their instruction rows.
SELECT b.batch_reference, b.total_amount_cents, SUM(pi.amount_cents) AS computed
  FROM payment_batches b
  JOIN payment_instructions pi ON pi.batch_id = b.id
 GROUP BY b.id, b.batch_reference, b.total_amount_cents
HAVING b.total_amount_cents <> SUM(pi.amount_cents);
-- Must return zero rows.

-- Every settled transaction must still carry its evidence.
SELECT COUNT(*) FROM transactions WHERE status = 'SUCCESS' AND mpesa_receipt_number IS NULL;
-- Must be 0.

SELECT COUNT(*) FROM transactions WHERE status = 'FAILED' AND (failure_reason IS NULL OR failure_reason = '');
-- Must be 0.
```

Then run the chain verification through the API against the restored database, which
recomputes every digest:

```
POST /admin/audit/verify  { "fromSequence": 1, "limit": 5000 }
```

### 6. What is deliberately not restored

The snapshot **excludes** password hashes, authorization PIN hashes, recovery code hashes
and sessions. That is intentional:

- A restore must not resurrect live sessions from the moment of the backup.
- Credential material has no business travelling to object storage, even hashed.

So a restored database has users who cannot sign in. Recovering from a real disaster
therefore includes re-enrolling credentials, which is a deliberate, audited process rather
than an automatic one. Plan for it: a disaster-recovery exercise that does not include
re-enrolment has not tested the real recovery.

### 7. Record the result and clean up

```bash
dropdb solvaren_restore_test
```

Record the date, the backup reference and the outcome wherever your organisation keeps
disaster-recovery evidence. An auditor will ask when the last successful restore was, and
"the backups are green" is not an answer to that question.

---

## When a backup fails

The Backups screen shows failures as failures. Common causes:

| Symptom                                       | Cause                                     | Action                                                                     |
| --------------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------- |
| `The storage target rejected the credentials` | Rotated or revoked access key             | Reconfigure the target; five consecutive failures suspend the schedule     |
| Status `MISSED`                               | The scheduled window passed without a run | Check whether the scheduler is firing (see below); run a manual backup now |
| `SUCCESS` with `retentionComplete: false`     | Some old objects could not be deleted     | Storage permissions; the retained count is not guaranteed until resolved   |
| Repeated failures, then suspension            | Threshold reached                         | Deliberate. Correct the configuration, which clears the suspension         |
