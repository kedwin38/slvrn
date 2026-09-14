/**
 * Organisation policy (spec §5, §6).
 *
 * These are the limits the release ceremony enforces: the largest single payment, the
 * largest batch, the risk band that blocks a release, the cooling-off period between the
 * last edit and submission. They shipped with defaults and no way to change them, so every
 * organisation ran on the same numbers whether or not those numbers suited it.
 *
 * Amounts are held in cents and shown in shillings, because an operator thinks in KES and a
 * ledger must not think in floats. The conversion happens at the edge, once, here.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type OrganizationPolicyView } from '../lib/api.js';
import { Notice, Field, TableSkeleton } from '../components/primitives.js';

const toShillings = (cents: number) => (cents / 100).toFixed(2);
const toCents = (shillings: string) => Math.round(Number(shillings) * 100);

export function PolicySettingsPage() {
  const [policy, setPolicy] = useState<OrganizationPolicyView | null>(null);
  const [draft, setDraft] = useState<OrganizationPolicyView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.admin.policies.get();
      setPolicy(result.policy);
      setDraft(result.policy);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The policy could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!draft) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.admin.policies.update(draft);
      setPolicy(result.policy);
      setDraft(result.policy);
      setNotice('Policy updated. It applies to the next validation and release.');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The policy could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  if (!draft || !policy) {
    return (
      <div className="stack">
        <h1 className="page-title">Policy</h1>
        <TableSkeleton rows={6} columns={2} />
      </div>
    );
  }

  const dirty = JSON.stringify(draft) !== JSON.stringify(policy);
  const money = (label: string, key: keyof OrganizationPolicyView, hint: string) => (
    <Field label={label} hint={hint}>
      {(props) => (
        <input
          {...props}
          className="input"
          type="number"
          min="0"
          step="0.01"
          value={toShillings(draft[key] as number)}
          onChange={(event) => setDraft({ ...draft, [key]: toCents(event.target.value) })}
        />
      )}
    </Field>
  );

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Policy</h1>
          <p className="page-subtitle">
            The limits the release ceremony enforces. Changing them requires a recent sign-in, and
            every change is recorded in the audit trail.
          </p>
        </div>
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}
      {notice && (
        <Notice tone="success" live="polite">
          {notice}
        </Notice>
      )}

      <form className="stack" onSubmit={save}>
        <div className="card">
          <div className="card-body stack">
            <h2 className="section-title">Amount limits (KES)</h2>
            {money(
              'Largest single payment',
              'maxInstructionAmountCents',
              'Also capped by the M-PESA per-transaction limit',
            )}
            {money(
              'Largest batch total',
              'maxBatchTotalCents',
              'Across every instruction in one batch',
            )}
            {money(
              'High-value threshold',
              'highValueThresholdCents',
              'At or above this, the authorizer must acknowledge the risk report explicitly',
            )}
            {money(
              'Daily disbursement ceiling',
              'dailyDisbursementCeilingCents',
              'A circuit breaker across all batches in a day. 0 disables it',
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-body stack">
            <h2 className="section-title">Batch and review</h2>

            <Field label="Largest number of instructions in a batch" hint="1 to 20,000">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="number"
                  min="1"
                  max="20000"
                  value={draft.maxBatchInstructions}
                  onChange={(event) =>
                    setDraft({ ...draft, maxBatchInstructions: Number(event.target.value) })
                  }
                />
              )}
            </Field>

            <Field
              label="Cooling-off period (seconds)"
              hint="Time that must pass between the last material edit and submission, so a rushed change cannot be released immediately"
            >
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="number"
                  min="0"
                  max="86400"
                  value={draft.coolingOffSeconds}
                  onChange={(event) =>
                    setDraft({ ...draft, coolingOffSeconds: Number(event.target.value) })
                  }
                />
              )}
            </Field>

            <Field
              label="Blocking risk band"
              hint="Release is blocked at or above this band until every finding is dispositioned"
            >
              {(props) => (
                <select
                  {...props}
                  className="input"
                  value={draft.blockingRiskBand}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      blockingRiskBand: event.target
                        .value as OrganizationPolicyView['blockingRiskBand'],
                    })
                  }
                >
                  <option value="NEVER">Never block</option>
                  <option value="HIGH">High and above</option>
                  <option value="CRITICAL">Critical only</option>
                </select>
              )}
            </Field>
          </div>
        </div>

        <div className="card">
          <div className="card-body stack">
            <h2 className="section-title">Exports</h2>

            <Field label="Maximum rows in one export" hint="100 to 100,000">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="number"
                  min="100"
                  max="100000"
                  value={draft.maxExportRows}
                  onChange={(event) =>
                    setDraft({ ...draft, maxExportRows: Number(event.target.value) })
                  }
                />
              )}
            </Field>

            <label
              className="field"
              style={{ flexDirection: 'row', alignItems: 'center', gap: 'var(--s2)' }}
            >
              <input
                type="checkbox"
                checked={draft.allowL1FailedExport}
                onChange={(event) =>
                  setDraft({ ...draft, allowL1FailedExport: event.target.checked })
                }
              />
              <span className="label" style={{ margin: 0 }}>
                Payment Operations may download the failed-transactions CSV
              </span>
            </label>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 'var(--s3)' }}>
          <button className="button" data-variant="primary" type="submit" disabled={busy || !dirty}>
            {busy ? 'Saving…' : 'Save policy'}
          </button>
          {dirty && (
            <button
              className="button"
              data-variant="ghost"
              type="button"
              onClick={() => setDraft(policy)}
              disabled={busy}
            >
              Discard changes
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
