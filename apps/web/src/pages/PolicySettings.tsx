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
import {
  api,
  ApiError,
  type OrganizationPolicyView,
  type OrganizationUserView,
} from '../lib/api.js';
import { Notice, Field, TableSkeleton, Modal, RelativeTime } from '../components/primitives.js';

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

      <ConflictRegistry />
    </div>
  );
}

/**
 * Conflict-of-interest registry.
 *
 * A declared conflict bars that approver from authorizing payments in its scope, and the
 * release path has enforced that from the beginning against a table nothing could write to.
 * An executive who sits on a supplier's board, or is related to an employee, could not say
 * so — so the control existed and could never be invoked.
 *
 * Declarations are withdrawn rather than deleted. Who was barred from authorizing what, and
 * when that stopped, is the first thing an investigation asks.
 */
function ConflictRegistry() {
  const [conflicts, setConflicts] = useState<ConflictView[] | null>(null);
  const [members, setMembers] = useState<OrganizationUserView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [declaring, setDeclaring] = useState(false);

  const [userId, setUserId] = useState('');
  const [scopeType, setScopeType] = useState<'ORGANIZATION' | 'RECIPIENT' | 'DEPARTMENT'>(
    'ORGANIZATION',
  );
  const [scopeId, setScopeId] = useState('');
  const [reason, setReason] = useState('');

  const load = useCallback(async () => {
    try {
      const [registry, people] = await Promise.all([
        api.conflicts.list(),
        api.admin.users.list().catch(() => ({ users: [] as OrganizationUserView[] })),
      ]);
      setConflicts(registry.conflicts);
      setMembers(people.users);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The registry could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function act<T>(operation: () => Promise<T>, done?: () => void) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await operation();
      done?.();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  const live = (conflicts ?? []).filter((c) => c.withdrawnAt === null);

  return (
    <div className="card">
      <div className="card-body stack">
        <div className="page-header" style={{ marginBlockEnd: 0 }}>
          <div>
            <h2 className="section-title">Conflicts of interest</h2>
            <p className="small muted">
              A declared conflict stops that person authorizing payments in its scope. The release
              ceremony refuses them; it is not a reminder.
            </p>
          </div>
          <button
            className="button"
            data-variant="ghost"
            disabled={busy}
            onClick={() => setDeclaring(true)}
          >
            Declare a conflict
          </button>
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

        {conflicts === null ? (
          <TableSkeleton rows={2} columns={4} />
        ) : live.length === 0 ? (
          <p className="small muted">Nobody has a declared conflict.</p>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Person</th>
                  <th scope="col">Barred from</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Declared</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {live.map((conflict) => (
                  <tr key={conflict.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{conflict.userName}</div>
                      <div className="small muted">{conflict.email}</div>
                    </td>
                    <td className="small">
                      {conflict.scopeType === 'ORGANIZATION'
                        ? 'every payment in this organisation'
                        : `${conflict.scopeType.toLowerCase()}: ${conflict.scopeName ?? conflict.scopeId}`}
                    </td>
                    <td className="small">{conflict.reason}</td>
                    <td className="small">
                      <RelativeTime value={conflict.declaredAt} />
                      {conflict.declaredBy && <div className="muted">by {conflict.declaredBy}</div>}
                    </td>
                    <td>
                      <button
                        className="button button-sm"
                        data-variant="ghost"
                        disabled={busy}
                        onClick={() => {
                          const why = window.prompt(
                            'Why is this conflict no longer in force? (recorded in the audit trail)',
                          );
                          if (!why || why.trim().length < 10) return;
                          void act(
                            () => api.conflicts.withdraw(conflict.id, why.trim()),
                            () => setNotice('The declaration has been withdrawn.'),
                          );
                        }}
                      >
                        Withdraw
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {declaring && (
        <Modal open onClose={() => setDeclaring(false)} labelledBy="declare-conflict-title">
          <h2 id="declare-conflict-title" className="section-title">
            Declare a conflict of interest
          </h2>
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void act(
                () =>
                  api.conflicts.declare({
                    userId,
                    scopeType,
                    scopeId: scopeType === 'ORGANIZATION' ? null : scopeId,
                    reason,
                  }),
                () => {
                  setDeclaring(false);
                  setUserId('');
                  setScopeId('');
                  setReason('');
                  setNotice('Recorded. That person can no longer authorize within this scope.');
                },
              );
            }}
          >
            <Field label="Who">
              {(props) => (
                <select
                  {...props}
                  className="input"
                  required
                  value={userId}
                  onChange={(event) => setUserId(event.target.value)}
                >
                  <option value="">Choose a member</option>
                  {members.map((member) => (
                    <option key={member.userId} value={member.userId}>
                      {member.fullName} ({member.level})
                    </option>
                  ))}
                </select>
              )}
            </Field>

            <Field label="Scope">
              {(props) => (
                <select
                  {...props}
                  className="input"
                  value={scopeType}
                  onChange={(event) =>
                    setScopeType(event.target.value as 'ORGANIZATION' | 'RECIPIENT' | 'DEPARTMENT')
                  }
                >
                  <option value="ORGANIZATION">Every payment in this organisation</option>
                  <option value="RECIPIENT">One recipient</option>
                  <option value="DEPARTMENT">One department</option>
                </select>
              )}
            </Field>

            {scopeType !== 'ORGANIZATION' && (
              <Field
                label={`${scopeType === 'RECIPIENT' ? 'Recipient' : 'Department'} id`}
                hint="Copy it from the recipients or departments list."
              >
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    required
                    value={scopeId}
                    onChange={(event) => setScopeId(event.target.value)}
                  />
                )}
              </Field>
            )}

            <Field label="Why" hint="At least ten characters. Readable by anyone reviewing later.">
              {(props) => (
                <textarea
                  {...props}
                  className="input"
                  rows={3}
                  required
                  minLength={10}
                  maxLength={500}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              )}
            </Field>

            <div className="row" style={{ gap: 'var(--s2)' }}>
              <button className="button" data-variant="primary" type="submit" disabled={busy}>
                {busy ? 'Recording…' : 'Declare'}
              </button>
              <button
                className="button"
                data-variant="ghost"
                type="button"
                onClick={() => setDeclaring(false)}
              >
                Cancel
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}

interface ConflictView {
  id: string;
  userName: string;
  email: string;
  scopeType: string;
  scopeId: string | null;
  scopeName: string | null;
  reason: string;
  declaredAt: string;
  declaredBy: string | null;
  withdrawnAt: string | null;
}
