/**
 * Batch detail and review (spec §5, §7.3 — the middle of the command hierarchy).
 *
 * This screen was the hole the whole three-level hierarchy fell through. The console could
 * create a batch in a one-shot wizard and an L3 could authorize one that had reached
 * L3_READY — but nothing could move a batch between those two points, and nothing could
 * reopen a draft after the wizard closed. Concretely, before this file:
 *
 *   - an L1 who closed the wizard could see their draft in the list and never touch it
 *     again: no upload, no validate, no submit;
 *   - no L2 anywhere could approve, reject, return or hold, so a batch submitted to Finance
 *     Control could never reach the executive. Every payment was stuck one step short of
 *     the ceremony that the rest of the system exists to protect.
 *
 * The actions offered come from `availableCommands`, which the server computes for this
 * caller against this batch's state. The screen renders what it is given rather than
 * deciding for itself, so it cannot offer a button the API would refuse — and an L1 is
 * never shown Approve at all rather than discovering the refusal by pressing it.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type BatchDetailView } from '../lib/api.js';
import {
  Amount,
  Notice,
  EmptyState,
  BatchStateChip,
  Modal,
  Field,
  RelativeTime,
  TableSkeleton,
} from '../components/primitives.js';

/** What each command is called where an operator can see it, and how alarming it looks. */
const ACTIONS: Record<
  string,
  { label: string; variant: 'primary' | 'ghost'; needsReason: boolean; confirm?: string }
> = {
  VALIDATE: { label: 'Validate', variant: 'primary', needsReason: false },
  SUBMIT_TO_L2: { label: 'Submit to Finance Control', variant: 'primary', needsReason: false },
  APPROVE_TO_L3: { label: 'Approve for release', variant: 'primary', needsReason: true },
  REJECT: { label: 'Return for correction', variant: 'ghost', needsReason: true },
  HOLD: { label: 'Place on hold', variant: 'ghost', needsReason: true },
  RELEASE_HOLD: { label: 'Lift the hold', variant: 'ghost', needsReason: false },
  CANCEL: {
    label: 'Cancel batch',
    variant: 'ghost',
    needsReason: true,
    confirm: 'A cancelled batch cannot be revived. Its instructions will never be paid.',
  },
};

/** Commands driven from elsewhere: the ceremony has its own screen, editing its own flow. */
const HANDLED_ELSEWHERE = new Set(['BEGIN_AUTHORIZATION', 'ABANDON_AUTHORIZATION', 'INVALIDATE']);

export function BatchDetail({
  batchId,
  onClose,
  onChanged,
  onAuthorize,
}: {
  batchId: string;
  onClose: () => void;
  onChanged: () => void;
  onAuthorize: (batchId: string) => void;
}) {
  const [data, setData] = useState<BatchDetailView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [acknowledge, setAcknowledge] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploadResult, setUploadResult] = useState<{
    accepted: number;
    rejected: { lineNumber: number; column: string; value: string; reason: string }[];
    duplicateWarnings: { reason: string }[];
  } | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.batches.detail(batchId));
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The batch could not be loaded.');
    }
  }, [batchId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function act<T>(operation: () => Promise<T>, done?: (result: T) => void) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await operation();
      done?.(result);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  function run(command: string, why: string) {
    switch (command) {
      case 'VALIDATE':
        return act(
          () => api.batches.validate(batchId),
          (result) =>
            setNotice(
              `Validated. Risk ${result.risk.band.toLowerCase()} (${result.risk.score}), ${result.risk.signals.length} finding${result.risk.signals.length === 1 ? '' : 's'}.`,
            ),
        );
      case 'SUBMIT_TO_L2':
        return act(
          () => api.batches.submit(batchId),
          () =>
            setNotice(
              'Submitted to Finance Control. You cannot approve your own batch — that is the separation working.',
            ),
        );
      case 'APPROVE_TO_L3':
        return act(
          () => api.batches.approve(batchId, why, acknowledge),
          () => setNotice('Approved. It is now with the executive authority for release.'),
        );
      case 'REJECT':
        return act(
          () => api.batches.reject(batchId, why),
          () => setNotice('Returned to Payment Operations with your reason.'),
        );
      case 'HOLD':
        return act(
          () => api.batches.hold(batchId, why),
          () => setNotice('Placed on hold. Nothing will be paid until the hold is lifted.'),
        );
      case 'RELEASE_HOLD':
        return act(
          () => api.batches.releaseHold(batchId, why || undefined),
          () => setNotice('The hold is lifted and the batch is back in the review queue.'),
        );
      case 'CANCEL':
        return act(
          () => api.batches.cancel(batchId, why),
          () => setNotice('The batch is cancelled. Its instructions will never be paid.'),
        );
      default:
        return undefined;
    }
  }

  if (error && !data) {
    return (
      <Modal open onClose={onClose} labelledBy="batch-detail-title">
        <h2 id="batch-detail-title" className="section-title">
          Batch
        </h2>
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
        <button className="button" data-variant="ghost" onClick={onClose}>
          Close
        </button>
      </Modal>
    );
  }

  if (!data) {
    return (
      <Modal open onClose={onClose} labelledBy="batch-detail-title">
        <h2 id="batch-detail-title" className="section-title">
          Loading batch…
        </h2>
        <TableSkeleton rows={4} columns={4} />
      </Modal>
    );
  }

  const { batch, instructions, approvals, riskFindings } = data;
  const commands = batch.availableCommands.filter(
    (command) => ACTIONS[command] && !HANDLED_ELSEWHERE.has(command),
  );
  const canAuthorize = batch.availableCommands.includes('BEGIN_AUTHORIZATION');
  const openFindings = riskFindings.filter((f) => f.disposition === 'OPEN' && f.currentVersion);
  const needsUpload = batch.instructionCount === 0;

  return (
    <Modal open onClose={onClose} labelledBy="batch-detail-title" dismissible={!busy}>
      <div className="stack">
        <div>
          <h2 id="batch-detail-title" className="section-title">
            {batch.batchReference}
          </h2>
          <p className="small muted">
            {batch.purpose} · <BatchStateChip state={batch.state} /> · version {batch.version}
          </p>
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

        <div className="row" style={{ gap: 'var(--s4)', flexWrap: 'wrap' }}>
          <div>
            <div className="stat-label">Recipients</div>
            <div className="stat-value">{batch.instructionCount.toLocaleString('en-KE')}</div>
          </div>
          <div>
            <div className="stat-label">Total</div>
            <div className="stat-value">
              <Amount cents={batch.totalAmountCents} />
            </div>
          </div>
          {batch.riskBand && (
            <div>
              <div className="stat-label">Risk</div>
              <div className="stat-value">
                {batch.riskBand.toLowerCase()} ({batch.riskScore})
              </div>
            </div>
          )}
        </div>

        {/* ---- Resuming a draft ------------------------------------------- */}
        {batch.editable && (
          <div className="card">
            <div className="card-body stack">
              <h3 className="section-title">
                {needsUpload ? 'Add the recipients' : 'Replace the recipients'}
              </h3>
              <p className="small muted">
                {needsUpload
                  ? 'This draft has no rows yet. Upload the CSV to fill it in — you can come back to an unfinished draft at any time.'
                  : 'Uploading again replaces every row in this draft, and returns the batch to DRAFT so it must be validated again.'}
              </p>

              <input
                className="input"
                type="file"
                accept=".csv,text/csv"
                aria-label="CSV file"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              />
              <button
                className="button"
                data-variant={needsUpload ? 'primary' : 'ghost'}
                disabled={busy || !file}
                onClick={() =>
                  void act(
                    () => api.batches.uploadCsv(batchId, file!),
                    (result) => {
                      setUploadResult(result);
                      setFile(null);
                      setNotice(
                        `${result.accepted} row${result.accepted === 1 ? '' : 's'} accepted.`,
                      );
                    },
                  )
                }
              >
                {busy ? 'Uploading…' : 'Upload CSV'}
              </button>

              {uploadResult && uploadResult.rejected.length > 0 && (
                <>
                  <Notice tone="warning">
                    {uploadResult.rejected.length} row
                    {uploadResult.rejected.length === 1 ? ' was' : 's were'} rejected. The rest were
                    accepted — fix these lines and upload again, or carry on without them.
                  </Notice>
                  <div className="table-scroll">
                    <table className="table">
                      <thead>
                        <tr>
                          <th scope="col">Line</th>
                          <th scope="col">Value</th>
                          <th scope="col">Why</th>
                        </tr>
                      </thead>
                      <tbody>
                        {uploadResult.rejected.map((row) => (
                          <tr key={`${row.lineNumber}-${row.column}`}>
                            <td>{row.lineNumber}</td>
                            <td className="small">{row.value || '—'}</td>
                            <td className="small">{row.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
              {uploadResult?.duplicateWarnings.map((warning) => (
                <Notice tone="warning" key={warning.reason}>
                  {warning.reason}
                </Notice>
              ))}
            </div>
          </div>
        )}

        {/* ---- Risk findings ---------------------------------------------- */}
        {openFindings.length > 0 && (
          <div className="card">
            <div className="card-body stack">
              <h3 className="section-title">Risk findings</h3>
              {openFindings.map((finding, index) => (
                <Notice
                  key={`${finding.type}-${index}`}
                  tone={
                    finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                      ? 'danger'
                      : 'warning'
                  }
                >
                  <strong>{finding.severity}</strong> · {finding.summary}
                </Notice>
              ))}
            </div>
          </div>
        )}

        {/* ---- Instructions ------------------------------------------------ */}
        <div className="card">
          <div className="card-body">
            <h3 className="section-title">Recipients</h3>
          </div>
          {instructions.length === 0 ? (
            <div className="card-body">
              <EmptyState title="No rows yet">Upload a CSV above to fill this batch in.</EmptyState>
            </div>
          ) : (
            <div className="table-scroll" style={{ maxHeight: '18rem' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Recipient</th>
                    <th scope="col">Phone</th>
                    <th scope="col">Amount</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {instructions.map((instruction) => (
                    <tr key={instruction.instructionId}>
                      <td>{instruction.recipientName}</td>
                      <td className="small mono">{instruction.msisdn}</td>
                      <td className="numeric">
                        <Amount cents={instruction.amountCents} showCurrency={false} />
                      </td>
                      <td className="small">{instruction.status.toLowerCase()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ---- Approval history -------------------------------------------- */}
        {approvals.length > 0 && (
          <div className="card">
            <div className="card-body">
              <h3 className="section-title">Decisions</h3>
            </div>
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">When</th>
                    <th scope="col">Decision</th>
                    <th scope="col">By</th>
                    <th scope="col">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {approvals.map((approval) => (
                    <tr key={approval.approval_reference}>
                      <td className="small">
                        <RelativeTime value={approval.created_at} />
                      </td>
                      <td className="small">{approval.action.replace(/_/g, ' ').toLowerCase()}</td>
                      <td className="small">{approval.actor_level}</td>
                      <td className="small">{approval.reason ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ---- What this person may do next -------------------------------- */}
        <div className="row" style={{ gap: 'var(--s2)', flexWrap: 'wrap' }}>
          {canAuthorize && (
            <button
              className="button"
              data-variant="primary"
              disabled={busy}
              onClick={() => onAuthorize(batchId)}
            >
              Review &amp; authorize
            </button>
          )}
          {commands.map((command) => {
            const action = ACTIONS[command]!;
            return (
              <button
                key={command}
                className="button"
                data-variant={action.variant}
                disabled={busy || (command === 'SUBMIT_TO_L2' && batch.instructionCount === 0)}
                onClick={() => {
                  if (action.needsReason || action.confirm) {
                    setReason('');
                    setAcknowledge(false);
                    setPending(command);
                  } else {
                    void run(command, '');
                  }
                }}
              >
                {action.label}
              </button>
            );
          })}
          <button className="button" data-variant="ghost" onClick={onClose} disabled={busy}>
            Close
          </button>
        </div>

        {commands.length === 0 && !canAuthorize && (
          <p className="small muted">
            Nothing is waiting on you for this batch at your authority level.
          </p>
        )}
      </div>

      {pending && (
        <Modal open onClose={() => setPending(null)} labelledBy="batch-decision-title">
          <h2 id="batch-decision-title" className="section-title">
            {ACTIONS[pending]!.label}
          </h2>
          {ACTIONS[pending]!.confirm && <Notice tone="warning">{ACTIONS[pending]!.confirm}</Notice>}

          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              const command = pending;
              setPending(null);
              void run(command, reason);
            }}
          >
            <Field
              label="Reason"
              hint="Recorded against the batch and readable by everyone who reviews it later."
            >
              {(props) => (
                <textarea
                  {...props}
                  className="input"
                  rows={3}
                  required={ACTIONS[pending]!.needsReason}
                  maxLength={1000}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              )}
            </Field>

            {pending === 'APPROVE_TO_L3' && openFindings.length > 0 && (
              <label className="small" style={{ display: 'flex', gap: 'var(--s2)' }}>
                <input
                  type="checkbox"
                  checked={acknowledge}
                  onChange={(event) => setAcknowledge(event.target.checked)}
                />
                I have reviewed the {openFindings.length} open risk finding
                {openFindings.length === 1 ? '' : 's'} and am approving anyway.
              </label>
            )}

            <div className="row" style={{ gap: 'var(--s2)' }}>
              <button className="button" data-variant="primary" type="submit" disabled={busy}>
                {ACTIONS[pending]!.label}
              </button>
              <button
                className="button"
                data-variant="ghost"
                type="button"
                onClick={() => setPending(null)}
              >
                Cancel
              </button>
            </div>
          </form>
        </Modal>
      )}
    </Modal>
  );
}
