/**
 * Reconciliation (spec §6.5, §9.3).
 *
 * Every row here is a payment the organisation cannot account for: M-PESA accepted the
 * request and never came back with an answer. That is worse than a failure, because a
 * failure is known.
 *
 * The screen offers exactly two actions, and the difference between them is the whole point:
 *
 *   "Ask M-PESA again" puts the question back to the provider. The provider's answer settles
 *   the ledger, as it does for every other payment.
 *
 *   "Close the case" records what a human established — from the M-PESA organisation portal,
 *   or from Safaricom support — as evidence. Closing as failed writes the ledger, because the
 *   state machine permits it with a provider code. There is no "mark as paid": a payment the
 *   provider never confirmed stays unconfirmed in the ledger however sure the operator is,
 *   because the ledger is what the auditor reads.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type ReconciliationCaseView, type SessionResponse } from '../lib/api.js';
import {
  Amount,
  Notice,
  EmptyState,
  TableSkeleton,
  Modal,
  Field,
  RelativeTime,
} from '../components/primitives.js';

const STATE_TONE: Record<string, string> = {
  OPEN: 'warning',
  QUERYING: 'info',
  ESCALATED: 'danger',
  RESOLVED_SUCCESS: 'success',
  RESOLVED_FAILED: 'neutral',
  RESOLVED_MANUAL: 'neutral',
};

export function ReconciliationPage({
  capabilities,
}: {
  capabilities: SessionResponse['capabilities'];
}) {
  const [cases, setCases] = useState<ReconciliationCaseView[] | null>(null);
  const [summary, setSummary] = useState<{ outstanding: number; discrepancies: number } | null>(
    null,
  );
  const [outstandingOnly, setOutstandingOnly] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resolving, setResolving] = useState<ReconciliationCaseView | null>(null);

  const canResolve = Boolean(capabilities['reconciliation:resolve']);

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ pageSize: '100' });
      if (outstandingOnly) params.set('outstanding', 'true');
      const [list, counts] = await Promise.all([
        api.reconciliation.list(params),
        api.reconciliation.summary(),
      ]);
      setCases(list.cases);
      setSummary({ outstanding: counts.outstanding, discrepancies: counts.discrepancies });
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The cases could not be loaded.');
    }
  }, [outstandingOnly]);

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
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Reconciliation</h1>
          <p className="page-subtitle">
            Payments M-PESA accepted but never confirmed. Until one of these is settled, the
            organisation cannot say whether that person was paid.
          </p>
        </div>
        <label
          className="small"
          style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}
        >
          <input
            type="checkbox"
            checked={outstandingOnly}
            onChange={(event) => setOutstandingOnly(event.target.checked)}
          />
          Outstanding only
        </label>
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

      {summary && summary.discrepancies > 0 && (
        <Notice tone="warning">
          {summary.discrepancies} case{summary.discrepancies === 1 ? '' : 's'} where a status query
          contradicted a settled ledger row. The ledger was not rewritten; a person decides what
          happened.
        </Notice>
      )}

      {cases === null ? (
        <TableSkeleton rows={5} columns={6} />
      ) : cases.length === 0 ? (
        <EmptyState title={outstandingOnly ? 'Nothing outstanding' : 'No cases'}>
          Every payment has a confirmed outcome. This is the state you want to be in.
        </EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Case</th>
                  <th scope="col">Recipient</th>
                  <th scope="col">Amount</th>
                  <th scope="col">Ledger says</th>
                  <th scope="col">Opened because</th>
                  <th scope="col">Waiting</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item) => {
                  const open = ['OPEN', 'QUERYING', 'ESCALATED'].includes(item.state);
                  return (
                    <tr key={item.caseId}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{item.caseReference}</div>
                        <div className="small">
                          <span className="chip" data-tone={STATE_TONE[item.state] ?? 'neutral'}>
                            {item.state.replace(/_/g, ' ').toLowerCase()}
                          </span>
                        </div>
                        {item.discrepancy && (
                          <div className="small">
                            <span className="chip" data-tone="danger">
                              discrepancy
                            </span>
                          </div>
                        )}
                      </td>
                      <td>
                        <div>{item.transaction.recipientName}</div>
                        <div className="small muted">{item.transaction.msisdn}</div>
                        <div className="small muted">{item.transaction.batchReference}</div>
                      </td>
                      <td>
                        <Amount cents={item.transaction.amountCents} />
                      </td>
                      <td>
                        <span className="chip" data-tone="info">
                          {item.transaction.status.toLowerCase()}
                        </span>
                        {item.transaction.mpesaReceiptNumber && (
                          <div className="small muted">{item.transaction.mpesaReceiptNumber}</div>
                        )}
                      </td>
                      <td className="small">
                        {item.openedReason}
                        <div className="muted">
                          {item.queryAttempts} status quer
                          {item.queryAttempts === 1 ? 'y' : 'ies'} so far
                        </div>
                        {item.resolutionNote && (
                          <div className="muted">Resolved: {item.resolutionNote}</div>
                        )}
                      </td>
                      <td className="small">
                        <RelativeTime value={item.openedAt} />
                      </td>
                      <td>
                        {canResolve && open ? (
                          <div className="row-actions">
                            <button
                              className="button button-sm"
                              data-variant="ghost"
                              disabled={busy}
                              onClick={() =>
                                void act(
                                  () => api.reconciliation.query(item.caseId),
                                  (result) => setNotice(result.message),
                                )
                              }
                            >
                              Ask M-PESA again
                            </button>
                            <button
                              className="button button-sm"
                              data-variant="ghost"
                              disabled={busy}
                              onClick={() => setResolving(item)}
                            >
                              Close case
                            </button>
                          </div>
                        ) : (
                          <span className="small muted">
                            {open ? 'view only' : (item.resolvedBy ?? 'closed')}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {resolving && (
        <ResolveDialog
          item={resolving}
          busy={busy}
          onCancel={() => setResolving(null)}
          onSubmit={(body) =>
            void act(
              () => api.reconciliation.resolve(resolving.caseId, body),
              (result) => {
                setNotice(result.message);
                setResolving(null);
              },
            )
          }
        />
      )}
    </div>
  );
}

function ResolveDialog({
  item,
  busy,
  onCancel,
  onSubmit,
}: {
  item: ReconciliationCaseView;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (body: {
    outcome: 'FAILED' | 'MANUAL';
    failureCode?: string;
    providerReceipt?: string;
    note: string;
  }) => void;
}) {
  const [outcome, setOutcome] = useState<'FAILED' | 'MANUAL'>('MANUAL');
  const [failureCode, setFailureCode] = useState('');
  const [providerReceipt, setProviderReceipt] = useState('');
  const [note, setNote] = useState('');

  return (
    <Modal open onClose={onCancel} labelledBy="resolve-case-title">
      <h2 id="resolve-case-title" className="section-title">
        Close {item.caseReference}
      </h2>
      <p className="small muted">
        {item.transaction.recipientName} · {item.transaction.msisdn}
      </p>

      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({
            outcome,
            failureCode: outcome === 'FAILED' ? failureCode : undefined,
            providerReceipt: providerReceipt || undefined,
            note,
          });
        }}
      >
        <Field label="What did you establish?">
          {(props) => (
            <select
              {...props}
              className="input"
              value={outcome}
              onChange={(event) => setOutcome(event.target.value as 'FAILED' | 'MANUAL')}
            >
              <option value="MANUAL">
                Settled outside the system — record my findings, leave the ledger alone
              </option>
              <option value="FAILED">
                M-PESA confirmed this payment failed — record it as failed
              </option>
            </select>
          )}
        </Field>

        {outcome === 'FAILED' && (
          <Field
            label="Provider failure code"
            hint="From the M-PESA portal or Safaricom support. A failure is never recorded without one."
          >
            {(props) => (
              <input
                {...props}
                className="input"
                required
                maxLength={32}
                value={failureCode}
                onChange={(event) => setFailureCode(event.target.value)}
              />
            )}
          </Field>
        )}

        <Field label="M-PESA receipt, if you have one" hint="Kept as evidence on the case.">
          {(props) => (
            <input
              {...props}
              className="input"
              maxLength={64}
              value={providerReceipt}
              onChange={(event) => setProviderReceipt(event.target.value)}
            />
          )}
        </Field>

        <Field
          label="What you found, and where"
          hint="Read by whoever audits this payment. At least ten characters."
        >
          {(props) => (
            <textarea
              {...props}
              className="input"
              rows={4}
              required
              minLength={10}
              maxLength={2000}
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          )}
        </Field>

        {outcome === 'MANUAL' && (
          <Notice tone="info">
            The transaction stays as it is. M-PESA never confirmed an outcome, and the ledger will
            keep saying so — your findings are attached to the case instead.
          </Notice>
        )}

        <div style={{ display: 'flex', gap: 'var(--s2)' }}>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Closing…' : 'Close case'}
          </button>
          <button className="button" data-variant="ghost" type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}
