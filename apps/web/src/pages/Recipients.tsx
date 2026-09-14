/**
 * Recipients (spec §5.1, §11).
 *
 * The master record of who gets paid. Changing a phone number here is the cheapest payment
 * fraud in the product — no batch is touched, no approval is sought, and next payroll the
 * salary lands somewhere else — so the number is edited through its own dialog that insists
 * on a reason, and the old number is shown next to the new one before anything is saved.
 *
 * The payment history is on the same screen for the same reason: "was this number changed
 * just before that payment" is a question asked during an investigation, and it should not
 * require two screens and a database query to answer.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  api,
  ApiError,
  type RecipientView,
  type RecipientPayment,
  type DepartmentView,
  type SessionResponse,
} from '../lib/api.js';
import {
  Amount,
  Notice,
  EmptyState,
  TableSkeleton,
  Modal,
  Field,
  RelativeTime,
} from '../components/primitives.js';

export function RecipientsPage({
  capabilities,
}: {
  capabilities: SessionResponse['capabilities'];
}) {
  const [recipients, setRecipients] = useState<RecipientView[] | null>(null);
  const [departments, setDepartments] = useState<DepartmentView[]>([]);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [editingNumber, setEditingNumber] = useState<RecipientView | null>(null);
  const [viewing, setViewing] = useState<{
    recipient: RecipientView;
    totals: { successfulPayments: number; totalPaidCents: number };
    history: RecipientPayment[];
  } | null>(null);

  const canWrite = Boolean(capabilities['recipients:write']);
  const canReadDepartments = Boolean(capabilities['departments:read']);

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ pageSize: '200' });
      if (search.trim()) params.set('search', search.trim());
      if (statusFilter) params.set('status', statusFilter);
      const list = await api.recipients.list(params);
      setRecipients(list.recipients);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The recipient list could not be loaded.');
    }
  }, [search, statusFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!canReadDepartments) return;
    api.recipients
      .departments()
      .then((result) => setDepartments(result.departments))
      // A missing department list degrades the picker to "no department"; it must not take
      // the whole screen down with it.
      .catch(() => setDepartments([]));
  }, [canReadDepartments]);

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
          <h1 className="page-title">Recipients</h1>
          <p className="page-subtitle">
            Who this organisation pays. One record per phone number — two records for one number is
            how the same person gets paid twice.
          </p>
        </div>
        {canWrite && (
          <button
            className="button"
            data-variant="primary"
            disabled={busy}
            onClick={() => setCreating(true)}
          >
            Add recipient
          </button>
        )}
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

      <div className="card">
        <div className="card-body" style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
          <input
            className="input"
            placeholder="Search name, number or reference"
            aria-label="Search recipients"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            style={{ flex: '1 1 240px' }}
          />
          <select
            className="input"
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="">Every status</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
            <option value="BLOCKED">Blocked</option>
          </select>
        </div>
      </div>

      {recipients === null ? (
        <TableSkeleton rows={6} columns={5} />
      ) : recipients.length === 0 ? (
        <EmptyState title="No recipients">
          {search || statusFilter
            ? 'Nothing matches that filter.'
            : 'Add the people and suppliers this organisation pays, or let a CSV upload create them.'}
        </EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Recipient</th>
                  <th scope="col">Pays to</th>
                  <th scope="col">Department</th>
                  <th scope="col">Status</th>
                  <th scope="col">Number last changed</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {recipients.map((recipient) => (
                  <tr key={recipient.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{recipient.fullName}</div>
                      {recipient.externalReference && (
                        <div className="small muted">{recipient.externalReference}</div>
                      )}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono, monospace)' }}>
                      {recipient.msisdn}
                    </td>
                    <td className="small">{recipient.departmentName ?? '—'}</td>
                    <td>
                      <span
                        className="chip"
                        data-tone={
                          recipient.status === 'ACTIVE'
                            ? 'success'
                            : recipient.status === 'BLOCKED'
                              ? 'danger'
                              : 'neutral'
                        }
                      >
                        {recipient.status.toLowerCase()}
                      </span>
                    </td>
                    <td className="small">
                      <RelativeTime value={recipient.paymentDetailsModifiedAt} />
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                        <button
                          className="button button-sm"
                          data-variant="ghost"
                          disabled={busy}
                          onClick={() =>
                            void act(
                              () => api.recipients.detail(recipient.id),
                              (result) =>
                                setViewing({
                                  recipient: result.recipient,
                                  totals: result.totals,
                                  history: result.history,
                                }),
                            )
                          }
                        >
                          History
                        </button>
                        {canWrite && (
                          <>
                            <button
                              className="button button-sm"
                              data-variant="ghost"
                              disabled={busy}
                              onClick={() => setEditingNumber(recipient)}
                            >
                              Change number
                            </button>
                            <button
                              className="button button-sm"
                              data-variant="ghost"
                              disabled={busy}
                              onClick={() =>
                                void act(
                                  () =>
                                    api.recipients.update(recipient.id, {
                                      status: recipient.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE',
                                    }),
                                  () =>
                                    setNotice(
                                      recipient.status === 'ACTIVE'
                                        ? `${recipient.fullName} is now inactive and will not be paid.`
                                        : `${recipient.fullName} is active again.`,
                                    ),
                                )
                              }
                            >
                              {recipient.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {creating && (
        <Modal open onClose={() => setCreating(false)} labelledBy="new-recipient-title">
          <h2 id="new-recipient-title" className="section-title">
            Add recipient
          </h2>
          <NewRecipientForm
            departments={departments}
            busy={busy}
            onCancel={() => setCreating(false)}
            onSubmit={(body) =>
              void act(
                () => api.recipients.create(body),
                () => {
                  setNotice(`${body.fullName} has been added.`);
                  setCreating(false);
                },
              )
            }
          />
        </Modal>
      )}

      {editingNumber && (
        <ChangeNumberDialog
          recipient={editingNumber}
          busy={busy}
          onCancel={() => setEditingNumber(null)}
          onSubmit={(msisdn, reason) =>
            void act(
              () => api.recipients.update(editingNumber.id, { msisdn, reason }),
              (result) => {
                setNotice(result.message);
                setEditingNumber(null);
              },
            )
          }
        />
      )}

      {viewing && (
        <Modal open onClose={() => setViewing(null)} labelledBy="recipient-history-title">
          <h2 id="recipient-history-title" className="section-title">
            {viewing.recipient.fullName}
          </h2>
          <p className="small muted">
            {viewing.totals.successfulPayments} successful payment
            {viewing.totals.successfulPayments === 1 ? '' : 's'}, totalling{' '}
            <Amount cents={viewing.totals.totalPaidCents} />
          </p>
          {viewing.history.length === 0 ? (
            <EmptyState title="Never paid">
              This recipient has no payment history in the ledger.
            </EmptyState>
          ) : (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">When</th>
                    <th scope="col">Batch</th>
                    <th scope="col">Amount</th>
                    <th scope="col">Paid to</th>
                    <th scope="col">Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {viewing.history.map((payment) => (
                    <tr key={payment.transactionId}>
                      <td className="small">
                        <RelativeTime value={payment.completedAt ?? payment.createdAt} />
                      </td>
                      <td className="small">{payment.batchReference}</td>
                      <td>
                        <Amount cents={payment.amountCents} />
                      </td>
                      <td
                        className="small"
                        style={{ fontFamily: 'var(--font-mono, monospace)' }}
                        /* The number at the time, not today's — that difference is the
                           whole reason this column exists. */
                      >
                        {payment.paidToMsisdn}
                        {payment.paidToMsisdn !== viewing.recipient.msisdn && (
                          <div className="chip" data-tone="warning">
                            not the current number
                          </div>
                        )}
                      </td>
                      <td className="small">
                        {payment.status.toLowerCase()}
                        {payment.mpesaReceiptNumber && (
                          <div className="muted">{payment.mpesaReceiptNumber}</div>
                        )}
                        {payment.failureReason && (
                          <div className="muted">{payment.failureReason}</div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <button className="button" data-variant="ghost" onClick={() => setViewing(null)}>
            Close
          </button>
        </Modal>
      )}
    </div>
  );
}

function NewRecipientForm({
  departments,
  busy,
  onCancel,
  onSubmit,
}: {
  departments: DepartmentView[];
  busy: boolean;
  onCancel: () => void;
  onSubmit: (body: {
    fullName: string;
    msisdn: string;
    departmentId?: string | null;
    externalReference?: string | null;
  }) => void;
}) {
  const [fullName, setFullName] = useState('');
  const [msisdn, setMsisdn] = useState('');
  const [departmentId, setDepartmentId] = useState('');
  const [externalReference, setExternalReference] = useState('');

  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          fullName,
          msisdn,
          departmentId: departmentId || null,
          externalReference: externalReference || null,
        });
      }}
    >
      <Field label="Full name">
        {(props) => (
          <input
            {...props}
            className="input"
            required
            minLength={2}
            maxLength={160}
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
          />
        )}
      </Field>
      <Field label="Phone number" hint="0712345678 or 254712345678 — both are accepted.">
        {(props) => (
          <input
            {...props}
            className="input"
            required
            inputMode="tel"
            value={msisdn}
            onChange={(event) => setMsisdn(event.target.value)}
          />
        )}
      </Field>
      <Field label="Department">
        {(props) => (
          <select
            {...props}
            className="input"
            value={departmentId}
            onChange={(event) => setDepartmentId(event.target.value)}
          >
            <option value="">No department</option>
            {departments.map((department) => (
              <option key={department.id} value={department.id}>
                {department.name}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field label="Your reference" hint="Staff number, supplier code — whatever you file by.">
        {(props) => (
          <input
            {...props}
            className="input"
            maxLength={64}
            value={externalReference}
            onChange={(event) => setExternalReference(event.target.value)}
          />
        )}
      </Field>
      <div style={{ display: 'flex', gap: 'var(--s2)' }}>
        <button className="button" data-variant="primary" type="submit" disabled={busy}>
          {busy ? 'Adding…' : 'Add recipient'}
        </button>
        <button className="button" data-variant="ghost" type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function ChangeNumberDialog({
  recipient,
  busy,
  onCancel,
  onSubmit,
}: {
  recipient: RecipientView;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (msisdn: string, reason: string) => void;
}) {
  const [msisdn, setMsisdn] = useState('');
  const [reason, setReason] = useState('');

  return (
    <Modal open onClose={onCancel} labelledBy="change-number-title">
      <h2 id="change-number-title" className="section-title">
        Change where {recipient.fullName} is paid
      </h2>

      <Notice tone="warning">
        This changes the destination of every future payment to this person. The old and the new
        number are both recorded, with your reason, and any batch prepared before now still carries
        the old number.
      </Notice>

      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit(msisdn, reason);
        }}
      >
        <Field label="Current number">
          {(props) => (
            <input {...props} className="input" value={recipient.msisdn} readOnly disabled />
          )}
        </Field>
        <Field label="New number">
          {(props) => (
            <input
              {...props}
              className="input"
              required
              inputMode="tel"
              value={msisdn}
              onChange={(event) => setMsisdn(event.target.value)}
            />
          )}
        </Field>
        <Field
          label="Why is it changing?"
          hint="Read by whoever reviews the risk signal this raises. At least ten characters."
        >
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
        <div style={{ display: 'flex', gap: 'var(--s2)' }}>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Saving…' : 'Change the number'}
          </button>
          <button className="button" data-variant="ghost" type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}
