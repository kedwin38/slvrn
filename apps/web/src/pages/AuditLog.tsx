/**
 * Audit trail (spec §4.3, §14).
 *
 * The audit log is the system's evidence, and evidence nobody can look at is not evidence.
 * The API has served it from the start; there was no screen, so the only way to read it was
 * `psql`.
 *
 * The chain verification button is the point of this page. Every event carries the hash of
 * its predecessor, so re-computing the chain proves that nothing has been inserted, removed,
 * reordered or edited — including by someone with database access. A log you cannot verify
 * only tells you what it currently says, which is a different claim entirely.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type AuditEventView } from '../lib/api.js';
import { Notice, EmptyState, TableSkeleton, RelativeTime } from '../components/primitives.js';

const EVENT_CLASSES = ['', 'PAYMENT', 'IDENTITY', 'SECURITY', 'ADMIN', 'DATA'] as const;

export function AuditLogPage() {
  const [events, setEvents] = useState<AuditEventView[] | null>(null);
  const [eventClass, setEventClass] = useState('');
  const [outcome, setOutcome] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [verification, setVerification] = useState<{ valid: boolean; message: string } | null>(
    null,
  );

  const load = useCallback(async () => {
    const params = new URLSearchParams({ limit: '200' });
    if (eventClass) params.set('eventClass', eventClass);
    if (outcome) params.set('outcome', outcome);
    try {
      const result = await api.admin.audit.list(params);
      setEvents(result.events);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The audit trail could not be loaded.');
    }
  }, [eventClass, outcome]);

  useEffect(() => {
    void load();
  }, [load]);

  async function verify() {
    setBusy(true);
    setError(null);
    setVerification(null);
    try {
      const result = await api.admin.audit.verify();
      setVerification({
        valid: result.valid,
        message: result.valid
          ? `${result.eventsVerified} events verified. ${result.interpretation}`
          : `${result.interpretation}${
              result.brokenEventId ? ` Event: ${result.brokenEventId}.` : ''
            }${result.reason ? ` ${result.reason}` : ''}`,
      });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Verification could not be run.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit trail</h1>
          <p className="page-subtitle">
            Every action that changed money, identity or configuration. Append-only: the database
            refuses updates and deletes.
          </p>
        </div>
        <button
          className="button"
          data-variant="primary"
          onClick={() => void verify()}
          disabled={busy}
        >
          {busy ? 'Verifying…' : 'Verify chain'}
        </button>
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      {verification && (
        <Notice tone={verification.valid ? 'success' : 'danger'} live="assertive">
          {verification.message}
        </Notice>
      )}

      <div className="card">
        <div className="card-body" style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
          <label className="field" style={{ minWidth: 200 }}>
            <span className="label">Event class</span>
            <select
              className="input"
              value={eventClass}
              onChange={(event) => setEventClass(event.target.value)}
            >
              {EVENT_CLASSES.map((value) => (
                <option key={value || 'all'} value={value}>
                  {value || 'All classes'}
                </option>
              ))}
            </select>
          </label>

          <label className="field" style={{ minWidth: 200 }}>
            <span className="label">Outcome</span>
            <select
              className="input"
              value={outcome}
              onChange={(event) => setOutcome(event.target.value)}
            >
              <option value="">All outcomes</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
              <option value="DENIED">Denied</option>
            </select>
          </label>
        </div>
      </div>

      {events === null ? (
        <TableSkeleton rows={8} columns={6} />
      ) : events.length === 0 ? (
        <EmptyState title="No matching events">
          Nothing has been recorded under this filter yet.
        </EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Seq</th>
                  <th scope="col">When</th>
                  <th scope="col">Action</th>
                  <th scope="col">Object</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.event_reference}>
                    <td className="small muted">{event.sequence}</td>
                    <td>
                      <RelativeTime value={event.occurred_at} />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{event.action}</div>
                      <div className="small muted">{event.event_class}</div>
                    </td>
                    <td className="small">
                      {event.object_type ?? '—'}
                      {event.object_id && (
                        <div className="muted">{event.object_id.slice(0, 8)}…</div>
                      )}
                    </td>
                    <td className="small">{event.actor_level ?? '—'}</td>
                    <td>
                      <span
                        className="chip"
                        data-tone={
                          event.outcome === 'SUCCESS'
                            ? 'positive'
                            : event.outcome === 'DENIED'
                              ? 'warning'
                              : 'negative'
                        }
                      >
                        {event.outcome.toLowerCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
