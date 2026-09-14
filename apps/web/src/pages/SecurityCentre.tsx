/**
 * Security Centre (spec §8, §13).
 *
 * The platform has been recording security events since the first commit — failed sign-ins,
 * callback signature mismatches, changed payment details, reconciliation escalations — and
 * until this screen there was no way to read any of them. A detection nobody can see is not
 * a control, it is a log file.
 *
 * Acknowledging is a recorded act, not a dismiss button: it captures who reviewed a critical
 * event and when, which is the first question asked after an incident. Already-acknowledged
 * events keep the first reviewer's name; a second pass over the list cannot overwrite it.
 */

import { useCallback, useEffect, useState } from 'react';
import {
  api,
  ApiError,
  type SecurityEventView,
  type LiveSessionView,
  type TrustedDeviceView,
} from '../lib/api.js';
import { Notice, EmptyState, TableSkeleton, RelativeTime } from '../components/primitives.js';

const SEVERITY_TONE: Record<string, string> = {
  CRITICAL: 'danger',
  WARNING: 'warning',
  INFO: 'neutral',
};

export function SecurityCentrePage() {
  const [events, setEvents] = useState<SecurityEventView[] | null>(null);
  const [counts, setCounts] = useState<{ severity: string; open: number; total: number }[]>([]);
  const [sessions, setSessions] = useState<LiveSessionView[] | null>(null);
  const [devices, setDevices] = useState<TrustedDeviceView[]>([]);
  const [unacknowledgedOnly, setUnacknowledgedOnly] = useState(true);
  const [severity, setSeverity] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ pageSize: '100' });
      if (unacknowledgedOnly) params.set('unacknowledgedOnly', 'true');
      if (severity) params.set('severity', severity);
      const [eventResult, sessionResult] = await Promise.all([
        api.security.events(params),
        api.security.sessions(),
      ]);
      setEvents(eventResult.events);
      setCounts(eventResult.counts);
      setSessions(sessionResult.sessions);
      setDevices(sessionResult.devices);
      setSelected(new Set());
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The security centre could not be loaded.');
    }
  }, [unacknowledgedOnly, severity]);

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

  const criticalOpen = counts.find((row) => row.severity === 'CRITICAL')?.open ?? 0;

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security centre</h1>
          <p className="page-subtitle">
            What the platform noticed, who is signed in, and from which devices. Everything here is
            recorded whether or not anybody reads it — this is where somebody reads it.
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
      {criticalOpen > 0 && (
        <Notice tone="danger">
          {criticalOpen} critical event{criticalOpen === 1 ? '' : 's'} nobody has reviewed.
        </Notice>
      )}

      <div className="card">
        <div className="card-body" style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
          <label
            className="small"
            style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}
          >
            <input
              type="checkbox"
              checked={unacknowledgedOnly}
              onChange={(event) => setUnacknowledgedOnly(event.target.checked)}
            />
            Unreviewed only
          </label>
          <select
            className="input"
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="">Every severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="WARNING">Warning</option>
            <option value="INFO">Information</option>
          </select>
          <button
            className="button"
            data-variant="primary"
            disabled={busy || selected.size === 0}
            onClick={() =>
              void act(
                () => api.security.acknowledge([...selected]),
                (result) =>
                  setNotice(
                    `${result.acknowledged} event${result.acknowledged === 1 ? '' : 's'} marked as reviewed by you.`,
                  ),
              )
            }
          >
            Mark {selected.size > 0 ? `${selected.size} ` : ''}as reviewed
          </button>
        </div>
      </div>

      {events === null ? (
        <TableSkeleton rows={6} columns={5} />
      ) : events.length === 0 ? (
        <EmptyState title="Nothing to review">No security events match this filter.</EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">
                    <span className="visually-hidden">Select</span>
                  </th>
                  <th scope="col">When</th>
                  <th scope="col">Event</th>
                  <th scope="col">Who</th>
                  <th scope="col">Where from</th>
                  <th scope="col">Reviewed</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>
                      {event.acknowledgedAt === null && (
                        <input
                          type="checkbox"
                          aria-label={`Select ${event.description}`}
                          checked={selected.has(event.id)}
                          onChange={(change) => {
                            const next = new Set(selected);
                            if (change.target.checked) next.add(event.id);
                            else next.delete(event.id);
                            setSelected(next);
                          }}
                        />
                      )}
                    </td>
                    <td className="small">
                      <RelativeTime value={event.createdAt} />
                    </td>
                    <td>
                      <span className="chip" data-tone={SEVERITY_TONE[event.severity] ?? 'neutral'}>
                        {event.severity.toLowerCase()}
                      </span>
                      <div style={{ fontWeight: 600 }}>{event.description}</div>
                      <div className="small muted">{event.eventType}</div>
                    </td>
                    <td className="small">
                      {event.user ? (
                        <>
                          <div>{event.user.name}</div>
                          <div className="muted">{event.user.email}</div>
                        </>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="small">
                      {event.ip ?? '—'}
                      {event.userAgent && (
                        <div className="muted" style={{ maxWidth: '22ch', overflow: 'hidden' }}>
                          {event.userAgent}
                        </div>
                      )}
                    </td>
                    <td className="small">
                      {event.acknowledgedAt ? (
                        <>
                          <RelativeTime value={event.acknowledgedAt} />
                          <div className="muted">{event.acknowledgedBy}</div>
                        </>
                      ) : (
                        <span className="chip" data-tone="warning">
                          not reviewed
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Signed in right now</h2>
          <p className="small muted">
            Two live sessions for one account from two places is what a stolen session looks like.
            Revoking one signs that browser out immediately.
          </p>
          {sessions === null ? (
            <TableSkeleton rows={3} columns={4} />
          ) : sessions.length === 0 ? (
            <EmptyState title="Nobody is signed in" />
          ) : (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Who</th>
                    <th scope="col">Verified</th>
                    <th scope="col">From</th>
                    <th scope="col">Last active</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{session.userName}</div>
                        <div className="small muted">
                          {session.email} · {session.authorityLevel}
                        </div>
                      </td>
                      <td>
                        {session.webauthnVerified ? (
                          <span className="chip" data-tone="success">
                            security key
                          </span>
                        ) : (
                          <span className="chip" data-tone="neutral">
                            password only
                          </span>
                        )}
                      </td>
                      <td className="small">
                        {session.ip ?? '—'}
                        {session.deviceLabel && <div className="muted">{session.deviceLabel}</div>}
                      </td>
                      <td className="small">
                        <RelativeTime value={session.lastSeenAt} />
                      </td>
                      <td>
                        <button
                          className="button button-sm"
                          data-variant="ghost"
                          disabled={busy}
                          onClick={() =>
                            void act(
                              () => api.security.revokeSession(session.id),
                              () =>
                                setNotice(`${session.userName} was signed out of that session.`),
                            )
                          }
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Known devices</h2>
          <p className="small muted">
            Revoking a device also ends its live sessions — leaving them open would keep the
            attacker signed in on the machine just declared untrusted.
          </p>
          {devices.length === 0 ? (
            <EmptyState title="No devices recorded yet" />
          ) : (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Who</th>
                    <th scope="col">Device</th>
                    <th scope="col">Trust</th>
                    <th scope="col">Last active</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((device) => (
                    <tr key={device.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{device.userName}</div>
                        <div className="small muted">{device.email}</div>
                      </td>
                      <td className="small">
                        {device.label ?? 'unnamed'}
                        <div className="muted">
                          {device.lastSeenIp ?? device.firstSeenIp ?? '—'}
                        </div>
                      </td>
                      <td>
                        <span
                          className="chip"
                          data-tone={
                            device.trustStatus === 'TRUSTED'
                              ? 'success'
                              : device.trustStatus === 'BLOCKED'
                                ? 'danger'
                                : 'warning'
                          }
                        >
                          {device.trustStatus.toLowerCase()}
                        </span>
                      </td>
                      <td className="small">
                        <RelativeTime value={device.lastActivityAt} />
                      </td>
                      <td>
                        <button
                          className="button button-sm"
                          data-variant="ghost"
                          disabled={busy}
                          onClick={() =>
                            void act(
                              () => api.security.revokeDevice(device.id),
                              () => setNotice('The device was revoked and its sessions ended.'),
                            )
                          }
                        >
                          Revoke
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
