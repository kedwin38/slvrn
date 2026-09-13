/**
 * Backups (spec §13).
 *
 * The screen's job is to answer one question honestly: *is there a usable backup?*
 *
 * So a failure is shown as a failure, never smoothed into "no recent backups"; the
 * retention result distinguishes "complete" from "partial"; and the restore-validation
 * caveat is on the page rather than buried in documentation, because a backup that has
 * never been restored is not disaster-recovery proven and the person reading this screen
 * is the one who needs to know that.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '../lib/api.js';
import { Notice, EmptyState, RelativeTime, TableSkeleton } from '../components/primitives.js';

export function BackupsPage() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.backups.overview>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.backups.overview());
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The backup configuration could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function runBackup() {
    setRunning(true);
    setMessage(null);
    try {
      const result = await api.backups.run();
      setMessage(`${result.attemptReference}: ${result.message}`);
      // The job is asynchronous (BAK-004); poll once so the new attempt appears.
      setTimeout(() => void load(), 4000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The backup could not be started.');
    } finally {
      setRunning(false);
    }
  }

  const configuration = data?.configuration as Record<string, unknown> | null;
  const latest = data?.latestResult as Record<string, unknown> | null;
  const latestFailed = latest?.status === 'FAILED' || latest?.status === 'MISSED';

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Backups</h1>
          <p className="page-subtitle">
            Full database snapshots to S3-compatible storage, with schedules, retention and a
            durable record of every attempt.
          </p>
        </div>
        {configuration && (
          <button className="button" data-variant="primary" onClick={runBackup} disabled={running}>
            {running ? 'Queuing…' : 'Run backup now'}
          </button>
        )}
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}
      {message && (
        <Notice tone="info" live="polite">
          {message}
        </Notice>
      )}

      {loading ? (
        <div className="card">
          <TableSkeleton rows={4} columns={4} />
        </div>
      ) : !configuration ? (
        <div className="card">
          <EmptyState title="No backup target configured">
            Connect S3-compatible object storage to enable snapshots. Credentials are held by the
            secrets store and masked after saving.
          </EmptyState>
        </div>
      ) : (
        <>
          {/* The most recent result, shown plainly. BAK-008 requires it always visible,
              and §13.7 requires a failure never to be presented as success. */}
          {latest && (
            <Notice
              tone={latest.status === 'SUCCESS' ? 'success' : latestFailed ? 'danger' : 'info'}
              title={`Last backup: ${String(latest.status)}`}
            >
              <div>
                {String(latest.attemptReference)} ·{' '}
                <RelativeTime value={String(latest.startedAt)} />
                {latest.sizeBytes ? ` · ${formatBytes(Number(latest.sizeBytes))}` : ''}
              </div>
              {latest.errorMessage ? <div className="small">{String(latest.errorMessage)}</div> : null}
              {latest.status === 'SUCCESS' && latest.retentionComplete === false && (
                <div className="small">
                  Retention did not complete: some older objects could not be removed. The retained
                  count is therefore not guaranteed.
                </div>
              )}
            </Notice>
          )}

          <div className="card">
            <div className="card-header">
              <span className="card-title">Target</span>
              <span className="chip" data-tone={configuration.status === 'CONNECTED' ? 'success' : 'warning'}>
                {String(configuration.status)}
              </span>
            </div>
            <div className="card-body">
              <dl className="grid" style={{ gap: 'var(--s4)' }}>
                <Detail label="Provider" value={String(configuration.providerLabel)} />
                <Detail label="Bucket" value={String(configuration.bucket)} />
                <Detail label="Prefix" value={String(configuration.pathPrefix)} />
                {/* Masked, always. BAK-002: the plaintext is unreachable from any response. */}
                <Detail label="Access key" value={String(configuration.accessKeyMasked)} mono />
                <Detail label="Secret key" value={String(configuration.secretKeyMasked)} mono />
                <Detail label="Encryption" value={String(configuration.encryptionMode)} />
                <Detail
                  label="Schedule"
                  value={
                    configuration.scheduleEnabled
                      ? `${String(configuration.scheduleCron)} (${String(configuration.scheduleTimezone)})`
                      : 'Disabled'
                  }
                />
                <Detail label="Retention" value={`${String(configuration.retentionMaxCount)} backups`} />
              </dl>

              {configuration.suspended === true && (
                <Notice tone="danger" >
                  Backups are suspended: {String(configuration.suspensionReason)}. Correct the target
                  configuration to resume.
                </Notice>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Attempt history</span>
              <span className="small muted">Every attempt, including failures and missed windows</span>
            </div>
            {data && data.history.length === 0 ? (
              <EmptyState title="No backups have run yet" />
            ) : (
              <div className="table-scroll">
                <table className="table">
                  <thead>
                    <tr>
                      <th scope="col">Attempt</th>
                      <th scope="col">Trigger</th>
                      <th scope="col">Status</th>
                      <th scope="col">Started</th>
                      <th scope="col" className="numeric">
                        Size
                      </th>
                      <th scope="col">Object</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data?.history.map((attempt) => (
                      <tr key={attempt.attemptReference}>
                        <td className="mono small">{attempt.attemptReference}</td>
                        <td className="small">{attempt.trigger}</td>
                        <td>
                          <span
                            className="chip"
                            data-tone={
                              attempt.status === 'SUCCESS'
                                ? 'success'
                                : attempt.status === 'STARTED'
                                  ? 'info'
                                  : 'danger'
                            }
                          >
                            {attempt.status}
                          </span>
                          {attempt.errorMessage && (
                            <div className="small muted" style={{ maxWidth: '40ch' }}>
                              {attempt.errorMessage}
                            </div>
                          )}
                        </td>
                        <td>
                          <RelativeTime value={attempt.startedAt} />
                        </td>
                        <td className="numeric small">
                          {attempt.sizeBytes ? formatBytes(attempt.sizeBytes) : '—'}
                        </td>
                        <td className="small">
                          {attempt.objectRetained ? 'Retained' : 'Removed by retention'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Stated on the screen rather than in a document nobody opens. */}
          <Notice tone="warning" title="Restore validation">
            {data?.restoreValidationNote}
          </Notice>
        </>
      )}
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="stat-label">{label}</dt>
      <dd className={mono ? 'mono' : undefined} style={{ margin: 0 }}>
        {value}
      </dd>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}
