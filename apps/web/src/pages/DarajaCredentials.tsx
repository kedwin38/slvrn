/**
 * M-PESA credentials (spec §9.1, §4.4).
 *
 * Without this screen a deployed SOLVAREN cannot pay anybody: there is no other way to tell
 * it which shortcode to disburse from. The API has always had the endpoints; nothing called
 * them.
 *
 * The screen is built around one honest admission — **credentials that have never been
 * tested are not known to work**. So the test result is a first-class column rather than a
 * footnote, an untested configuration says so plainly, and enabling is a separate act from
 * saving. The failure this avoids is discovering a bad initiator password at the moment a
 * payroll run is released.
 *
 * Secrets are write-only. The API returns the last four of the consumer key (a public
 * identifier, useful for telling two keys apart mid-rotation) and nothing else. Re-saving
 * rotates; there is no "reveal".
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type DarajaConfigurationView } from '../lib/api.js';
import {
  Notice,
  EmptyState,
  TableSkeleton,
  Modal,
  Field,
  RelativeTime,
} from '../components/primitives.js';

type Environment = 'sandbox' | 'production';
type CommandId = 'BusinessPayment' | 'SalaryPayment' | 'PromotionPayment';

const BLANK = {
  environment: 'sandbox' as Environment,
  shortCode: '',
  initiatorName: '',
  commandId: 'BusinessPayment' as CommandId,
  consumerKey: '',
  consumerSecret: '',
  initiatorPasswordOrCredential: '',
  mpesaCertificatePem: '',
};

export function DarajaCredentialsPage() {
  const [configurations, setConfigurations] = useState<DarajaConfigurationView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ ...BLANK });

  const load = useCallback(async () => {
    try {
      const result = await api.admin.daraja.list();
      setConfigurations(result.configurations);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The credential list could not be loaded.');
    }
  }, []);

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
          <h1 className="page-title">M-PESA credentials</h1>
          <p className="page-subtitle">
            The shortcode and initiator this organisation disburses from. Nothing can be paid until
            one configuration is tested and enabled.
          </p>
        </div>
        <button
          className="button"
          data-variant="primary"
          disabled={busy}
          onClick={() => {
            setForm({ ...BLANK });
            setEditing(true);
          }}
        >
          Add credentials
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

      {configurations === null ? (
        <TableSkeleton rows={2} columns={5} />
      ) : configurations.length === 0 ? (
        <EmptyState title="No credentials configured">
          SOLVAREN cannot disburse until a Daraja shortcode is configured, tested and enabled.
        </EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Environment</th>
                  <th scope="col">Shortcode</th>
                  <th scope="col">Initiator</th>
                  <th scope="col">Consumer key</th>
                  <th scope="col">Last test</th>
                  <th scope="col">Status</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {configurations.map((config) => {
                  const enabled = config.status === 'ACTIVE' || config.status === 'ENABLED';
                  const untested = config.lastTestOk === null;
                  return (
                    <tr key={config.id}>
                      <td>
                        <span
                          className="chip"
                          data-tone={config.environment === 'production' ? 'warning' : 'neutral'}
                        >
                          {config.environment}
                        </span>
                      </td>
                      <td>{config.shortCode}</td>
                      <td>
                        <div>{config.initiatorName}</div>
                        <div className="small muted">{config.commandId}</div>
                      </td>
                      <td>
                        <code className="small">{config.consumerKeyMasked}</code>
                        <div className="small muted">version {config.credentialVersion}</div>
                      </td>
                      <td>
                        {untested ? (
                          <span className="chip" data-tone="warning">
                            never tested
                          </span>
                        ) : (
                          <>
                            <span
                              className="chip"
                              data-tone={config.lastTestOk ? 'positive' : 'negative'}
                            >
                              {config.lastTestOk ? 'passed' : 'failed'}
                            </span>
                            <div className="small muted">
                              <RelativeTime value={config.lastTestAt} />
                            </div>
                            {config.lastTestMessage && !config.lastTestOk && (
                              <div className="small">{config.lastTestMessage}</div>
                            )}
                          </>
                        )}
                      </td>
                      <td>
                        <span className="chip" data-tone={enabled ? 'positive' : 'neutral'}>
                          {enabled ? 'enabled' : config.status.toLowerCase()}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                          <button
                            className="button"
                            data-variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void act(
                                () => api.admin.daraja.test(config.id),
                                (result) =>
                                  setNotice(
                                    result.ok
                                      ? `The credentials authenticated against Daraja${
                                          result.latencyMs ? ` in ${result.latencyMs} ms` : ''
                                        }.`
                                      : `The test failed: ${result.message}`,
                                  ),
                              )
                            }
                          >
                            Test
                          </button>
                          <button
                            className="button"
                            data-variant="ghost"
                            disabled={busy || (!enabled && untested)}
                            title={
                              !enabled && untested
                                ? 'Test the credentials before enabling them'
                                : undefined
                            }
                            onClick={() =>
                              void act(() =>
                                enabled
                                  ? api.admin.daraja.disable(config.id)
                                  : api.admin.daraja.enable(config.id),
                              )
                            }
                          >
                            {enabled ? 'Disable' : 'Enable'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Notice tone="info">
        Saving credentials requires a recent sign-in and your security key, and rotating them
        creates a new version rather than overwriting the old one. Secrets are encrypted at rest and
        never returned by the API — not even to you.
      </Notice>

      {editing && (
        <Modal open onClose={() => setEditing(false)} labelledBy="daraja-title" dismissible={!busy}>
          <h2 id="daraja-title" className="page-title">
            Daraja credentials
          </h2>
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void act(
                () =>
                  api.admin.daraja.save({
                    environment: form.environment,
                    shortCode: form.shortCode.trim(),
                    initiatorName: form.initiatorName.trim(),
                    commandId: form.commandId,
                    consumerKey: form.consumerKey.trim(),
                    consumerSecret: form.consumerSecret.trim(),
                    initiatorPasswordOrCredential: form.initiatorPasswordOrCredential.trim(),
                    ...(form.mpesaCertificatePem.trim()
                      ? { mpesaCertificatePem: form.mpesaCertificatePem.trim() }
                      : {}),
                  }),
                () => {
                  setEditing(false);
                  setNotice('Credentials saved. Test them before enabling.');
                },
              );
            }}
          >
            <Field label="Environment">
              {(props) => (
                <select
                  {...props}
                  className="input"
                  value={form.environment}
                  onChange={(event) =>
                    setForm({ ...form, environment: event.target.value as Environment })
                  }
                >
                  <option value="sandbox">Sandbox</option>
                  <option value="production">Production — moves real money</option>
                </select>
              )}
            </Field>

            {form.environment === 'production' && (
              <Notice tone="warning">
                Production credentials disburse real funds. The API refuses them unless the
                deployment itself is configured for production.
              </Notice>
            )}

            <Field label="Shortcode" hint="5 to 9 digits">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  inputMode="numeric"
                  pattern="\d{5,9}"
                  required
                  value={form.shortCode}
                  onChange={(event) => setForm({ ...form, shortCode: event.target.value })}
                />
              )}
            </Field>

            <Field label="Initiator name">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  required
                  value={form.initiatorName}
                  onChange={(event) => setForm({ ...form, initiatorName: event.target.value })}
                />
              )}
            </Field>

            <Field label="Command">
              {(props) => (
                <select
                  {...props}
                  className="input"
                  value={form.commandId}
                  onChange={(event) =>
                    setForm({ ...form, commandId: event.target.value as CommandId })
                  }
                >
                  <option value="BusinessPayment">BusinessPayment</option>
                  <option value="SalaryPayment">SalaryPayment</option>
                  <option value="PromotionPayment">PromotionPayment</option>
                </select>
              )}
            </Field>

            <Field label="Consumer key">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  autoComplete="off"
                  required
                  value={form.consumerKey}
                  onChange={(event) => setForm({ ...form, consumerKey: event.target.value })}
                />
              )}
            </Field>

            <Field label="Consumer secret">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="password"
                  autoComplete="off"
                  required
                  value={form.consumerSecret}
                  onChange={(event) => setForm({ ...form, consumerSecret: event.target.value })}
                />
              )}
            </Field>

            <Field
              label="Initiator password or security credential"
              hint="The plain initiator password, or an already-encrypted SecurityCredential"
            >
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="password"
                  autoComplete="off"
                  required
                  value={form.initiatorPasswordOrCredential}
                  onChange={(event) =>
                    setForm({ ...form, initiatorPasswordOrCredential: event.target.value })
                  }
                />
              )}
            </Field>

            <Field
              label="M-PESA certificate (optional)"
              hint="PEM public certificate, if the initiator password must be encrypted here"
            >
              {(props) => (
                <textarea
                  {...props}
                  className="input"
                  rows={3}
                  value={form.mpesaCertificatePem}
                  onChange={(event) =>
                    setForm({ ...form, mpesaCertificatePem: event.target.value })
                  }
                />
              )}
            </Field>

            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Saving…' : 'Save credentials'}
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
