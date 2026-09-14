/**
 * Organisation members (spec §4, §7.3).
 *
 * Separation of duties is only real if there is somebody else to be the other party. Until
 * this screen existed, adding a second approver meant running a script against the database,
 * so a deployed organisation had exactly the people it was seeded with — and an L1 preparing
 * a batch had nobody to submit it to.
 *
 * Two things this screen deliberately does not do:
 *
 *   It does not edit permissions. What an L1, L2 or L3 may do is a fixed matrix in
 *   packages/core/src/rbac.ts. An administrator who can edit that can grant themselves
 *   release authority, which defeats the control everything else here is built to protect.
 *   Assigning a *level* to a person is the intended lever.
 *
 *   It does not show anyone's credentials. It shows whether an account HAS an authenticator
 *   and a PIN, because an account missing either cannot complete a release — and the moment
 *   to discover that is now, not during a payroll run.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type OrganizationUserView } from '../lib/api.js';
import {
  Notice,
  EmptyState,
  TableSkeleton,
  Modal,
  Field,
  RelativeTime,
} from '../components/primitives.js';

type Level = 'L1' | 'L2' | 'L3';

const LEVEL_LABEL: Record<Level, string> = {
  L1: 'L1 · Payment Operations',
  L2: 'L2 · Finance Control',
  L3: 'L3 · Executive Authority',
};

export function UsersPage() {
  const [users, setUsers] = useState<OrganizationUserView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [creating, setCreating] = useState(false);
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [level, setLevel] = useState<Level>('L1');

  /** Shown once, never retrievable: a one-time password or an enrolment token. */
  const [handover, setHandover] = useState<{ title: string; label: string; value: string } | null>(
    null,
  );

  const load = useCallback(async () => {
    try {
      const result = await api.admin.users.list();
      setUsers(result.users);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The member list could not be loaded.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function act<T>(operation: () => Promise<T>, onDone?: (result: T) => void) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const result = await operation();
      onDone?.(result);
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
          <h1 className="page-title">Members</h1>
          <p className="page-subtitle">
            Who may act in this organisation, and at what authority. A batch needs a different
            person to prepare, approve and release it.
          </p>
        </div>
        <button
          className="button"
          data-variant="primary"
          onClick={() => setCreating(true)}
          disabled={busy}
        >
          Add member
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

      {users === null ? (
        <TableSkeleton rows={4} columns={5} />
      ) : users.length === 0 ? (
        <EmptyState title="No members yet">
          Add the people who will prepare, approve and release payments.
        </EmptyState>
      ) : (
        <div className="card">
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Member</th>
                  <th scope="col">Authority</th>
                  <th scope="col">Status</th>
                  <th scope="col">Can release</th>
                  <th scope="col">Last signed in</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => {
                  const privileged = user.level !== 'L1';
                  const ready = !privileged || (user.hasAuthenticator && user.hasAuthorizationPin);
                  return (
                    <tr key={user.userId}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{user.fullName}</div>
                        <div className="small muted">{user.email}</div>
                      </td>
                      <td>
                        <select
                          className="input"
                          value={user.level}
                          disabled={busy}
                          aria-label={`Authority level for ${user.fullName}`}
                          onChange={(event) =>
                            void act(() =>
                              api.admin.users.setLevel(user.userId, event.target.value as Level),
                            )
                          }
                        >
                          <option value="L1">L1 · Operations</option>
                          <option value="L2">L2 · Finance Control</option>
                          <option value="L3">L3 · Executive</option>
                        </select>
                      </td>
                      <td>
                        <span
                          className="chip"
                          data-tone={user.status === 'ACTIVE' ? 'positive' : 'neutral'}
                        >
                          {user.status.replace('_', ' ').toLowerCase()}
                        </span>
                      </td>
                      <td>
                        {ready ? (
                          <span className="chip" data-tone="positive">
                            ready
                          </span>
                        ) : (
                          <span className="chip" data-tone="warning">
                            {!user.hasAuthenticator ? 'needs a security key' : 'needs a PIN'}
                          </span>
                        )}
                      </td>
                      <td>
                        <RelativeTime value={user.lastLoginAt} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                          {/*
                            Controlled administrative recovery (§11). Before this the only
                            remedy for a forgotten password was editing the database by
                            hand, so an employee who forgot theirs was locked out for good.
                          */}
                          <button
                            className="button"
                            data-variant="ghost"
                            disabled={busy}
                            onClick={() => {
                              const why = window.prompt(
                                `Why are you resetting access for ${user.fullName}? (recorded in the audit trail)`,
                              );
                              if (!why || why.trim().length < 10) return;
                              const alsoKeys = window.confirm(
                                'Also remove their security keys? Choose OK only if the key itself is lost — they will need a new enrolment token before they can sign in.',
                              );
                              void act(
                                () =>
                                  api.admin.users.resetAccess(user.userId, why.trim(), alsoKeys),
                                (result) =>
                                  setHandover({
                                    title: `One-time password for ${result.email}`,
                                    label: 'Password',
                                    value: result.oneTimePassword,
                                  }),
                              );
                            }}
                          >
                            Reset access
                          </button>

                          {!user.hasAuthenticator && (
                            <button
                              className="button"
                              data-variant="ghost"
                              disabled={busy}
                              onClick={() =>
                                void act(
                                  () => api.admin.users.issueEnrolmentToken(user.userId),
                                  (result) =>
                                    setHandover({
                                      title: `Enrolment token for ${user.email}`,
                                      label: 'Token',
                                      value: result.token,
                                    }),
                                )
                              }
                            >
                              Enrolment token
                            </button>
                          )}
                          <button
                            className="button"
                            data-variant="ghost"
                            disabled={busy}
                            onClick={() =>
                              void act(() =>
                                api.admin.users.setStatus(
                                  user.userId,
                                  user.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE',
                                ),
                              )
                            }
                          >
                            {user.status === 'ACTIVE' ? 'Disable' : 'Enable'}
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
        Authority levels are fixed roles, not editable permission sets. What each level may do lives
        in the code and changes through review — an administrator who could edit it could grant
        themselves the ability to release money.
      </Notice>

      {creating && (
        <Modal open onClose={() => setCreating(false)} labelledBy="add-member-title">
          <h2 id="add-member-title" className="page-title">
            Add member
          </h2>
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void act(
                () => api.admin.users.create({ email, fullName, level }),
                (result) => {
                  setCreating(false);
                  setEmail('');
                  setFullName('');
                  setLevel('L1');
                  setHandover({
                    title: `One-time password for ${result.email}`,
                    label: 'Password',
                    value: result.temporaryPassword,
                  });
                },
              );
            }}
          >
            <Field label="Full name">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  required
                  value={fullName}
                  onChange={(event) => setFullName(event.target.value)}
                />
              )}
            </Field>

            <Field label="Work email">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              )}
            </Field>

            <Field label="Authority level">
              {(props) => (
                <select
                  {...props}
                  className="input"
                  value={level}
                  onChange={(event) => setLevel(event.target.value as Level)}
                >
                  {(['L1', 'L2', 'L3'] as Level[]).map((value) => (
                    <option key={value} value={value}>
                      {LEVEL_LABEL[value]}
                    </option>
                  ))}
                </select>
              )}
            </Field>

            {level !== 'L1' && (
              <Notice tone="info">
                Above L1 an account cannot sign in until a security key is enrolled and a PIN is
                set. It will be created pending enrolment; issue an enrolment token from the list
                afterwards.
              </Notice>
            )}

            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Creating…' : 'Create member'}
            </button>
          </form>
        </Modal>
      )}

      {handover && (
        <Modal open onClose={() => setHandover(null)} labelledBy="handover-title">
          <div className="stack">
            <h2 id="handover-title" className="page-title">
              {handover.title}
            </h2>
            <Notice tone="warning">
              Shown once. Only a hash is stored, so this cannot be retrieved again. Hand it over in
              person or by another channel — not by email.
            </Notice>
            <div className="card">
              <div className="card-body">
                <div className="small muted">{handover.label}</div>
                <code style={{ fontSize: '1.05rem', wordBreak: 'break-all' }}>
                  {handover.value}
                </code>
              </div>
            </div>
            <button className="button" data-variant="primary" onClick={() => setHandover(null)}>
              I have written it down
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
