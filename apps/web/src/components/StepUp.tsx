/**
 * Step-up confirmation (spec §8.2, §9).
 *
 * Nine administrative actions and the release ceremony refuse anything attempted more than
 * five minutes after sign-in. Until now that refusal was a dead end: the API said "this
 * action requires you to confirm your identity again" and nothing in the console could.
 * Saving M-PESA credentials was the clearest casualty — nobody pastes a certificate and six
 * other fields inside five minutes — which meant a real deployment could never be configured
 * to pay anybody at all.
 *
 * This is the missing half. It is deliberately the same challenge as signing in, because it
 * is the same question asked again: the password, and then the authenticator for anyone who
 * has one. A stolen session with a known password cannot elevate itself.
 *
 * The dialog is driven from `api.ts` rather than by each caller, so the original request is
 * replayed automatically once identity is confirmed. From the operator's side the action
 * they asked for simply happens, after one prompt.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, setStepUpHandler } from '../lib/api.js';
import { requestAssertion } from '../pages/Login.js';
import { Modal, Field, Notice } from './primitives.js';

export function StepUpGate() {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  /*
   * The pending promise handed back to `request()`. Resolving true replays the original
   * call; false lets the original error surface, so a cancelled prompt does not look like
   * a silent failure.
   */
  const resolver = useRef<((confirmed: boolean) => void) | null>(null);

  const finish = useCallback((confirmed: boolean) => {
    setOpen(false);
    setPassword('');
    setError(null);
    setBusy(false);
    resolver.current?.(confirmed);
    resolver.current = null;
  }, []);

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<boolean>((resolve) => {
          resolver.current = resolve;
          setOpen(true);
        }),
    );
    return () => setStepUpHandler(null);
  }, []);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      const started = await api.stepUp.start(password);
      if (started.stage === 'WEBAUTHN_REQUIRED') {
        const assertion = await requestAssertion(started.options.challenge);
        await api.stepUp.verify(started.ticket, assertion);
      }
      finish(true);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'That did not work.',
      );
      setBusy(false);
    }
  }

  if (!open) return null;

  return (
    <Modal open onClose={() => finish(false)} labelledBy="step-up-title" dismissible={!busy}>
      <h2 id="step-up-title" className="section-title">
        Confirm it is you
      </h2>
      <p className="small muted">
        This action changes payment infrastructure, so SOLVAREN asks again rather than trusting a
        session that has been open a while.
      </p>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void confirm();
        }}
      >
        <Field label="Your password">
          {(props) => (
            <input
              {...props}
              className="input"
              type="password"
              autoComplete="current-password"
              required
              autoFocus
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          )}
        </Field>

        <p className="small muted">
          If you have a security key or passkey enrolled, you will be asked for it next.
        </p>

        <div className="row" style={{ gap: 'var(--s2)' }}>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Confirming…' : 'Confirm'}
          </button>
          <button
            className="button"
            data-variant="ghost"
            type="button"
            disabled={busy}
            onClick={() => finish(false)}
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}
