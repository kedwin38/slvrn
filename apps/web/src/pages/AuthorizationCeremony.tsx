/**
 * The payment release ceremony (spec §5.4, §7.5, NFR-UX-001).
 *
 * This is the screen where money leaves the organisation. Everything about it is designed
 * to make the authorizer *read before acting*, because the failure mode here is not a
 * technical one — it is an experienced officer clicking through a familiar dialog.
 *
 *   - The amount is the largest element on the screen, by a wide margin.
 *   - The recipient count and batch reference sit directly beneath it, unabbreviated.
 *   - The release control is visually distinct from every other button in the product; it
 *     is not "the primary button, in red", and it never appears on a list screen.
 *   - Each acknowledgement is a separate checkbox carrying the exact sentence the server
 *     will require back, so ticking is a real confirmation rather than a formality.
 *   - The button stays disabled until every gate is satisfied, and the disabled state says
 *     which gate is outstanding rather than leaving the officer to guess.
 *
 * The security itself is all server-side (services/authorization.ts). This screen cannot
 * weaken it: skipping a step here produces a refusal, not a release.
 */

import { useEffect, useState } from 'react';
import { formatCents } from '@solvaren/core';
import { api, ApiError, type CeremonyResponse } from '../lib/api.js';
import { Notice, Modal } from '../components/primitives.js';
import { IconAccountSecurity } from '../components/icons.js';

interface Props {
  batchId: string;
  onClose: () => void;
  onReleased: (summary: {
    batchReference: string;
    instructionsQueued: number;
    message: string;
  }) => void;
}

type Phase = 'loading' | 'review' | 'signing' | 'releasing' | 'error';

export function AuthorizationCeremony({ batchId, onClose, onReleased }: Props) {
  const [phase, setPhase] = useState<Phase>('loading');
  const [ceremony, setCeremony] = useState<CeremonyResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [acknowledged, setAcknowledged] = useState<Set<string>>(new Set());
  const [pin, setPin] = useState('');
  const [manifestConfirmed, setManifestConfirmed] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState<number | null>(null);

  // ---- Open the ceremony ---------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const result = await api.authorization.begin(batchId);
        if (cancelled) return;
        setCeremony(result);
        setPhase('review');
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err : null);
        setPhase('error');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [batchId]);

  // ---- Challenge expiry ----------------------------------------------------
  // Shown as a live countdown: a ceremony that silently expires and then fails on submit
  // is a confusing experience during a payroll run.
  useEffect(() => {
    if (!ceremony) return;
    const expiry = new Date(ceremony.expiresAt).getTime();
    const tick = () => setSecondsRemaining(Math.max(0, Math.floor((expiry - Date.now()) / 1000)));
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [ceremony]);

  async function abandon() {
    try {
      await api.authorization.abandon(batchId, 'Closed by the authorizer');
    } catch {
      // The housekeeping job expires abandoned ceremonies regardless; closing the dialog
      // must not be blocked by a failed cleanup call.
    }
    onClose();
  }

  async function release() {
    if (!ceremony) return;
    setPhase('signing');
    setError(null);

    try {
      // ---- WebAuthn assertion over the manifest-bound challenge -----------
      const assertion = await requestAssertion(ceremony.webauthnChallenge);

      setPhase('releasing');
      const result = await api.authorization.release(batchId, {
        challengeId: ceremony.challengeId,
        webauthnResponse: assertion,
        authorizationPin: pin,
        acknowledgements: [...acknowledged],
      });

      onReleased({
        batchReference: result.batchReference,
        instructionsQueued: result.instructionsQueued,
        message: result.message,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err);
      } else if (err instanceof Error && err.name === 'NotAllowedError') {
        setError(
          new ApiError(400, {
            code: 'WEBAUTHN_CANCELLED',
            category: 'AUTHENTICATION',
            message:
              'The security key prompt was dismissed or timed out. No payment has been released. Try again when ready.',
          }),
        );
      } else {
        setError(
          new ApiError(500, {
            code: 'RELEASE_FAILED',
            category: 'INTERNAL',
            message:
              'The release could not be completed. No payment has been released unless this screen says otherwise.',
          }),
        );
      }
      setPhase('review');
      // The PIN is cleared on any failure: re-entering it is a small cost, and leaving it
      // in a field after a failed attempt is not something a payment console should do.
      setPin('');
    }
  }

  const expired = secondsRemaining !== null && secondsRemaining <= 0;
  const allAcknowledged =
    ceremony?.acknowledgementsRequired.every((statement) => acknowledged.has(statement)) ?? false;
  const pinValid = /^\d{6,12}$/.test(pin);
  const busy = phase === 'signing' || phase === 'releasing';

  const blockingReason = !ceremony
    ? 'Loading the payment manifest'
    : expired
      ? 'This authorization has expired — close and start again'
      : !manifestConfirmed
        ? 'Confirm you have checked the amount and recipient count'
        : !allAcknowledged
          ? 'Confirm every acknowledgement above'
          : !pinValid
            ? 'Enter your SOLVAREN Authorization PIN'
            : null;

  return (
    <Modal open onClose={abandon} labelledBy="ceremony-title" dismissible={!busy} bleed>
      {phase === 'loading' && (
        <div className="ceremony-body">
          <div className="skeleton" style={{ height: 24, width: '60%' }} />
          <div className="skeleton" style={{ height: 48 }} />
          <div className="skeleton" style={{ height: 80 }} />
          <span className="visually-hidden">Preparing the authorization</span>
        </div>
      )}

      {phase === 'error' && !ceremony && (
        <>
          <div className="ceremony-header">
            <div className="ceremony-step">Authorization</div>
            <h2 className="ceremony-title" id="ceremony-title">
              This batch cannot be authorized
            </h2>
          </div>
          <div className="ceremony-body">
            <Notice tone="danger" title={error?.code} live="assertive">
              {error?.message ?? 'The authorization could not be opened.'}
            </Notice>
            {/* Refusals here are informative by design — "the batch was edited after
                approval" tells the officer exactly what to do next. */}
            {error?.code === 'APPROVAL_STALE' && (
              <Notice tone="info">
                Send the batch back to Finance Control for re-review. The previous approval covered
                a different version of this batch and is no longer valid.
              </Notice>
            )}
          </div>
          <div className="ceremony-footer">
            <button className="button" onClick={onClose}>
              Close
            </button>
          </div>
        </>
      )}

      {ceremony && phase !== 'loading' && (
        <>
          <div className="ceremony-header">
            <div className="ceremony-step">Executive payment authorization</div>
            <h2 className="ceremony-title" id="ceremony-title">
              {ceremony.manifest.batchReference}
            </h2>
          </div>

          {/* ---- The figure the authorizer must actually read -------------- */}
          <div className="ceremony-amount">
            <div className="ceremony-amount-value">
              <span className="amount-currency" aria-hidden="true">
                KES
              </span>
              <span
                aria-label={`${formatCents(ceremony.manifest.totalAmountCents)} Kenyan shillings`}
              >
                {formatCents(ceremony.manifest.totalAmountCents)}
              </span>
            </div>
            <div className="ceremony-amount-detail">
              to <strong>{ceremony.manifest.recipientCount.toLocaleString('en-KE')}</strong>{' '}
              recipients · approval {ceremony.manifest.approvalId} · batch version{' '}
              {ceremony.manifest.batchVersion}
            </div>
          </div>

          <div className="ceremony-body">
            {error && (
              <Notice tone="danger" title={error.code} live="assertive">
                {error.message}
              </Notice>
            )}

            {expired && (
              <Notice tone="warning" live="assertive">
                This authorization challenge has expired. Close this dialog and start again —
                nothing has been released.
              </Notice>
            )}

            {/* ---- Risk summary ------------------------------------------- */}
            {ceremony.risk.signals.length > 0 && (
              <details open={ceremony.risk.band === 'HIGH' || ceremony.risk.band === 'CRITICAL'}>
                <summary className="row" style={{ cursor: 'pointer' }}>
                  <span className="strong">
                    Risk assessment: {ceremony.risk.score} ({ceremony.risk.band})
                  </span>
                  <span className="muted small">
                    {ceremony.risk.signals.length} finding
                    {ceremony.risk.signals.length === 1 ? '' : 's'}
                  </span>
                </summary>
                <div className="stack" style={{ marginBlockStart: 'var(--s3)' }}>
                  {ceremony.risk.signals.slice(0, 8).map((signal, index) => (
                    <div className="finding" data-severity={signal.severity} key={index}>
                      <div className="finding-summary">{signal.summary}</div>
                      <dl className="finding-evidence">
                        {Object.entries(signal.evidence)
                          .slice(0, 4)
                          .map(([key, value]) => (
                            <div key={key}>
                              <dt>{key}: </dt>
                              <dd>{String(value)}</dd>
                            </div>
                          ))}
                      </dl>
                    </div>
                  ))}
                  {ceremony.risk.signals.length > 8 && (
                    <p className="small muted">
                      {ceremony.risk.signals.length - 8} further findings are listed on the batch
                      page.
                    </p>
                  )}
                </div>
              </details>
            )}

            {/* ---- Manifest confirmation ----------------------------------- */}
            <label className="acknowledgement">
              <input
                type="checkbox"
                checked={manifestConfirmed}
                onChange={(event) => setManifestConfirmed(event.target.checked)}
                disabled={busy || expired}
              />
              <span>
                I have checked the amount and the recipient count above against the approved batch.
                <div className="manifest-digest" style={{ marginBlockStart: 'var(--s2)' }}>
                  Manifest {ceremony.confirmation.manifestDigestShort}…
                </div>
              </span>
            </label>

            {/* ---- Policy acknowledgements --------------------------------- */}
            {ceremony.acknowledgementsRequired.map((statement) => (
              <label className="acknowledgement" key={statement}>
                <input
                  type="checkbox"
                  checked={acknowledged.has(statement)}
                  onChange={(event) => {
                    setAcknowledged((current) => {
                      const next = new Set(current);
                      if (event.target.checked) next.add(statement);
                      else next.delete(statement);
                      return next;
                    });
                  }}
                  disabled={busy || expired}
                />
                <span>{statement}</span>
              </label>
            ))}

            {/* ---- SPAC PIN ------------------------------------------------ */}
            <div className="field">
              <label className="label" htmlFor="spac-pin">
                SOLVAREN Authorization PIN
              </label>
              <input
                id="spac-pin"
                className="input pin-input"
                type="password"
                inputMode="numeric"
                autoComplete="off"
                // Not a password field the browser should remember: the PIN is a second
                // factor of authority, and a saved PIN defeats the point of having one.
                data-1p-ignore
                data-lpignore="true"
                maxLength={12}
                value={pin}
                onChange={(event) => setPin(event.target.value.replace(/\D/g, ''))}
                disabled={busy || expired}
                aria-describedby="spac-pin-hint"
              />
              <span className="hint" id="spac-pin-hint">
                Separate from your sign-in password. Required for every payment release.
              </span>
            </div>

            <Notice tone="warning">{ceremony.confirmation.warning}</Notice>

            {secondsRemaining !== null && !expired && (
              <p className="small muted" role="timer">
                This authorization expires in {Math.floor(secondsRemaining / 60)}:
                {String(secondsRemaining % 60).padStart(2, '0')}.
              </p>
            )}
          </div>

          <div className="ceremony-footer">
            <button className="button" onClick={abandon} disabled={busy}>
              Cancel
            </button>

            <div
              className="stack"
              style={{ gap: 'var(--s2)', alignItems: 'flex-end', minWidth: 0, textAlign: 'right' }}
            >
              <button
                className="button"
                data-variant="release"
                onClick={release}
                disabled={Boolean(blockingReason) || busy}
                aria-describedby={blockingReason ? 'release-blocked' : undefined}
              >
                {phase === 'signing' ? (
                  'Waiting for your security key…'
                ) : phase === 'releasing' ? (
                  'Releasing…'
                ) : (
                  <>
                    {/* Drawn, not 🔒. The nav icons were moved off Unicode because a glyph
                        renders as whatever font the OS substitutes — line art here, emoji
                        there, a tofu box elsewhere. That is worse on the release button
                        than anywhere else in the product. */}
                    <IconAccountSecurity size={16} />
                    Release KES {formatCents(ceremony.manifest.totalAmountCents)}
                  </>
                )}
              </button>
              {/* The disabled state always says what is outstanding. A greyed-out button
                  with no explanation is the most common cause of a support call. */}
              {blockingReason && !busy && (
                <span className="small muted" id="release-blocked">
                  {blockingReason}
                </span>
              )}
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}

/**
 * Perform the WebAuthn assertion.
 *
 * The challenge is the server's manifest-bound digest, so the signature the authenticator
 * produces is cryptographically tied to this exact set of payments. `userVerification:
 * 'required'` means the authenticator itself demands a PIN or biometric — a security key
 * left plugged in is not sufficient to release money.
 */
async function requestAssertion(challengeBase64Url: string): Promise<unknown> {
  if (!('credentials' in navigator) || !window.PublicKeyCredential) {
    throw new Error(
      'This browser does not support security keys, which are required for payment release.',
    );
  }

  const challenge = base64UrlToBuffer(challengeBase64Url);

  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      userVerification: 'required',
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('No assertion was produced.');

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined,
    },
  };
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
