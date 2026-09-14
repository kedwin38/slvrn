/**
 * Sign-in (spec §7.1, §7.3).
 *
 * Two stages, because WebAuthn is mandatory for L2 and L3: the password stage returns a
 * challenge and no session, so a stolen password on its own opens nothing.
 *
 * There is no "forgot password — we'll text you a code" link, and no place to add one.
 * Recovery uses a stored recovery code or administrative review (§8.3); the schema has no
 * phone column on any identity table.
 */

import { useState } from 'react';
import { api, ApiError, setSessionToken, type SessionResponse } from '../lib/api.js';
import { Notice, Field } from '../components/primitives.js';

export function Login({
  onAuthenticated,
}: {
  onAuthenticated: (session: SessionResponse) => void;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [stage, setStage] = useState<'credentials' | 'webauthn' | 'enrol'>('credentials');
  const [enrolmentToken, setEnrolmentToken] = useState('');
  const [enrolled, setEnrolled] = useState(false);
  const [ticket, setTicket] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function completeSignIn(token: string) {
    setSessionToken(token);
    onAuthenticated(await api.auth.session());
  }

  async function submitCredentials(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.auth.login(email, password);
      if (result.stage === 'AUTHENTICATED') {
        await completeSignIn(result.token);
        return;
      }
      setTicket(result.ticket);
      setStage('webauthn');
      // Chain straight into the authenticator prompt: making the officer press a second
      // button between the password and the key serves no security purpose.
      await performWebAuthn(result.ticket, result.options.challenge);
    } catch (err) {
      setError(asApiError(err));
      setStage('credentials');
    } finally {
      setBusy(false);
    }
  }

  async function performWebAuthn(currentTicket: string, challenge: string) {
    setBusy(true);
    setError(null);
    try {
      const assertion = await requestAssertion(challenge);
      const result = await api.auth.completeWebAuthn(currentTicket, assertion);
      await completeSignIn(result.token);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  /*
   * Enrol the first authenticator on an L2/L3 account.
   *
   * These accounts cannot sign in until a key exists, and the authenticated enrolment
   * endpoint needs a session they cannot get — so this path is gated on the password plus a
   * single-use token issued out of band. It produces a credential and no session: the user
   * then signs in normally, above.
   */
  async function submitEnrolment(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const options = await api.auth.enrolmentOptions(email, password, enrolmentToken);
      const attestation = await createCredential(options);
      await api.auth.completeEnrolment(email, password, enrolmentToken, attestation);
      setEnrolled(true);
      setStage('credentials');
      setEnrolmentToken('');
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      style={{
        minHeight: '100dvh',
        display: 'grid',
        placeItems: 'center',
        padding: 'var(--s4)',
        background: 'var(--ground)',
      }}
    >
      <main className="card" style={{ width: 'min(420px, 100%)' }}>
        <div className="card-body" style={{ display: 'grid', gap: 'var(--s5)' }}>
          <div>
            <div className="brand" style={{ paddingInline: 0 }}>
              <svg className="brand-mark" viewBox="0 0 32 32" aria-hidden="true">
                <rect x="1" y="1" width="30" height="30" rx="8" fill="var(--accent)" />
                <path
                  d="M10 20.5 L16 12.5 L22 20.5"
                  fill="none"
                  stroke="var(--ink-inverse)"
                  strokeWidth="2.4"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <path
                  d="M10 25 L22 25"
                  stroke="var(--ink-inverse)"
                  strokeWidth="2.4"
                  strokeLinecap="round"
                  opacity="0.55"
                />
              </svg>
              <div>
                <div className="brand-name">SOLVAREN</div>
                <div className="brand-tagline">Move money with certainty</div>
              </div>
            </div>
          </div>

          {error && (
            <Notice tone="danger" live="assertive">
              {error.message}
            </Notice>
          )}

          {enrolled && (
            <Notice tone="success" live="polite">
              Security key enrolled. Sign in with your password and that key.
            </Notice>
          )}

          {stage === 'credentials' ? (
            <form onSubmit={submitCredentials} className="stack">
              <Field label="Work email">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="email"
                    autoComplete="username"
                    required
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                )}
              </Field>

              <Field label="Password">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                )}
              </Field>

              <button className="button" data-variant="primary" type="submit" disabled={busy}>
                {busy ? 'Checking…' : 'Continue'}
              </button>

              <button
                className="button"
                data-variant="ghost"
                type="button"
                onClick={() => {
                  setStage('enrol');
                  setError(null);
                  setEnrolled(false);
                }}
              >
                Enrol a security key
              </button>
            </form>
          ) : stage === 'enrol' ? (
            <form onSubmit={submitEnrolment} className="stack">
              <Notice tone="info">
                For a new account that has been given an enrolment token. This registers one key;
                you then sign in with your password and that key.
              </Notice>

              <Field label="Work email">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="email"
                    autoComplete="username"
                    required
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                )}
              </Field>

              <Field label="Password">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                )}
              </Field>

              <Field label="Enrolment token">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="text"
                    autoComplete="off"
                    spellCheck={false}
                    required
                    value={enrolmentToken}
                    onChange={(event) => setEnrolmentToken(event.target.value)}
                  />
                )}
              </Field>

              <button className="button" data-variant="primary" type="submit" disabled={busy}>
                {busy ? 'Waiting…' : 'Enrol key'}
              </button>

              <button
                className="button"
                data-variant="ghost"
                type="button"
                onClick={() => {
                  setStage('credentials');
                  setError(null);
                }}
              >
                Back to sign in
              </button>
            </form>
          ) : (
            <div className="stack">
              <Notice tone="info">Complete the verification prompt to finish signing in.</Notice>
              <button
                className="button"
                data-variant="primary"
                disabled={busy || !ticket}
                onClick={() => ticket && void performWebAuthn(ticket, '')}
              >
                {busy ? 'Waiting…' : 'Try again'}
              </button>
              <button
                className="button"
                data-variant="ghost"
                onClick={() => {
                  setStage('credentials');
                  setError(null);
                }}
              >
                Start over
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function asApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  if (err instanceof Error && err.name === 'NotAllowedError') {
    return new ApiError(400, {
      code: 'WEBAUTHN_CANCELLED',
      category: 'AUTHENTICATION',
      message: 'The verification prompt was dismissed or timed out. Try again when ready.',
    });
  }
  return new ApiError(0, {
    code: 'NETWORK',
    category: 'INTERNAL',
    message: 'Could not reach SOLVAREN. Check your connection and try again.',
  });
}

async function requestAssertion(challengeBase64Url: string): Promise<unknown> {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support the required verification method.');
  }

  const padded = challengeBase64Url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(challengeBase64Url.length / 4) * 4, '=');
  const binary = atob(padded);
  const challenge = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) challenge[i] = binary.charCodeAt(i);

  const credential = (await navigator.credentials.get({
    publicKey: { challenge: challenge.buffer, userVerification: 'required', timeout: 120_000 },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('No assertion was produced.');
  const response = credential.response as AuthenticatorAssertionResponse;
  const encode = (buffer: ArrayBuffer) => {
    const bytes = new Uint8Array(buffer);
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : undefined,
    },
  };
}

/**
 * Create a new credential from the server's registration options.
 *
 * The counterpart to requestAssertion above. The server sends challenge and user.id as
 * base64url text because JSON has no bytes; WebAuthn wants ArrayBuffers, and hands back
 * buffers that have to be encoded again on the way home.
 */
async function createCredential(options: {
  challenge: string;
  user: { id: string; name: string; displayName: string };
  rp?: { id?: string; name?: string };
  pubKeyCredParams?: PublicKeyCredentialParameters[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}): Promise<unknown> {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support the required verification method.');
  }

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: decodeBase64Url(options.challenge).buffer as ArrayBuffer,
      rp: { id: options.rp?.id, name: options.rp?.name ?? 'SOLVAREN' },
      user: {
        id: decodeBase64Url(options.user.id).buffer as ArrayBuffer,
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams ?? [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: options.authenticatorSelection ?? {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      timeout: 120_000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('No credential was created.');
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      attestationObject: encodeBase64Url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };
}

function decodeBase64Url(value: string): Uint8Array {
  const padded = value
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
