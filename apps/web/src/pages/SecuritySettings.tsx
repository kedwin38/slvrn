/**
 * Your own security settings (spec §7.4, §8.3).
 *
 * The Authorization PIN is the credential the release ceremony asks for, and it is separate
 * from the password on purpose: signing in and authorising a payment are different acts, and
 * a session captured after sign-in still cannot release money.
 *
 * It was unreachable. `scripts/create-user.mjs` does not set a PIN, and nothing in the
 * console offered to — so a real L2 or L3 could sign in, reach the ceremony, and be stopped
 * at the last step with no way forward. The demo accounts only worked because the seed
 * script writes PINs straight into the database.
 *
 * Each action re-asks for the password. That is not friction for its own sake: it means a
 * borrowed unlocked laptop cannot be used to set a new PIN, add an authenticator, or mint
 * recovery codes.
 */

import { useState } from 'react';
import { api, ApiError, type SessionResponse } from '../lib/api.js';
import { Notice, Field } from '../components/primitives.js';

export function SecuritySettingsPage({ session }: { session: SessionResponse }) {
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [pinPassword, setPinPassword] = useState('');
  const [pin, setPin] = useState('');
  const [pinConfirm, setPinConfirm] = useState('');

  const [keyName, setKeyName] = useState('');

  const [recoveryPassword, setRecoveryPassword] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const privileged = session.user.level !== 'L1';

  async function run(operation: () => Promise<void>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await operation();
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
          <h1 className="page-title">Security</h1>
          <p className="page-subtitle">
            Your Authorization PIN, security keys and recovery codes. These belong to you alone — an
            administrator can reset your access but cannot read any of them.
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

      {privileged && (
        <Notice tone="info">
          Releasing a payment asks for this PIN, not your password. Without one set, the ceremony
          cannot be completed.
        </Notice>
      )}

      {/* ---- Authorization PIN ---- */}
      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Authorization PIN</h2>
          <p className="small muted">
            Six to twelve digits, asked for at the moment a payment is released. Choose something
            you have not used elsewhere.
          </p>

          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              if (pin !== pinConfirm) {
                setError('The two PINs do not match.');
                return;
              }
              void run(async () => {
                await api.account.setAuthorizationPin(pinPassword, pin);
                setPinPassword('');
                setPin('');
                setPinConfirm('');
                setNotice('Your Authorization PIN has been set.');
              });
            }}
          >
            <Field label="Current password">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={pinPassword}
                  onChange={(event) => setPinPassword(event.target.value)}
                />
              )}
            </Field>

            <Field label="New PIN" hint="6 to 12 digits">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="password"
                  inputMode="numeric"
                  pattern="\d{6,12}"
                  autoComplete="off"
                  required
                  value={pin}
                  onChange={(event) => setPin(event.target.value)}
                />
              )}
            </Field>

            <Field label="Confirm PIN">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  type="password"
                  inputMode="numeric"
                  autoComplete="off"
                  required
                  value={pinConfirm}
                  onChange={(event) => setPinConfirm(event.target.value)}
                />
              )}
            </Field>

            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Saving…' : 'Set PIN'}
            </button>
          </form>
        </div>
      </div>

      {/* ---- Security keys ---- */}
      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Security keys</h2>
          <p className="small muted">
            Enrol a second key. Recovery from a single lost key is deliberately slow, so an
            executive authority with only one is one lost device away from being locked out.
          </p>

          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              void run(async () => {
                const options = await api.account.registerKeyOptions();
                const attestation = await createCredential(options);
                await api.account.registerKey(attestation, keyName || undefined);
                setKeyName('');
                setNotice('The security key has been enrolled.');
              });
            }}
          >
            <Field label="Name this key" hint="For example: work laptop, backup key in the safe">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  maxLength={80}
                  value={keyName}
                  onChange={(event) => setKeyName(event.target.value)}
                />
              )}
            </Field>

            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Waiting…' : 'Enrol another key'}
            </button>
          </form>
        </div>
      </div>

      {/* ---- Recovery codes ---- */}
      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Recovery codes</h2>
          <p className="small muted">
            Single-use codes for when you lose your key. There is no SMS reset and no way for
            support to send you a code — these, or administrative review, are the only routes back
            in.
          </p>

          {recoveryCodes ? (
            <>
              <Notice tone="warning">
                Shown once. Print them or put them somewhere a thief would not look, and treat each
                as equal to your key.
              </Notice>
              <ul style={{ columns: 2, fontFamily: 'var(--font-mono, monospace)' }}>
                {recoveryCodes.map((code) => (
                  <li key={code}>{code}</li>
                ))}
              </ul>
              <button
                className="button"
                data-variant="ghost"
                onClick={() => setRecoveryCodes(null)}
              >
                I have stored them
              </button>
            </>
          ) : (
            <form
              className="stack"
              onSubmit={(event) => {
                event.preventDefault();
                void run(async () => {
                  const result = await api.account.generateRecoveryCodes(recoveryPassword);
                  setRecoveryPassword('');
                  setRecoveryCodes(result.codes);
                });
              }}
            >
              <Notice tone="info">
                Generating a new set invalidates any codes you were given before.
              </Notice>

              <Field label="Current password">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="password"
                    autoComplete="current-password"
                    required
                    value={recoveryPassword}
                    onChange={(event) => setRecoveryPassword(event.target.value)}
                  />
                )}
              </Field>

              <button className="button" data-variant="primary" type="submit" disabled={busy}>
                {busy ? 'Generating…' : 'Generate recovery codes'}
              </button>
            </form>
          )}
        </div>
      </div>

      {/* ---- Sessions ---- */}
      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">Sessions</h2>
          <p className="small muted">
            Signs you out on every device, including this one. Use it if you think a session has
            been left open somewhere.
          </p>
          <button
            className="button"
            data-variant="ghost"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await api.account.signOutEverywhere();
                window.location.reload();
              })
            }
          >
            Sign out everywhere
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Turn the server's registration options into a credential.
 *
 * challenge and user.id arrive as base64url text because JSON has no bytes; WebAuthn wants
 * ArrayBuffers and returns buffers that have to be encoded again on the way back.
 */
async function createCredential(options: {
  challenge: string;
  user: { id: string; name: string; displayName: string };
  rp?: { id?: string; name?: string };
  excludeCredentials?: { id: string }[];
}): Promise<unknown> {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support the required verification method.');
  }

  const decode = (value: string) => {
    const padded = value
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(value.length / 4) * 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  };

  const encode = (buffer: ArrayBuffer) => {
    const bytes = new Uint8Array(buffer);
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: decode(options.challenge).buffer,
      rp: { id: options.rp?.id, name: options.rp?.name ?? 'SOLVAREN' },
      user: {
        id: decode(options.user.id).buffer,
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      // Refuses a key that is already enrolled, which would otherwise silently halve the
      // value of a "two keys registered" policy.
      excludeCredentials: (options.excludeCredentials ?? []).map((cred) => ({
        type: 'public-key' as const,
        id: decode(cred.id).buffer,
      })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      timeout: 120_000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('No credential was created.');
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      attestationObject: encode(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };
}
