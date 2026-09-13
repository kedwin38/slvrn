/**
 * Password, PIN and token cryptography.
 *
 * Argon2id is required by spec 7.2. The usual Node binding (`argon2`) is a native module
 * and cannot run in a Worker, so SOLVAREN uses `hash-wasm`, a WebAssembly implementation
 * that runs identically in Workers and in Node — meaning the hashes produced by the test
 * suite are the same hashes production verifies.
 *
 * Parameters follow OWASP's 2024 guidance for Argon2id (19 MiB, t=2, p=1). Memory is the
 * expensive dimension for an attacker and the constrained one in a Worker isolate (128 MB),
 * so 19 MiB is the point where those meet: it leaves ample headroom while making
 * large-scale offline cracking costly.
 */

import { argon2id, argon2Verify } from 'hash-wasm';
import { authenticationError, validationError } from '@solvaren/core';

export const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 19_456, // KiB — 19 MiB
  hashLength: 32,
  outputType: 'encoded' as const,
};

function randomSalt(): Uint8Array {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return salt;
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw validationError('PASSWORD_TOO_SHORT', 'The password must be at least 12 characters');
  }
  if (password.length > 1024) {
    // Unbounded input into a memory-hard function is a denial-of-service vector.
    throw validationError('PASSWORD_TOO_LONG', 'The password must be at most 1024 characters');
  }
  return argon2id({ password, salt: randomSalt(), ...ARGON2_PARAMS });
}

/**
 * Verify a password. Returns a boolean rather than throwing, because the caller must
 * perform identical work on success and failure to avoid leaking which accounts exist.
 */
export async function verifyPassword(password: string, encodedHash: string): Promise<boolean> {
  if (!encodedHash || password.length > 1024) return false;
  try {
    return await argon2Verify({ password, hash: encodedHash });
  } catch {
    // A malformed stored hash must fail closed, never throw into the auth path.
    return false;
  }
}

/**
 * SOLVAREN Authorization PIN (SPAC, spec 7.4).
 *
 * The PIN is hashed with the *same* Argon2id cost as a password despite being much shorter,
 * because its short length is exactly why it needs the work factor. It is additionally
 * bound to the user id, so a PIN hash lifted from the database cannot be tested against a
 * different account's PIN.
 */
export async function hashAuthorizationPin(pin: string, userId: string): Promise<string> {
  assertPinShape(pin);
  return argon2id({ password: `${userId}${pin}`, salt: randomSalt(), ...ARGON2_PARAMS });
}

export async function verifyAuthorizationPin(
  pin: string,
  userId: string,
  encodedHash: string | null,
): Promise<boolean> {
  if (!encodedHash) return false;
  try {
    return await argon2Verify({ password: `${userId}${pin}`, hash: encodedHash });
  } catch {
    return false;
  }
}

const TRIVIAL_PINS = new Set([
  '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777',
  '888888', '999999', '123456', '654321', '012345', '543210', '121212', '112233',
]);

export function assertPinShape(pin: string): void {
  if (!/^\d{6,12}$/.test(pin)) {
    throw validationError('PIN_FORMAT', 'The authorization PIN must be 6 to 12 digits');
  }
  if (TRIVIAL_PINS.has(pin)) {
    throw validationError('PIN_TRIVIAL', 'That authorization PIN is too easily guessed. Choose another.');
  }
  // Reject strictly ascending or descending runs of any length, e.g. 345678.
  const digits = [...pin].map(Number);
  const ascending = digits.every((d, i) => i === 0 || d === digits[i - 1]! + 1);
  const descending = digits.every((d, i) => i === 0 || d === digits[i - 1]! - 1);
  if (ascending || descending) {
    throw validationError(
      'PIN_SEQUENTIAL',
      'The authorization PIN must not be a sequence of consecutive digits',
    );
  }
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array {
  const padded = text
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(text.length / 4) * 4, '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** 256 bits of entropy. Returned to the client once; only its digest is stored. */
export function generateSessionToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/**
 * HMAC-SHA-256 of a session token under the Worker's signing key.
 *
 * A plain SHA-256 would let anyone who dumped the sessions table mount an offline search
 * against captured tokens; keying the digest means a database leak alone does not yield
 * usable session tokens.
 */
export async function hashSessionToken(token: string, signingKey: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(signingKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(token));
  return toBase64Url(new Uint8Array(signature));
}

/**
 * Constant-time string comparison, for any place a secret is compared to user input.
 * A `===` on a shared secret leaks its prefix through timing.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  // The loop always runs the same number of iterations for a given `a`, and the length
  // difference is folded into the accumulator rather than short-circuiting.
  let mismatch = aBytes.length === bBytes.length ? 0 : 1;
  const length = Math.max(aBytes.length, bBytes.length);
  for (let i = 0; i < length; i++) {
    mismatch |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
  }
  return mismatch === 0;
}

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return toBase64Url(new Uint8Array(digest));
}

/** Recovery codes: four groups of Crockford base32, shown once and stored hashed. */
export function generateRecoveryCode(): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
  return `${chars.slice(0, 5)}-${chars.slice(5, 10)}-${chars.slice(10, 15)}-${chars.slice(15, 20)}`;
}

/**
 * Envelope-encrypt an organisation secret (Daraja credentials, S3 keys) with AES-GCM
 * before it is handed to the Cloudflare Secrets Store or, in self-hosted deployments,
 * stored in a vault. The IV is random per encryption and prefixed to the ciphertext.
 */
export async function encryptSecret(plaintext: string, masterKey: string): Promise<string> {
  const keyMaterial = await crypto.subtle.digest('SHA-256', encoder.encode(masterKey));
  const key = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext),
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return toBase64Url(combined);
}

export async function decryptSecret(envelope: string, masterKey: string): Promise<string> {
  const combined = fromBase64Url(envelope);
  if (combined.length < 13) {
    throw authenticationError('SECRET_MALFORMED', 'The stored secret could not be read');
  }
  const keyMaterial = await crypto.subtle.digest('SHA-256', encoder.encode(masterKey));
  const key = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: combined.slice(0, 12) },
      key,
      combined.slice(12),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    // AES-GCM authentication failure: the ciphertext was altered or the key is wrong.
    throw authenticationError('SECRET_TAMPERED', 'The stored secret failed its integrity check');
  }
}
