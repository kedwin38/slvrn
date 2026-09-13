/**
 * Daraja `SecurityCredential` generation.
 *
 * Safaricom specifies: take the initiator password, encrypt it with M-PESA's public key
 * (an X.509 certificate) using **RSA with PKCS #1 v1.5 padding — explicitly not OAEP** —
 * and base64-encode the result.
 *
 * The Web Crypto API available in Cloudflare Workers deliberately does not implement
 * RSAES-PKCS1-v1_5 *encryption* (it is considered legacy and is vulnerable to Bleichenbacher
 * padding-oracle attacks against a *decrypting* party). We are the encrypting party and the
 * scheme is mandated by the provider, so the operation is implemented here directly:
 *
 *   - the padding is built per RFC 8017 §7.2.1 (EME-PKCS1-v1_5), with the non-zero padding
 *     bytes drawn from `crypto.getRandomValues`, never from `Math.random`;
 *   - the modular exponentiation is plain BigInt `m^e mod n`. It involves only public key
 *     material, so there is no private-key timing surface to protect;
 *   - the certificate is parsed with a minimal DER walker rather than a dependency, so the
 *     Worker bundle carries no ASN.1 library.
 *
 * Operators who prefer not to hold the initiator password in the platform at all can
 * instead paste a credential generated offline on the Daraja portal; `isPrecomputedCredential`
 * recognises that case and the client uses the stored value as-is. Either way the plaintext
 * password is never persisted — see `apps/api/src/services/daraja-config.ts`.
 */

import { providerError, validationError } from '@solvaren/core';

// ---------------------------------------------------------------------------
// Minimal DER / PEM handling
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '');
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function pemToDer(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN [A-Z0-9 ]+-----([\s\S]*?)-----END [A-Z0-9 ]+-----/);
  const body = match ? match[1]! : pem;
  if (!/^[A-Za-z0-9+/=\s]+$/.test(body)) {
    throw validationError('DARAJA_CERT_INVALID', 'The certificate is not valid PEM or base64 data');
  }
  return base64ToBytes(body);
}

interface DerNode {
  tag: number;
  /** Offset of the content within the buffer. */
  start: number;
  length: number;
  end: number;
  /** Offset immediately after this node, including its header. */
  next: number;
}

function readDer(buf: Uint8Array, offset: number): DerNode {
  if (offset >= buf.length) {
    throw validationError('DARAJA_CERT_INVALID', 'Malformed certificate: read past end of data');
  }
  const tag = buf[offset]!;
  let i = offset + 1;
  const first = buf[i]!;
  let length: number;
  if (first < 0x80) {
    length = first;
    i += 1;
  } else {
    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) {
      throw validationError('DARAJA_CERT_INVALID', 'Malformed certificate: unsupported DER length encoding');
    }
    length = 0;
    for (let k = 1; k <= byteCount; k++) length = length * 256 + buf[i + k]!;
    i += byteCount + 1;
  }
  const start = i;
  const end = start + length;
  if (end > buf.length) {
    throw validationError('DARAJA_CERT_INVALID', 'Malformed certificate: declared length exceeds the data');
  }
  return { tag, start, length, end, next: end };
}

const TAG_SEQUENCE = 0x30;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;

export interface RsaPublicKey {
  modulus: bigint;
  exponent: bigint;
  /** Modulus size in bytes — the length of the ciphertext we must produce. */
  modulusBytes: number;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw providerError('DARAJA_CREDENTIAL_OVERFLOW', 'Encrypted value does not fit the RSA modulus');
  }
  return out;
}

/** Parse `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`. */
function parseRsaPublicKeyDer(buf: Uint8Array, offset: number): RsaPublicKey {
  const seq = readDer(buf, offset);
  if (seq.tag !== TAG_SEQUENCE) {
    throw validationError('DARAJA_CERT_INVALID', 'Expected an RSA public key SEQUENCE');
  }
  const modNode = readDer(buf, seq.start);
  if (modNode.tag !== TAG_INTEGER) {
    throw validationError('DARAJA_CERT_INVALID', 'Expected an INTEGER modulus in the RSA public key');
  }
  const expNode = readDer(buf, modNode.next);
  if (expNode.tag !== TAG_INTEGER) {
    throw validationError('DARAJA_CERT_INVALID', 'Expected an INTEGER exponent in the RSA public key');
  }

  // DER INTEGERs are signed, so a leading 0x00 is present when the high bit is set.
  let modBytes = buf.subarray(modNode.start, modNode.end);
  while (modBytes.length > 1 && modBytes[0] === 0x00) modBytes = modBytes.subarray(1);

  return {
    modulus: bytesToBigInt(modBytes),
    exponent: bytesToBigInt(buf.subarray(expNode.start, expNode.end)),
    modulusBytes: modBytes.length,
  };
}

/**
 * Extract the RSA public key from an X.509 certificate, a SubjectPublicKeyInfo, or a bare
 * RSAPublicKey — all three forms turn up in the wild when operators export the M-PESA cert.
 */
export function extractRsaPublicKey(pemOrDer: string | Uint8Array): RsaPublicKey {
  const der = typeof pemOrDer === 'string' ? pemToDer(pemOrDer) : pemOrDer;

  const outer = readDer(der, 0);
  if (outer.tag !== TAG_SEQUENCE) {
    throw validationError('DARAJA_CERT_INVALID', 'The certificate does not begin with a DER SEQUENCE');
  }

  // Case 1: bare RSAPublicKey — SEQUENCE { INTEGER, INTEGER }.
  const firstChild = readDer(der, outer.start);
  if (firstChild.tag === TAG_INTEGER) {
    const second = readDer(der, firstChild.next);
    if (second.tag === TAG_INTEGER && second.next >= outer.end) {
      return parseRsaPublicKeyDer(der, 0);
    }
  }

  // Case 2 & 3: walk the structure looking for the BIT STRING that wraps the public key.
  // In an SPKI this is the second element; in a certificate it is nested inside
  // tbsCertificate.subjectPublicKeyInfo. A bounded depth-first search finds both without
  // needing a full X.509 parser.
  const findBitString = (start: number, end: number, depth: number): DerNode | null => {
    if (depth > 6) return null;
    let cursor = start;
    while (cursor < end) {
      const node = readDer(der, cursor);
      if (node.tag === TAG_BIT_STRING) {
        // Confirm it really wraps an RSAPublicKey: first content byte is the unused-bits
        // count, which must be 0, and the remainder must parse as SEQUENCE{INT,INT}.
        if (der[node.start] === 0x00) {
          try {
            parseRsaPublicKeyDer(der, node.start + 1);
            return node;
          } catch {
            // Not the key — keep looking (certificates contain other BIT STRINGs, such as
            // the signature).
          }
        }
      }
      if (node.tag === TAG_SEQUENCE || (node.tag & 0x20) !== 0) {
        const nested = findBitString(node.start, node.end, depth + 1);
        if (nested) return nested;
      }
      cursor = node.next;
    }
    return null;
  };

  const bitString = findBitString(outer.start, outer.end, 0);
  if (!bitString) {
    throw validationError(
      'DARAJA_CERT_NO_RSA_KEY',
      'No RSA public key could be found in the supplied certificate. Upload the M-PESA public certificate issued by Safaricom.',
    );
  }
  return parseRsaPublicKeyDer(der, bitString.start + 1);
}

// ---------------------------------------------------------------------------
// RSAES-PKCS1-v1_5 encryption (RFC 8017 §7.2.1)
// ---------------------------------------------------------------------------

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

/** Build `EM = 0x00 || 0x02 || PS || 0x00 || M` with cryptographically random non-zero PS. */
export function pkcs1v15Pad(message: Uint8Array, modulusBytes: number): Uint8Array {
  // RFC 8017 requires at least 8 bytes of padding, plus the three structural bytes.
  if (message.length > modulusBytes - 11) {
    throw validationError(
      'DARAJA_CREDENTIAL_TOO_LONG',
      `The initiator password is too long for this key: at most ${modulusBytes - 11} bytes can be encrypted`,
    );
  }
  const em = new Uint8Array(modulusBytes);
  em[0] = 0x00;
  em[1] = 0x02;

  const padLength = modulusBytes - message.length - 3;
  const padding = new Uint8Array(padLength);
  crypto.getRandomValues(padding);
  // PS must contain no zero bytes; a zero would be mistaken for the terminator.
  for (let i = 0; i < padLength; i++) {
    while (padding[i] === 0) {
      const replacement = new Uint8Array(1);
      crypto.getRandomValues(replacement);
      padding[i] = replacement[0]!;
    }
  }
  em.set(padding, 2);
  em[2 + padLength] = 0x00;
  em.set(message, 3 + padLength);
  return em;
}

/**
 * Encrypt the initiator password into a Daraja `SecurityCredential`.
 *
 * The result may be reused across requests (Safaricom explicitly permits this), but a fresh
 * value is generated on each rotation because the padding is randomised, which means two
 * encryptions of the same password differ — a useful property when proving that a rotation
 * actually took effect.
 */
export function generateSecurityCredential(initiatorPassword: string, certificatePem: string): string {
  if (!initiatorPassword || initiatorPassword.trim() === '') {
    throw validationError('DARAJA_INITIATOR_PASSWORD_REQUIRED', 'The initiator password is required');
  }
  const key = extractRsaPublicKey(certificatePem);
  if (key.modulusBytes < 128) {
    throw validationError('DARAJA_CERT_WEAK', 'The certificate key is smaller than 1024 bits and will not be used');
  }
  const message = new TextEncoder().encode(initiatorPassword);
  const padded = pkcs1v15Pad(message, key.modulusBytes);
  const cipher = modPow(bytesToBigInt(padded), key.exponent, key.modulus);
  return bytesToBase64(bigIntToBytes(cipher, key.modulusBytes));
}

/**
 * Heuristic for "this is already an encrypted credential, not a password".
 * A Daraja credential is base64 of a 2048-bit (256-byte) ciphertext — 344 characters — or
 * 172 for a 1024-bit key. Passwords are never that shape.
 */
export function isPrecomputedCredential(value: string): boolean {
  const v = value.trim();
  return v.length >= 150 && /^[A-Za-z0-9+/]+={0,2}$/.test(v);
}

/**
 * Portal password rules, enforced at configuration time so that an operator does not
 * discover the constraint via a `2001` on a live payroll run. Safaricom restricts special
 * characters to `#`, `&`, `%`, `$` and treats `@` and `.` badly.
 */
export function validateInitiatorPassword(password: string): { ok: boolean; problems: string[] } {
  const problems: string[] = [];
  if (password.length < 8) problems.push('The password must be at least 8 characters');
  if (password.length > 30) problems.push('The password must be at most 30 characters');
  if (/[@.]/.test(password)) {
    problems.push('M-PESA portal passwords must not contain "@" or "." — Safaricom treats them inconsistently');
  }
  const disallowed = password.match(/[^A-Za-z0-9#&%$]/g);
  if (disallowed) {
    problems.push(
      `M-PESA permits only the special characters # & % $; remove: ${[...new Set(disallowed)].join(' ')}`,
    );
  }
  return { ok: problems.length === 0, problems };
}
