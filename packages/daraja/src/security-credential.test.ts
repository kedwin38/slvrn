import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateSecurityCredential,
  extractRsaPublicKey,
  pkcs1v15Pad,
  isPrecomputedCredential,
  validateInitiatorPassword,
  pemToDer,
} from './security-credential.js';
import {
  generateKeyPairSync,
  privateDecrypt,
  constants,
  createSign,
  X509Certificate,
  createPrivateKey,
} from 'node:crypto';

/**
 * These tests prove the hand-rolled RSAES-PKCS1-v1_5 implementation is correct by
 * decrypting its output with Node's OpenSSL bindings. If the padding or the modular
 * exponentiation were wrong, `privateDecrypt` with RSA_PKCS1_PADDING would throw or return
 * the wrong plaintext — there is no way to fake this.
 */

let keyPair: ReturnType<typeof generateKeyPairSync<'pem', 'pem'>>;
let publicKeyPem: string;
let privateKeyPem: string;

beforeAll(() => {
  keyPair = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  publicKeyPem = keyPair.publicKey;
  privateKeyPem = keyPair.privateKey;
});

describe('RSAES-PKCS1-v1_5 encryption', () => {
  it('produces ciphertext that OpenSSL decrypts back to the original password', () => {
    const password = 'Safaricom#2026$Init';
    const credential = generateSecurityCredential(password, publicKeyPem);

    const decrypted = privateDecrypt(
      { key: privateKeyPem, padding: constants.RSA_PKCS1_PADDING },
      Buffer.from(credential, 'base64'),
    );
    expect(decrypted.toString('utf8')).toBe(password);
  });

  it('round-trips passwords containing every M-PESA-permitted special character', () => {
    for (const password of ['abc12345', 'Pa$$w0rd#&%', 'A'.repeat(30), '12345678']) {
      const credential = generateSecurityCredential(password, publicKeyPem);
      const decrypted = privateDecrypt(
        { key: privateKeyPem, padding: constants.RSA_PKCS1_PADDING },
        Buffer.from(credential, 'base64'),
      );
      expect(decrypted.toString('utf8')).toBe(password);
    }
  });

  it('emits a credential of exactly the modulus size in base64 (344 chars for 2048-bit)', () => {
    const credential = generateSecurityCredential('testpass', publicKeyPem);
    expect(Buffer.from(credential, 'base64')).toHaveLength(256);
    expect(credential).toHaveLength(344);
  });

  it('is randomised: encrypting the same password twice yields different ciphertext', () => {
    const a = generateSecurityCredential('testpass', publicKeyPem);
    const b = generateSecurityCredential('testpass', publicKeyPem);
    expect(a).not.toBe(b);
    // …but both decrypt to the same plaintext.
    for (const c of [a, b]) {
      expect(
        privateDecrypt(
          { key: privateKeyPem, padding: constants.RSA_PKCS1_PADDING },
          Buffer.from(c, 'base64'),
        ).toString(),
      ).toBe('testpass');
    }
  });

  it('uses OAEP-incompatible padding, as Safaricom requires', () => {
    const credential = generateSecurityCredential('testpass', publicKeyPem);
    // Decrypting PKCS1 ciphertext as OAEP must fail; if this ever succeeds we have
    // silently switched schemes and Daraja would reject every payment with 2001.
    expect(() =>
      privateDecrypt(
        { key: privateKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        Buffer.from(credential, 'base64'),
      ),
    ).toThrow();
  });
});

describe('PKCS#1 v1.5 padding structure (RFC 8017 §7.2.1)', () => {
  it('builds 0x00 0x02 || PS || 0x00 || M with no zero bytes in PS', () => {
    const message = new TextEncoder().encode('hello');
    const em = pkcs1v15Pad(message, 256);
    expect(em).toHaveLength(256);
    expect(em[0]).toBe(0x00);
    expect(em[1]).toBe(0x02);

    const terminator = em.indexOf(0x00, 2);
    expect(terminator).toBe(256 - message.length - 1);
    for (let i = 2; i < terminator; i++) expect(em[i]).not.toBe(0x00);
    expect(Array.from(em.subarray(terminator + 1))).toEqual(Array.from(message));
    // At least 8 padding bytes, per the RFC.
    expect(terminator - 2).toBeGreaterThanOrEqual(8);
  });

  it('refuses a message too long for the modulus', () => {
    expect(() => pkcs1v15Pad(new Uint8Array(250), 256)).toThrow(/too long/);
  });
});

describe('certificate parsing', () => {
  it('extracts the modulus and exponent from an SPKI PEM', () => {
    const key = extractRsaPublicKey(publicKeyPem);
    expect(key.modulusBytes).toBe(256);
    expect(key.exponent).toBe(65537n);
    expect(key.modulus.toString(2)).toHaveLength(2048);
  });

  it('extracts the key from a real X.509 certificate, as Safaricom distributes it', () => {
    // Build a self-signed certificate so the parser is exercised against a genuine
    // X.509 structure rather than a hand-made fixture.
    const cert = makeSelfSignedCertificate(privateKeyPem, publicKeyPem);
    const fromCert = extractRsaPublicKey(cert);
    const fromSpki = extractRsaPublicKey(publicKeyPem);
    expect(fromCert.modulus).toBe(fromSpki.modulus);
    expect(fromCert.exponent).toBe(fromSpki.exponent);
  });

  it('encrypts correctly using a key taken from a certificate', () => {
    const cert = makeSelfSignedCertificate(privateKeyPem, publicKeyPem);
    const credential = generateSecurityCredential('certpass', cert);
    expect(
      privateDecrypt(
        { key: privateKeyPem, padding: constants.RSA_PKCS1_PADDING },
        Buffer.from(credential, 'base64'),
      ).toString(),
    ).toBe('certpass');
  });

  it('rejects junk rather than producing an unusable credential', () => {
    expect(() => extractRsaPublicKey('not a certificate at all !!!')).toThrow(/not valid PEM/);
    expect(() =>
      extractRsaPublicKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'),
    ).toThrow();
  });

  it('rejects an empty initiator password', () => {
    expect(() => generateSecurityCredential('', publicKeyPem)).toThrow(/required/);
  });

  it('strips PEM armour correctly', () => {
    expect(pemToDer(publicKeyPem)[0]).toBe(0x30);
  });
});

describe('operator guardrails', () => {
  it('recognises a pre-computed credential so it is used as-is', () => {
    const credential = generateSecurityCredential('testpass', publicKeyPem);
    expect(isPrecomputedCredential(credential)).toBe(true);
    expect(isPrecomputedCredential('MyPassword#1')).toBe(false);
  });

  it('enforces the M-PESA portal password character rules before go-live', () => {
    expect(validateInitiatorPassword('Valid#Pass1').ok).toBe(true);
    expect(validateInitiatorPassword('has@at.com').problems.join(' ')).toMatch(/must not contain/);
    expect(validateInitiatorPassword('paren(s)here').problems.join(' ')).toMatch(
      /only the special characters/,
    );
    expect(validateInitiatorPassword('short').problems.join(' ')).toMatch(/at least 8/);
  });
});

/**
 * Minimal self-signed X.509 builder. Node has no public API to create certificates, so the
 * DER is assembled by hand — which is fine here, because the only property under test is
 * that our parser can find the public key inside a real certificate structure.
 */
function makeSelfSignedCertificate(privatePem: string, publicPem: string): string {
  const spki = Buffer.from(
    publicPem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''),
    'base64',
  );

  const der = (tag: number, content: Buffer): Buffer => {
    let lengthBytes: Buffer;
    if (content.length < 0x80) lengthBytes = Buffer.from([content.length]);
    else {
      const bytes: number[] = [];
      let len = content.length;
      while (len > 0) {
        bytes.unshift(len & 0xff);
        len >>= 8;
      }
      lengthBytes = Buffer.from([0x80 | bytes.length, ...bytes]);
    }
    return Buffer.concat([Buffer.from([tag]), lengthBytes, content]);
  };

  const int = (n: number) => der(0x02, Buffer.from([n]));
  const oidSha256Rsa = Buffer.from('06092a864886f70d01010b0500', 'hex'); // sha256WithRSAEncryption + NULL
  const algId = der(0x30, oidSha256Rsa);

  // Name ::= SEQUENCE OF RDN; one CN=solvaren-test
  const cn = der(
    0x31,
    der(
      0x30,
      Buffer.concat([Buffer.from('0603550403', 'hex'), der(0x0c, Buffer.from('solvaren-test'))]),
    ),
  );
  const name = der(0x30, cn);

  const validity = der(
    0x30,
    Buffer.concat([
      der(0x17, Buffer.from('260913000000Z')),
      der(0x17, Buffer.from('360913000000Z')),
    ]),
  );

  const tbs = der(
    0x30,
    Buffer.concat([
      der(0xa0, int(2)), // version v3
      int(1), // serial
      algId,
      name,
      validity,
      name,
      spki,
    ]),
  );

  const signature = createSign('sha256').update(tbs).sign(createPrivateKey(privatePem));
  const cert = der(
    0x30,
    Buffer.concat([tbs, algId, der(0x03, Buffer.concat([Buffer.from([0x00]), signature]))]),
  );

  const pem = `-----BEGIN CERTIFICATE-----\n${cert
    .toString('base64')
    .match(/.{1,64}/g)!
    .join('\n')}\n-----END CERTIFICATE-----\n`;

  // Sanity check: Node must accept what we built, otherwise the test proves nothing.
  new X509Certificate(pem);
  return pem;
}
