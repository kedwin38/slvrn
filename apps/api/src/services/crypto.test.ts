import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  hashAuthorizationPin,
  verifyAuthorizationPin,
  assertPinShape,
  generateSessionToken,
  hashSessionToken,
  timingSafeEqual,
  generateRecoveryCode,
  encryptSecret,
  decryptSecret,
  ARGON2_PARAMS,
  sha256Hex,
} from './crypto.js';

describe('Argon2id password hashing (§7.2)', () => {
  it('produces an Argon2id encoded hash with the documented parameters', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(ARGON2_PARAMS.memorySize).toBe(19_456);
  });

  it('verifies the correct password and rejects a wrong one', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('Correct horse battery staple', hash)).toBe(false);
    expect(await verifyPassword('', hash)).toBe(false);
  });

  it('salts every hash, so identical passwords do not collide in the database', async () => {
    const a = await hashPassword('identical password here');
    const b = await hashPassword('identical password here');
    expect(a).not.toBe(b);
    expect(await verifyPassword('identical password here', a)).toBe(true);
    expect(await verifyPassword('identical password here', b)).toBe(true);
  });

  it('fails closed on a malformed stored hash rather than throwing into the auth path', async () => {
    expect(await verifyPassword('anything', 'not-a-hash')).toBe(false);
    expect(await verifyPassword('anything', '')).toBe(false);
  });

  it('bounds input length in both directions', async () => {
    await expect(hashPassword('short')).rejects.toMatchObject({ code: 'PASSWORD_TOO_SHORT' });
    await expect(hashPassword('a'.repeat(2000))).rejects.toMatchObject({
      code: 'PASSWORD_TOO_LONG',
    });
    // An oversized candidate is refused without doing the memory-hard work.
    const hash = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('a'.repeat(2000), hash)).toBe(false);
  });
});

describe('SOLVAREN Authorization PIN (SPAC, §7.4)', () => {
  it('verifies a correct PIN for the right user', async () => {
    const hash = await hashAuthorizationPin('482913', 'user-l3');
    expect(await verifyAuthorizationPin('482913', 'user-l3', hash)).toBe(true);
    expect(await verifyAuthorizationPin('482914', 'user-l3', hash)).toBe(false);
  });

  it('binds the PIN to its user, so a stolen hash cannot be tested against another account', async () => {
    const hash = await hashAuthorizationPin('482913', 'user-l3');
    expect(await verifyAuthorizationPin('482913', 'user-other', hash)).toBe(false);
  });

  it('returns false rather than throwing when no PIN is enrolled', async () => {
    expect(await verifyAuthorizationPin('482913', 'user-l3', null)).toBe(false);
  });

  it('rejects guessable PINs at enrolment', () => {
    expect(() => assertPinShape('123456')).toThrow(/too easily guessed/);
    expect(() => assertPinShape('000000')).toThrow(/too easily guessed/);
    expect(() => assertPinShape('345678')).toThrow(/consecutive digits/);
    expect(() => assertPinShape('987654')).toThrow(/consecutive digits/);
    expect(() => assertPinShape('12345')).toThrow(/6 to 12 digits/);
    expect(() => assertPinShape('abcdef')).toThrow(/6 to 12 digits/);
    expect(() => assertPinShape('482913')).not.toThrow();
  });
});

describe('session tokens', () => {
  it('generates 256 bits of entropy per token', () => {
    const tokens = new Set(Array.from({ length: 500 }, () => generateSessionToken()));
    expect(tokens.size).toBe(500);
    expect(generateSessionToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('stores only a keyed digest, so a database leak yields no usable tokens', async () => {
    const token = generateSessionToken();
    const withKeyA = await hashSessionToken(token, 'signing-key-a');
    const withKeyB = await hashSessionToken(token, 'signing-key-b');

    expect(withKeyA).not.toBe(token);
    // Without the Worker's signing key, the same token hashes differently.
    expect(withKeyA).not.toBe(withKeyB);
    // Deterministic under the same key, so lookup works.
    expect(await hashSessionToken(token, 'signing-key-a')).toBe(withKeyA);
  });
});

describe('timing-safe comparison', () => {
  it('compares correctly regardless of length or content', () => {
    expect(timingSafeEqual('secret-value', 'secret-value')).toBe(true);
    expect(timingSafeEqual('secret-value', 'secret-valuf')).toBe(false);
    expect(timingSafeEqual('secret-value', 'secret')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
    expect(timingSafeEqual('a', '')).toBe(false);
  });

  it('does not short-circuit on the first differing byte', () => {
    // A leading-difference and a trailing-difference comparison must both examine the
    // whole input; this asserts the implementation shape rather than wall-clock timing,
    // which is far too noisy to assert on reliably in CI.
    const source = timingSafeEqual.toString();
    expect(source).not.toMatch(/return false/);
    expect(source).toMatch(/\|=/);
  });
});

describe('recovery codes (§8.3 — no SMS)', () => {
  it('generates unique, readable, grouped codes', () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(
      /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/,
    );
    // Crockford base32 excludes I, L, O and U so codes cannot be misread aloud.
    expect(code).not.toMatch(/[ILOU]/);
    expect(new Set(Array.from({ length: 200 }, generateRecoveryCode)).size).toBe(200);
  });
});

describe('secret envelope encryption (§8.4)', () => {
  const masterKey = 'master-key-for-tests-only-0123456789';

  it('round-trips a Daraja credential', async () => {
    const secret = 'RC6E9WDxXR4b9X2c6z3gp0oC5Th==';
    const envelope = await encryptSecret(secret, masterKey);
    expect(envelope).not.toContain(secret);
    expect(await decryptSecret(envelope, masterKey)).toBe(secret);
  });

  it('uses a fresh IV, so the same secret encrypts differently each time', async () => {
    const a = await encryptSecret('consumer-secret', masterKey);
    const b = await encryptSecret('consumer-secret', masterKey);
    expect(a).not.toBe(b);
    expect(await decryptSecret(a, masterKey)).toBe('consumer-secret');
    expect(await decryptSecret(b, masterKey)).toBe('consumer-secret');
  });

  it('refuses to decrypt under the wrong key', async () => {
    const envelope = await encryptSecret('consumer-secret', masterKey);
    await expect(
      decryptSecret(envelope, 'wrong-master-key-here-000000000000'),
    ).rejects.toMatchObject({
      code: 'SECRET_TAMPERED',
    });
  });

  it('detects tampering through the AES-GCM authentication tag', async () => {
    const envelope = await encryptSecret('consumer-secret', masterKey);
    // Flip a character in the ciphertext body, past the 16-char IV prefix.
    const tampered =
      envelope.slice(0, 20) + (envelope[20] === 'A' ? 'B' : 'A') + envelope.slice(21);
    await expect(decryptSecret(tampered, masterKey)).rejects.toMatchObject({
      code: 'SECRET_TAMPERED',
    });
  });

  it('rejects a truncated envelope', async () => {
    await expect(decryptSecret('AAAA', masterKey)).rejects.toMatchObject({
      code: 'SECRET_MALFORMED',
    });
  });
});

describe('sha256Hex', () => {
  it('matches the digest a plain node:crypto script produces', async () => {
    // scripts/issue-enrolment-token.mjs stores createHash('sha256').digest('hex'); the API
    // compares with this. If the two ever disagree, no enrolment token would validate.
    const { createHash } = await import('node:crypto');
    for (const value of ['', 'token', 'zBr4JVEV3l_v88dx4K6_ehifzoZLe63JtbBAEef8EwU']) {
      expect(await sha256Hex(value)).toBe(createHash('sha256').update(value).digest('hex'));
    }
  });

  it('produces 64 lowercase hex characters', async () => {
    expect(await sha256Hex('anything')).toMatch(/^[0-9a-f]{64}$/);
  });
});
