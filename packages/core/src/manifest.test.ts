import { describe, it, expect } from 'vitest';
import {
  buildManifest,
  canonicalizeManifest,
  buildChallenge,
  verifyChallengeBinding,
  CHALLENGE_TTL_MS,
  MANIFEST_VERSION,
  sha256Hex,
  type ManifestInput,
  type ManifestInstruction,
} from './manifest.js';
import { SolvarenError } from './errors.js';
import { randomToken } from './ids.js';

const instruction = (id: string, msisdn: string, cents: number): ManifestInstruction => ({
  instructionId: id,
  recipientId: `rcp-${id}`,
  msisdn,
  amountCents: cents,
});

/** Swap one instruction for a mutated copy, keeping the rest of the set intact. */
const replaceInstruction = (
  input: ManifestInput,
  instructionId: string,
  replacement: ManifestInstruction,
): ManifestInstruction[] => input.instructions.map((i) => (i.instructionId === instructionId ? replacement : i));

const baseInput = (): ManifestInput => ({
  organizationId: 'org-1',
  batchId: 'batch-1',
  batchReference: 'SLV-2026-00981',
  batchVersion: 4,
  approvalId: 'APR-8821',
  approvedBatchVersion: 4,
  instructions: [
    instruction('ins-003', '254705912645', 120_000_00),
    instruction('ins-001', '254712345678', 45_500_00),
    instruction('ins-002', '254733111222', 8_000_00),
  ],
});

describe('manifest canonicalization', () => {
  it('is deterministic regardless of instruction order', async () => {
    const a = await buildManifest(baseInput());
    const shuffled = { ...baseInput(), instructions: [...baseInput().instructions].reverse() };
    const b = await buildManifest(shuffled);
    expect(a.manifestHash).toBe(b.manifestHash);
  });

  it('totals and counts the instruction set', async () => {
    const m = await buildManifest(baseInput());
    expect(m.recipientCount).toBe(3);
    expect(m.totalAmountCents).toBe(120_000_00 + 45_500_00 + 8_000_00);
    expect(m.version).toBe(MANIFEST_VERSION);
  });

  it('produces a stable 64-character uppercase hex digest', async () => {
    const m = await buildManifest(baseInput());
    expect(m.manifestHash).toMatch(/^[0-9A-F]{64}$/);
    expect(m.manifestHash).toBe(await sha256Hex(m.canonicalForm));
  });

  // ---- §23: "Change a payment amount after Level 3 review and confirm the prior
  // signature is invalid" — each mutation must move the digest.
  it.each([
    [
      'amount change of one cent',
      (i: ManifestInput): ManifestInput => ({
        ...i,
        instructions: replaceInstruction(i, 'ins-001', instruction('ins-001', '254712345678', 45_500_01)),
      }),
    ],
    [
      'recipient MSISDN change',
      (i: ManifestInput): ManifestInput => ({
        ...i,
        instructions: replaceInstruction(i, 'ins-001', instruction('ins-001', '254712345679', 45_500_00)),
      }),
    ],
    [
      'added recipient',
      (i: ManifestInput): ManifestInput => ({
        ...i,
        instructions: [...i.instructions, instruction('ins-004', '254799888777', 1_000_00)],
      }),
    ],
    [
      'removed recipient',
      (i: ManifestInput): ManifestInput => ({ ...i, instructions: i.instructions.slice(1) }),
    ],
    [
      'different approval record',
      (i: ManifestInput): ManifestInput => ({ ...i, approvalId: 'APR-9999' }),
    ],
    [
      'different organization',
      (i: ManifestInput): ManifestInput => ({ ...i, organizationId: 'org-2' }),
    ],
  ])('a %s changes the manifest digest', async (_label, mutate) => {
    const original = await buildManifest(baseInput());
    const mutated = await buildManifest(mutate(baseInput()));
    expect(mutated.manifestHash).not.toBe(original.manifestHash);
  });

  it('refuses to hash a manifest whose approval is stale', async () => {
    const input = { ...baseInput(), batchVersion: 5, approvedBatchVersion: 4 };
    await expect(buildManifest(input)).rejects.toMatchObject({ code: 'MANIFEST_APPROVAL_STALE' });
  });

  it('refuses an empty instruction set', () => {
    expect(() => canonicalizeManifest({ ...baseInput(), instructions: [] })).toThrow(SolvarenError);
  });

  it('refuses duplicate instruction ids', () => {
    const dup = {
      ...baseInput(),
      instructions: [instruction('ins-001', '254712345678', 100_00), instruction('ins-001', '254712345678', 100_00)],
    };
    expect(() => canonicalizeManifest(dup)).toThrow(/appears twice/);
  });

  it('refuses a non-positive amount', () => {
    const bad = { ...baseInput(), instructions: [instruction('ins-001', '254712345678', 0)] };
    expect(() => canonicalizeManifest(bad)).toThrow(/non-positive/);
  });

  it('cannot be confused by field values containing separators-in-spirit', async () => {
    // Two different splits of the same concatenated text must not collide.
    const a = await buildManifest({
      ...baseInput(),
      batchId: 'batch',
      batchReference: '1SLV',
      instructions: [instruction('ins-001', '254712345678', 100_00)],
    });
    const b = await buildManifest({
      ...baseInput(),
      batchId: 'batch1',
      batchReference: 'SLV',
      instructions: [instruction('ins-001', '254712345678', 100_00)],
    });
    expect(a.manifestHash).not.toBe(b.manifestHash);
  });
});

describe('authorization challenge binding (§7.5, §23)', () => {
  const now = Date.UTC(2026, 8, 13, 10, 0, 0);

  async function ceremony(overrides: Partial<ManifestInput> = {}) {
    const manifest = await buildManifest({ ...baseInput(), ...overrides });
    const challenge = await buildChallenge({
      manifest,
      nonce: randomToken(32),
      expiresAt: now + CHALLENGE_TTL_MS,
      authorizerUserId: 'user-l3',
    });
    return { manifest, challenge };
  }

  it('issues a challenge bound to the manifest, user, nonce and expiry', async () => {
    const { manifest, challenge } = await ceremony();
    expect(challenge.manifestHash).toBe(manifest.manifestHash);
    expect(challenge.challengeHash).toMatch(/^[0-9A-F]{64}$/);
    expect(challenge.display.totalAmountCents).toBe(manifest.totalAmountCents);
    expect(challenge.display.recipientCount).toBe(3);
  });

  it('a different nonce produces a different challenge for the same manifest', async () => {
    const manifest = await buildManifest(baseInput());
    const c1 = await buildChallenge({ manifest, nonce: randomToken(32), expiresAt: now + 1000, authorizerUserId: 'u' });
    const c2 = await buildChallenge({ manifest, nonce: randomToken(32), expiresAt: now + 1000, authorizerUserId: 'u' });
    expect(c1.challengeHash).not.toBe(c2.challengeHash);
  });

  it('rejects a weak nonce', async () => {
    const manifest = await buildManifest(baseInput());
    await expect(
      buildChallenge({ manifest, nonce: 'short', expiresAt: now + 1000, authorizerUserId: 'u' }),
    ).rejects.toMatchObject({ code: 'CHALLENGE_NONCE_WEAK' });
  });

  it('accepts a valid, fresh, unconsumed challenge', async () => {
    const { manifest, challenge } = await ceremony();
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'user-l3',
        now,
      }),
    ).not.toThrow();
  });

  it('§23 replay: refuses a challenge that has already been consumed', async () => {
    const { manifest, challenge } = await ceremony();
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: now - 1000 },
        current: manifest,
        presentingUserId: 'user-l3',
        now,
      }),
    ).toThrow(/already been used/);
  });

  it('§23 replay: refuses an expired challenge', async () => {
    const { manifest, challenge } = await ceremony();
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'user-l3',
        now: now + CHALLENGE_TTL_MS + 1,
      }),
    ).toThrow(/expired/);
  });

  it('refuses a challenge presented by a different user', async () => {
    const { manifest, challenge } = await ceremony();
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'user-other-l3',
        now,
      }),
    ).toThrow(/issued to a different user/);
  });

  it('§23 manifest tampering: refuses release when an amount changed after authorization began', async () => {
    const { challenge } = await ceremony();
    // Someone edits one salary upward while the ceremony is open.
    const tampered = await buildManifest({
      ...baseInput(),
      instructions: [
        instruction('ins-003', '254705912645', 120_000_00),
        instruction('ins-001', '254712345678', 450_000_00), // 45,500 -> 450,000
        instruction('ins-002', '254733111222', 8_000_00),
      ],
    });
    try {
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: tampered,
        presentingUserId: 'user-l3',
        now,
      });
      expect.unreachable('release must not proceed on a changed manifest');
    } catch (err) {
      const e = err as SolvarenError;
      expect(e.code).toBe('MANIFEST_CHANGED');
      expect(e.details.authorizedManifest).not.toBe(e.details.currentManifest);
    }
  });

  it('refuses a challenge belonging to a different batch', async () => {
    const { challenge } = await ceremony();
    const other = await buildManifest({ ...baseInput(), batchId: 'batch-2' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: other,
        presentingUserId: 'user-l3',
        now,
      }),
    ).toThrow(/different batch/);
  });
});
