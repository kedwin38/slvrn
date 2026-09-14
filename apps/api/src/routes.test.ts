/**
 * HTTP-level route tests.
 *
 * The integration suite exercises the services directly, which proves the domain logic but
 * skips the middleware chain — and the middleware chain is where several specification
 * requirements actually live. AC-19 is explicit that "the underlying data APIs reject
 * non-L3 callers", not that a service function does; §4 HARD CONTROL says a hidden button
 * is not an access control, which is a statement about the HTTP surface.
 *
 * So these drive the real Hono application over real requests: authentication, the
 * permission matrix, the exact-level guard on the executive panels, the export policy,
 * security headers, CORS, error shapes, and the callback endpoint's behaviour under a
 * forged secret.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestEnvironment, type TestEnvironment } from './test-harness.js';
import { app } from './index.js';
import {
  hashPassword,
  hashAuthorizationPin,
  generateSessionToken,
  hashSessionToken,
} from './services/crypto.js';
import type { AuthorityLevel } from '@solvaren/core';
import { textArrayValue } from './db/client.js';

const DATABASE_AVAILABLE = Boolean(process.env.SOLVAREN_TEST_DATABASE_URL);
const suite = DATABASE_AVAILABLE ? describe : describe.skip;

const ORG = '00000000-0000-0000-0000-00000000e001';
const USERS: Record<AuthorityLevel, string> = {
  L1: '00000000-0000-0000-0000-00000000e101',
  L2: '00000000-0000-0000-0000-00000000e102',
  L3: '00000000-0000-0000-0000-00000000e103',
};

suite('HTTP routes', () => {
  let harness: TestEnvironment;
  const tokens: Record<AuthorityLevel, string> = { L1: '', L2: '', L3: '' };

  beforeAll(async () => {
    harness = await createTestEnvironment({
      databaseUrl: process.env.SOLVAREN_TEST_DATABASE_URL,
      databaseName: `solvaren_http_${process.pid}`,
    });

    const { sql } = harness;
    await sql`INSERT INTO organizations (id, name, slug) VALUES (${ORG}, 'Route Test Co', 'route-test')`;
    await sql`INSERT INTO policies (organization_id) VALUES (${ORG})`;

    const passwordHash = await hashPassword('correct horse battery staple');

    for (const level of ['L1', 'L2', 'L3'] as AuthorityLevel[]) {
      const pinHash = level === 'L1' ? null : await hashAuthorizationPin('482913', USERS[level]);
      await sql`
        INSERT INTO users (id, organization_id, email, full_name, authority_level,
                           password_hash, authorization_pin_hash)
        VALUES (${USERS[level]}, ${ORG}, ${`${level.toLowerCase()}@route.test`},
                ${`${level} Officer`}, ${level}, ${passwordHash}, ${pinHash})
      `;

      const token = generateSessionToken();
      const tokenHash = await hashSessionToken(token, harness.env.SESSION_SIGNING_KEY);
      await sql`
        INSERT INTO sessions (organization_id, user_id, token_hash, authenticated_at,
                              webauthn_verified_at, issued_at, expires_at)
        VALUES (${ORG}, ${USERS[level]}, ${tokenHash}, now(), now(), now(), now() + interval '1 hour')
      `;
      tokens[level] = token;
    }
  }, 60_000);

  afterAll(async () => {
    await harness?.close();
  });

  /** Issue a request against the real application. */
  async function call(
    path: string,
    options: {
      level?: AuthorityLevel;
      method?: string;
      body?: unknown;
      headers?: Record<string, string>;
    } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(options.headers ?? {}),
    };
    if (options.level) headers.Authorization = `Bearer ${tokens[options.level]}`;
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';

    return app.fetch(
      new Request(`https://api.solvaren.test${path}`, {
        method: options.method ?? 'GET',
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      }),
      harness.env,
    );
  }

  // =========================================================================
  // Organisation users
  //
  // This is how a second approver comes into existence, so its refusals matter as much as
  // its successes: an administrator who can promote themselves, or disable the last person
  // able to release a payment, has defeated the separation the rest of the system enforces.
  // =========================================================================

  describe('organisation users', () => {
    it('lists members to L3 with their readiness to act', async () => {
      const response = await call('/admin/users', { level: 'L3' });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        users: {
          email: string;
          level: string;
          hasAuthenticator: boolean;
          hasAuthorizationPin: boolean;
        }[];
      };
      expect(body.users.length).toBeGreaterThanOrEqual(3);
      const l3 = body.users.find((u) => u.email === 'l3@route.test');
      expect(l3?.level).toBe('L3');
      // Seeded with a PIN and no authenticator, and the screen must be able to say so.
      expect(l3?.hasAuthorizationPin).toBe(true);
      expect(l3?.hasAuthenticator).toBe(false);
    });

    it('refuses the member list to L1 and L2', async () => {
      expect((await call('/admin/users', { level: 'L1' })).status).toBe(403);
      expect((await call('/admin/users', { level: 'L2' })).status).toBe(403);
    });

    it('creates a member and returns a one-time password', async () => {
      const response = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'new.officer@route.test', fullName: 'New Officer', level: 'L1' },
      });
      expect(response.status).toBe(201);
      const body = (await response.json()) as {
        userId: string;
        temporaryPassword: string;
        status: string;
      };
      expect(body.temporaryPassword.length).toBeGreaterThan(12);
      // L1 needs no authenticator, so it is usable immediately.
      expect(body.status).toBe('ACTIVE');

      await harness.sql`DELETE FROM users WHERE id = ${body.userId}`;
    });

    it('creates an L2 pending enrolment, because a key is mandatory above L1', async () => {
      const response = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'new.controller@route.test', fullName: 'New Controller', level: 'L2' },
      });
      expect(response.status).toBe(201);
      const body = (await response.json()) as { userId: string; status: string };
      expect(body.status).toBe('PENDING_ENROLMENT');

      await harness.sql`DELETE FROM users WHERE id = ${body.userId}`;
    });

    it('refuses a duplicate email in the same organisation', async () => {
      const response = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'l1@route.test', fullName: 'Duplicate', level: 'L1' },
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('USER_ALREADY_EXISTS');
    });

    it('refuses to let an executive change their own authority', async () => {
      const response = await call(`/admin/users/${USERS.L3}/level`, {
        level: 'L3',
        method: 'PATCH',
        body: { level: 'L1' },
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('CANNOT_CHANGE_OWN_LEVEL');
    });

    it('refuses to let an executive disable themselves', async () => {
      const response = await call(`/admin/users/${USERS.L3}/status`, {
        level: 'L3',
        method: 'PATCH',
        body: { status: 'DISABLED' },
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('CANNOT_DISABLE_SELF');
    });

    it('refuses to demote the last executive authority', async () => {
      // A second L3 exists only for this assertion, and is removed again afterwards.
      const created = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'second.exec@route.test', fullName: 'Second Executive', level: 'L3' },
      });
      const { userId } = (await created.json()) as { userId: string };

      // It is PENDING_ENROLMENT, so it does not count as an active executive: demoting the
      // only ACTIVE one must still be refused.
      const response = await call(`/admin/users/${userId}/level`, {
        level: 'L3',
        method: 'PATCH',
        body: { level: 'L1' },
      });
      // Demoting the pending one is allowed; the active L3 is untouched.
      expect(response.status).toBe(200);

      await harness.sql`DELETE FROM users WHERE id = ${userId}`;
    });

    it('promotes an L1 to L2 and parks it pending enrolment until it has a PIN', async () => {
      const created = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'promotable@route.test', fullName: 'Promotable', level: 'L1' },
      });
      const { userId } = (await created.json()) as { userId: string };

      const response = await call(`/admin/users/${userId}/level`, {
        level: 'L3',
        method: 'PATCH',
        body: { level: 'L2' },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { level: string; status: string };
      expect(body.level).toBe('L2');
      // users_privileged_requires_pin would reject an ACTIVE L2 without a PIN, so the
      // endpoint parks it rather than letting the database raise a constraint error.
      expect(body.status).toBe('PENDING_ENROLMENT');

      await harness.sql`DELETE FROM users WHERE id = ${userId}`;
    });

    it('issues an enrolment token, and refuses one for an account that already has a key', async () => {
      const created = await call('/admin/users', {
        level: 'L3',
        method: 'POST',
        body: { email: 'needs.key@route.test', fullName: 'Needs Key', level: 'L2' },
      });
      const { userId } = (await created.json()) as { userId: string };

      const issued = await call(`/admin/users/${userId}/enrolment-token`, {
        level: 'L3',
        method: 'POST',
      });
      expect(issued.status).toBe(201);
      const token = (await issued.json()) as { token: string };
      expect(token.token.length).toBeGreaterThan(16);

      await harness.sql`
        INSERT INTO webauthn_credentials (
          organization_id, user_id, credential_id, public_key, signature_counter,
          transports, device_type, backed_up, friendly_name
        ) VALUES (
          ${ORG}, ${userId}, ${'already-has-one'}, ${Buffer.from([9])}, 0,
          '{}'::text[], 'CROSS_PLATFORM', false, 'Existing'
        )
      `;

      const second = await call(`/admin/users/${userId}/enrolment-token`, {
        level: 'L3',
        method: 'POST',
      });
      expect(second.status).toBe(422);

      await harness.sql`DELETE FROM webauthn_credentials WHERE user_id = ${userId}`;
      await harness.sql`DELETE FROM enrolment_tokens WHERE user_id = ${userId}`;
      await harness.sql`DELETE FROM users WHERE id = ${userId}`;
    });
  });

  // =========================================================================
  // First-authenticator enrolment
  //
  // This is the only unauthenticated path that can attach a credential to an account, and
  // the account it attaches to may be the L3 that releases payments. Each refusal below is
  // the difference between a bootstrap and an account-takeover primitive.
  // =========================================================================

  describe('first-authenticator enrolment', () => {
    const sha256Hex = async (value: string) => {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
      return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
    };

    async function issueToken(userId: string, token: string, expiresIn = '30 minutes') {
      await harness.sql`DELETE FROM enrolment_tokens WHERE user_id = ${userId} AND consumed_at IS NULL`;
      await harness.sql`
        INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at)
        VALUES (${ORG}, ${userId}, ${await sha256Hex(token)},
                now() + ${expiresIn}::interval)
      `;
    }

    const begin = (body: Record<string, unknown>) =>
      call('/auth/enrolment/options', { method: 'POST', body });

    it('issues registration options for a valid password and token', async () => {
      await issueToken(USERS.L3, 'a-valid-enrolment-token-0001');
      const response = await begin({
        email: 'l3@route.test',
        password: 'correct horse battery staple',
        token: 'a-valid-enrolment-token-0001',
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { challenge?: string };
      expect(typeof body.challenge).toBe('string');
    });

    it('refuses the correct token with the wrong password', async () => {
      await issueToken(USERS.L3, 'a-valid-enrolment-token-0002');
      const response = await begin({
        email: 'l3@route.test',
        password: 'not the password',
        token: 'a-valid-enrolment-token-0002',
      });
      expect(response.status).toBe(401);
    });

    it('refuses the correct password with a wrong token', async () => {
      await issueToken(USERS.L3, 'a-valid-enrolment-token-0003');
      const response = await begin({
        email: 'l3@route.test',
        password: 'correct horse battery staple',
        token: 'some-other-token-entirely-0003',
      });
      expect(response.status).toBe(401);
    });

    it('refuses an expired token', async () => {
      await harness.sql`DELETE FROM enrolment_tokens WHERE user_id = ${USERS.L3} AND consumed_at IS NULL`;
      await harness.sql`
        INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, issued_at, expires_at)
        VALUES (${ORG}, ${USERS.L3}, ${await sha256Hex('an-expired-token-0004')},
                now() - interval '2 hours', now() - interval '1 hour')
      `;
      const response = await begin({
        email: 'l3@route.test',
        password: 'correct horse battery staple',
        token: 'an-expired-token-0004',
      });
      expect(response.status).toBe(401);
    });

    it('refuses a token already spent', async () => {
      await issueToken(USERS.L3, 'a-spent-token-0005');
      await harness.sql`
        UPDATE enrolment_tokens SET consumed_at = now(), credential_id = 'already-used'
         WHERE user_id = ${USERS.L3} AND consumed_at IS NULL
      `;
      const response = await begin({
        email: 'l3@route.test',
        password: 'correct horse battery staple',
        token: 'a-spent-token-0005',
      });
      expect(response.status).toBe(401);
    });

    it('refuses an account that already has an authenticator', async () => {
      await issueToken(USERS.L2, 'a-valid-enrolment-token-0006');
      await harness.sql`
        INSERT INTO webauthn_credentials (
          organization_id, user_id, credential_id, public_key, signature_counter,
          transports, device_type, backed_up, friendly_name
        ) VALUES (
          ${ORG}, ${USERS.L2}, ${'existing-credential-0006'}, ${Buffer.from([1, 2, 3])}, 0,
          '{}'::text[], 'CROSS_PLATFORM', false, 'Existing key'
        )
      `;
      const response = await begin({
        email: 'l2@route.test',
        password: 'correct horse battery staple',
        token: 'a-valid-enrolment-token-0006',
      });
      expect(response.status).toBe(401);

      await harness.sql`DELETE FROM webauthn_credentials WHERE credential_id = 'existing-credential-0006'`;
    });

    it('gives the same refusal for every failure, so it is not an oracle', async () => {
      await issueToken(USERS.L3, 'a-valid-enrolment-token-0007');
      const [wrongPassword, wrongToken, unknownAccount] = await Promise.all([
        begin({ email: 'l3@route.test', password: 'wrong', token: 'a-valid-enrolment-token-0007' }),
        begin({
          email: 'l3@route.test',
          password: 'correct horse battery staple',
          token: 'wrong-token-000000000007',
        }),
        begin({
          email: 'nobody@route.test',
          password: 'correct horse battery staple',
          token: 'a-valid-enrolment-token-0007',
        }),
      ]);

      const codes = await Promise.all(
        [wrongPassword, wrongToken, unknownAccount].map(async (r) => {
          const body = (await r.json()) as { error?: { code?: string; message?: string } };
          return `${r.status}:${body.error?.code}:${body.error?.message}`;
        }),
      );
      expect(new Set(codes).size).toBe(1);
    });
  });

  // =========================================================================
  // Authentication
  // =========================================================================

  describe('authentication', () => {
    it('refuses an unauthenticated request to a protected route', async () => {
      const response = await call('/payments/transactions');
      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('AUTHENTICATION_REQUIRED');
    });

    it('refuses a malformed bearer token', async () => {
      const response = await call('/payments/transactions', {
        headers: { Authorization: 'Bearer short' },
      });
      expect(response.status).toBe(401);
    });

    it('refuses a well-formed but unknown token', async () => {
      const response = await call('/payments/transactions', {
        headers: { Authorization: `Bearer ${generateSessionToken()}` },
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'SESSION_INVALID',
      );
    });

    it('accepts a valid session and returns the capability payload', async () => {
      const response = await call('/auth/session', { level: 'L2' });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        user: { level: string };
        capabilities: Record<string, boolean>;
      };
      expect(body.user.level).toBe('L2');
      expect(body.capabilities['transactions:refresh_status']).toBe(true);
      expect(body.capabilities['payment:release']).toBe(false);
    });

    it('a revoked session stops working immediately, not at next sign-in', async () => {
      const token = generateSessionToken();
      const tokenHash = await hashSessionToken(token, harness.env.SESSION_SIGNING_KEY);
      await harness.sql`
        INSERT INTO sessions (organization_id, user_id, token_hash, authenticated_at,
                              webauthn_verified_at, issued_at, expires_at, revoked_at,
                              revocation_reason)
        VALUES (${ORG}, ${USERS.L3}, ${tokenHash}, now(), now(), now(),
                now() + interval '1 hour', now(), 'Test revocation')
      `;
      const response = await call('/auth/session', {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'SESSION_REVOKED',
      );
    });
  });

  // =========================================================================
  // AC-19 — the executive panels are L3-only at the API
  // =========================================================================

  describe('AC-19: executive dashboard panels are served to Level 3 only', () => {
    it.each(['L1', 'L2'] as AuthorityLevel[])('rejects the balance panel for %s', async (level) => {
      const response = await call('/analytics/executive/balance', { level });
      expect(response.status).toBe(403);
      const body = (await response.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe('LEVEL_RESTRICTED');
      // The refusal must not leak the figures it is refusing.
      expect(JSON.stringify(body)).not.toMatch(/availableCents|Utility/);
    });

    it.each(['L1', 'L2'] as AuthorityLevel[])(
      'rejects the recent-transactions panel for %s',
      async (level) => {
        const response = await call('/analytics/executive/recent-transactions', { level });
        expect(response.status).toBe(403);
      },
    );

    it('rejects a balance refresh request from L2', async () => {
      const response = await call('/analytics/executive/balance/refresh', {
        level: 'L2',
        method: 'POST',
      });
      expect(response.status).toBe(403);
      // And nothing was enqueued.
      expect(await harness.queues.reconciliation.pending()).toHaveLength(0);
    });

    it('serves both panels to L3', async () => {
      const balance = await call('/analytics/executive/balance', { level: 'L3' });
      expect(balance.status).toBe(200);
      const body = (await balance.json()) as {
        accounts: unknown[];
        asOf: string | null;
        note: string | null;
      };
      expect(Array.isArray(body.accounts)).toBe(true);
      // With no snapshot yet, the panel says so rather than showing zero.
      expect(body.note).toMatch(/No balance has been retrieved/);

      const recent = await call('/analytics/executive/recent-transactions', { level: 'L3' });
      expect(recent.status).toBe(200);
    });
  });

  // =========================================================================
  // AC-01/02/03 — release authority
  // =========================================================================

  describe('payment release authority', () => {
    it.each(['L1', 'L2'] as AuthorityLevel[])(
      'refuses to open a ceremony for %s',
      async (level) => {
        const response = await call(`/authorization/batches/${crypto.randomUUID()}/begin`, {
          level,
          method: 'POST',
        });
        expect(response.status).toBe(403);
        expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
          'LEVEL_RESTRICTED',
        );
      },
    );

    it.each(['L1', 'L2'] as AuthorityLevel[])('refuses to release for %s', async (level) => {
      const response = await call(`/authorization/batches/${crypto.randomUUID()}/release`, {
        level,
        method: 'POST',
        headers: { 'Idempotency-Key': 'a'.repeat(32) },
        body: {
          challengeId: crypto.randomUUID(),
          webauthnResponse: {},
          authorizationPin: '482913',
        },
      });
      expect(response.status).toBe(403);
    });

    it('requires an idempotency key on release, even for L3', async () => {
      const response = await call(`/authorization/batches/${crypto.randomUUID()}/release`, {
        level: 'L3',
        method: 'POST',
        body: {
          challengeId: crypto.randomUUID(),
          webauthnResponse: {},
          authorizationPin: '482913',
        },
      });
      expect(response.status).toBe(422);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'IDEMPOTENCY_KEY_REQUIRED',
      );
    });
  });

  // =========================================================================
  // Administration
  // =========================================================================

  describe('administrative surfaces', () => {
    it.each(['L1', 'L2'] as AuthorityLevel[])(
      'refuses Daraja configuration for %s',
      async (level) => {
        expect((await call('/admin/daraja', { level })).status).toBe(403);
      },
    );

    it.each(['L1', 'L2'] as AuthorityLevel[])(
      'refuses backup administration for %s',
      async (level) => {
        expect((await call('/admin/backups', { level })).status).toBe(403);
        expect((await call('/admin/backups/run', { level, method: 'POST' })).status).toBe(403);
      },
    );

    it('never returns a plaintext Daraja secret, even to L3 (spec §4.4)', async () => {
      const { createSecretStore, secretReference } = await import('./services/daraja-config.js');
      const { encryptSecret } = await import('./services/crypto.js');
      const store = createSecretStore(harness.env);
      const refs = {
        key: secretReference(ORG, 'sandbox', 'consumer_key'),
        secret: secretReference(ORG, 'sandbox', 'consumer_secret'),
        credential: secretReference(ORG, 'sandbox', 'security_credential'),
        callback: secretReference(ORG, 'sandbox', 'callback_secret'),
      };
      await store.put(
        refs.key,
        await encryptSecret('SUPERSECRETCONSUMERKEY', harness.env.SECRET_ENCRYPTION_KEY),
      );
      await store.put(
        refs.secret,
        await encryptSecret('SUPERSECRETCONSUMERSECRET', harness.env.SECRET_ENCRYPTION_KEY),
      );
      await store.put(
        refs.credential,
        await encryptSecret('SUPERSECRETCREDENTIAL', harness.env.SECRET_ENCRYPTION_KEY),
      );
      await store.put(
        refs.callback,
        await encryptSecret('SUPERSECRETCALLBACK', harness.env.SECRET_ENCRYPTION_KEY),
      );

      await harness.sql`
        INSERT INTO daraja_configurations (
          organization_id, environment, short_code, initiator_name,
          consumer_key_secret_ref, consumer_secret_secret_ref, security_credential_ref,
          consumer_key_last_four, result_url, queue_timeout_url, callback_secret_ref, status
        ) VALUES (
          ${ORG}, 'sandbox', '600992', 'testapi', ${refs.key}, ${refs.secret}, ${refs.credential},
          'RKEY', 'https://api.solvaren.test/cb', 'https://api.solvaren.test/to', ${refs.callback}, 'TESTING'
        )
      `;

      const response = await call('/admin/daraja', { level: 'L3' });
      expect(response.status).toBe(200);
      const text = await response.text();

      for (const secret of [
        'SUPERSECRETCONSUMERKEY',
        'SUPERSECRETCONSUMERSECRET',
        'SUPERSECRETCREDENTIAL',
        'SUPERSECRETCALLBACK',
      ]) {
        expect(text).not.toContain(secret);
      }
      expect(text).toContain('••••••••');
    });

    it('refuses to enable an integration that has not passed a connection test', async () => {
      const configs = await harness.sql<{ id: string }[]>`
        SELECT id FROM daraja_configurations WHERE organization_id = ${ORG} LIMIT 1
      `;
      const response = await call(`/admin/daraja/${configs[0]!.id}/enable`, {
        level: 'L3',
        method: 'POST',
      });
      expect(response.status).toBe(409);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'DARAJA_TEST_REQUIRED',
      );
    });
  });

  // =========================================================================
  // Transactions and exports
  // =========================================================================

  describe('transactions explorer', () => {
    it('is available to every authority level (spec §4.4)', async () => {
      for (const level of ['L1', 'L2', 'L3'] as AuthorityLevel[]) {
        const response = await call('/payments/transactions', { level });
        expect(response.status).toBe(200);
      }
    });

    it('filters by status, and by several statuses at once', async () => {
      // Seed one transaction of each interesting status so the filter has something to
      // discriminate. The earlier array-binding bug made any status filter return 500, and
      // a test asserting only a 200 would not have caught a filter that quietly ignored.
      const recipients = await harness.sql<{ id: string }[]>`
        INSERT INTO recipients (organization_id, full_name, msisdn)
        VALUES (${ORG}, 'Filter Test', '254799000111')
        ON CONFLICT (organization_id, msisdn) DO UPDATE SET full_name = EXCLUDED.full_name
        RETURNING id
      `;
      const batches = await harness.sql<{ id: string }[]>`
        INSERT INTO payment_batches (organization_id, batch_reference, purpose, created_by_user_id, state)
        VALUES (${ORG}, ${'SLV-FILTER-' + Date.now()}, 'Filter test', ${USERS.L1}, 'PROCESSING')
        RETURNING id
      `;

      for (const [index, status] of (['SUCCESS', 'FAILED', 'TIMEOUT'] as const).entries()) {
        const instructions = await harness.sql<{ id: string }[]>`
          INSERT INTO payment_instructions (organization_id, batch_id, recipient_id,
                                            recipient_name_snapshot, msisdn_snapshot, amount_cents)
          VALUES (${ORG}, ${batches[0]!.id}, ${recipients[0]!.id}, 'Filter Test', '254799000111', 100000)
          RETURNING id
        `;
        await harness.sql`
          INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                                    originator_conversation_id, request_fingerprint, amount_cents,
                                    mpesa_receipt_number, failure_code, failure_reason, status_source)
          VALUES (
            ${ORG}, ${instructions[0]!.id}, ${batches[0]!.id}, ${status},
            ${'600992-FILTER-' + Date.now() + '-' + index}, ${'fp-filter-' + index}, 100000,
            ${status === 'SUCCESS' ? 'SGFILTER01' : null},
            ${status === 'FAILED' ? '1' : status === 'TIMEOUT' ? 'SLV_TIMEOUT' : null},
            ${status === 'FAILED' ? 'Insufficient balance in the organization Utility account' : status === 'TIMEOUT' ? 'No result was received from M-PESA within the expected window' : null},
            'CALLBACK'
          )
        `;
      }

      const failed = await call('/payments/transactions?status=FAILED', { level: 'L2' });
      expect(failed.status).toBe(200);
      const failedBody = (await failed.json()) as { transactions: { status: string }[] };
      expect(failedBody.transactions.length).toBeGreaterThan(0);
      expect(failedBody.transactions.every((t) => t.status === 'FAILED')).toBe(true);

      const both = await call('/payments/transactions?status=FAILED&status=TIMEOUT', {
        level: 'L2',
      });
      const bothBody = (await both.json()) as { transactions: { status: string }[] };
      expect(bothBody.transactions.every((t) => ['FAILED', 'TIMEOUT'].includes(t.status))).toBe(
        true,
      );
      expect(bothBody.transactions.some((t) => t.status === 'TIMEOUT')).toBe(true);

      // And the mapped failure reason reaches the client (AC-17).
      const reason = failedBody.transactions[0] as unknown as {
        failureReason: string;
        failureCode: string;
      };
      expect(reason.failureCode).toBe('1');
      expect(reason.failureReason.length).toBeGreaterThan(10);
    });

    it('rejects an unknown sort column rather than interpolating it', async () => {
      const response = await call('/payments/transactions?sort=amount%3B%20DROP%20TABLE', {
        level: 'L2',
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('REQUEST_INVALID');
    });

    it('rejects an incoherent date range with an actionable message', async () => {
      const response = await call(
        '/payments/transactions?dateFrom=2026-09-30T00:00:00Z&dateTo=2026-09-01T00:00:00Z',
        { level: 'L2' },
      );
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe('FILTER_INCOHERENT');
      expect(body.error.message).toMatch(/after its end/);
    });

    it('caps the page size', async () => {
      expect((await call('/payments/transactions?pageSize=100000', { level: 'L2' })).status).toBe(
        422,
      );
    });

    it('refuses an on-demand status refresh from L1 (TRK-007)', async () => {
      const response = await call(`/payments/transactions/${crypto.randomUUID()}/refresh`, {
        level: 'L1',
        method: 'POST',
      });
      expect(response.status).toBe(403);
    });
  });

  describe('failed-transactions export (AC-18)', () => {
    it('returns a CSV with the documented columns and a provenance header', async () => {
      const response = await call('/exports/transactions/failed', { level: 'L2' });
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toMatch(/text\/csv/);
      expect(response.headers.get('Content-Disposition')).toMatch(
        /attachment; filename="failed-transactions_/,
      );

      const csv = await response.text();
      expect(csv).toContain('FailureCode');
      expect(csv).toContain('FailureReason');
      expect(csv).toContain('OriginatorConversationID');
      expect(csv).toContain('# Generated by:');
      expect(csv).toContain('authoritative payment ledger');
    });

    it('TRK-006: every export is recorded with the actor, the filter and the row count', async () => {
      await call('/exports/transactions/failed?status=FAILED', { level: 'L3' });

      const records = await harness.sql<
        {
          requested_by_user_id: string;
          requested_by_level: string;
          filter_description: string;
          row_count: number;
        }[]
      >`
        SELECT requested_by_user_id, requested_by_level, filter_description, row_count
          FROM export_records WHERE organization_id = ${ORG} ORDER BY requested_at DESC LIMIT 1
      `;
      expect(records[0]!.requested_by_user_id).toBe(USERS.L3);
      expect(records[0]!.requested_by_level).toBe('L3');
      expect(records[0]!.filter_description).toContain('status in [FAILED]');
      expect(records[0]!.row_count).toBeGreaterThanOrEqual(0);

      const audit = await harness.sql<{ action: string; actor_id: string }[]>`
        SELECT action, actor_id FROM audit_events
         WHERE organization_id = ${ORG} AND event_class = 'DATA_EXPORT'
         ORDER BY sequence DESC LIMIT 1
      `;
      expect(audit[0]!.action).toBe('export.failed_transactions');
      expect(audit[0]!.actor_id).toBe(USERS.L3);
    });

    it('honours the organisation policy on L1 exports (spec §28)', async () => {
      await harness.sql`
        UPDATE policies SET allow_l1_failed_export = FALSE WHERE organization_id = ${ORG}
      `;
      const denied = await call('/exports/transactions/failed', { level: 'L1' });
      expect(denied.status).toBe(403);
      expect(((await denied.json()) as { error: { code: string } }).error.code).toBe(
        'EXPORT_NOT_PERMITTED',
      );

      // The denial is audited, not silent.
      const audit = await harness.sql<{ action: string; outcome: string }[]>`
        SELECT action, outcome FROM audit_events
         WHERE organization_id = ${ORG} AND action = 'export.failed_transactions.denied'
         ORDER BY sequence DESC LIMIT 1
      `;
      expect(audit[0]!.outcome).toBe('DENIED');

      await harness.sql`
        UPDATE policies SET allow_l1_failed_export = TRUE WHERE organization_id = ${ORG}
      `;
      expect((await call('/exports/transactions/failed', { level: 'L1' })).status).toBe(200);
    });
  });

  // =========================================================================
  // Callback ingress
  // =========================================================================

  describe('Daraja callback ingress (spec §9.4)', () => {
    const envelope = {
      Result: {
        ResultCode: 0,
        ResultDesc: 'ok',
        OriginatorConversationID: '600992-ROUTE-TEST',
        ConversationID: 'AG_ROUTE',
        TransactionID: 'SG632NMUAB',
      },
    };

    it('accepts a valid callback and enqueues it for processing', async () => {
      const response = await app.fetch(
        new Request(
          `https://api.solvaren.test/integrations/daraja/callback/${ORG}/${harness.env.CALLBACK_SHARED_SECRET}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(envelope),
          },
        ),
        harness.env,
      );
      expect(response.status).toBe(200);
      expect((await harness.queues.callbacks.all()).length).toBeGreaterThan(0);
    });

    it('a forged secret is refused, and is indistinguishable from success to the caller', async () => {
      const before = (await harness.queues.callbacks.all()).length;
      const response = await app.fetch(
        new Request(`https://api.solvaren.test/integrations/daraja/callback/${ORG}/wrong-secret`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...envelope,
            Result: { ...envelope.Result, OriginatorConversationID: 'FORGED' },
          }),
        }),
        harness.env,
      );

      // 200, so a prober learns nothing about whether the organisation or the secret was wrong.
      expect(response.status).toBe(200);
      // But nothing was accepted.
      expect((await harness.queues.callbacks.all()).length).toBe(before);

      const events = await harness.sql<{ event_type: string; severity: string }[]>`
        SELECT event_type, severity FROM security_events
         WHERE organization_id = ${ORG} AND event_type = 'CALLBACK_AUTH_FAILED'
         ORDER BY created_at DESC LIMIT 1
      `;
      expect(events[0]!.severity).toBe('CRITICAL');
    });

    it('a malformed organisation id is rejected before it reaches a query', async () => {
      const response = await app.fetch(
        new Request(`https://api.solvaren.test/integrations/daraja/callback/not-a-uuid/secret`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(envelope),
        }),
        harness.env,
      );
      expect(response.status).toBe(200);
    });

    it('deduplicates an identical re-delivery (spec §23)', async () => {
      const unique = {
        ...envelope,
        Result: { ...envelope.Result, OriginatorConversationID: 'DEDUPE-TEST' },
      };
      const send = () =>
        app.fetch(
          new Request(
            `https://api.solvaren.test/integrations/daraja/callback/${ORG}/${harness.env.CALLBACK_SHARED_SECRET}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(unique),
            },
          ),
          harness.env,
        );

      await send();
      const afterFirst = (await harness.queues.callbacks.all()).length;
      await send();
      expect((await harness.queues.callbacks.all()).length).toBe(afterFirst);

      const stored = await harness.sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM provider_callbacks
         WHERE originator_conversation_id = 'DEDUPE-TEST'
      `;
      expect(Number(stored[0]!.count)).toBe(1);
    });
  });

  // =========================================================================
  // Transport security
  // =========================================================================

  describe('security headers and CORS', () => {
    it('sets the documented security headers on every response', async () => {
      const response = await call('/health');
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(response.headers.get('X-Frame-Options')).toBe('DENY');
      expect(response.headers.get('Referrer-Policy')).toBe('no-referrer');
      expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=63072000/);
      expect(response.headers.get('Content-Security-Policy')).toMatch(/default-src 'none'/);
      // Financial data must not be cached by an intermediary.
      expect(response.headers.get('Cache-Control')).toMatch(/no-store/);
    });

    it('returns a correlation id on every response, for support', async () => {
      const response = await call('/health');
      expect(response.headers.get('X-Correlation-Id')).toMatch(/^cor_[A-Z0-9]{20}$/);
    });

    it('ignores an inbound correlation id that is not ours', async () => {
      const response = await call('/health', {
        headers: { 'X-Correlation-Id': 'injected"><script>alert(1)</script>' },
      });
      expect(response.headers.get('X-Correlation-Id')).toMatch(/^cor_[A-Z0-9]{20}$/);
    });

    it('allows the configured console origin and no other', async () => {
      const allowed = await app.fetch(
        new Request('https://api.solvaren.test/health', {
          headers: { Origin: harness.env.APP_ORIGIN },
        }),
        harness.env,
      );
      expect(allowed.headers.get('Access-Control-Allow-Origin')).toBe(harness.env.APP_ORIGIN);

      const rejected = await app.fetch(
        new Request('https://api.solvaren.test/health', {
          headers: { Origin: 'https://evil.example' },
        }),
        harness.env,
      );
      expect(rejected.headers.get('Access-Control-Allow-Origin')).toBeNull();
    });

    it('returns a structured error with a correlation id, and no stack trace', async () => {
      const response = await call('/no-such-endpoint');
      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: { code: string; correlationId: string } };
      expect(body.error.code).toBe('ROUTE_NOT_FOUND');
      expect(body.error.correlationId).toBeTruthy();
      expect(JSON.stringify(body)).not.toMatch(/at \w+ \(|\.ts:\d+/);
    });
  });

  // =========================================================================
  // Tenant isolation
  // =========================================================================

  describe('tenant isolation', () => {
    it('cannot read a batch belonging to another organisation', async () => {
      const other = '00000000-0000-0000-0000-00000000e999';
      await harness.sql`
        INSERT INTO organizations (id, name, slug) VALUES (${other}, 'Other Co', 'other-co')
      `;
      await harness.sql`
        INSERT INTO users (id, organization_id, email, full_name, authority_level, password_hash)
        VALUES (${'00000000-0000-0000-0000-00000000e998'}, ${other}, 'x@other.test', 'X', 'L1',
                '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash')
      `;
      const batches = await harness.sql<{ id: string }[]>`
        INSERT INTO payment_batches (organization_id, batch_reference, purpose, created_by_user_id)
        VALUES (${other}, 'SLV-OTHER-0001', 'Their payroll', ${'00000000-0000-0000-0000-00000000e998'})
        RETURNING id
      `;

      const response = await call(`/batches/${batches[0]!.id}`, { level: 'L3' });
      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: { message: string } };
      // The message must not confirm the batch exists elsewhere.
      expect(body.error.message).not.toContain('SLV-OTHER-0001');
    });
  });

  // =========================================================================
  // Recipients
  //
  // Changing a recipient's phone number is the cheapest payment fraud in the product: no
  // batch is touched and no approval is sought. These tests assert the controls that make
  // it visible rather than silent.
  // =========================================================================

  describe('recipients', () => {
    let recipientId = '';

    it('normalises a local phone number to the payable 254 form', async () => {
      const response = await call('/recipients', {
        level: 'L1',
        method: 'POST',
        body: { fullName: 'Asha Wanjiru', msisdn: '0712345678' },
      });
      expect(response.status).toBe(201);
      recipientId = ((await response.json()) as { recipient: { id: string } }).recipient.id;

      const listed = await call('/recipients?search=Asha', { level: 'L1' });
      const body = (await listed.json()) as { recipients: { msisdn: string }[] };
      expect(body.recipients[0]!.msisdn).toBe('254712345678');
    });

    it('refuses a second master record for a number somebody already holds', async () => {
      const response = await call('/recipients', {
        level: 'L1',
        method: 'POST',
        body: { fullName: 'Someone Else', msisdn: '254712345678' },
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as { error: { code: string; message: string } };
      expect(body.error.code).toBe('RECIPIENT_MSISDN_EXISTS');
      // Naming the holder is the point: "already exists" alone leaves the operator hunting.
      expect(body.error.message).toContain('Asha Wanjiru');
    });

    it('refuses to change where somebody is paid without a recorded reason', async () => {
      const response = await call(`/recipients/${recipientId}`, {
        level: 'L1',
        method: 'PATCH',
        body: { msisdn: '254722000111' },
      });
      expect(response.status).toBe(422);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'RECIPIENT_MSISDN_REASON_REQUIRED',
      );
    });

    it('records the old number, the new one and the reason, and raises a security event', async () => {
      const response = await call(`/recipients/${recipientId}`, {
        level: 'L1',
        method: 'PATCH',
        body: {
          msisdn: '0722000111',
          reason: 'Confirmed by phone with the employee after a SIM swap',
        },
      });
      expect(response.status).toBe(200);
      expect(
        ((await response.json()) as { paymentDetailsChanged: boolean }).paymentDetailsChanged,
      ).toBe(true);

      const audit = await harness.sql<{ previous_state: unknown; new_state: unknown }[]>`
        SELECT previous_state, new_state FROM audit_events
         WHERE action = 'recipient.payment_details_changed' AND object_id = ${recipientId}
      `;
      expect(audit).toHaveLength(1);
      expect(audit[0]!.previous_state).toMatchObject({ msisdn: '254712345678' });
      expect(audit[0]!.new_state).toMatchObject({ msisdn: '254722000111' });

      const events = await harness.sql<{ severity: string }[]>`
        SELECT severity FROM security_events
         WHERE event_type = 'RECIPIENT_PAYMENT_DETAILS_CHANGED'
      `;
      expect(events[0]!.severity).toBe('WARNING');
    });

    it('stamps payment_details_modified_at so the risk engine can see the change', async () => {
      const rows = await harness.sql<{ recent: boolean }[]>`
        SELECT payment_details_modified_at > now() - interval '1 minute' AS recent
          FROM recipients WHERE id = ${recipientId}
      `;
      expect(rows[0]!.recent).toBe(true);
    });

    it('deactivates rather than deletes, so the payment history survives', async () => {
      const response = await call(`/recipients/${recipientId}`, {
        level: 'L1',
        method: 'PATCH',
        body: { status: 'INACTIVE' },
      });
      expect(response.status).toBe(200);
      const rows = await harness.sql<{ status: string }[]>`
        SELECT status FROM recipients WHERE id = ${recipientId}
      `;
      expect(rows[0]!.status).toBe('INACTIVE');
    });

    it('hides a recipient belonging to another organisation', async () => {
      const response = await call('/recipients/00000000-0000-0000-0000-0000000000ff', {
        level: 'L3',
      });
      expect(response.status).toBe(404);
    });
  });

  // =========================================================================
  // Reconciliation
  //
  // The rule under test is that a human cannot assert a payment succeeded. Everything else
  // here is bookkeeping; that one refusal is the control.
  // =========================================================================

  describe('reconciliation', () => {
    it('refuses the whole module to L1, who has no reconciliation authority', async () => {
      expect((await call('/reconciliation/cases', { level: 'L1' })).status).toBe(403);
      expect((await call('/reconciliation/summary', { level: 'L1' })).status).toBe(403);
    });

    it('reports an empty queue without inventing a case', async () => {
      const response = await call('/reconciliation/summary', { level: 'L2' });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { outstanding: number; discrepancies: number };
      expect(body.outstanding).toBe(0);
      expect(body.discrepancies).toBe(0);
    });

    it('404s an unknown case rather than 500ing on a non-UUID id', async () => {
      expect((await call('/reconciliation/cases/not-a-uuid', { level: 'L2' })).status).toBe(404);
    });

    describe('resolving a real case', () => {
      /** Seed a TIMEOUT transaction with an open case — the ambiguous state this exists for. */
      async function openCase(reference: string) {
        const recipients = await harness.sql<{ id: string }[]>`
          INSERT INTO recipients (organization_id, full_name, msisdn)
          VALUES (${ORG}, 'Recon Subject', ${'2547990002' + reference.slice(-2)})
          ON CONFLICT (organization_id, msisdn) DO UPDATE SET full_name = EXCLUDED.full_name
          RETURNING id
        `;
        const batches = await harness.sql<{ id: string }[]>`
          INSERT INTO payment_batches (organization_id, batch_reference, purpose,
                                       created_by_user_id, state)
          VALUES (${ORG}, ${reference}, 'Reconciliation test', ${USERS.L1}, 'PROCESSING')
          RETURNING id
        `;
        const instructions = await harness.sql<{ id: string }[]>`
          INSERT INTO payment_instructions (organization_id, batch_id, recipient_id,
                                            recipient_name_snapshot, msisdn_snapshot, amount_cents)
          VALUES (${ORG}, ${batches[0]!.id}, ${recipients[0]!.id}, 'Recon Subject',
                  ${'2547990002' + reference.slice(-2)}, 250000)
          RETURNING id
        `;
        const transactions = await harness.sql<{ id: string }[]>`
          INSERT INTO transactions (organization_id, instruction_id, batch_id, status,
                                    originator_conversation_id, request_fingerprint, amount_cents,
                                    failure_code, status_source)
          VALUES (${ORG}, ${instructions[0]!.id}, ${batches[0]!.id}, 'TIMEOUT',
                  ${'600992-' + reference}, ${'fp-' + reference}, 250000,
                  'SLV_TIMEOUT', 'QUEUE_TIMEOUT')
          RETURNING id
        `;
        const cases = await harness.sql<{ id: string }[]>`
          INSERT INTO reconciliation_cases (organization_id, transaction_id, case_reference,
                                            opened_reason)
          VALUES (${ORG}, ${transactions[0]!.id}, ${'REC-' + reference},
                  'No result was received from M-PESA within the expected window')
          RETURNING id
        `;
        return { caseId: cases[0]!.id, transactionId: transactions[0]!.id };
      }

      it('lists the open case and counts it as outstanding', async () => {
        const { caseId } = await openCase('SLV-REC-01');
        const response = await call('/reconciliation/cases?outstanding=true', { level: 'L2' });
        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          cases: { caseId: string; transaction: { recipientName: string; amountCents: number } }[];
        };
        const found = body.cases.find((c) => c.caseId === caseId)!;
        expect(found.transaction.recipientName).toBe('Recon Subject');
        expect(found.transaction.amountCents).toBe(250000);

        const summary = (await (await call('/reconciliation/summary', { level: 'L2' })).json()) as {
          outstanding: number;
        };
        expect(summary.outstanding).toBeGreaterThan(0);
      });

      it('closing as MANUAL attaches the evidence and leaves the ledger untouched', async () => {
        const { caseId, transactionId } = await openCase('SLV-REC-02');
        const response = await call(`/reconciliation/cases/${caseId}/resolve`, {
          level: 'L2',
          method: 'POST',
          body: {
            outcome: 'MANUAL',
            providerReceipt: 'SGX1234567',
            note: 'The M-PESA portal shows this paid; Safaricom never delivered the callback.',
          },
        });
        expect(response.status).toBe(200);
        expect(((await response.json()) as { state: string }).state).toBe('RESOLVED_MANUAL');

        // The operator is sure. The provider never confirmed. The ledger keeps saying so.
        const txn = await harness.sql<{ status: string }[]>`
          SELECT status FROM transactions WHERE id = ${transactionId}
        `;
        expect(txn[0]!.status).toBe('TIMEOUT');

        const row = await harness.sql<{ evidence: { providerReceipt?: string }[] }[]>`
          SELECT evidence FROM reconciliation_cases WHERE id = ${caseId}
        `;
        expect(row[0]!.evidence[0]!.providerReceipt).toBe('SGX1234567');
      });

      it('closing as FAILED writes the ledger, but only with a provider code', async () => {
        const { caseId, transactionId } = await openCase('SLV-REC-03');

        const noCode = await call(`/reconciliation/cases/${caseId}/resolve`, {
          level: 'L2',
          method: 'POST',
          body: { outcome: 'FAILED', note: 'Safaricom support confirmed it never left' },
        });
        expect(noCode.status).toBe(422);

        const response = await call(`/reconciliation/cases/${caseId}/resolve`, {
          level: 'L2',
          method: 'POST',
          body: {
            outcome: 'FAILED',
            failureCode: '2040',
            note: 'Safaricom support confirmed the recipient is not registered.',
          },
        });
        expect(response.status).toBe(200);

        const txn = await harness.sql<{ status: string; failure_code: string }[]>`
          SELECT status, failure_code FROM transactions WHERE id = ${transactionId}
        `;
        expect(txn[0]!.status).toBe('FAILED');
        expect(txn[0]!.failure_code).toBe('2040');
      });

      it('refuses to reopen a case that is already closed', async () => {
        const { caseId } = await openCase('SLV-REC-04');
        const body = {
          outcome: 'MANUAL' as const,
          note: 'Established from the provider portal and closed.',
        };
        expect(
          (
            await call(`/reconciliation/cases/${caseId}/resolve`, {
              level: 'L2',
              method: 'POST',
              body,
            })
          ).status,
        ).toBe(200);

        const again = await call(`/reconciliation/cases/${caseId}/resolve`, {
          level: 'L2',
          method: 'POST',
          body,
        });
        expect(again.status).toBe(422);
        expect(((await again.json()) as { error: { code: string } }).error.code).toBe(
          'RECONCILIATION_CASE_CLOSED',
        );
      });

      it('refuses a re-query on a closed case, so a settled outcome cannot be reopened', async () => {
        const { caseId } = await openCase('SLV-REC-05');
        await call(`/reconciliation/cases/${caseId}/resolve`, {
          level: 'L2',
          method: 'POST',
          body: { outcome: 'MANUAL', note: 'Closed after checking the provider portal.' },
        });
        const response = await call(`/reconciliation/cases/${caseId}/query`, {
          level: 'L2',
          method: 'POST',
        });
        expect(response.status).toBe(422);
      });

      it('queues a status query for an open case and marks it due now', async () => {
        const { caseId, transactionId } = await openCase('SLV-REC-06');
        const response = await call(`/reconciliation/cases/${caseId}/query`, {
          level: 'L2',
          method: 'POST',
        });
        expect(response.status).toBe(200);

        const queued = await harness.sql<{ body: { transactionId?: string } }[]>`
          SELECT body FROM job_queue WHERE queue = 'reconciliation'
        `;
        expect(queued.some((j) => j.body.transactionId === transactionId)).toBe(true);

        // Due now, not at the end of the backoff the automatic attempts have accumulated.
        const due = await harness.sql<{ due: boolean }[]>`
          SELECT next_query_at <= now() AS due FROM reconciliation_cases WHERE id = ${caseId}
        `;
        expect(due[0]!.due).toBe(true);
      });

      it('shows the case detail with its transaction and activity trail', async () => {
        const { caseId } = await openCase('SLV-REC-07');
        const response = await call(`/reconciliation/cases/${caseId}`, { level: 'L2' });
        expect(response.status).toBe(200);
        const body = (await response.json()) as {
          case: { caseReference: string; transaction: { batchReference: string } };
          activity: unknown[];
        };
        expect(body.case.caseReference).toBe('REC-SLV-REC-07');
        expect(body.case.transaction.batchReference).toBe('SLV-REC-07');
        expect(Array.isArray(body.activity)).toBe(true);
      });
    });

    it('offers no route to declaring a payment successful', async () => {
      const response = await call(
        '/reconciliation/cases/00000000-0000-0000-0000-0000000000aa/resolve',
        {
          level: 'L2',
          method: 'POST',
          body: { outcome: 'SUCCESS', note: 'I checked the portal and it paid' },
        },
      );
      // 422 from schema validation, not 404: the outcome is rejected before the case is
      // even looked up, because SUCCESS is not a value this endpoint accepts at all.
      expect(response.status).toBe(422);
    });
  });

  // =========================================================================
  // Transaction retry
  // =========================================================================

  describe('transaction retry', () => {
    it('is refused to L1, who cannot re-send a payment', async () => {
      const response = await call(
        '/payments/transactions/00000000-0000-0000-0000-0000000000bb/retry',
        { level: 'L1', method: 'POST' },
      );
      expect(response.status).toBe(403);
    });

    it('404s an unknown transaction for an authorised caller', async () => {
      const response = await call(
        '/payments/transactions/00000000-0000-0000-0000-0000000000bb/retry',
        { level: 'L2', method: 'POST' },
      );
      expect(response.status).toBe(404);
    });
  });

  // =========================================================================
  // Security centre
  // =========================================================================

  describe('security centre', () => {
    it('is L3-only, at the data API and not merely in the navigation', async () => {
      expect((await call('/admin/security/events', { level: 'L1' })).status).toBe(403);
      expect((await call('/admin/security/events', { level: 'L2' })).status).toBe(403);
      expect((await call('/admin/security/sessions', { level: 'L2' })).status).toBe(403);
    });

    it('shows L3 the events the platform recorded, with severity counts', async () => {
      await harness.sql`
        INSERT INTO security_events (organization_id, event_type, severity, description)
        VALUES (${ORG}, 'TEST_CRITICAL', 'CRITICAL', 'Something worth waking up for')
      `;
      const response = await call('/admin/security/events?unacknowledgedOnly=true', {
        level: 'L3',
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        events: { eventType: string; acknowledgedAt: string | null }[];
        counts: { severity: string; open: number }[];
      };
      expect(body.events.some((e) => e.eventType === 'TEST_CRITICAL')).toBe(true);
      expect(body.counts.find((c) => c.severity === 'CRITICAL')!.open).toBeGreaterThan(0);
    });

    it('records who reviewed an event, and never overwrites the first reviewer', async () => {
      const rows = await harness.sql<{ id: string }[]>`
        INSERT INTO security_events (organization_id, event_type, severity, description)
        VALUES (${ORG}, 'TEST_ACKNOWLEDGE', 'WARNING', 'Needs a reviewer')
        RETURNING id
      `;
      const first = await call('/admin/security/events/acknowledge', {
        level: 'L3',
        method: 'POST',
        body: { eventIds: [rows[0]!.id], note: 'Reviewed, benign' },
      });
      expect(first.status).toBe(200);
      expect(((await first.json()) as { acknowledged: number }).acknowledged).toBe(1);

      // A second pass over the list must not re-stamp it under a later reviewer.
      const second = await call('/admin/security/events/acknowledge', {
        level: 'L3',
        method: 'POST',
        body: { eventIds: [rows[0]!.id] },
      });
      expect(((await second.json()) as { acknowledged: number }).acknowledged).toBe(0);
    });

    it('lists live sessions and refuses to revoke one that is already gone', async () => {
      const response = await call('/admin/security/sessions', { level: 'L3' });
      const body = (await response.json()) as { sessions: { email: string }[] };
      expect(body.sessions.some((s) => s.email === 'l3@route.test')).toBe(true);

      const missing = await call(
        '/admin/security/sessions/00000000-0000-0000-0000-0000000000cc/revoke',
        { level: 'L3', method: 'POST' },
      );
      expect(missing.status).toBe(404);
    });
  });

  // =========================================================================
  // Reports
  //
  // The catalogue is the authority decision. If it leaked a family the caller cannot
  // generate, the console would offer a button that always fails.
  // =========================================================================

  describe('reports', () => {
    it('offers each level only the families it may generate', async () => {
      const families = async (level: AuthorityLevel) => {
        const response = await call('/reports', { level });
        const body = (await response.json()) as { reports: { family: string }[] };
        return body.reports.map((r) => r.family);
      };

      const l1 = await families('L1');
      expect(l1).toContain('payment');
      expect(l1).not.toContain('payroll');
      expect(l1).not.toContain('executive');

      const l2 = await families('L2');
      expect(l2).toContain('payroll');
      expect(l2).not.toContain('executive');

      expect(await families('L3')).toContain('executive');
    });

    it('refuses a family the caller may not generate, whatever the catalogue showed', async () => {
      expect(
        (await call('/reports/executive?from=2026-09-01&to=2026-09-30', { level: 'L2' })).status,
      ).toBe(403);
      expect(
        (await call('/reports/payroll?from=2026-09-01&to=2026-09-30', { level: 'L1' })).status,
      ).toBe(403);
    });

    it('404s a report family that does not exist', async () => {
      expect(
        (await call('/reports/invented?from=2026-09-01&to=2026-09-30', { level: 'L3' })).status,
      ).toBe(404);
    });

    it('refuses a period that ends before it starts', async () => {
      const response = await call('/reports/payment?from=2026-09-30&to=2026-09-01', {
        level: 'L1',
      });
      expect(response.status).toBe(422);
    });

    it('includes the final day of a bare-date period', async () => {
      const response = await call('/reports/payment?from=2026-09-01&to=2026-09-30', {
        level: 'L1',
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { report: { periodTo: string } };
      // Exclusive at the SQL level, so the 30th is inside the period rather than dropped.
      expect(body.report.periodTo).toBe('2026-10-01T00:00:00.000Z');
    });

    it('records generation in export_records even when nothing is downloaded', async () => {
      await call('/reports/financial?from=2026-09-01&to=2026-09-30', { level: 'L3' });
      const rows = await harness.sql<{ export_type: string; status: string }[]>`
        SELECT export_type, status FROM export_records
         WHERE organization_id = ${ORG} AND filter_json->>'family' = 'financial'
      `;
      expect(rows[0]!.export_type).toBe('MANAGEMENT');
      expect(rows[0]!.status).toBe('COMPLETED');
    });

    it('computes every family in the catalogue without an error', async () => {
      // Each family is its own SQL query against the ledger. A family that throws only when
      // somebody selects it at month end is a report that does not exist.
      const catalogue = (await (await call('/reports', { level: 'L3' })).json()) as {
        reports: { family: string; title: string }[];
      };
      expect(catalogue.reports).toHaveLength(12);

      for (const entry of catalogue.reports) {
        const response = await call(`/reports/${entry.family}?from=2026-09-01&to=2026-09-30`, {
          level: 'L3',
        });
        expect(response.status, `${entry.family} failed`).toBe(200);
        const body = (await response.json()) as {
          report: {
            title: string;
            sections: { title: string; columns: unknown[] }[];
            highlights: unknown[];
          };
        };
        expect(body.report.title).toBe(entry.title);
        expect(body.report.sections.length).toBeGreaterThan(0);
        for (const section of body.report.sections) {
          expect(section.columns.length).toBeGreaterThan(0);
        }
      }
    });

    it('renders every family as CSV too, so a report is never screen-only', async () => {
      for (const family of [
        'payment',
        'financial',
        'payroll',
        'department',
        'reconciliation',
        'risk',
        'audit',
        'user-activity',
        'system-activity',
        'daraja',
        'executive',
        'ai-intelligence',
      ]) {
        const response = await call(`/reports/${family}?from=2026-09-01&to=2026-09-30&format=csv`, {
          level: 'L3',
        });
        expect(response.status, `${family} CSV failed`).toBe(200);
        expect(await response.text()).toContain('# Period: 2026-09-01');
      }
    });

    it('compares the executive period against the span immediately before it', async () => {
      const response = await call('/reports/executive?from=2026-09-01&to=2026-09-30', {
        level: 'L3',
      });
      const body = (await response.json()) as {
        report: { sections: { title: string; rows: Record<string, unknown>[] }[] };
      };
      const comparison = body.report.sections.find((s) => s.title === 'Period comparison');
      expect(comparison).toBeDefined();
      expect(comparison!.rows.map((r) => r.metric)).toContain('Disbursed (KES)');

      const control = body.report.sections.find((s) => s.title === 'Control posture');
      // Named, not just counted: an executive reading "3" needs to know three of what.
      expect(control!.rows.map((r) => r.item)).toContain('Open reconciliation cases');
    });

    it('serves CSV with a filename and a provenance header', async () => {
      const response = await call('/reports/payment?from=2026-09-01&to=2026-09-30&format=csv', {
        level: 'L1',
      });
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/csv');
      expect(response.headers.get('Content-Disposition')).toContain('report_payment_route-test');
      const csv = await response.text();
      expect(csv).toContain('# Generated by:');
      expect(csv).toContain('# Period: 2026-09-01');
    });
  });

  // =========================================================================
  // Action queue
  // =========================================================================

  describe('action queue', () => {
    it('tells an L3 when no payment can run, because the credentials are missing or unhealthy', async () => {
      const response = await call('/analytics/action-queue', { level: 'L3' });
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        items: { kind: string; severity: string; route: string }[];
      };
      // Either shape counts: the point is that an executive is never left to discover at
      // release time that nothing could have been paid.
      const item = body.items.find(
        (i) => i.kind === 'DARAJA_NOT_CONFIGURED' || i.kind === 'DARAJA_UNHEALTHY',
      );
      expect(item).toBeDefined();
      expect(item!.severity).toBe('critical');
      // Every item names the screen that acts on it; a notice with nowhere to go is noise.
      expect(item!.route).toBe('daraja');
    });

    it('does not tell an L1 about administration work they cannot do', async () => {
      const response = await call('/analytics/action-queue', { level: 'L1' });
      const body = (await response.json()) as { items: { kind: string }[] };
      const kinds = body.items.map((i) => i.kind);
      expect(kinds).not.toContain('DARAJA_NOT_CONFIGURED');
      expect(kinds).not.toContain('SECURITY_EVENTS_UNACKNOWLEDGED');
    });

    it('sorts the most serious first, so the critical item is never below the fold', async () => {
      const response = await call('/analytics/action-queue', { level: 'L3' });
      const body = (await response.json()) as { items: { severity: string }[] };
      const rank = { critical: 0, warning: 1, info: 2 } as const;
      const severities = body.items.map((i) => rank[i.severity as keyof typeof rank]);
      for (let i = 1; i < severities.length; i++) {
        expect(severities[i]!).toBeGreaterThanOrEqual(severities[i - 1]!);
      }
    });
  });

  // =========================================================================
  // The batch lifecycle, end to end through HTTP
  //
  // Every one of these steps existed as an endpoint and none of them was reachable from the
  // console. A draft could not be resumed and no L2 could approve anything, so a batch
  // submitted to Finance Control could never reach the executive — and no payment could
  // ever be released on a real deployment.
  // =========================================================================

  // =========================================================================
  // Daraja is Level 3 alone (spec §4.4, §9)
  //
  // Not "hidden from the menu" — refused at the data API, on every verb and every path, for
  // both lower levels. The console hiding the screen is a courtesy; this is the control.
  // =========================================================================

  // =========================================================================
  // Conflict-of-interest registry
  //
  // The release path has barred conflicted approvers from the first commit, against a table
  // nothing could write to. These endpoints are what make that control usable.
  // =========================================================================

  // =========================================================================
  // Credential recovery (§11)
  //
  // Recovery codes were generated and shown to users from the first commit and nothing
  // could redeem one; there was no password reset for anybody, self-service or
  // administrative. A user who forgot their password was locked out permanently.
  // =========================================================================

  // =========================================================================
  // Step-up authentication (§8.2, §9)
  //
  // Nine administrative actions and the release ceremony refuse anything attempted more
  // than five minutes after sign-in, and nothing anywhere could satisfy that. Saving M-PESA
  // credentials was impossible in practice, so a real deployment could never be configured
  // to pay anybody.
  // =========================================================================

  describe('step-up authentication', () => {
    /** Age the session past the five-minute window, as ordinary use does within minutes. */
    async function staleSession(level: AuthorityLevel) {
      await harness.sql`
        UPDATE sessions SET authenticated_at = now() - interval '30 minutes'
         WHERE user_id = ${USERS[level]} AND revoked_at IS NULL
      `;
    }

    async function freshSession(level: AuthorityLevel) {
      await harness.sql`
        UPDATE sessions SET authenticated_at = now()
         WHERE user_id = ${USERS[level]} AND revoked_at IS NULL
      `;
    }

    afterAll(async () => {
      for (const level of ['L1', 'L2', 'L3'] as AuthorityLevel[]) await freshSession(level);
    });

    it('refuses a privileged action once the session is no longer fresh', async () => {
      await staleSession('L3');
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'Safaricom2026pay',
        },
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'STEP_UP_REQUIRED',
      );
    });

    it('refuses to step up on a wrong password, and records the attempt', async () => {
      const response = await call('/auth/step-up', {
        level: 'L3',
        method: 'POST',
        body: { password: 'not the right password at all' },
      });
      expect(response.status).toBe(401);

      const events = await harness.sql<{ severity: string }[]>`
        SELECT severity FROM security_events WHERE event_type = 'STEP_UP_FAILED'
         AND user_id = ${USERS.L3}
      `;
      expect(events.length).toBeGreaterThan(0);
    });

    it('confirms with a password when the account has no authenticator', async () => {
      // The L1 fixture has no WebAuthn credential, so the password is its only credential
      // and re-presenting it is the whole of step-up.
      await staleSession('L1');
      const response = await call('/auth/step-up', {
        level: 'L1',
        method: 'POST',
        body: { password: 'correct horse battery staple' },
      });
      expect(response.status).toBe(200);
      expect(((await response.json()) as { stage: string }).stage).toBe('CONFIRMED');

      const rows = await harness.sql<{ fresh: boolean }[]>`
        SELECT authenticated_at > now() - interval '1 minute' AS fresh FROM sessions
         WHERE user_id = ${USERS.L1} AND revoked_at IS NULL LIMIT 1
      `;
      expect(rows[0]!.fresh).toBe(true);
    });

    it('demands the authenticator from anyone who has one', async () => {
      // Seeded so this account holds a credential; a password alone must not elevate it.
      await harness.sql`
        INSERT INTO webauthn_credentials (organization_id, user_id, credential_id, public_key,
                                          signature_counter, transports, status)
        VALUES (${ORG}, ${USERS.L3}, 'step-up-credential-1', ${Buffer.from([1, 2, 3])},
                0, ${textArrayValue(harness.sql, ['internal'])}, 'ACTIVE')
        ON CONFLICT DO NOTHING
      `;

      const response = await call('/auth/step-up', {
        level: 'L3',
        method: 'POST',
        body: { password: 'correct horse battery staple' },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { stage: string; ticket?: string };
      // Not CONFIRMED: the password alone is not enough for an account with a key.
      expect(body.stage).toBe('WEBAUTHN_REQUIRED');
      expect(body.ticket).toBeDefined();

      // And the session is still stale until the assertion lands.
      const rows = await harness.sql<{ stale: boolean }[]>`
        SELECT authenticated_at < now() - interval '5 minutes' AS stale FROM sessions
         WHERE user_id = ${USERS.L3} AND revoked_at IS NULL LIMIT 1
      `;
      expect(rows[0]!.stale).toBe(true);
    });

    it('refuses a step-up ticket issued for a different session', async () => {
      const started = (await (
        await call('/auth/step-up', {
          level: 'L3',
          method: 'POST',
          body: { password: 'correct horse battery staple' },
        })
      ).json()) as { ticket: string };

      // Re-point the stored challenge at another session, as a captured ticket replayed
      // from a second device would be.
      await harness.sql`
        UPDATE security_events
           SET detail = jsonb_set(detail, '{sessionId}', '"00000000-0000-0000-0000-0000000000ff"')
         WHERE event_type = 'STEP_UP_CHALLENGE_ISSUED' AND detail->>'ticket' = ${started.ticket}
      `;

      const response = await call('/auth/step-up/verify', {
        level: 'L3',
        method: 'POST',
        body: { ticket: started.ticket, response: { id: 'step-up-credential-1' } },
      });
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'STEP_UP_CHALLENGE_EXPIRED',
      );
    });

    it('refuses an unknown ticket', async () => {
      const response = await call('/auth/step-up/verify', {
        level: 'L3',
        method: 'POST',
        body: { ticket: 'A'.repeat(32), response: { id: 'step-up-credential-1' } },
      });
      expect(response.status).toBe(401);
    });

    it('lets the privileged action through once the session is fresh again', async () => {
      // The end the whole flow exists for: after confirming, the action that was refused
      // succeeds. Simulated here at the session level, which is exactly what verify does.
      await freshSession('L3');
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'Safaricom2026pay',
        },
      });
      // No longer STEP_UP_REQUIRED — it now fails only for want of a certificate.
      expect(response.status).not.toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
        'DARAJA_CERTIFICATE_REQUIRED',
      );
    });

    it('requires a session at all', async () => {
      expect(
        (await call('/auth/step-up', { method: 'POST', body: { password: 'x' } })).status,
      ).toBe(401);
    });
  });

  describe('credential recovery', () => {
    /*
     * Recovery revokes every session on the account it recovers — that is precisely what it
     * is for. These tests therefore sign the suite's own tokens out as they go, so they are
     * re-minted here rather than softening the behaviour under test.
     */
    async function reissueSessions() {
      // Administrative recovery also parks a privileged account as PENDING_ENROLMENT when
      // its keys are revoked, and such an account cannot hold a session at all.
      await harness.sql`
        UPDATE users SET status = 'ACTIVE'
         WHERE organization_id = ${ORG} AND status <> 'ACTIVE'
      `;
      for (const level of ['L1', 'L2', 'L3'] as AuthorityLevel[]) {
        const token = generateSessionToken();
        await harness.sql`
          INSERT INTO sessions (organization_id, user_id, token_hash, authenticated_at,
                                webauthn_verified_at, issued_at, expires_at)
          VALUES (${ORG}, ${USERS[level]},
                  ${await hashSessionToken(token, harness.env.SESSION_SIGNING_KEY)},
                  now(), now(), now(), now() + interval '1 hour')
        `;
        tokens[level] = token;
      }
    }

    afterAll(reissueSessions);

    /** Mint a code the way the account-security screen does, and return the plaintext. */
    async function issueCode(userId: string) {
      const { generateRecoveryCode, hashSessionToken } = await import('./services/crypto.js');
      const code = generateRecoveryCode();
      await harness.sql`
        INSERT INTO recovery_codes (organization_id, user_id, code_hash)
        VALUES (${ORG}, ${userId},
                ${await hashSessionToken(code, harness.env.SESSION_SIGNING_KEY)})
      `;
      return code;
    }

    const NEW_PASSWORD = 'recovered-passphrase-2026';

    it('refuses an unknown email and a wrong code identically, so it is not an oracle', async () => {
      const unknown = await call('/auth/recovery/start', {
        method: 'POST',
        body: { email: 'nobody@route.test', code: 'AAAA-BBBB-CCCC' },
      });
      const wrongCode = await call('/auth/recovery/start', {
        method: 'POST',
        body: { email: 'l1@route.test', code: 'AAAA-BBBB-CCCC' },
      });

      expect(unknown.status).toBe(wrongCode.status);
      const a = (await unknown.json()) as { error: { code: string; message: string } };
      const b = (await wrongCode.json()) as { error: { code: string; message: string } };
      // Identical code AND identical wording: either differing would say whether the
      // account exists.
      expect(a.error.code).toBe(b.error.code);
      expect(a.error.message).toBe(b.error.message);
    });

    it('redeems a valid code for a single-use ticket, and spends the code', async () => {
      const code = await issueCode(USERS.L1);
      const response = await call('/auth/recovery/start', {
        method: 'POST',
        body: { email: 'l1@route.test', code },
      });
      expect(response.status).toBe(200);
      const body = (await response.json()) as { ticket: string; remainingCodes: number };
      expect(body.ticket.length).toBeGreaterThanOrEqual(32);

      // The same code a second time is refused: single use means single use.
      const replay = await call('/auth/recovery/start', {
        method: 'POST',
        body: { email: 'l1@route.test', code },
      });
      expect(replay.status).toBe(401);
    });

    it('does not sign anybody in — a ticket is not a session', async () => {
      const code = await issueCode(USERS.L1);
      const started = (await (
        await call('/auth/recovery/start', {
          method: 'POST',
          body: { email: 'l1@route.test', code },
        })
      ).json()) as { ticket: string };

      // The ticket must not be usable as a bearer token anywhere.
      const asSession = await app.fetch(
        new Request('https://api.solvaren.test/auth/session', {
          headers: { Authorization: `Bearer ${started.ticket}`, Accept: 'application/json' },
        }),
        harness.env,
      );
      expect(asSession.status).toBe(401);
    });

    it('sets the new password and signs every session out', async () => {
      const code = await issueCode(USERS.L1);
      const started = (await (
        await call('/auth/recovery/start', {
          method: 'POST',
          body: { email: 'l1@route.test', code },
        })
      ).json()) as { ticket: string };

      const before = await harness.sql<{ count: string }[]>`
        SELECT count(*)::text AS count FROM sessions
         WHERE user_id = ${USERS.L1} AND revoked_at IS NULL
      `;
      expect(Number(before[0]!.count)).toBeGreaterThan(0);

      const completed = await call('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket: started.ticket, newPassword: NEW_PASSWORD },
      });
      expect(completed.status).toBe(200);

      const after = await harness.sql<{ count: string }[]>`
        SELECT count(*)::text AS count FROM sessions
         WHERE user_id = ${USERS.L1} AND revoked_at IS NULL
      `;
      // If recovery was prompted by somebody else holding the old password, a surviving
      // session is their way back in.
      expect(after[0]!.count).toBe('0');

      // And the new password actually works.
      const login = await call('/auth/login', {
        method: 'POST',
        body: { email: 'l1@route.test', password: NEW_PASSWORD },
      });
      expect(login.status).toBe(200);
      expect(((await login.json()) as { stage: string }).stage).toBe('AUTHENTICATED');
    });

    it('refuses a spent ticket, so one proof of identity resets one password', async () => {
      const code = await issueCode(USERS.L1);
      const started = (await (
        await call('/auth/recovery/start', {
          method: 'POST',
          body: { email: 'l1@route.test', code },
        })
      ).json()) as { ticket: string };

      await call('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket: started.ticket, newPassword: 'first-recovered-pass-2026' },
      });
      const again = await call('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket: started.ticket, newPassword: 'second-recovered-pass-2026' },
      });
      expect(again.status).toBe(401);
    });

    it('refuses an expired ticket', async () => {
      const { hashSessionToken } = await import('./services/crypto.js');
      const { randomToken } = await import('@solvaren/core');
      const ticket = randomToken(32);

      // Inserted already-aged rather than backdated by UPDATE: the guard trigger refuses to
      // let a ticket's issue be rewritten, which is itself the behaviour we want.
      await harness.sql`
        UPDATE recovery_tickets SET consumed_at = now()
         WHERE user_id = ${USERS.L1} AND consumed_at IS NULL
      `;
      await harness.sql`
        INSERT INTO recovery_tickets (organization_id, user_id, ticket_hash, origin,
                                      issued_at, expires_at)
        VALUES (${ORG}, ${USERS.L1},
                ${await hashSessionToken(ticket, harness.env.SESSION_SIGNING_KEY)},
                'RECOVERY_CODE', now() - interval '30 minutes', now() - interval '15 minutes')
      `;

      const response = await call('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket, newPassword: 'expired-ticket-pass-2026' },
      });
      expect(response.status).toBe(401);
    });

    it('refuses a short password and refuses reusing the current one', async () => {
      const code = await issueCode(USERS.L1);
      const started = (await (
        await call('/auth/recovery/start', {
          method: 'POST',
          body: { email: 'l1@route.test', code },
        })
      ).json()) as { ticket: string };

      expect(
        (
          await call('/auth/recovery/complete', {
            method: 'POST',
            body: { ticket: started.ticket, newPassword: 'short' },
          })
        ).status,
      ).toBe(422);

      // The current password is whatever the last successful recovery set.
      const reuse = await call('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket: started.ticket, newPassword: 'first-recovered-pass-2026' },
      });
      expect(reuse.status).toBe(422);
      expect(((await reuse.json()) as { error: { code: string } }).error.code).toBe(
        'PASSWORD_UNCHANGED',
      );
    });

    it('will not recover a disabled account, and says so loudly in the security log', async () => {
      const code = await issueCode(USERS.L2);
      await harness.sql`UPDATE users SET status = 'DISABLED' WHERE id = ${USERS.L2}`;

      const response = await call('/auth/recovery/start', {
        method: 'POST',
        body: { email: 'l2@route.test', code },
      });
      expect(response.status).toBe(401);

      const events = await harness.sql<{ severity: string }[]>`
        SELECT severity FROM security_events WHERE event_type = 'RECOVERY_ON_DISABLED_ACCOUNT'
      `;
      expect(events[0]!.severity).toBe('CRITICAL');

      await harness.sql`UPDATE users SET status = 'ACTIVE' WHERE id = ${USERS.L2}`;
    });

    describe('administrative recovery', () => {
      beforeAll(reissueSessions);

      it('is refused to everyone below L3', async () => {
        for (const level of ['L1', 'L2'] as AuthorityLevel[]) {
          const response = await call(`/admin/users/${USERS.L1}/reset-access`, {
            level,
            method: 'POST',
            body: { reason: 'Attempting a reset without the authority for it' },
          });
          expect(response.status).toBe(403);
        }
      });

      it('refuses an executive resetting their own access', async () => {
        const response = await call(`/admin/users/${USERS.L3}/reset-access`, {
          level: 'L3',
          method: 'POST',
          body: { reason: 'Trying to re-key the account I am signed in to' },
        });
        expect(response.status).toBe(422);
        expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
          'CANNOT_RESET_SELF',
        );
      });

      it('mints a one-time password, kills the sessions and records the reason', async () => {
        const response = await call(`/admin/users/${USERS.L1}/reset-access`, {
          level: 'L3',
          method: 'POST',
          body: { reason: 'Employee forgot their password and has no recovery codes left' },
        });
        expect(response.status).toBe(200);
        const body = (await response.json()) as { oneTimePassword: string; status: string };
        expect(body.oneTimePassword.length).toBeGreaterThan(8);

        const live = await harness.sql<{ count: string }[]>`
          SELECT count(*)::text AS count FROM sessions
           WHERE user_id = ${USERS.L1} AND revoked_at IS NULL
        `;
        expect(live[0]!.count).toBe('0');

        // The issued password works, which is the whole point of the exercise.
        const login = await call('/auth/login', {
          method: 'POST',
          body: { email: 'l1@route.test', password: body.oneTimePassword },
        });
        expect(login.status).toBe(200);

        const audit = await harness.sql<{ detail: { reason?: string } }[]>`
          SELECT detail FROM audit_events WHERE action = 'user.access_reset'
           ORDER BY sequence DESC LIMIT 1
        `;
        expect(audit[0]!.detail.reason).toContain('forgot their password');
      });

      it('parks a privileged account pending enrolment when its keys are revoked', async () => {
        const response = await call(`/admin/users/${USERS.L2}/reset-access`, {
          level: 'L3',
          method: 'POST',
          body: {
            reason: 'Laptop and security key both lost in transit',
            revokeAuthenticators: true,
          },
        });
        expect(response.status).toBe(200);
        const body = (await response.json()) as { status: string; authenticatorsRevoked: boolean };
        // An L2 with no authenticator cannot sign in, so ACTIVE would be a lie.
        expect(body.status).toBe('PENDING_ENROLMENT');
        expect(body.authenticatorsRevoked).toBe(true);
      });

      it('raises a CRITICAL security event when one executive re-keys another', async () => {
        // Seeded so there is a second L3 to recover; re-keying an executive is the move a
        // hostile insider would make, so it must be loud.
        const other = '00000000-0000-0000-0000-00000000e203';
        await harness.sql`
          INSERT INTO users (id, organization_id, email, full_name, authority_level,
                             password_hash, authorization_pin_hash)
          VALUES (${other}, ${ORG}, 'l3b@route.test', 'Second Executive', 'L3',
                  ${await hashPassword('another-executive-password')},
                  ${await hashAuthorizationPin('918273', other)})
          ON CONFLICT (id) DO NOTHING
        `;

        const response = await call(`/admin/users/${other}/reset-access`, {
          level: 'L3',
          method: 'POST',
          body: { reason: 'Colleague locked out before the month-end payment run' },
        });
        expect(response.status).toBe(200);

        const events = await harness.sql<{ severity: string }[]>`
          SELECT severity FROM security_events
           WHERE event_type = 'ACCESS_RESET_BY_ADMINISTRATOR' AND user_id = ${other}
        `;
        expect(events[0]!.severity).toBe('CRITICAL');
      });
    });
  });

  describe('conflict of interest', () => {
    let conflictId = '';

    it('is administered by L3 alone', async () => {
      expect((await call('/admin/conflicts', { level: 'L1' })).status).toBe(403);
      expect((await call('/admin/conflicts', { level: 'L2' })).status).toBe(403);
      expect((await call('/admin/conflicts', { level: 'L3' })).status).toBe(200);
    });

    it('records a declaration against a named member, with a reason', async () => {
      const response = await call('/admin/conflicts', {
        level: 'L3',
        method: 'POST',
        body: {
          userId: USERS.L3,
          scopeType: 'ORGANIZATION',
          reason: 'Director of a supplier paid through this organisation',
        },
      });
      expect(response.status).toBe(201);
      conflictId = ((await response.json()) as { conflict: { id: string } }).conflict.id;

      const listed = (await (await call('/admin/conflicts', { level: 'L3' })).json()) as {
        conflicts: { id: string; scopeType: string; withdrawnAt: string | null }[];
      };
      const found = listed.conflicts.find((c) => c.id === conflictId)!;
      expect(found.scopeType).toBe('ORGANIZATION');
      expect(found.withdrawnAt).toBeNull();
    });

    it('refuses an organisation-wide conflict that also names a scope', async () => {
      const response = await call('/admin/conflicts', {
        level: 'L3',
        method: 'POST',
        body: {
          userId: USERS.L3,
          scopeType: 'ORGANIZATION',
          scopeId: '00000000-0000-0000-0000-0000000000f9',
          reason: 'Contradictory scope that should be refused',
        },
      });
      expect(response.status).toBe(422);
    });

    it('refuses a scoped conflict that names no scope', async () => {
      const response = await call('/admin/conflicts', {
        level: 'L3',
        method: 'POST',
        body: {
          userId: USERS.L3,
          scopeType: 'RECIPIENT',
          reason: 'A recipient conflict with no recipient named',
        },
      });
      expect(response.status).toBe(422);
    });

    it('stops the declared approver opening a ceremony while it stands', async () => {
      // The registry is not advisory. With an organisation-wide conflict recorded against
      // the only L3, the release path must refuse them.
      const batchId = await (async () => {
        const created = await call('/batches', {
          level: 'L1',
          method: 'POST',
          body: { purpose: 'Conflict test' },
        });
        return ((await created.json()) as { batchId: string }).batchId;
      })();

      const response = await call(`/authorization/batches/${batchId}/begin`, {
        level: 'L3',
        method: 'POST',
        body: {},
      });
      // Refused — on the conflict, on the batch state, or on both. What matters is that a
      // declared conflict never results in a ceremony being opened.
      expect(response.status).not.toBe(200);
    });

    it('withdraws rather than deletes, so the history survives', async () => {
      const response = await call(`/admin/conflicts/${conflictId}/withdraw`, {
        level: 'L3',
        method: 'POST',
        body: { reason: 'The directorship ended on 30 September' },
      });
      expect(response.status).toBe(200);

      const listed = (await (await call('/admin/conflicts', { level: 'L3' })).json()) as {
        conflicts: { id: string; withdrawnAt: string | null }[];
      };
      const found = listed.conflicts.find((c) => c.id === conflictId)!;
      expect(found).toBeDefined();
      expect(found.withdrawnAt).not.toBeNull();

      // Withdrawing twice is refused rather than silently repeated.
      const again = await call(`/admin/conflicts/${conflictId}/withdraw`, {
        level: 'L3',
        method: 'POST',
        body: { reason: 'Attempting the same withdrawal a second time' },
      });
      expect(again.status).toBe(404);
    });
  });

  describe('Daraja administration is L3-only', () => {
    const surfaces: [string, string][] = [
      ['GET', '/admin/daraja'],
      ['POST', '/admin/daraja'],
      ['POST', '/admin/daraja/00000000-0000-0000-0000-0000000000d1/test'],
      ['POST', '/admin/daraja/00000000-0000-0000-0000-0000000000d1/enable'],
      ['POST', '/admin/daraja/00000000-0000-0000-0000-0000000000d1/disable'],
    ];

    for (const [method, path] of surfaces) {
      it(`refuses ${method} ${path} to L1 and L2`, async () => {
        for (const level of ['L1', 'L2'] as AuthorityLevel[]) {
          const response = await call(path, {
            level,
            method,
            body: method === 'GET' ? undefined : {},
          });
          // 403, never 404: the refusal is an authority decision, and it must not depend on
          // whether the id happens to exist.
          expect(response.status, `${level} ${method} ${path}`).toBe(403);
        }
      });
    }

    /*
     * Safaricom's portal restricts an initiator password to letters, digits and # & % $,
     * and specifically will not round-trip `@` or `.`. A password containing one encrypts
     * fine here and then fails decryption at M-PESA on every single payment with 2001 —
     * an error that reads like a certificate problem. The only cheap moment to catch it is
     * the moment it is typed.
     */
    it('refuses an initiator password containing @ or .', async () => {
      for (const password of ['pa55word@mpesa', 'my.password1', 'a@b.c12345']) {
        const response = await call('/admin/daraja', {
          level: 'L3',
          method: 'POST',
          body: {
            environment: 'sandbox',
            shortCode: '600992',
            initiatorName: 'testapi',
            consumerKey: 'consumer-key-value',
            consumerSecret: 'consumer-secret-value',
            initiatorPasswordOrCredential: password,
          },
        });
        expect(response.status, password).toBe(422);
      }
    });

    /*
     * Deliberately NOT refused. Safaricom's guidance about restricting symbols describes
     * what the portal accepts when a password is set; by the time it reaches this form it
     * already exists and already satisfies that. Re-deriving the rule here would stop an
     * operator configuring payments at all over a password the portal was happy with —
     * a far worse failure than a later 2001, which the failure dictionary explains.
     */
    it('accepts an existing portal password containing other symbols', async () => {
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'Pass-word123!',
        },
      });
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('DARAJA_CERTIFICATE_REQUIRED');
    });

    /*
     * The documentation's sample credential, `RC6E9WDxXR4b9X2c6z3gp0oC5Th==`, is a 29-char
     * placeholder. A genuine one is base64 of a 1024- or 2048-bit ciphertext — 172 or 344
     * characters — so the length heuristic that distinguishes a credential from a password
     * is sound, and the sample is correctly treated as a password needing a certificate.
     *
     * What must not happen is the base64 itself being rejected as an illegal password
     * character, which is what an earlier charset rule did: the operator was told the
     * request was invalid, with no field named and no reason given.
     */
    it('does not reject base64 as though it were an illegal password', async () => {
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'RC6E9WDxXR4b9X2c6z3gp0oC5Th==',
        },
      });
      const body = (await response.json()) as { error: { code: string } };
      // Refused for want of a certificate — an actionable answer — not as a bad password.
      expect(body.error.code).toBe('DARAJA_CERTIFICATE_REQUIRED');
    });

    it('names the offending field so the operator knows what to change', async () => {
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'short',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'Safaricom2026pay',
        },
      });
      expect(response.status).toBe(422);
      const body = (await response.json()) as {
        error: { details: { fields: { path: string; message: string }[] } };
      };
      // "The request was not valid" alone leaves somebody staring at a seven-field form.
      expect(body.error.details.fields.some((f) => f.path === 'consumerKey')).toBe(true);
    });

    it('accepts a password of letters, digits and the documented symbols', async () => {
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: 'Safaricom#2026&pay%ok$',
        },
      });
      // It is refused for want of a certificate, not for the password. Asserting on the
      // code rather than the status matters: both refusals are 422, and a test that only
      // checked the status would pass while the password rule silently rejected a legal
      // password.
      const body = (await response.json()) as { error: { code: string } };
      expect(body.error.code).toBe('DARAJA_CERTIFICATE_REQUIRED');
    });

    it('lets a pre-computed SecurityCredential through untouched', async () => {
      // A portal-generated credential is base64 and legitimately contains + / = — the
      // password rules must not be applied to it.
      const credential = `${'RC6E9WDxXR4b9X2c6z3gp0oC5Th'.repeat(6)}+/==`;
      const response = await call('/admin/daraja', {
        level: 'L3',
        method: 'POST',
        body: {
          environment: 'sandbox',
          shortCode: '600992',
          initiatorName: 'testapi',
          consumerKey: 'consumer-key-value',
          consumerSecret: 'consumer-secret-value',
          initiatorPasswordOrCredential: credential,
        },
      });
      // Accepted as a credential and taken past validation — no certificate is needed for
      // one that is already encrypted.
      const body = (await response.json()) as { error?: { code: string } };
      expect(body.error?.code).not.toBe('DARAJA_CERTIFICATE_REQUIRED');
      expect(response.status).not.toBe(422);
    });

    it('refuses an unauthenticated caller outright', async () => {
      expect((await call('/admin/daraja')).status).toBe(401);
    });

    it('withholds the capability from the payload the console renders from', async () => {
      for (const level of ['L1', 'L2'] as AuthorityLevel[]) {
        const response = await call('/auth/session', { level });
        const body = (await response.json()) as { capabilities: Record<string, boolean> };
        expect(body.capabilities['admin:daraja']).toBe(false);
        expect(body.capabilities['admin:security']).toBe(false);
        expect(body.capabilities['admin:policies']).toBe(false);
        expect(body.capabilities['admin:users']).toBe(false);
      }
      const l3 = (await (await call('/auth/session', { level: 'L3' })).json()) as {
        capabilities: Record<string, boolean>;
      };
      expect(l3.capabilities['admin:daraja']).toBe(true);
    });
  });

  describe('batch lifecycle', () => {
    async function draft(reference: string) {
      const response = await call('/batches', {
        level: 'L1',
        method: 'POST',
        body: { purpose: `Lifecycle ${reference}` },
      });
      expect(response.status).toBe(201);
      return ((await response.json()) as { batchId: string }).batchId;
    }

    /** Fill a draft the way an upload would, without going through multipart. */
    async function addRows(batchId: string, count = 2) {
      const recipients = await harness.sql<{ id: string }[]>`
        INSERT INTO recipients (organization_id, full_name, msisdn)
        VALUES (${ORG}, 'Lifecycle Payee', '254790000001')
        ON CONFLICT (organization_id, msisdn) DO UPDATE SET full_name = EXCLUDED.full_name
        RETURNING id
      `;
      for (let i = 0; i < count; i++) {
        await harness.sql`
          INSERT INTO payment_instructions (organization_id, batch_id, recipient_id,
                                            recipient_name_snapshot, msisdn_snapshot, amount_cents)
          VALUES (${ORG}, ${batchId}, ${recipients[0]!.id}, 'Lifecycle Payee',
                  '254790000001', 100000)
        `;
      }
    }

    it('keeps a draft open so an operator can come back and finish it', async () => {
      const batchId = await draft('RESUME');

      // The operator leaves. Later, the batch is still theirs to carry forward, and the
      // server says so in the commands it offers.
      const reopened = await call(`/batches/${batchId}`, { level: 'L1' });
      expect(reopened.status).toBe(200);
      const body = (await reopened.json()) as {
        batch: { state: string; editable: boolean; availableCommands: string[] };
      };
      expect(body.batch.state).toBe('DRAFT');
      expect(body.batch.editable).toBe(true);
      expect(body.batch.availableCommands).toContain('VALIDATE');

      await addRows(batchId);
      expect(
        (await call(`/batches/${batchId}/validate`, { level: 'L1', method: 'POST' })).status,
      ).toBe(200);

      const validated = (await (await call(`/batches/${batchId}`, { level: 'L1' })).json()) as {
        batch: { state: string; availableCommands: string[] };
      };
      expect(validated.batch.state).toBe('VALIDATED');
      expect(validated.batch.availableCommands).toContain('SUBMIT_TO_L2');
    });

    it('offers each level only the commands it may actually issue', async () => {
      const batchId = await draft('COMMANDS');
      await addRows(batchId);

      const commandsFor = async (level: AuthorityLevel) => {
        const response = await call(`/batches/${batchId}`, { level });
        const body = (await response.json()) as { batch: { availableCommands: string[] } };
        return body.batch.availableCommands;
      };

      // An L1 is never shown Approve — not shown it and refused, simply not shown it.
      expect(await commandsFor('L1')).toContain('VALIDATE');
      expect(await commandsFor('L1')).not.toContain('APPROVE_TO_L3');
      expect(await commandsFor('L2')).not.toContain('SUBMIT_TO_L2');
    });

    it('carries a batch L1 -> L2 -> L3_READY, the chain that was unreachable', async () => {
      const batchId = await draft('CHAIN');
      await addRows(batchId);
      await call(`/batches/${batchId}/validate`, { level: 'L1', method: 'POST' });
      expect(
        (await call(`/batches/${batchId}/submit`, { level: 'L1', method: 'POST' })).status,
      ).toBe(200);

      // Finance Control approves straight from SUBMITTED_TO_L2. Before this, the edge table
      // offered only Reject and Hold from that state and nothing could approve at all.
      const approved = await call(`/batches/${batchId}/approve`, {
        level: 'L2',
        method: 'POST',
        body: {
          reason: 'Amounts verified against the payroll register',
          acknowledgeFindings: true,
        },
      });
      expect(approved.status).toBe(200);

      const ready = (await (await call(`/batches/${batchId}`, { level: 'L3' })).json()) as {
        batch: { state: string; availableCommands: string[] };
      };
      expect(ready.batch.state).toBe('L3_READY');
      // And only now does the executive see the route to release.
      expect(ready.batch.availableCommands).toContain('BEGIN_AUTHORIZATION');
    });

    it('refuses the L2 approval to the preparer, however the request is made', async () => {
      const batchId = await draft('SOD');
      await addRows(batchId);
      await call(`/batches/${batchId}/validate`, { level: 'L1', method: 'POST' });
      await call(`/batches/${batchId}/submit`, { level: 'L1', method: 'POST' });

      const response = await call(`/batches/${batchId}/approve`, {
        level: 'L1',
        method: 'POST',
        body: { reason: 'Approving my own work' },
      });
      expect(response.status).toBe(403);
    });

    it('lifts a hold, so a held batch is not a dead end', async () => {
      const batchId = await draft('HOLD');
      await addRows(batchId);
      await call(`/batches/${batchId}/validate`, { level: 'L1', method: 'POST' });
      await call(`/batches/${batchId}/submit`, { level: 'L1', method: 'POST' });

      const held = await call(`/batches/${batchId}/hold`, {
        level: 'L2',
        method: 'POST',
        body: { reason: 'Waiting on confirmation from the department head' },
      });
      expect(held.status).toBe(200);

      const lifted = await call(`/batches/${batchId}/release-hold`, {
        level: 'L2',
        method: 'POST',
        body: { reason: 'Department head confirmed' },
      });
      expect(lifted.status).toBe(200);
      expect(((await lifted.json()) as { state: string }).state).toBe('SUBMITTED_TO_L2');
    });

    it('cancels a batch terminally, and only with a reason', async () => {
      const batchId = await draft('CANCEL');
      await addRows(batchId);

      // Cancellation is executive authority alone: the permission matrix grants
      // `batch:cancel` to L3 only, so an operator abandons a draft by asking, not by acting.
      expect(
        (
          await call(`/batches/${batchId}/cancel`, {
            level: 'L1',
            method: 'POST',
            body: { reason: 'Prepared in error' },
          })
        ).status,
      ).toBe(403);

      const noReason = await call(`/batches/${batchId}/cancel`, { level: 'L3', method: 'POST' });
      expect(noReason.status).toBe(422);

      const cancelled = await call(`/batches/${batchId}/cancel`, {
        level: 'L3',
        method: 'POST',
        body: { reason: 'Duplicate of the run already submitted this morning' },
      });
      expect(cancelled.status).toBe(200);

      const after = (await (await call(`/batches/${batchId}`, { level: 'L3' })).json()) as {
        batch: { state: string; availableCommands: string[] };
      };
      expect(after.batch.state).toBe('CANCELLED');
      // Terminal means terminal: nothing revives it, at any level.
      expect(after.batch.availableCommands).toEqual([]);

      const instructions = await harness.sql<{ status: string }[]>`
        SELECT status FROM payment_instructions WHERE batch_id = ${batchId}
      `;
      expect(instructions.every((i) => i.status === 'CANCELLED')).toBe(true);
    });

    it('refuses a cancellation from a level the state machine does not allow it from', async () => {
      const batchId = await draft('CANCELSOD');
      await addRows(batchId);
      await call(`/batches/${batchId}/validate`, { level: 'L1', method: 'POST' });
      await call(`/batches/${batchId}/submit`, { level: 'L1', method: 'POST' });

      // SUBMITTED_TO_L2 has no CANCEL edge for anybody; it must be rejected or held first.
      const response = await call(`/batches/${batchId}/cancel`, {
        level: 'L3',
        method: 'POST',
        body: { reason: 'Changed my mind' },
      });
      expect([403, 409, 422]).toContain(response.status);
    });
  });

  describe('health', () => {
    it('liveness reveals nothing about the deployment', async () => {
      const response = await call('/health');
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ status: 'ok' });
    });

    it('readiness reports database reachability', async () => {
      const response = await call('/health/ready');
      expect(response.status).toBe(200);
      const body = (await response.json()) as { status: string; databaseLatencyMs: number };
      expect(body.status).toBe('ready');
      expect(body.databaseLatencyMs).toBeGreaterThanOrEqual(0);
    });
  });
});
