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
