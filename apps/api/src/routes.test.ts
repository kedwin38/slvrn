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
