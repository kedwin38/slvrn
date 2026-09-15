/**
 * Authentication routes (spec 7, 8).
 *
 * There is no SMS endpoint here, and no way to add one without changing the schema: there
 * is no phone column on any identity table. Recovery consumes a stored recovery code or
 * goes to administrative review (spec 8.3), and MFA is WebAuthn only.
 *
 * Login is two-staged for L2/L3 because WebAuthn is mandatory at those levels (spec 7.3):
 * the password stage returns a short-lived assertion challenge and *no session*, so a
 * stolen password alone yields nothing that can read financial data.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  authenticationError,
  validationError,
  capabilitiesFor,
  randomToken,
  LEVEL_TITLES,
} from '@solvaren/core';
import {
  verifyPasswordStage,
  issueSession,
  revokeSession,
  revokeAllSessions,
  deriveDeviceFingerprint,
  toActor,
  type UserRow,
} from '../services/auth.js';
import {
  hashAuthorizationPin,
  assertPinShape,
  verifyPassword,
  hashPassword,
  generateRecoveryCode,
  hashSessionToken,
  sha256Hex,
  timingSafeEqual,
  fromBase64Url,
  toBase64Url,
} from '../services/crypto.js';
import { requireAuth, actorOf, limitBodySize } from '../middleware/security.js';
import { withConnection, inTransaction, textArrayValue } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { AppContext } from '../env.js';

export const authRoutes = new Hono<AppContext>();

authRoutes.use('*', limitBodySize(16 * 1024));

const loginSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(1024),
  deviceId: z.string().max(200).optional(),
});

/**
 * POST /auth/login — stage one.
 *
 * L1 receives a session. L2 and L3 receive a WebAuthn challenge and must complete
 * `/auth/webauthn/authenticate` before any session exists.
 */
authRoutes.post('/login', async (c) => {
  const body = loginSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    let stage;
    try {
      stage = await verifyPasswordStage(sql, {
        email: body.email,
        password: body.password,
        deviceFingerprint: security.deviceFingerprint,
        ip: security.ip,
        userAgent: security.userAgent,
      });
    } catch (err) {
      // Failed logins are security events in their own right (spec 14).
      await sql`
        INSERT INTO security_events (event_type, severity, description, ip, user_agent, detail)
        VALUES ('LOGIN_FAILED', 'INFO', ${'A sign-in attempt failed'}, ${security.ip},
                ${security.userAgent}, ${sql.json({ email: body.email.slice(0, 3) + '***' })})
      `.catch(() => {});
      throw err;
    }

    const { user, requiresWebAuthn } = stage;
    const deviceFingerprint = await deriveDeviceFingerprint(
      body.deviceId ?? null,
      security.userAgent,
    );

    if (requiresWebAuthn) {
      const credentials = await sql<{ credential_id: string; transports: string[] }[]>`
        SELECT credential_id, transports FROM webauthn_credentials
         WHERE user_id = ${user.id} AND status = 'ACTIVE'
      `;
      if (credentials.length === 0) {
        // An L2/L3 account with no authenticator cannot sign in at all. The alternative —
        // falling back to a password-only session — is precisely the bypass spec 7.3 forbids.
        throw authenticationError(
          'WEBAUTHN_ENROLMENT_REQUIRED',
          'This account requires a security key or passkey, and none is enrolled. Contact your administrator to complete enrolment.',
        );
      }

      const options = await generateAuthenticationOptions({
        rpID: c.env.WEBAUTHN_RP_ID,
        userVerification: 'required',
        allowCredentials: credentials.map((cred) => ({
          id: cred.credential_id,
          transports: cred.transports as AuthenticatorTransportFuture[],
        })),
      });

      // The challenge is held server-side, keyed by a single-use ticket. Nothing the
      // client holds can be replayed into a session.
      const ticket = randomToken(32);
      await sql`
        INSERT INTO sessions (
          organization_id, user_id, token_hash, authenticated_at, issued_at, expires_at, ip, user_agent
        ) VALUES (
          ${user.organization_id}, ${user.id},
          ${await hashSessionToken(`pending:${ticket}`, c.env.SESSION_SIGNING_KEY)},
          now(), now(), now() + interval '5 minutes', ${security.ip}, ${security.userAgent}
        )
      `;
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${user.organization_id}, ${user.id}, 'WEBAUTHN_CHALLENGE_ISSUED', 'INFO',
                ${'A WebAuthn challenge was issued during sign-in'}, ${security.ip},
                ${sql.json({ challenge: options.challenge, ticket, deviceFingerprint })})
      `;

      return {
        stage: 'WEBAUTHN_REQUIRED' as const,
        ticket,
        options,
        level: user.authority_level,
      };
    }

    // L1: password is sufficient for identity, and L1 cannot release money.
    const session = await issueSession(sql, c.env, {
      user,
      trustedDeviceId: null,
      webauthnVerified: false,
      ip: security.ip,
      userAgent: security.userAgent,
    });

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.login',
        objectType: 'User',
        objectId: user.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { method: 'password', level: user.authority_level },
      }),
    );

    return {
      stage: 'AUTHENTICATED' as const,
      token: session.token,
      expiresAt: session.expiresAt.toISOString(),
      user: publicUser(user),
    };
  });

  return c.json(result);
});

const webauthnAuthSchema = z.object({
  ticket: z.string().min(16).max(64),
  response: z.record(z.unknown()),
  deviceId: z.string().max(200).optional(),
});

/**
 * POST /auth/webauthn/authenticate — stage two for L2/L3.
 *
 * Verifies the assertion and only then issues a session. The signature counter is checked:
 * a counter that fails to advance indicates a cloned authenticator, which is a security
 * event rather than a successful sign-in.
 */
authRoutes.post('/webauthn/authenticate', async (c) => {
  const body = webauthnAuthSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    const events = await sql<
      {
        id: string;
        organization_id: string;
        user_id: string;
        detail: { challenge: string; ticket: string };
        created_at: string;
      }[]
    >`
      SELECT id, organization_id, user_id, detail, created_at
        FROM security_events
       WHERE event_type = 'WEBAUTHN_CHALLENGE_ISSUED'
         AND detail->>'ticket' = ${body.ticket}
         AND created_at > now() - interval '5 minutes'
       ORDER BY created_at DESC
       LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw authenticationError(
        'WEBAUTHN_CHALLENGE_EXPIRED',
        'That sign-in attempt expired. Start again.',
      );
    }

    const response = body.response as Record<string, unknown> & { id?: string };
    const credentialId = typeof response.id === 'string' ? response.id : '';

    const credentials = await sql<
      {
        id: string;
        credential_id: string;
        public_key: Uint8Array;
        signature_counter: string;
        transports: string[];
      }[]
    >`
      SELECT id, credential_id, public_key, signature_counter, transports
        FROM webauthn_credentials
       WHERE user_id = ${pending.user_id} AND credential_id = ${credentialId} AND status = 'ACTIVE'
       LIMIT 1
    `;
    const credential = credentials[0];
    if (!credential) {
      throw authenticationError(
        'WEBAUTHN_CREDENTIAL_UNKNOWN',
        'That authenticator is not registered to this account',
      );
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.response as never,
        expectedChallenge: pending.detail.challenge,
        expectedOrigin: c.env.APP_ORIGIN,
        expectedRPID: c.env.WEBAUTHN_RP_ID,
        requireUserVerification: true,
        credential: {
          id: credential.credential_id,
          publicKey: new Uint8Array(credential.public_key),
          counter: Number(credential.signature_counter),
          transports: credential.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch (err) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${pending.organization_id}, ${pending.user_id}, 'WEBAUTHN_VERIFICATION_FAILED', 'WARNING',
                ${'A WebAuthn assertion failed verification'}, ${security.ip},
                ${sql.json({ error: err instanceof Error ? err.message : 'unknown' })})
      `;
      throw authenticationError(
        'WEBAUTHN_VERIFICATION_FAILED',
        'The security key verification failed',
      );
    }

    if (!verification.verified) {
      throw authenticationError(
        'WEBAUTHN_VERIFICATION_FAILED',
        'The security key verification failed',
      );
    }

    // Cloned-authenticator detection. Both counters at zero is normal for some platform
    // authenticators; a counter that goes backwards is not.
    const newCounter = verification.authenticationInfo.newCounter;
    const storedCounter = Number(credential.signature_counter);
    if (newCounter !== 0 && newCounter <= storedCounter) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${pending.organization_id}, ${pending.user_id}, 'WEBAUTHN_COUNTER_REGRESSION', 'CRITICAL',
                ${'An authenticator signature counter did not advance, which can indicate a cloned key'},
                ${security.ip}, ${sql.json({ storedCounter, newCounter })})
      `;
      throw authenticationError(
        'WEBAUTHN_COUNTER_REGRESSION',
        'This security key failed an integrity check and cannot be used. Contact your administrator.',
      );
    }

    await sql`
      UPDATE webauthn_credentials
         SET signature_counter = ${newCounter}, last_used_at = now()
       WHERE id = ${credential.id}
    `;

    const users = await sql<UserRow[]>`
      SELECT u.id, u.organization_id, o.slug AS organization_slug, u.email, u.full_name,
             u.authority_level, u.status, u.password_hash, u.authorization_pin_hash,
             u.failed_login_count, u.locked_until
        FROM users u JOIN organizations o ON o.id = u.organization_id
       WHERE u.id = ${pending.user_id} LIMIT 1
    `;
    const user = users[0]!;

    // Register or refresh the trusted device binding (spec 8.1).
    const deviceFingerprint = await deriveDeviceFingerprint(
      body.deviceId ?? null,
      security.userAgent,
    );
    let trustedDeviceId: string | null = null;
    if (deviceFingerprint) {
      const devices = await sql<{ id: string; trust_status: string }[]>`
        INSERT INTO trusted_devices (
          organization_id, user_id, device_fingerprint, webauthn_credential_id,
          trust_status, first_seen_ip, last_seen_ip, user_agent
        ) VALUES (
          ${user.organization_id}, ${user.id}, ${deviceFingerprint}, ${credential.id},
          'TRUSTED', ${security.ip}, ${security.ip}, ${security.userAgent}
        )
        ON CONFLICT (user_id, device_fingerprint) DO UPDATE
          SET last_activity_at = now(), last_seen_ip = EXCLUDED.last_seen_ip
        RETURNING id, trust_status
      `;
      if (devices[0]?.trust_status === 'BLOCKED' || devices[0]?.trust_status === 'REVOKED') {
        throw authenticationError(
          'DEVICE_BLOCKED',
          'This device is not permitted to access SOLVAREN',
        );
      }
      trustedDeviceId = devices[0]?.id ?? null;
    }

    // Burn the pending challenge so the ticket cannot be reused.
    await sql`
      UPDATE security_events SET detail = detail - 'ticket' WHERE id = ${pending.id}
    `;

    const session = await issueSession(sql, c.env, {
      user,
      trustedDeviceId,
      webauthnVerified: true,
      ip: security.ip,
      userAgent: security.userAgent,
    });

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.login.webauthn',
        objectType: 'User',
        objectId: user.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { credentialId: credential.id, trustedDeviceId, level: user.authority_level },
      }),
    );

    return {
      stage: 'AUTHENTICATED' as const,
      token: session.token,
      expiresAt: session.expiresAt.toISOString(),
      user: publicUser(user),
    };
  });

  return c.json(result);
});

/** POST /auth/webauthn/register/options — begin enrolling an authenticator. */
authRoutes.post('/webauthn/register/options', requireAuth, async (c) => {
  const actor = actorOf(c);

  const options = await withConnection(c.env, async (sql) => {
    const existing = await sql<{ credential_id: string }[]>`
      SELECT credential_id FROM webauthn_credentials WHERE user_id = ${actor.userId} AND status = 'ACTIVE'
    `;

    const generated = await generateRegistrationOptions({
      rpName: c.env.WEBAUTHN_RP_NAME,
      rpID: c.env.WEBAUTHN_RP_ID,
      userName: actor.email,
      userDisplayName: actor.fullName,
      attestationType: 'none',
      // Prevents enrolling the same authenticator twice, which would silently halve the
      // value of a "two keys registered" policy.
      excludeCredentials: existing.map((e) => ({ id: e.credential_id })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
    });

    await sql`
      INSERT INTO security_events (organization_id, user_id, event_type, severity, description, detail)
      VALUES (${actor.organizationId}, ${actor.userId}, 'WEBAUTHN_REGISTRATION_STARTED', 'INFO',
              ${'An authenticator enrolment was started'},
              ${sql.json({ challenge: generated.challenge })})
    `;
    return generated;
  });

  return c.json(options);
});

/** POST /auth/webauthn/register — complete enrolment. */
authRoutes.post('/webauthn/register', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ response: z.record(z.unknown()), friendlyName: z.string().trim().max(80).optional() })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, async (sql) => {
    const events = await sql<{ detail: { challenge: string } }[]>`
      SELECT detail FROM security_events
       WHERE user_id = ${actor.userId} AND event_type = 'WEBAUTHN_REGISTRATION_STARTED'
         AND created_at > now() - interval '10 minutes'
       ORDER BY created_at DESC LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw validationError(
        'WEBAUTHN_REGISTRATION_EXPIRED',
        'That enrolment expired. Start again.',
      );
    }

    const verification = await verifyRegistrationResponse({
      response: body.response as never,
      expectedChallenge: pending.detail.challenge,
      expectedOrigin: c.env.APP_ORIGIN,
      expectedRPID: c.env.WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw validationError(
        'WEBAUTHN_REGISTRATION_FAILED',
        'The authenticator could not be registered',
      );
    }

    const info = verification.registrationInfo;
    await inTransaction(sql, async (tx) => {
      await tx`
        INSERT INTO webauthn_credentials (
          organization_id, user_id, credential_id, public_key, signature_counter,
          transports, device_type, backed_up, friendly_name, aaguid
        ) VALUES (
          ${actor.organizationId}, ${actor.userId}, ${info.credential.id},
          ${Buffer.from(info.credential.publicKey)}, ${info.credential.counter},
          ${textArrayValue(tx, info.credential.transports ?? [])}, ${info.credentialDeviceType === 'multiDevice' ? 'PLATFORM' : 'CROSS_PLATFORM'},
          ${info.credentialBackedUp}, ${body.friendlyName ?? 'Security key'}, ${info.aaguid ?? null}
        )
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.webauthn.registered',
        objectType: 'WebAuthnCredential',
        objectId: info.credential.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          friendlyName: body.friendlyName,
          deviceType: info.credentialDeviceType,
          backedUp: info.credentialBackedUp,
        },
      });
    });

    return { registered: true, credentialId: info.credential.id };
  });

  return c.json(result, 201);
});

/**
 * POST /auth/authorization-pin — set or change the SPAC PIN (spec 7.4).
 * Requires the current password: the PIN is a second factor of authority, so changing it
 * must not be possible from a hijacked session alone.
 */
authRoutes.post('/authorization-pin', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ currentPassword: z.string().min(1).max(1024), pin: z.string().min(6).max(12) })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  assertPinShape(body.pin);

  await withConnection(c.env, async (sql) => {
    const users = await sql<{ password_hash: string }[]>`
      SELECT password_hash FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    if (!users[0] || !(await verifyPassword(body.currentPassword, users[0].password_hash))) {
      throw authenticationError('PASSWORD_INCORRECT', 'Your current password was not correct');
    }

    const hash = await hashAuthorizationPin(body.pin, actor.userId);
    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE users SET authorization_pin_hash = ${hash}, authorization_pin_updated_at = now()
         WHERE id = ${actor.userId}
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.authorization_pin.set',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        // The PIN itself never appears here; `redactForAudit` would strip it anyway.
        detail: { rotated: true },
      });
    });
  });

  return c.json({ updated: true });
});

/** POST /auth/recovery-codes — regenerate recovery codes. Shown once, stored hashed. */
authRoutes.post('/recovery-codes', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z.object({ currentPassword: z.string().min(1).max(1024) }).parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const codes = await withConnection(c.env, async (sql) => {
    const users = await sql<{ password_hash: string }[]>`
      SELECT password_hash FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    if (!users[0] || !(await verifyPassword(body.currentPassword, users[0].password_hash))) {
      throw authenticationError('PASSWORD_INCORRECT', 'Your current password was not correct');
    }

    const generated = Array.from({ length: 10 }, () => generateRecoveryCode());
    await inTransaction(sql, async (tx) => {
      // Regenerating invalidates the previous set: two live sets doubles the attack surface.
      await tx`
        UPDATE recovery_codes SET consumed_at = now()
         WHERE user_id = ${actor.userId} AND consumed_at IS NULL
      `;
      for (const code of generated) {
        const hash = await hashSessionToken(code, c.env.SESSION_SIGNING_KEY);
        await tx`
          INSERT INTO recovery_codes (organization_id, user_id, code_hash)
          VALUES (${actor.organizationId}, ${actor.userId}, ${hash})
        `;
      }
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.recovery_codes.regenerated',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { count: generated.length },
      });
    });
    return generated;
  });

  return c.json({
    codes,
    note: 'Store these somewhere safe. They are shown once and cannot be retrieved again. SOLVAREN never sends recovery codes by SMS.',
  });
});

/** GET /auth/session — who am I, and what may I do. */
authRoutes.get('/session', requireAuth, async (c) => {
  const actor = actorOf(c);
  return c.json({
    user: {
      userId: actor.userId,
      email: actor.email,
      fullName: actor.fullName,
      level: actor.level,
      levelTitle: LEVEL_TITLES[actor.level],
      organizationId: actor.organizationId,
      organizationSlug: actor.organizationSlug,
    },
    session: {
      authenticatedAt: new Date(actor.authenticatedAt).toISOString(),
      webauthnVerified: actor.webauthnVerifiedAt !== null,
      trustedDeviceId: actor.trustedDeviceId,
    },
    /*
     * Which deployment this is, and whether it can move real money.
     *
     * Nothing in the console said. An operator working in a sandbox deployment and one
     * working in production saw an identical screen, which is an unacceptable ambiguity in
     * a product whose whole purpose is disbursing funds: the mistake it invites is either
     * rehearsing against real money or releasing a real payroll into a sandbox and
     * believing it went out.
     *
     * `darajaEnvironment` is the one that actually decides, since a production deployment
     * pointed at the sandbox still pays nobody.
     */
    deployment: {
      environment: c.env.ENVIRONMENT,
      darajaEnvironment: c.env.DARAJA_ENVIRONMENT ?? 'sandbox',
      movesRealMoney:
        c.env.ENVIRONMENT === 'production' && c.env.DARAJA_ENVIRONMENT === 'production',
    },
    // The UI renders from this. It is a convenience, not a control: every endpoint
    // re-checks server-side (spec 4, HARD CONTROL).
    capabilities: capabilitiesFor(toActor(actor)),
  });
});

/** POST /auth/logout */
authRoutes.post('/logout', requireAuth, async (c) => {
  const actor = actorOf(c);
  const correlationId = c.get('correlationId');

  await withConnection(c.env, async (sql) => {
    await revokeSession(sql, actor.sessionId, 'User signed out');
    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.logout',
        objectType: 'Session',
        objectId: actor.sessionId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {},
      }),
    );
  });

  return c.json({ signedOut: true });
});

/** POST /auth/logout-all — revoke every session, for a suspected compromise. */
authRoutes.post('/logout-all', requireAuth, async (c) => {
  const actor = actorOf(c);
  const correlationId = c.get('correlationId');

  const revoked = await withConnection(c.env, async (sql) => {
    const count = await revokeAllSessions(sql, actor.userId, 'User revoked all sessions');
    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'auth.sessions.revoked_all',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { sessionsRevoked: count },
      }),
    );
    return count;
  });

  return c.json({ sessionsRevoked: revoked });
});

function publicUser(user: UserRow) {
  return {
    userId: user.id,
    email: user.email,
    fullName: user.full_name,
    level: user.authority_level,
    levelTitle: LEVEL_TITLES[user.authority_level],
    organizationId: user.organization_id,
    organizationSlug: user.organization_slug,
    authorizationPinEnrolled: user.authorization_pin_hash !== null,
  };
}

// `timingSafeEqual`, `fromBase64Url` and `toBase64Url` are re-exported through the crypto
// service for the callback and session paths; referenced here to keep the import surface
// explicit for reviewers auditing which routes touch credential material.
void timingSafeEqual;
void fromBase64Url;
void toBase64Url;

type AuthenticatorTransportFuture =
  'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

/*
 * ───────────────────────────────────────────────────────────────────────────────
 * First-authenticator enrolment (the bootstrap for L2 and L3)
 *
 * Registering an authenticator above requires a session. L2 and L3 cannot hold a session
 * without a verified assertion. So the first privileged account in an organisation could
 * never sign in at all — and L3 is the only level that can release a payment.
 *
 * These two endpoints are the way in, and they are deliberately narrow:
 *
 *   - They need the password AND a single-use token issued out of band
 *     (scripts/issue-enrolment-token.mjs). Letting a password alone enrol the first key
 *     would make a stolen password into an L3 who can move money, which is the exact
 *     bypass the WebAuthn requirement exists to prevent.
 *   - They refuse any account that already has a working authenticator. Adding a key to a
 *     live account stays an authenticated action; otherwise this would be an
 *     account-takeover primitive rather than a bootstrap.
 *   - They never issue a session. Success means one credential exists; the user then signs
 *     in normally, password plus key, through the ordinary two-stage flow.
 * ───────────────────────────────────────────────────────────────────────────────
 */

const enrolmentSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(1024),
  token: z.string().trim().min(16).max(200),
});

interface EnrolmentCandidate {
  user: UserRow;
  tokenId: string;
}

/**
 * Establish that this request may enrol a first authenticator, or refuse.
 *
 * Every refusal returns the same message. Distinguishing "no such token" from "wrong
 * password" from "already enrolled" would turn this endpoint into an oracle for which
 * privileged accounts exist and which are still unprotected — precisely the accounts worth
 * attacking.
 */
async function resolveEnrolment(
  sql: Parameters<typeof writeAuditEvent>[0],
  input: z.infer<typeof enrolmentSchema>,
): Promise<EnrolmentCandidate> {
  const refuse = () =>
    authenticationError(
      'ENROLMENT_REFUSED',
      'That enrolment could not be completed. Check the email, password and token, and that the token has not expired or already been used.',
    );

  const stage = await verifyPasswordStage(sql, {
    email: input.email,
    password: input.password,
    deviceFingerprint: null,
    ip: null,
    userAgent: null,
  }).catch(() => null);

  if (!stage) throw refuse();

  const existing = await sql<{ credential_id: string }[]>`
    SELECT credential_id FROM webauthn_credentials
     WHERE user_id = ${stage.user.id} AND status = 'ACTIVE' LIMIT 1
  `;
  if (existing.length > 0) throw refuse();

  const tokens = await sql<{ id: string }[]>`
    SELECT id FROM enrolment_tokens
     WHERE user_id = ${stage.user.id}
       AND token_hash = ${await sha256Hex(input.token)}
       AND consumed_at IS NULL
       AND expires_at > now()
     LIMIT 1
  `;
  const token = tokens[0];
  if (!token) throw refuse();

  return { user: stage.user, tokenId: token.id };
}

/** POST /auth/enrolment/options — begin enrolling the first authenticator. */
authRoutes.post('/enrolment/options', async (c) => {
  const body = enrolmentSchema.parse(await c.req.json());

  const options = await withConnection(c.env, async (sql) => {
    const { user } = await resolveEnrolment(sql, body);

    const generated = await generateRegistrationOptions({
      rpName: c.env.WEBAUTHN_RP_NAME,
      rpID: c.env.WEBAUTHN_RP_ID,
      userName: user.email,
      userDisplayName: user.full_name,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });

    // The challenge lives server-side, as it does for the authenticated path.
    await sql`
      INSERT INTO security_events (organization_id, user_id, event_type, severity, description, detail)
      VALUES (${user.organization_id}, ${user.id}, 'WEBAUTHN_REGISTRATION_STARTED', 'INFO',
              ${'A first-authenticator enrolment was started from an enrolment token'},
              ${sql.json({ challenge: generated.challenge })})
    `;
    return generated;
  });

  return c.json(options);
});

/** POST /auth/enrolment/complete — register the authenticator and spend the token. */
authRoutes.post('/enrolment/complete', async (c) => {
  const body = enrolmentSchema
    .extend({
      response: z.record(z.unknown()),
      friendlyName: z.string().trim().max(80).optional(),
    })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, async (sql) => {
    const { user, tokenId } = await resolveEnrolment(sql, body);

    const events = await sql<{ detail: { challenge: string } }[]>`
      SELECT detail FROM security_events
       WHERE user_id = ${user.id} AND event_type = 'WEBAUTHN_REGISTRATION_STARTED'
         AND created_at > now() - interval '10 minutes'
       ORDER BY created_at DESC LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw validationError(
        'WEBAUTHN_REGISTRATION_EXPIRED',
        'That enrolment expired. Start again.',
      );
    }

    const verification = await verifyRegistrationResponse({
      response: body.response as never,
      expectedChallenge: pending.detail.challenge,
      expectedOrigin: c.env.APP_ORIGIN,
      expectedRPID: c.env.WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw validationError(
        'WEBAUTHN_REGISTRATION_FAILED',
        'The authenticator could not be registered',
      );
    }

    const info = verification.registrationInfo;

    await inTransaction(sql, async (tx) => {
      await tx`
        INSERT INTO webauthn_credentials (
          organization_id, user_id, credential_id, public_key, signature_counter,
          transports, device_type, backed_up, friendly_name, aaguid
        ) VALUES (
          ${user.organization_id}, ${user.id}, ${info.credential.id},
          ${Buffer.from(info.credential.publicKey)}, ${info.credential.counter},
          ${textArrayValue(tx, info.credential.transports ?? [])},
          ${info.credentialDeviceType === 'multiDevice' ? 'PLATFORM' : 'CROSS_PLATFORM'},
          ${info.credentialBackedUp}, ${body.friendlyName ?? 'First security key'},
          ${info.aaguid ?? null}
        )
      `;

      /*
       * Spend the token in the same transaction that creates the credential, conditioned on
       * it still being unconsumed. Two enrolments racing the same token cannot both land:
       * the second updates zero rows and the whole transaction is abandoned.
       */
      const spent = await tx<{ id: string }[]>`
        UPDATE enrolment_tokens
           SET consumed_at = now(), credential_id = ${info.credential.id}
         WHERE id = ${tokenId} AND consumed_at IS NULL
        RETURNING id
      `;
      if (spent.length === 0) {
        throw authenticationError(
          'ENROLMENT_REFUSED',
          'That enrolment could not be completed. Check the email, password and token, and that the token has not expired or already been used.',
        );
      }

      /*
       * An account created by scripts/create-user.mjs sits at PENDING_ENROLMENT precisely
       * until this moment. Activating anything else would be wrong, so the status change is
       * conditioned on that exact value rather than written unconditionally.
       */
      await tx`
        UPDATE users SET status = 'ACTIVE'
         WHERE id = ${user.id} AND status = 'PENDING_ENROLMENT'
      `;

      await writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.webauthn.enrolled_with_token',
        objectType: 'WebAuthnCredential',
        objectId: info.credential.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          friendlyName: body.friendlyName,
          deviceType: info.credentialDeviceType,
          backedUp: info.credentialBackedUp,
          viaEnrolmentToken: true,
        },
      });
    });

    return { registered: true, credentialId: info.credential.id };
  });

  return c.json(result, 201);
});

// ---------------------------------------------------------------------------
// Credential recovery (spec §11 — NO WEAK RECOVERY PATH)
// ---------------------------------------------------------------------------

/**
 * Recovery, done the way §11 demands and no other way.
 *
 * The specification is explicit about what must never exist: no SMS reset, no email OTP,
 * no "forgot password" link that mails a new one. Those are backdoors around the entire
 * security architecture. What it requires instead is recovery through an existing recovery
 * credential OR controlled administrative recovery, under elevated review.
 *
 * Both routes end here, and both are narrow:
 *
 *   - A recovery code proves you are you. It buys exactly one thing: the right to set a new
 *     password. It does NOT sign you in, and it does NOT restore a lost security key — an
 *     L2 or L3 who has lost their authenticator still needs an administrator to issue an
 *     enrolment token, because a single code must never reconstitute payment authority on
 *     its own.
 *   - Administrative recovery (in admin.ts) is an executive vouching for somebody, and is
 *     recorded as such.
 *
 * Setting the new password revokes every session the account had. If the reason for
 * recovery was that somebody else had the old password, leaving their session alive would
 * defeat the whole exercise.
 */

const RECOVERY_TICKET_MINUTES = 15;

/** One refusal for every failure, so the endpoint cannot be used to enumerate accounts. */
const RECOVERY_REFUSED = 'That email address and recovery code combination was not accepted.';

authRoutes.post('/recovery/start', async (c) => {
  const body = z
    .object({
      email: z.string().trim().email().max(320),
      code: z.string().trim().min(8).max(64),
    })
    .parse(await c.req.json());
  const security = c.get('securityContext');
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, async (sql) => {
    /*
     * The code hash is deterministic (HMAC under the session signing key), so this is a
     * single indexed lookup rather than a scan that verifies candidates one at a time.
     * That matters for more than speed: a loop whose duration depends on how many codes an
     * account has is a timing oracle for whether the account exists.
     */
    const codeHash = await hashSessionToken(body.code, c.env.SESSION_SIGNING_KEY);
    const matches = await sql<
      {
        id: string;
        user_id: string;
        organization_id: string;
        email: string;
        authority_level: string;
        status: string;
      }[]
    >`
      SELECT rc.id, rc.user_id, rc.organization_id, u.email, u.authority_level, u.status
        FROM recovery_codes rc
        JOIN users u ON u.id = rc.user_id
       WHERE rc.code_hash = ${codeHash}
         AND rc.consumed_at IS NULL
         AND u.email = ${body.email.trim().toLowerCase()}
       LIMIT 1
    `;
    const match = matches[0];

    if (!match) {
      // Recorded against the organisation when we can attribute it, and always recorded:
      // a burst of these is somebody working through a stolen code list.
      await sql`
        INSERT INTO security_events (event_type, severity, description, ip, user_agent, detail)
        VALUES ('RECOVERY_CODE_REJECTED', 'WARNING',
                ${'A credential recovery attempt presented an unrecognised email and code'},
                ${security.ip}, ${security.userAgent},
                ${sql.json({ email: body.email.trim().toLowerCase() })})
      `;
      throw authenticationError('RECOVERY_REFUSED', RECOVERY_REFUSED);
    }

    // A disabled account is not recoverable by its own holder. Somebody disabled it on
    // purpose, and a recovery code must not undo an administrative decision.
    if (match.status === 'DISABLED') {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${match.organization_id}, ${match.user_id}, 'RECOVERY_ON_DISABLED_ACCOUNT', 'CRITICAL',
                ${'A valid recovery code was presented for a disabled account'},
                ${security.ip}, ${sql.json({ level: match.authority_level })})
      `;
      throw authenticationError('RECOVERY_REFUSED', RECOVERY_REFUSED);
    }

    const ticket = randomToken(32);
    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE recovery_codes SET consumed_at = now(), consumed_ip = ${security.ip}
         WHERE id = ${match.id}
      `;
      // Any earlier unspent ticket for this user is spent first, so the one-live-ticket
      // index never refuses a legitimate second attempt after an abandoned one.
      await tx`
        UPDATE recovery_tickets SET consumed_at = now()
         WHERE user_id = ${match.user_id} AND consumed_at IS NULL
      `;
      await tx`
        INSERT INTO recovery_tickets (
          organization_id, user_id, ticket_hash, origin, expires_at, issued_ip
        ) VALUES (
          ${match.organization_id}, ${match.user_id},
          ${await hashSessionToken(ticket, c.env.SESSION_SIGNING_KEY)}, 'RECOVERY_CODE',
          now() + interval '${sql.unsafe(String(RECOVERY_TICKET_MINUTES))} minutes', ${security.ip}
        )
      `;
      await tx`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, user_agent, detail)
        VALUES (${match.organization_id}, ${match.user_id}, 'RECOVERY_CODE_REDEEMED',
                ${match.authority_level === 'L3' ? 'CRITICAL' : 'WARNING'},
                ${'A recovery code was redeemed to reset a password'},
                ${security.ip}, ${security.userAgent},
                ${tx.json({ level: match.authority_level })})
      `;
      await writeAuditEvent(tx, {
        organizationId: match.organization_id,
        actorId: match.user_id,
        actorLevel: match.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.recovery.code_redeemed',
        objectType: 'User',
        objectId: match.user_id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
      });
    });

    const remaining = await sql<{ count: string }[]>`
      SELECT count(*)::text AS count FROM recovery_codes
       WHERE user_id = ${match.user_id} AND consumed_at IS NULL
    `;

    return {
      ticket,
      expiresInMinutes: RECOVERY_TICKET_MINUTES,
      remainingCodes: Number(remaining[0]?.count ?? '0'),
      level: match.authority_level,
    };
  });

  return c.json({
    ...result,
    note:
      result.level === 'L1'
        ? 'Set a new password to finish. Every session on this account will be signed out.'
        : 'Set a new password to finish. Your security key is still required to sign in — if you have lost that too, an administrator must issue an enrolment token.',
  });
});

const completeSchema = z.object({
  ticket: z.string().trim().min(16).max(128),
  newPassword: z
    .string()
    .min(12, 'Use at least 12 characters')
    .max(1024)
    .refine((value) => value.trim().length >= 12, 'Use at least 12 characters'),
});

authRoutes.post('/recovery/complete', async (c) => {
  const body = completeSchema.parse(await c.req.json());
  const security = c.get('securityContext');
  const correlationId = c.get('correlationId');

  await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const tickets = await tx<
        {
          id: string;
          user_id: string;
          organization_id: string;
          origin: string;
          authority_level: string;
          password_hash: string;
        }[]
      >`
        SELECT rt.id, rt.user_id, rt.organization_id, rt.origin,
               u.authority_level, u.password_hash
          FROM recovery_tickets rt
          JOIN users u ON u.id = rt.user_id
         WHERE rt.ticket_hash = ${await hashSessionToken(body.ticket, c.env.SESSION_SIGNING_KEY)}
           AND rt.consumed_at IS NULL
           AND rt.expires_at > now()
         FOR UPDATE OF rt
      `;
      const ticket = tickets[0];
      if (!ticket) {
        throw authenticationError(
          'RECOVERY_TICKET_INVALID',
          'That recovery link has expired or has already been used. Start again with another recovery code.',
        );
      }

      // Reusing the old password would leave the account exactly as compromised as the
      // event that prompted recovery.
      if (await verifyPassword(body.newPassword, ticket.password_hash)) {
        throw validationError(
          'PASSWORD_UNCHANGED',
          'Choose a password you have not used on this account before.',
        );
      }

      await tx`
        UPDATE users
           SET password_hash = ${await hashPassword(body.newPassword)},
               password_updated_at = now(),
               failed_login_count = 0,
               locked_until = NULL
         WHERE id = ${ticket.user_id}
      `;
      await tx`UPDATE recovery_tickets SET consumed_at = now() WHERE id = ${ticket.id}`;

      /*
       * Every session, without exception. If recovery was prompted by somebody else having
       * had the password, a surviving session is the attacker's way back in — and the new
       * password would give the legitimate owner false confidence that it was closed.
       */
      await tx`
        UPDATE sessions SET revoked_at = now(), revocation_reason = 'CREDENTIAL_RECOVERED'
         WHERE user_id = ${ticket.user_id} AND revoked_at IS NULL
      `;

      await tx`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, user_agent, detail)
        VALUES (${ticket.organization_id}, ${ticket.user_id}, 'PASSWORD_RECOVERED',
                ${ticket.authority_level === 'L3' ? 'CRITICAL' : 'WARNING'},
                ${'A password was reset through credential recovery'},
                ${security.ip}, ${security.userAgent},
                ${tx.json({ origin: ticket.origin, level: ticket.authority_level })})
      `;
      await writeAuditEvent(tx, {
        organizationId: ticket.organization_id,
        actorId: ticket.user_id,
        actorLevel: ticket.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.recovery.completed',
        objectType: 'User',
        objectId: ticket.user_id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { origin: ticket.origin },
      });
    }),
  );

  return c.json({
    recovered: true,
    message:
      'Your password has been changed and every session on this account has been signed out. Sign in with the new password.',
  });
});

// ---------------------------------------------------------------------------
// Step-up authentication (spec §8.2, §9)
// ---------------------------------------------------------------------------

/**
 * Re-confirm identity for a privileged action.
 *
 * Nine administrative operations and the payment release ceremony all call
 * `assertFreshAuthentication`, which refuses anything attempted more than five minutes
 * after sign-in — and there was no way anywhere to satisfy it. The error told the operator
 * to "confirm your identity again" and offered no means of doing so, so every one of those
 * actions became permanently unreachable a few minutes into a session. Saving M-PESA
 * credentials was impossible in practice: nobody pastes a certificate and six other fields
 * inside five minutes. Releasing a payment was impossible on the same terms.
 *
 * The chain here is the one spec §9 sets out for a credential change — re-authentication,
 * then WebAuthn — and it is deliberately the same shape as signing in, because it is the
 * same question being asked again. An L1 re-confirms with a password; anyone who holds an
 * authenticator must use it, so a stolen session with a known password cannot step itself
 * up to administrative authority.
 *
 * Only the *current* session is refreshed. Stepping up on one device must not quietly
 * elevate another device's session that happens to belong to the same person.
 */

authRoutes.post('/step-up', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z.object({ password: z.string().min(1).max(1024) }).parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    const users = await sql<{ password_hash: string; authority_level: string }[]>`
      SELECT password_hash, authority_level FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    const user = users[0];
    if (!user || !(await verifyPassword(body.password, user.password_hash))) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${actor.organizationId}, ${actor.userId}, 'STEP_UP_FAILED', 'WARNING',
                ${'A step-up authentication attempt failed on the password'},
                ${security.ip}, ${sql.json({ level: actor.level })})
      `;
      throw authenticationError('PASSWORD_INCORRECT', 'That password was not correct');
    }

    const credentials = await sql<{ credential_id: string; transports: string[] }[]>`
      SELECT credential_id, transports FROM webauthn_credentials
       WHERE user_id = ${actor.userId} AND status = 'ACTIVE'
    `;

    /*
     * Anyone with an authenticator must present it, not merely those whose level demands
     * one. Downgrading to password-only for a privileged action because the *level* happens
     * to be L1 would make step-up weaker than the sign-in that preceded it.
     */
    if (credentials.length > 0) {
      const options = await generateAuthenticationOptions({
        rpID: c.env.WEBAUTHN_RP_ID,
        userVerification: 'required',
        allowCredentials: credentials.map((cred) => ({
          id: cred.credential_id,
          transports: cred.transports as AuthenticatorTransportFuture[],
        })),
      });

      const ticket = randomToken(32);
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${actor.organizationId}, ${actor.userId}, 'STEP_UP_CHALLENGE_ISSUED', 'INFO',
                ${'A WebAuthn challenge was issued to re-confirm identity'}, ${security.ip},
                ${sql.json({ challenge: options.challenge, ticket, sessionId: actor.sessionId })})
      `;

      return { stage: 'WEBAUTHN_REQUIRED' as const, ticket, options };
    }

    // No authenticator enrolled: the password is the only credential this account has, and
    // it has just been re-presented.
    await sql`
      UPDATE sessions SET authenticated_at = now() WHERE id = ${actor.sessionId}
    `;
    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.step_up',
        objectType: 'Session',
        objectId: actor.sessionId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { method: 'password' },
      }),
    );

    return { stage: 'CONFIRMED' as const };
  });

  return c.json(result);
});

authRoutes.post('/step-up/verify', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ ticket: z.string().min(16).max(64), response: z.record(z.unknown()) })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  await withConnection(c.env, async (sql) => {
    const events = await sql<{ detail: { challenge: string; sessionId: string } }[]>`
      SELECT detail FROM security_events
       WHERE event_type = 'STEP_UP_CHALLENGE_ISSUED'
         AND detail->>'ticket' = ${body.ticket}
         AND user_id = ${actor.userId}
         AND created_at > now() - interval '5 minutes'
       ORDER BY created_at DESC
       LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw authenticationError(
        'STEP_UP_CHALLENGE_EXPIRED',
        'That confirmation expired. Try the action again.',
      );
    }

    // The challenge is bound to the session it was issued for: a ticket obtained on one
    // device must not elevate another.
    if (pending.detail.sessionId !== actor.sessionId) {
      throw authenticationError(
        'STEP_UP_CHALLENGE_EXPIRED',
        'That confirmation belongs to a different session.',
      );
    }

    const response = body.response as Record<string, unknown> & { id?: string };
    const credentialId = typeof response.id === 'string' ? response.id : '';
    const credentials = await sql<
      {
        id: string;
        credential_id: string;
        public_key: Uint8Array;
        signature_counter: string;
        transports: string[];
      }[]
    >`
      SELECT id, credential_id, public_key, signature_counter, transports
        FROM webauthn_credentials
       WHERE user_id = ${actor.userId} AND credential_id = ${credentialId} AND status = 'ACTIVE'
       LIMIT 1
    `;
    const credential = credentials[0];
    if (!credential) {
      throw authenticationError(
        'WEBAUTHN_CREDENTIAL_UNKNOWN',
        'That authenticator is not registered to this account',
      );
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.response as never,
        expectedChallenge: pending.detail.challenge,
        expectedOrigin: c.env.APP_ORIGIN,
        expectedRPID: c.env.WEBAUTHN_RP_ID,
        requireUserVerification: true,
        credential: {
          id: credential.credential_id,
          publicKey: new Uint8Array(credential.public_key),
          counter: Number(credential.signature_counter),
          transports: credential.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch {
      throw authenticationError(
        'WEBAUTHN_VERIFICATION_FAILED',
        'The security key verification failed',
      );
    }
    if (!verification.verified) {
      throw authenticationError(
        'WEBAUTHN_VERIFICATION_FAILED',
        'The security key verification failed',
      );
    }

    const newCounter = verification.authenticationInfo.newCounter;
    const storedCounter = Number(credential.signature_counter);
    if (newCounter !== 0 && newCounter <= storedCounter) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${actor.organizationId}, ${actor.userId}, 'WEBAUTHN_COUNTER_REGRESSION', 'CRITICAL',
                ${'An authenticator signature counter did not advance during step-up, which can indicate a cloned key'},
                ${security.ip}, ${sql.json({ storedCounter, newCounter })})
      `;
      throw authenticationError(
        'WEBAUTHN_COUNTER_REGRESSION',
        'That authenticator failed a security check. Contact your administrator.',
      );
    }

    await sql`
      UPDATE webauthn_credentials
         SET signature_counter = ${newCounter}, last_used_at = now()
       WHERE id = ${credential.id}
    `;
    await sql`
      UPDATE sessions SET authenticated_at = now(), webauthn_verified_at = now()
       WHERE id = ${actor.sessionId}
    `;
    // Spent, so a captured ticket cannot be replayed into a second elevation.
    await sql`
      UPDATE security_events SET detail = detail - 'ticket'
       WHERE event_type = 'STEP_UP_CHALLENGE_ISSUED' AND detail->>'ticket' = ${body.ticket}
    `;

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.step_up',
        objectType: 'Session',
        objectId: actor.sessionId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { method: 'webauthn' },
      }),
    );
  });

  return c.json({ stage: 'CONFIRMED' as const });
});
