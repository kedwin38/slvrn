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
  generateRecoveryCode,
  hashSessionToken,
  timingSafeEqual,
  fromBase64Url,
  toBase64Url,
} from '../services/crypto.js';
import { requireAuth, actorOf, limitBodySize } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
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

  const result = await withConnection(c.env, c.executionCtx, async (sql) => {
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

  const result = await withConnection(c.env, c.executionCtx, async (sql) => {
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

  const options = await withConnection(c.env, c.executionCtx, async (sql) => {
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

  const result = await withConnection(c.env, c.executionCtx, async (sql) => {
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
          ${info.credential.transports ?? []}, ${info.credentialDeviceType === 'multiDevice' ? 'PLATFORM' : 'CROSS_PLATFORM'},
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

  await withConnection(c.env, c.executionCtx, async (sql) => {
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

  const codes = await withConnection(c.env, c.executionCtx, async (sql) => {
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
    // The UI renders from this. It is a convenience, not a control: every endpoint
    // re-checks server-side (spec 4, HARD CONTROL).
    capabilities: capabilitiesFor(toActor(actor)),
  });
});

/** POST /auth/logout */
authRoutes.post('/logout', requireAuth, async (c) => {
  const actor = actorOf(c);
  const correlationId = c.get('correlationId');

  await withConnection(c.env, c.executionCtx, async (sql) => {
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

  const revoked = await withConnection(c.env, c.executionCtx, async (sql) => {
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
