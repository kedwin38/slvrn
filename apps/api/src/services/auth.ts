/**
 * Identity authentication and session management (spec 7, 8).
 *
 * The separation this module exists to preserve: **logging in establishes identity; it
 * never establishes authority to move money.** A valid session gets you into the
 * application. Releasing a payment additionally requires fresh authentication, a WebAuthn
 * signature over the exact manifest, and the SPAC PIN — see `services/authorization.ts`.
 *
 * There is no SMS path here, and there is nowhere to add one: the schema has no phone
 * column on any identity table, and the recovery flow consumes a stored recovery code or
 * goes through administrative review.
 */

import {
  authenticationError,
  authorizationError,
  type AuthorityLevel,
  type Actor,
} from '@solvaren/core';
import {
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
  sha256Base64Url,
} from './crypto.js';
import type { Sql } from '../db/client.js';
import type { AuthenticatedActor, Env } from '../env.js';

/** Access sessions are short; the refresh path re-checks user status and device trust. */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours — one working day
/** Privileged actions require authentication no older than this (spec 8.2). */
export const STEP_UP_MAX_AGE_MS = 5 * 60 * 1000;
/** Account lockout thresholds. */
export const MAX_FAILED_LOGINS = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;

export interface LoginInput {
  email: string;
  password: string;
  deviceFingerprint: string | null;
  ip: string | null;
  userAgent: string | null;
}

export interface UserRow {
  id: string;
  organization_id: string;
  organization_slug: string;
  email: string;
  full_name: string;
  authority_level: AuthorityLevel;
  status: 'ACTIVE' | 'DISABLED' | 'LOCKED' | 'PENDING_ENROLMENT';
  password_hash: string;
  authorization_pin_hash: string | null;
  failed_login_count: number;
  locked_until: string | null;
}

/**
 * A dummy Argon2id hash used to equalise work when an account does not exist.
 *
 * Without it, a non-existent email returns in ~1 ms and a real one in ~50 ms, which hands
 * an attacker a reliable account-enumeration oracle. This hash is never a valid credential
 * for anything: it is the encoding of a random 32-byte value no one holds.
 */
const DUMMY_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$c29sdmFyZW5kdW1teXNhbHQ$c29sdmFyZW5kdW1teWhhc2h2YWx1ZTAwMDAwMDAw';

export interface PasswordStageResult {
  user: UserRow;
  /** WebAuthn is mandatory for L2 and L3 (spec 7.3), so the session is not yet usable. */
  requiresWebAuthn: boolean;
}

/**
 * Stage one of login: verify the password.
 *
 * Returns the same error for "no such account", "wrong password" and "account disabled".
 * Distinguishing them would tell an attacker which emails are real and which officers have
 * been offboarded.
 */
export async function verifyPasswordStage(sql: Sql, input: LoginInput): Promise<PasswordStageResult> {
  const rows = await sql<UserRow[]>`
    SELECT u.id, u.organization_id, o.slug AS organization_slug, u.email, u.full_name,
           u.authority_level, u.status, u.password_hash, u.authorization_pin_hash,
           u.failed_login_count, u.locked_until
      FROM users u
      JOIN organizations o ON o.id = u.organization_id
     WHERE u.email = ${input.email.trim().toLowerCase()}
       AND o.status = 'ACTIVE'
     LIMIT 1
  `;

  const user = rows[0];
  const invalid = () =>
    authenticationError('INVALID_CREDENTIALS', 'That email address and password combination was not recognised');

  if (!user) {
    // Equalise timing against the real path before failing.
    await verifyPassword(input.password, DUMMY_HASH);
    throw invalid();
  }

  if (user.locked_until && new Date(user.locked_until).getTime() > Date.now()) {
    await verifyPassword(input.password, DUMMY_HASH);
    throw authenticationError(
      'ACCOUNT_LOCKED',
      'This account is temporarily locked after repeated failed sign-in attempts. Try again later or contact your administrator.',
    );
  }

  const passwordOk = await verifyPassword(input.password, user.password_hash);

  if (!passwordOk) {
    const nextCount = user.failed_login_count + 1;
    const shouldLock = nextCount >= MAX_FAILED_LOGINS;
    await sql`
      UPDATE users
         SET failed_login_count = ${nextCount},
             locked_until = ${shouldLock ? new Date(Date.now() + LOCKOUT_MS) : null},
             status = ${shouldLock ? 'LOCKED' : user.status}
       WHERE id = ${user.id}
    `;
    throw invalid();
  }

  if (user.status !== 'ACTIVE') {
    // Deliberately the same message as a bad password: an offboarded officer's status is
    // not information an unauthenticated caller is entitled to.
    throw invalid();
  }

  await sql`UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ${user.id}`;

  return {
    user,
    requiresWebAuthn: user.authority_level === 'L2' || user.authority_level === 'L3',
  };
}

export interface SessionIssueInput {
  user: UserRow;
  trustedDeviceId: string | null;
  webauthnVerified: boolean;
  ip: string | null;
  userAgent: string | null;
}

export interface IssuedSession {
  token: string;
  sessionId: string;
  expiresAt: Date;
}

/**
 * Issue a session.
 *
 * Refuses to issue a usable session for an L2/L3 account that has not completed WebAuthn,
 * so a bug in the login route cannot produce a password-only privileged session.
 */
export async function issueSession(
  sql: Sql,
  env: Env,
  input: SessionIssueInput,
): Promise<IssuedSession> {
  const privileged = input.user.authority_level !== 'L1';
  if (privileged && !input.webauthnVerified) {
    throw authenticationError(
      'WEBAUTHN_REQUIRED',
      'Level 2 and Level 3 accounts must complete a security key or passkey verification to sign in',
    );
  }

  const token = generateSessionToken();
  const tokenHash = await hashSessionToken(token, env.SESSION_SIGNING_KEY);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);

  const rows = await sql<{ id: string }[]>`
    INSERT INTO sessions (
      organization_id, user_id, token_hash, trusted_device_id, authenticated_at,
      webauthn_verified_at, issued_at, expires_at, ip, user_agent
    ) VALUES (
      ${input.user.organization_id}, ${input.user.id}, ${tokenHash}, ${input.trustedDeviceId},
      ${now}, ${input.webauthnVerified ? now : null}, ${now}, ${expiresAt},
      ${input.ip}, ${input.userAgent}
    )
    RETURNING id
  `;

  await sql`UPDATE users SET last_login_at = ${now} WHERE id = ${input.user.id}`;

  return { token, sessionId: rows[0]!.id, expiresAt };
}

/**
 * Resolve a bearer token to an actor.
 *
 * Every check here runs on every authenticated request, because each corresponds to
 * something that can change between login and now: the session can be revoked, the account
 * can be disabled or demoted, the device can be blocked.
 */
export async function resolveSession(
  sql: Sql,
  env: Env,
  token: string,
): Promise<AuthenticatedActor> {
  const tokenHash = await hashSessionToken(token, env.SESSION_SIGNING_KEY);

  const rows = await sql<
    {
      session_id: string;
      user_id: string;
      organization_id: string;
      organization_slug: string;
      email: string;
      full_name: string;
      authority_level: AuthorityLevel;
      user_status: 'ACTIVE' | 'DISABLED' | 'LOCKED' | 'PENDING_ENROLMENT';
      authenticated_at: string;
      webauthn_verified_at: string | null;
      expires_at: string;
      revoked_at: string | null;
      trusted_device_id: string | null;
      device_trust_status: string | null;
    }[]
  >`
    SELECT s.id            AS session_id,
           s.user_id, s.organization_id, o.slug AS organization_slug,
           u.email, u.full_name, u.authority_level, u.status AS user_status,
           s.authenticated_at, s.webauthn_verified_at, s.expires_at, s.revoked_at,
           s.trusted_device_id, td.trust_status AS device_trust_status
      FROM sessions s
      JOIN users u          ON u.id = s.user_id
      JOIN organizations o  ON o.id = s.organization_id
      LEFT JOIN trusted_devices td ON td.id = s.trusted_device_id
     WHERE s.token_hash = ${tokenHash}
     LIMIT 1
  `;

  const row = rows[0];
  if (!row) {
    throw authenticationError('SESSION_INVALID', 'Your session is not valid. Please sign in again.');
  }
  if (row.revoked_at) {
    throw authenticationError('SESSION_REVOKED', 'This session has been signed out. Please sign in again.');
  }
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw authenticationError('SESSION_EXPIRED', 'Your session has expired. Please sign in again.');
  }
  if (row.user_status !== 'ACTIVE') {
    // A privilege change or offboarding takes effect on the next request, not at next login.
    throw authenticationError('ACCOUNT_INACTIVE', 'This account is no longer active.');
  }
  if (row.device_trust_status === 'BLOCKED' || row.device_trust_status === 'REVOKED') {
    throw authorizationError(
      'DEVICE_REVOKED',
      'This device is no longer trusted for SOLVAREN. Sign in again from an approved device.',
    );
  }

  // Best-effort activity timestamp; a failure here must not fail the request.
  await sql`UPDATE sessions SET last_seen_at = now() WHERE id = ${row.session_id}`.catch(() => {});

  return {
    userId: row.user_id,
    organizationId: row.organization_id,
    organizationSlug: row.organization_slug,
    level: row.authority_level,
    status: 'ACTIVE',
    email: row.email,
    fullName: row.full_name,
    sessionId: row.session_id,
    authenticatedAt: new Date(row.authenticated_at).getTime(),
    webauthnVerifiedAt: row.webauthn_verified_at ? new Date(row.webauthn_verified_at).getTime() : null,
    trustedDeviceId: row.trusted_device_id,
  };
}

/**
 * Require recent authentication for a privileged action (spec 8.2).
 *
 * "Recent" is deliberately short. The attack this blocks is an unattended, still-valid
 * session being used to release a payment hours after the officer walked away.
 */
export function assertFreshAuthentication(
  actor: AuthenticatedActor,
  maxAgeMs: number = STEP_UP_MAX_AGE_MS,
  now: number = Date.now(),
): void {
  const age = now - actor.authenticatedAt;
  if (age > maxAgeMs) {
    throw authenticationError(
      'STEP_UP_REQUIRED',
      'This action requires you to confirm your identity again.',
      { authenticatedSecondsAgo: Math.floor(age / 1000), maxAgeSeconds: Math.floor(maxAgeMs / 1000) },
    );
  }
}

/** Require that the session was established with a WebAuthn authenticator. */
export function assertWebAuthnSession(actor: AuthenticatedActor): void {
  if (actor.webauthnVerifiedAt === null) {
    throw authenticationError(
      'WEBAUTHN_REQUIRED',
      'This action requires a security key or passkey. Sign in again with your authenticator.',
    );
  }
}

export function toActor(actor: AuthenticatedActor): Actor {
  return {
    userId: actor.userId,
    organizationId: actor.organizationId,
    level: actor.level,
    status: actor.status,
  };
}

export async function revokeSession(sql: Sql, sessionId: string, reason: string): Promise<void> {
  await sql`
    UPDATE sessions
       SET revoked_at = now(), revocation_reason = ${reason}
     WHERE id = ${sessionId} AND revoked_at IS NULL
  `;
}

/** Revoke every session for a user — used on device revocation and security events. */
export async function revokeAllSessions(sql: Sql, userId: string, reason: string): Promise<number> {
  const rows = await sql<{ id: string }[]>`
    UPDATE sessions
       SET revoked_at = now(), revocation_reason = ${reason}
     WHERE user_id = ${userId} AND revoked_at IS NULL
    RETURNING id
  `;
  return rows.length;
}

/** Stable per-device identifier derived from request characteristics plus a client value. */
export async function deriveDeviceFingerprint(
  clientDeviceId: string | null,
  userAgent: string | null,
): Promise<string | null> {
  if (!clientDeviceId) return null;
  return sha256Base64Url(`${clientDeviceId}|${userAgent ?? ''}`);
}
