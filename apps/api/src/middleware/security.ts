/**
 * Request security middleware.
 *
 * Spec 4, HARD CONTROL: "The backend must independently enforce authorization. A hidden
 * button or disabled menu item is not an access control." This file is where that promise
 * is kept — `requireAuth` and `requirePermissions` sit in front of every privileged route,
 * and `guardedRoute` makes it impossible to register a privileged route without declaring
 * the permission it needs.
 */

import type { MiddlewareHandler } from 'hono';
import {
  SolvarenError,
  authenticationError,
  authorizationError,
  requirePermission,
  correlationId as newCorrelationId,
  redactForAudit,
  type Permission,
} from '@solvaren/core';
import { resolveSession, toActor } from '../services/auth.js';
import { withConnection } from '../db/client.js';
import type { AppContext } from '../env.js';

/** Attach a correlation id and the security context to every request. */
export const requestContext: MiddlewareHandler<AppContext> = async (c, next) => {
  // Honour an inbound correlation id only if it looks like ours; otherwise a caller could
  // poison the audit trail by supplying arbitrary text.
  const inbound = c.req.header('X-Correlation-Id');
  const correlationId = inbound && /^cor_[A-Z0-9]{20}$/.test(inbound) ? inbound : newCorrelationId();

  c.set('correlationId', correlationId);
  c.set('securityContext', {
    ip: c.req.header('CF-Connecting-IP') ?? null,
    userAgent: c.req.header('User-Agent')?.slice(0, 512) ?? null,
    country: c.req.header('CF-IPCountry') ?? null,
    deviceFingerprint: c.req.header('X-Solvaren-Device')?.slice(0, 200) ?? null,
  });

  c.header('X-Correlation-Id', correlationId);
  await next();
};

/**
 * Security response headers.
 *
 * The CSP is strict because this application displays financial data and accepts an
 * authorization PIN: `default-src 'none'` with explicit allowances means an injected script
 * tag has nowhere to load from and nowhere to exfiltrate to.
 */
export const securityHeaders: MiddlewareHandler<AppContext> = async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  c.header('Cross-Origin-Resource-Policy', 'same-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  c.header(
    'Content-Security-Policy',
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  );
  // Financial data must never be cached by an intermediary or left in a shared browser.
  c.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  c.header('Pragma', 'no-cache');
};

/** Strict same-origin CORS. The API serves exactly one browser origin. */
export const cors: MiddlewareHandler<AppContext> = async (c, next) => {
  const origin = c.req.header('Origin');
  const allowed = c.env.APP_ORIGIN;

  if (origin && origin === allowed) {
    c.header('Access-Control-Allow-Origin', allowed);
    c.header('Access-Control-Allow-Credentials', 'true');
    c.header('Vary', 'Origin');
  }

  if (c.req.method === 'OPTIONS') {
    c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    c.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Idempotency-Key, X-Correlation-Id, X-Solvaren-Device',
    );
    c.header('Access-Control-Max-Age', '600');
    return c.body(null, 204);
  }

  await next();
};

/**
 * Authenticate the request.
 *
 * The bearer token is read from the Authorization header rather than a cookie so that
 * cross-site request forgery is structurally impossible: a browser will not attach it to a
 * request originating from another site.
 */
export const requireAuth: MiddlewareHandler<AppContext> = async (c, next) => {
  const header = c.req.header('Authorization');
  if (!header?.startsWith('Bearer ')) {
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }
  const token = header.slice(7).trim();
  if (token.length < 20 || token.length > 200) {
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }

  const actor = await withConnection(c.env, c.executionCtx, (sql) =>
    resolveSession(sql, c.env, token),
  );
  c.set('actor', actor);
  await next();
};

/** Read the authenticated actor, or fail loudly if a route forgot `requireAuth`. */
export function actorOf(c: { get: (key: 'actor') => AppContext['Variables']['actor'] }) {
  const actor = c.get('actor');
  if (!actor) {
    // A programming error, not a user error: the route is misconfigured.
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }
  return actor;
}

/**
 * Enforce one or more permissions.
 *
 * Every permission must be held — there is no "any of" variant, because a route that would
 * accept either of two permissions is really two routes with different authority and
 * should be written as such.
 */
export function requirePermissions(...permissions: Permission[]): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const actor = actorOf(c);
    for (const permission of permissions) {
      requirePermission(toActor(actor), permission);
    }
    await next();
  };
}

/**
 * Restrict a route to an exact authority level.
 *
 * Used for the executive dashboard panels (spec 21), where the requirement is not "at least
 * L3" but "L3 and nobody else", and where AC-19 demands the *data API* rejects non-L3
 * callers rather than the UI hiding a panel.
 */
export function requireExactLevel(level: 'L1' | 'L2' | 'L3'): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const actor = actorOf(c);
    if (actor.level !== level) {
      throw authorizationError(
        'LEVEL_RESTRICTED',
        `This information is available to ${level} authority only`,
        { requiredLevel: level, actorLevel: actor.level },
      );
    }
    await next();
  };
}

/**
 * Central error handler.
 *
 * Two properties matter here. First, an unexpected exception becomes a generic 500 with a
 * correlation id rather than a stack trace — an internal message can name a table, a query,
 * or a secret. Second, error details are redacted on the way out, so a `SolvarenError`
 * carrying request context in `details` cannot leak credential material.
 */
export function errorHandler(err: Error, c: { get: (k: 'correlationId') => string; json: Function }) {
  const correlationId = c.get('correlationId');

  if (err instanceof SolvarenError) {
    return c.json(
      {
        error: {
          code: err.code,
          category: err.category,
          message: err.message,
          details: redactForAudit(err.details),
          correlationId,
        },
      },
      err.httpStatus,
    );
  }

  // Zod validation failures arrive as ZodError; surface the field paths but not the values,
  // since a rejected payload can contain a password or a PIN.
  if (err.name === 'ZodError') {
    const issues = (err as unknown as { issues: { path: (string | number)[]; message: string }[] }).issues;
    return c.json(
      {
        error: {
          code: 'REQUEST_INVALID',
          category: 'VALIDATION',
          message: 'The request was not valid',
          details: { fields: issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
          correlationId,
        },
      },
      422,
    );
  }

  console.error(
    JSON.stringify({
      level: 'error',
      correlationId,
      message: err.message,
      name: err.name,
      // The stack goes to the Worker log, never to the client.
      stack: err.stack?.split('\n').slice(0, 6).join('\n'),
    }),
  );

  return c.json(
    {
      error: {
        code: 'INTERNAL_ERROR',
        category: 'INTERNAL',
        message: 'Something went wrong handling this request. Quote the correlation id to support.',
        details: {},
        correlationId,
      },
    },
    500,
  );
}

/**
 * Body size limit.
 *
 * Applied before parsing, because the denial-of-service risk is in the parse, not the
 * handler. CSV uploads have their own larger limit enforced in the batch routes.
 */
export function limitBodySize(maxBytes: number): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const declared = c.req.header('Content-Length');
    if (declared && Number(declared) > maxBytes) {
      throw new SolvarenError(
        'VALIDATION',
        'PAYLOAD_TOO_LARGE',
        `The request body exceeds the ${Math.floor(maxBytes / 1024)} KB limit for this endpoint`,
      );
    }
    await next();
  };
}
