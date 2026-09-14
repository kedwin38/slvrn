/**
 * Environment validation.
 *
 * This module runs once, before the server binds a port, and its job is to refuse to start
 * rather than to start wrong.
 *
 * That posture matters more here than on most services. A payment platform that boots with
 * `SECRET_ENCRYPTION_KEY` unset does not fail at boot — it fails the first time an
 * administrator saves a Daraja credential, halfway through a write, in production, at the
 * worst possible moment. A platform that boots with a *weak* key does not fail at all; it
 * just stores recoverable secrets and nobody finds out until they are recovered.
 *
 * So every secret is checked for presence and for minimum entropy, every URL is parsed,
 * and the process exits non-zero with the complete list of problems. Railway will show the
 * failed deploy, which is the outcome we want — a deployment that never serves traffic is
 * cheap, and one that serves traffic with no encryption key is not.
 */

/** Minimum length for a key used to sign sessions or encrypt secrets at rest. */
const MIN_KEY_LENGTH = 32;

/**
 * Values that look like a key but are not one.
 *
 * Every one of these has been committed to a production environment variable by somebody.
 * Rejecting them is cheaper than explaining afterwards why the audit log was forgeable.
 */
const FORBIDDEN_KEY_VALUES = new Set([
  'changeme',
  'change-me',
  'secret',
  'password',
  'test',
  'development',
  'placeholder',
  'REPLACE_ME',
  'your-secret-here',
]);

export interface LoadedConfig {
  DATABASE_URL: string;
  PORT: number;
  ENVIRONMENT: 'development' | 'staging' | 'production';

  SESSION_SIGNING_KEY: string;
  SECRET_ENCRYPTION_KEY: string;
  CALLBACK_SHARED_SECRET: string;
  AI_API_KEY?: string;

  APP_ORIGIN: string;
  API_BASE_URL: string;
  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;
  DARAJA_ENVIRONMENT?: 'sandbox' | 'production';
  AI_MODEL?: string;

  // ---- Object storage (S3-compatible; BAK-001) ----------------------------
  S3_ENDPOINT: string;
  S3_REGION: string;
  S3_BUCKET: string;
  S3_ACCESS_KEY_ID: string;
  S3_SECRET_ACCESS_KEY: string;
  /** Path-style addressing, which MinIO and some S3 clones require. */
  S3_FORCE_PATH_STYLE: boolean;

  // ---- Worker behaviour ---------------------------------------------------
  /** Run the queue consumers in this process. Off for a web-only replica. */
  RUN_WORKERS: boolean;
  /** Run the cron scheduler in this process. Guarded by an advisory lock regardless. */
  RUN_SCHEDULER: boolean;
  /** Maximum concurrent payment submissions, bounding Daraja-facing throughput. */
  PAYMENT_CONCURRENCY: number;
}

class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Configuration is invalid:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
  }
}

/**
 * Read and validate configuration from an environment.
 *
 * Takes the environment as a parameter rather than reading `process.env` directly so the
 * test suite can exercise the validation itself — a validator nobody tests is a validator
 * that passes everything.
 */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const problems: string[] = [];

  const required = (name: string): string => {
    const value = source[name]?.trim();
    if (!value) {
      problems.push(`${name} is required but not set`);
      return '';
    }
    return value;
  };

  const requiredKey = (name: string): string => {
    const value = required(name);
    if (!value) return '';
    if (value.length < MIN_KEY_LENGTH) {
      problems.push(
        `${name} must be at least ${MIN_KEY_LENGTH} characters (got ${value.length}). ` +
          `Generate one with: openssl rand -base64 48`,
      );
    }
    if (FORBIDDEN_KEY_VALUES.has(value) || FORBIDDEN_KEY_VALUES.has(value.toLowerCase())) {
      problems.push(`${name} is set to a placeholder value and must be a real generated key`);
    }
    return value;
  };

  const requiredUrl = (name: string): string => {
    const value = required(name);
    if (!value) return '';
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        problems.push(`${name} must be an http(s) URL`);
      }
      // Spec 9.4: a provider callback URL must be HTTPS. Enforced in the database too, but
      // a staging deployment pointing Daraja at http:// should never reach that check.
      if (url.protocol === 'http:' && source.ENVIRONMENT === 'production') {
        problems.push(`${name} must be HTTPS in production`);
      }
    } catch {
      problems.push(`${name} is not a valid URL: ${value}`);
    }
    return value.replace(/\/$/, '');
  };

  const optionalEnum = <T extends string>(name: string, allowed: readonly T[]): T | undefined => {
    const value = source[name]?.trim();
    if (!value) return undefined;
    if (!(allowed as readonly string[]).includes(value)) {
      problems.push(`${name} must be one of ${allowed.join(', ')} (got ${value})`);
      return undefined;
    }
    return value as T;
  };

  const integer = (name: string, fallback: number, min: number, max: number): number => {
    const raw = source[name]?.trim();
    if (!raw) return fallback;
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
      problems.push(`${name} must be an integer between ${min} and ${max} (got ${raw})`);
      return fallback;
    }
    return parsed;
  };

  const boolean = (name: string, fallback: boolean): boolean => {
    const raw = source[name]?.trim().toLowerCase();
    if (raw === undefined || raw === '') return fallback;
    if (['1', 'true', 'yes', 'on'].includes(raw)) return true;
    if (['0', 'false', 'no', 'off'].includes(raw)) return false;
    problems.push(`${name} must be a boolean (true/false), got ${raw}`);
    return fallback;
  };

  const environment =
    optionalEnum('ENVIRONMENT', ['development', 'staging', 'production'] as const) ?? 'development';

  // Railway provides DATABASE_URL automatically when a PostgreSQL service is attached.
  const databaseUrl = required('DATABASE_URL');
  if (databaseUrl && !/^postgres(ql)?:\/\//.test(databaseUrl)) {
    problems.push('DATABASE_URL must be a postgres:// or postgresql:// connection string');
  }

  const config: LoadedConfig = {
    DATABASE_URL: databaseUrl,
    // Railway injects PORT and expects the service to bind it.
    PORT: integer('PORT', 8080, 1, 65535),
    ENVIRONMENT: environment,

    SESSION_SIGNING_KEY: requiredKey('SESSION_SIGNING_KEY'),
    SECRET_ENCRYPTION_KEY: requiredKey('SECRET_ENCRYPTION_KEY'),
    CALLBACK_SHARED_SECRET: requiredKey('CALLBACK_SHARED_SECRET'),
    AI_API_KEY: source.AI_API_KEY?.trim() || undefined,

    APP_ORIGIN: requiredUrl('APP_ORIGIN'),
    API_BASE_URL: requiredUrl('API_BASE_URL'),
    WEBAUTHN_RP_ID: required('WEBAUTHN_RP_ID'),
    WEBAUTHN_RP_NAME: source.WEBAUTHN_RP_NAME?.trim() || 'SOLVAREN Payment Solutions',
    DARAJA_ENVIRONMENT: optionalEnum('DARAJA_ENVIRONMENT', ['sandbox', 'production'] as const),
    AI_MODEL: source.AI_MODEL?.trim() || undefined,

    S3_ENDPOINT: requiredUrl('S3_ENDPOINT'),
    S3_REGION: source.S3_REGION?.trim() || 'auto',
    S3_BUCKET: required('S3_BUCKET'),
    S3_ACCESS_KEY_ID: required('S3_ACCESS_KEY_ID'),
    S3_SECRET_ACCESS_KEY: required('S3_SECRET_ACCESS_KEY'),
    S3_FORCE_PATH_STYLE: boolean('S3_FORCE_PATH_STYLE', false),

    RUN_WORKERS: boolean('RUN_WORKERS', true),
    RUN_SCHEDULER: boolean('RUN_SCHEDULER', true),
    PAYMENT_CONCURRENCY: integer('PAYMENT_CONCURRENCY', 3, 1, 20),
  };

  // A staging deployment that could disburse real money is not a staging deployment.
  if (config.ENVIRONMENT !== 'production' && config.DARAJA_ENVIRONMENT === 'production') {
    problems.push(
      `DARAJA_ENVIRONMENT=production is refused when ENVIRONMENT=${config.ENVIRONMENT}. ` +
        'A non-production deployment must not be able to move real money.',
    );
  }

  // The two keys must differ. Reusing one value means a leaked session key also decrypts
  // every stored Daraja credential.
  if (config.SESSION_SIGNING_KEY && config.SESSION_SIGNING_KEY === config.SECRET_ENCRYPTION_KEY) {
    problems.push(
      'SESSION_SIGNING_KEY and SECRET_ENCRYPTION_KEY must be different values: ' +
        'reusing one means a leaked session key also decrypts every stored credential',
    );
  }

  // WebAuthn will silently fail to verify if the RP ID is not a registrable suffix of the
  // origin. Catching it here saves a confusing "assertion failed" during enrolment.
  if (config.APP_ORIGIN && config.WEBAUTHN_RP_ID) {
    try {
      const host = new URL(config.APP_ORIGIN).hostname;
      if (host !== config.WEBAUTHN_RP_ID && !host.endsWith(`.${config.WEBAUTHN_RP_ID}`)) {
        problems.push(
          `WEBAUTHN_RP_ID (${config.WEBAUTHN_RP_ID}) must equal the APP_ORIGIN host ` +
            `(${host}) or be a registrable parent of it, or WebAuthn will refuse every assertion`,
        );
      }
    } catch {
      /* APP_ORIGIN already reported as invalid above. */
    }
  }

  if (problems.length > 0) throw new ConfigError(problems);
  return config;
}

/**
 * Load configuration, or print the problems and exit non-zero.
 *
 * Used by the server entry point. The message goes to stderr in full because the one thing
 * worse than a failed deploy is a failed deploy that does not say why.
 */
export function loadConfigOrExit(source: NodeJS.ProcessEnv = process.env): LoadedConfig {
  try {
    return loadConfig(source);
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error('');
      console.error('  SOLVAREN cannot start: the environment is not valid.');
      console.error('  ─────────────────────────────────────────────────────');
      for (const problem of error.problems) console.error(`  ✗ ${problem}`);
      console.error('');
      console.error('  See docs/deployment.md for the full variable list.');
      console.error('');
      process.exit(1);
    }
    throw error;
  }
}

export { ConfigError };
