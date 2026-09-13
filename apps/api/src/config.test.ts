/**
 * Configuration validation.
 *
 * This file exists because `config.ts` is a security gate, and an unverified gate is a gate
 * that passes everything. It is the only thing standing between a typo in a Railway
 * variable and a payment platform running with a guessable encryption key.
 *
 * Every test here asserts a *refusal*. The one acceptance test at the end exists to prove
 * the others are not passing because the validator rejects everything.
 */

import { describe, it, expect } from 'vitest';
import { loadConfig, ConfigError } from './config.js';

/** A complete, valid environment. Each test breaks exactly one thing in it. */
function validEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    DATABASE_URL: 'postgres://user:pw@postgres.railway.internal:5432/railway',
    SESSION_SIGNING_KEY: 'a'.repeat(48),
    SECRET_ENCRYPTION_KEY: 'b'.repeat(48),
    CALLBACK_SHARED_SECRET: 'c'.repeat(48),
    APP_ORIGIN: 'https://app.solvaren.example',
    API_BASE_URL: 'https://api.solvaren.example',
    WEBAUTHN_RP_ID: 'solvaren.example',
    S3_ENDPOINT: 'https://s3.example.com',
    S3_BUCKET: 'solvaren-backups',
    S3_ACCESS_KEY_ID: 'access-key',
    S3_SECRET_ACCESS_KEY: 'secret-key',
    ...overrides,
  };
}

/** Collect the problems from a refusal, so assertions can name the specific one. */
function problemsFrom(env: NodeJS.ProcessEnv): string[] {
  try {
    loadConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return error.problems;
    throw error;
  }
}

describe('configuration validation', () => {
  it('accepts a complete environment', () => {
    const config = loadConfig(validEnv());
    expect(config.ENVIRONMENT).toBe('development');
    expect(config.PORT).toBe(8080);
    expect(config.RUN_WORKERS).toBe(true);
  });

  describe('secrets', () => {
    it('refuses a missing key rather than starting without encryption', () => {
      const problems = problemsFrom(validEnv({ SECRET_ENCRYPTION_KEY: undefined }));
      expect(problems.join('\n')).toContain('SECRET_ENCRYPTION_KEY is required');
    });

    it('refuses a key short enough to be brute-forced, and says how to make one', () => {
      const problems = problemsFrom(validEnv({ SESSION_SIGNING_KEY: 'short' }));
      expect(problems.join('\n')).toContain('at least 32 characters');
      expect(problems.join('\n')).toContain('openssl rand');
    });

    it('refuses a placeholder that looks like a key but is not one', () => {
      const problems = problemsFrom(validEnv({ CALLBACK_SHARED_SECRET: 'changeme' }));
      expect(problems.join('\n')).toContain('placeholder');
    });

    it('refuses reusing one value for both keys', () => {
      const same = 'x'.repeat(48);
      const problems = problemsFrom(
        validEnv({ SESSION_SIGNING_KEY: same, SECRET_ENCRYPTION_KEY: same }),
      );
      // A leaked session key would otherwise also decrypt every stored Daraja credential.
      expect(problems.join('\n')).toContain('must be different values');
    });
  });

  describe('a non-production deployment cannot move real money', () => {
    it('refuses DARAJA_ENVIRONMENT=production outside production', () => {
      for (const environment of ['development', 'staging']) {
        const problems = problemsFrom(
          validEnv({ ENVIRONMENT: environment, DARAJA_ENVIRONMENT: 'production' }),
        );
        expect(problems.join('\n')).toContain('refused when ENVIRONMENT=' + environment);
      }
    });

    it('permits it in production', () => {
      const config = loadConfig(
        validEnv({ ENVIRONMENT: 'production', DARAJA_ENVIRONMENT: 'production' }),
      );
      expect(config.DARAJA_ENVIRONMENT).toBe('production');
    });
  });

  describe('WebAuthn relying party', () => {
    it('refuses an RP ID that is not a registrable suffix of the origin', () => {
      // Caught here rather than as an unexplained "assertion failed" during enrolment.
      const problems = problemsFrom(validEnv({ WEBAUTHN_RP_ID: 'attacker.example' }));
      expect(problems.join('\n')).toContain('WEBAUTHN_RP_ID');
      expect(problems.join('\n')).toContain('registrable parent');
    });

    it('accepts a registrable parent of the origin host', () => {
      expect(() =>
        loadConfig(
          validEnv({
            APP_ORIGIN: 'https://console.solvaren.example',
            WEBAUTHN_RP_ID: 'solvaren.example',
          }),
        ),
      ).not.toThrow();
    });

    it('accepts an exact host match', () => {
      expect(() =>
        loadConfig(
          validEnv({
            APP_ORIGIN: 'https://app.solvaren.example',
            WEBAUTHN_RP_ID: 'app.solvaren.example',
          }),
        ),
      ).not.toThrow();
    });
  });

  describe('URLs and the database', () => {
    it('refuses a DATABASE_URL that is not a PostgreSQL connection string', () => {
      const problems = problemsFrom(validEnv({ DATABASE_URL: 'mysql://host/db' }));
      expect(problems.join('\n')).toContain('must be a postgres://');
    });

    it('refuses a malformed origin', () => {
      const problems = problemsFrom(validEnv({ APP_ORIGIN: 'not-a-url' }));
      expect(problems.join('\n')).toContain('APP_ORIGIN is not a valid URL');
    });

    it('refuses plaintext HTTP in production', () => {
      const problems = problemsFrom(
        validEnv({ ENVIRONMENT: 'production', API_BASE_URL: 'http://api.solvaren.example' }),
      );
      expect(problems.join('\n')).toContain('must be HTTPS in production');
    });

    it('strips a trailing slash so callback URLs do not double up', () => {
      const config = loadConfig(validEnv({ API_BASE_URL: 'https://api.solvaren.example/' }));
      expect(config.API_BASE_URL).toBe('https://api.solvaren.example');
    });
  });

  describe('numbers and booleans', () => {
    it('refuses a port outside the valid range', () => {
      expect(problemsFrom(validEnv({ PORT: '99999' })).join('\n')).toContain('between 1 and 65535');
    });

    it('refuses a non-boolean where a boolean is expected', () => {
      expect(problemsFrom(validEnv({ RUN_WORKERS: 'maybe' })).join('\n')).toContain(
        'must be a boolean',
      );
    });

    it('accepts the usual boolean spellings', () => {
      expect(loadConfig(validEnv({ RUN_WORKERS: 'false' })).RUN_WORKERS).toBe(false);
      expect(loadConfig(validEnv({ RUN_WORKERS: 'no' })).RUN_WORKERS).toBe(false);
      expect(loadConfig(validEnv({ RUN_WORKERS: '1' })).RUN_WORKERS).toBe(true);
    });
  });

  it('reports every problem at once rather than one per restart', () => {
    // A deploy loop that surfaces one missing variable per attempt wastes an outage.
    const problems = problemsFrom({
      DATABASE_URL: undefined,
      SESSION_SIGNING_KEY: undefined,
      APP_ORIGIN: undefined,
    });
    expect(problems.length).toBeGreaterThan(5);
  });
});
