/**
 * SOLVAREN domain errors.
 *
 * Every error carries a stable machine code so that API responses, audit events and
 * operator runbooks can reference the same identifier. Error messages are safe to show
 * to an authenticated user of the owning organization; they never embed secret material.
 */

export type ErrorCategory =
  | 'VALIDATION'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'STATE'
  | 'POLICY'
  | 'CONFLICT'
  | 'NOT_FOUND'
  | 'RATE_LIMIT'
  | 'PROVIDER'
  | 'INTERNAL';

const STATUS_BY_CATEGORY: Record<ErrorCategory, number> = {
  VALIDATION: 422,
  AUTHENTICATION: 401,
  AUTHORIZATION: 403,
  STATE: 409,
  POLICY: 403,
  CONFLICT: 409,
  NOT_FOUND: 404,
  RATE_LIMIT: 429,
  PROVIDER: 502,
  INTERNAL: 500,
};

export class SolvarenError extends Error {
  readonly code: string;
  readonly category: ErrorCategory;
  readonly details: Record<string, unknown>;
  readonly httpStatus: number;

  constructor(
    category: ErrorCategory,
    code: string,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'SolvarenError';
    this.category = category;
    this.code = code;
    this.details = details;
    this.httpStatus = STATUS_BY_CATEGORY[category];
  }

  toJSON() {
    return {
      error: { code: this.code, category: this.category, message: this.message, details: this.details },
    };
  }
}

export const validationError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('VALIDATION', code, message, details);
export const authenticationError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('AUTHENTICATION', code, message, details);
export const authorizationError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('AUTHORIZATION', code, message, details);
export const stateError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('STATE', code, message, details);
export const policyError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('POLICY', code, message, details);
export const conflictError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('CONFLICT', code, message, details);
export const notFoundError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('NOT_FOUND', code, message, details);
export const providerError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('PROVIDER', code, message, details);
export const internalError = (code: string, message: string, details?: Record<string, unknown>) =>
  new SolvarenError('INTERNAL', code, message, details);
