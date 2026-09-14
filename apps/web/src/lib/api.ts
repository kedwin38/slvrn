/**
 * API client.
 *
 * Deliberately small and explicit. Three properties matter:
 *
 *  - **The session token is held in memory, not in localStorage.** A token in
 *    localStorage survives the tab and is readable by any script that gets injected;
 *    a token in a module-scoped variable dies with the tab, which is the correct
 *    lifetime for a payment console. The cost is re-authenticating after a refresh,
 *    which is the right trade for this application.
 *  - **Errors keep their server shape.** The API returns a code, a message written for
 *    the person reading it, and a correlation id. The client preserves all three rather
 *    than collapsing them into "Something went wrong", because "Batch edited since
 *    approval — re-review required" is actionable and a generic message is not.
 *  - **Capabilities are advisory.** The UI uses them to decide what to render; the server
 *    decides what is permitted. A stale capability set can only produce a 403, never an
 *    unauthorised action.
 */

import type { Permission } from '@solvaren/core';

export interface ApiErrorShape {
  code: string;
  category: string;
  message: string;
  details?: Record<string, unknown>;
  correlationId?: string;
}

export class ApiError extends Error {
  readonly code: string;
  readonly category: string;
  readonly status: number;
  readonly details: Record<string, unknown>;
  readonly correlationId: string | null;

  constructor(status: number, shape: ApiErrorShape) {
    super(shape.message);
    this.name = 'ApiError';
    this.status = status;
    this.code = shape.code;
    this.category = shape.category;
    this.details = shape.details ?? {};
    this.correlationId = shape.correlationId ?? null;
  }

  /** True when signing in again would resolve it. */
  get requiresReauthentication(): boolean {
    return this.status === 401 || this.code === 'STEP_UP_REQUIRED';
  }
}

/*
 * Where the API lives, inlined by Vite at build time.
 *
 * There is deliberately no meaningful fallback. An earlier version defaulted to '/api',
 * which read as a safe default and was not one: when the variable was missing the console
 * called *itself*, the static file server answered with index.html or 405, and the only
 * thing the user saw was a generic failure that pointed at neither the cause nor the fix.
 *
 * `apps/web/vite.config.ts` now fails the production build when this is unset, so an
 * unconfigured bundle cannot be produced at all. The empty string here is what `vite dev`
 * uses to talk to a same-origin dev proxy, and nothing else relies on it.
 */
const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() ?? '';

let sessionToken: string | null = null;

/** A stable per-browser device identifier, used for trusted-device binding (spec §8.1). */
function deviceId(): string {
  const key = 'solvaren.device';
  try {
    let existing = localStorage.getItem(key);
    if (!existing) {
      existing = crypto.randomUUID();
      localStorage.setItem(key, existing);
    }
    return existing;
  } catch {
    // Private browsing or blocked storage: fall back to a per-tab identifier. The device
    // simply will not be remembered as trusted, which is a safe degradation.
    return 'ephemeral';
  }
}

export function setSessionToken(token: string | null): void {
  sessionToken = token;
}

export function hasSession(): boolean {
  return sessionToken !== null;
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  /** Required on mutating payment endpoints. */
  idempotencyKey?: string;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Solvaren-Device': deviceId(),
  };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey;

  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
    // The token travels in a header, so no cookies and therefore no CSRF surface.
    credentials: 'omit',
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  let unparseable = false;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
    unparseable = true;
  }

  if (!response.ok) {
    const shape = (payload as { error?: ApiErrorShape } | null)?.error;
    throw new ApiError(
      response.status,
      shape ?? {
        code: 'UNEXPECTED_RESPONSE',
        category: 'INTERNAL',
        message: `The server returned ${response.status}.`,
      },
    );
  }

  /*
   * A 2xx that is not JSON means we are not talking to the API at all — the usual cause is
   * a console pointed at its own origin, where the static server answers every unknown path
   * with index.html and HTTP 200. Returning null here instead would push a TypeError into
   * whichever caller unpacked the result, and the user would be told the network was down.
   */
  if (unparseable) {
    throw new ApiError(response.status, {
      code: 'UNEXPECTED_RESPONSE',
      category: 'INTERNAL',
      message:
        'The server returned a response that was not JSON. The console is configured with ' +
        'the wrong API address.',
    });
  }

  return payload as T;
}

/** Download a generated file, preserving the server-supplied filename. */
export async function downloadCsv(
  path: string,
): Promise<{ blob: Blob; filename: string; truncated: boolean }> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'text/csv',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      'X-Solvaren-Device': deviceId(),
    },
    credentials: 'omit',
  });

  if (!response.ok) {
    const text = await response.text();
    let shape: ApiErrorShape | undefined;
    try {
      shape = (JSON.parse(text) as { error?: ApiErrorShape }).error;
    } catch {
      /* not a JSON error body */
    }
    throw new ApiError(
      response.status,
      shape ?? {
        code: 'EXPORT_FAILED',
        category: 'INTERNAL',
        message: 'The export could not be generated.',
      },
    );
  }

  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = disposition.match(/filename="([^"]+)"/);
  return {
    blob: await response.blob(),
    filename: match?.[1] ?? 'export.csv',
    truncated: response.headers.get('X-Solvaren-Row-Truncated') === 'true',
  };
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

export interface SessionResponse {
  user: {
    userId: string;
    email: string;
    fullName: string;
    level: 'L1' | 'L2' | 'L3';
    levelTitle: string;
    organizationId: string;
    organizationSlug: string;
  };
  session: {
    authenticatedAt: string;
    webauthnVerified: boolean;
    trustedDeviceId: string | null;
  };
  capabilities: Record<Permission, boolean>;
}

export type TransactionStatus =
  | 'PENDING'
  | 'SUBMITTED'
  | 'AWAITING_CALLBACK'
  | 'PROCESSING'
  | 'RECONCILING'
  | 'SUCCESS'
  | 'FAILED'
  | 'TIMEOUT'
  | 'CANCELLED';

export interface TransactionRow {
  transactionId: string;
  instructionId: string;
  batchId: string;
  batchReference: string;
  recipientId: string;
  recipientName: string;
  msisdn: string;
  departmentId: string | null;
  departmentName: string | null;
  amountCents: number;
  status: TransactionStatus;
  statusTone: 'success' | 'danger' | 'warning' | 'info' | 'neutral';
  failureCode: string | null;
  failureReason: string | null;
  failureClass: string | null;
  operatorAction: string | null;
  providerResultDescription: string | null;
  mpesaReceiptNumber: string | null;
  conversationId: string | null;
  originatorConversationId: string | null;
  statusSource: string | null;
  lastStatusCheckAt: string | null;
  createdAt: string;
  submittedAt: string | null;
  completedAt: string | null;
  updatedAt: string;
  retryEligible: boolean;
}

export interface ExplorerResponse {
  transactions: TransactionRow[];
  page: {
    page: number;
    pageSize: number;
    totalRows: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
  filter: { text: string; parts: string[] };
}

export interface OperationalDashboard {
  batchesByState: Record<string, number>;
  transactions: {
    total: number;
    success: number;
    failed: number;
    timeout: number;
    inFlight: number;
    successRate: number | null;
    failureRate: number | null;
  };
  processingSeconds: { median: number | null; p95: number | null };
  dailyTrend: { day: string; total: number; failed: number }[];
  needsAttention: { failed: number; timeout: number; reconciling: number };
}

export interface BalancePanel {
  accounts: {
    accountType: string;
    currency: string;
    availableCents: number;
    unclearedCents: number;
    reservedCents: number;
    asOf: string;
    source: string;
  }[];
  asOf: string | null;
  awaitingRefresh: boolean;
  note: string | null;
}

export interface RiskSignalView {
  type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  summary: string;
  evidence: Record<string, unknown>;
  instructionIds: string[];
}

export interface CeremonyResponse {
  challengeId: string;
  challengeHash: string;
  webauthnChallenge: string;
  expiresAt: string;
  manifest: {
    manifestHash: string;
    batchReference: string;
    recipientCount: number;
    totalAmountCents: number;
    approvalId: string;
    batchVersion: number;
  };
  acknowledgementsRequired: string[];
  risk: {
    score: number;
    band: string;
    signals: RiskSignalView[];
    requiresAcknowledgement: boolean;
  };
  confirmation: {
    headline: string;
    batchReference: string;
    manifestDigestShort: string;
    warning: string;
  };
}

export interface BatchSummary {
  batchId: string;
  batchReference: string;
  state: string;
  instructionCount: number;
  totalAmountCents: number;
  outcomes: { success: number; failed: number; timeout: number; inFlight: number };
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/**
 * The backup configuration as the server is willing to describe it.
 *
 * Credential fields arrive already masked (BAK-002) and are typed as the masked strings
 * they are, so there is no shape in this file that could hold a plaintext secret.
 */
export interface BackupConfigurationView {
  configurationId: string;
  providerLabel: string;
  bucket: string;
  pathPrefix: string | null;
  region: string | null;
  endpoint: string | null;
  accessKeyMasked: string;
  secretKeyMasked: string;
  encryptionMode: string;
  status: string;
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
  scheduleEnabled: boolean;
  scheduleCron: string | null;
  scheduleTimezone: string | null;
  retentionMaxCount: number | null;
  lastScheduledRunAt: string | null;
  nextScheduledRunAt: string | null;
  suspended: boolean;
  suspensionReason: string | null;
  consecutiveFailures: number;
}

/**
 * A single backup attempt.
 *
 * `errorMessage` is typed rather than left as `unknown` deliberately: BAK-008 requires a
 * failure to be shown as a failure, and an untyped value rendered through `String()` will
 * silently present an operator with "[object Object]" in place of the reason a backup
 * failed.
 */
export interface BackupAttemptView {
  attemptReference: string;
  trigger: string;
  status: string;
  startedAt: string;
  endedAt: string | null;
  sizeBytes: number | null;
  checksum: string | null;
  errorMessage: string | null;
  retentionDeletedCount: number | null;
  retentionComplete: boolean | null;
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<
        | {
            stage: 'AUTHENTICATED';
            token: string;
            expiresAt: string;
            user: SessionResponse['user'];
          }
        | {
            stage: 'WEBAUTHN_REQUIRED';
            ticket: string;
            options: PublicKeyCredentialRequestOptionsJSON;
            level: string;
          }
      >('/auth/login', { method: 'POST', body: { email, password, deviceId: deviceId() } }),

    completeWebAuthn: (ticket: string, response: unknown) =>
      request<{
        stage: 'AUTHENTICATED';
        token: string;
        expiresAt: string;
        user: SessionResponse['user'];
      }>('/auth/webauthn/authenticate', {
        method: 'POST',
        body: { ticket, response, deviceId: deviceId() },
      }),

    session: () => request<SessionResponse>('/auth/session'),
    logout: () => request<{ signedOut: boolean }>('/auth/logout', { method: 'POST' }),
  },

  transactions: {
    list: (params: URLSearchParams, signal?: AbortSignal) =>
      request<ExplorerResponse>(`/payments/transactions?${params.toString()}`, { signal }),

    detail: (id: string) =>
      request<{
        transaction: TransactionRow;
        activity: {
          action: string;
          outcome: string;
          occurred_at: string;
          actor_id: string;
          detail: unknown;
        }[];
        reconciliationCases: {
          case_reference: string;
          state: string;
          opened_reason: string;
          discrepancy: boolean;
          query_attempts: number;
        }[];
      }>(`/payments/transactions/${id}`),

    refresh: (id: string) =>
      request<{ accepted: boolean; message: string }>(`/payments/transactions/${id}/refresh`, {
        method: 'POST',
      }),

    failureSummary: (batchId?: string) =>
      request<{
        failures: {
          failureCode: string;
          failureReason: string;
          failureClass: string;
          operatorAction: string;
          count: number;
          totalCents: number;
        }[];
      }>(`/payments/failure-summary${batchId ? `?batchId=${batchId}` : ''}`),
  },

  exports: {
    failedTransactions: (params: URLSearchParams) =>
      downloadCsv(`/exports/transactions/failed?${params.toString()}`),
  },

  batches: {
    list: (state?: string) =>
      request<{ batches: BatchSummary[] }>(`/batches${state ? `?state=${state}` : ''}`),
    detail: (id: string) =>
      request<{
        batch: {
          batchId: string;
          batchReference: string;
          purpose: string;
          state: string;
          version: number;
          instructionCount: number;
          totalAmountCents: number;
          createdAt: string;
          submittedAt: string | null;
          approvedAt: string | null;
          authorizedAt: string | null;
          riskScore: number | null;
          riskBand: string | null;
          editable: boolean;
          availableCommands: string[];
        };
        instructions: {
          instructionId: string;
          recipientName: string;
          msisdn: string;
          amountCents: number;
          status: string;
          sourceLineNumber: number | null;
        }[];
        approvals: {
          approval_reference: string;
          action: string;
          actor_level: string;
          reason: string | null;
          batch_version: number;
          created_at: string;
        }[];
        riskFindings: (RiskSignalView & { disposition: string; currentVersion: boolean })[];
      }>(`/batches/${id}`),
    rollup: (id: string) =>
      request<{
        batchReference: string;
        state: string;
        instructionCount: number;
        totalAmountCents: number;
        successCount: number;
        failedCount: number;
        timeoutCount: number;
        inFlightCount: number;
        disbursedCents: number;
        failedCents: number;
      }>(`/payments/batches/${id}/rollup`),
    approve: (id: string, reason: string, acknowledgeFindings: boolean) =>
      request(`/batches/${id}/approve`, { method: 'POST', body: { reason, acknowledgeFindings } }),
    reject: (id: string, reason: string) =>
      request(`/batches/${id}/reject`, { method: 'POST', body: { reason } }),
  },

  authorization: {
    begin: (batchId: string) =>
      request<CeremonyResponse>(`/authorization/batches/${batchId}/begin`, { method: 'POST' }),

    release: (
      batchId: string,
      payload: {
        challengeId: string;
        webauthnResponse: unknown;
        authorizationPin: string;
        acknowledgements: string[];
      },
    ) =>
      request<{
        released: boolean;
        batchReference: string;
        instructionsQueued: number;
        totalAmountCents: number;
        manifestHash: string;
        message: string;
      }>(`/authorization/batches/${batchId}/release`, {
        method: 'POST',
        body: payload,
        // A double-clicked release button must not open a second attempt.
        idempotencyKey: crypto.randomUUID() + crypto.randomUUID(),
      }),

    abandon: (batchId: string, reason: string) =>
      request(`/authorization/batches/${batchId}/abandon`, { method: 'POST', body: { reason } }),
  },

  analytics: {
    operational: () => request<OperationalDashboard>('/analytics/operational'),
    balance: () => request<BalancePanel>('/analytics/executive/balance'),
    refreshBalance: () =>
      request<{ accepted: boolean; message: string }>('/analytics/executive/balance/refresh', {
        method: 'POST',
      }),
    recentTransactions: () =>
      request<{
        transactions: {
          transactionId: string;
          status: string;
          amountCents: number;
          recipientName: string;
          msisdn: string;
          mpesaReceiptNumber: string | null;
          batchReference: string;
          failureReason: string | null;
          at: string;
        }[];
      }>('/analytics/executive/recent-transactions'),
  },

  backups: {
    overview: () =>
      request<{
        configuration: BackupConfigurationView | null;
        latestResult: BackupAttemptView | null;
        history: {
          attemptReference: string;
          trigger: string;
          status: string;
          startedAt: string;
          endedAt: string | null;
          sizeBytes: number | null;
          errorMessage: string | null;
          objectRetained: boolean;
        }[];
        restoreValidationNote: string;
      }>('/admin/backups'),
    run: () =>
      request<{ accepted: boolean; attemptReference: string; message: string }>(
        '/admin/backups/run',
        {
          method: 'POST',
        },
      ),
  },
};

/** Minimal shape of the WebAuthn options the server returns. */
export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  rpId?: string;
  allowCredentials?: { id: string; type: 'public-key'; transports?: string[] }[];
  userVerification?: string;
  timeout?: number;
}
