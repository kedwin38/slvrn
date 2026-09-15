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
    /*
     * A validation failure arrives with per-field reasons in `details.fields`, and the
     * top-level message is only ever the generic "The request was not valid". Rendering
     * that alone — which every screen did, because `message` is what they show — left an
     * operator staring at a seven-field credential form with no idea which field was wrong
     * or why. The reason for each one is already on the wire; it was simply thrown away.
     *
     * Composed here rather than in each screen so every form gets it, and so a message is
     * never assembled from values: the server deliberately sends field paths and reasons
     * only, never the rejected input, which may be a password or a PIN.
     */
    super(ApiError.describe(shape));
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

  /** Field-level reasons, when the server sent any. */
  get fieldErrors(): { path: string; message: string }[] {
    const fields = (this.details as { fields?: unknown }).fields;
    return Array.isArray(fields)
      ? (fields as { path?: unknown; message?: unknown }[])
          .filter((f) => typeof f?.message === 'string')
          .map((f) => ({
            path: typeof f.path === 'string' ? f.path : '',
            message: String(f.message),
          }))
      : [];
  }

  private static describe(shape: ApiErrorShape): string {
    const fields = (shape.details as { fields?: unknown } | undefined)?.fields;
    if (!Array.isArray(fields) || fields.length === 0) return shape.message;

    const reasons = (fields as { path?: unknown; message?: unknown }[])
      .filter((field) => typeof field?.message === 'string')
      .map((field) => {
        const path = typeof field.path === 'string' && field.path ? `${label(field.path)}: ` : '';
        return `${path}${String(field.message)}`;
      });

    return reasons.length > 0 ? reasons.join(' ') : shape.message;
  }
}

/** `initiatorPasswordOrCredential` reads badly in a sentence; "Initiator password" does not. */
function label(path: string): string {
  const leaf = path.split('.').pop() ?? path;
  const spaced = leaf.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
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
  /** Set on the internal replay after a step-up, so a persistent refusal cannot loop. */
  retried?: boolean;
}

/**
 * The console's response to `STEP_UP_REQUIRED`.
 *
 * Nine administrative actions and the release ceremony refuse anything attempted more than
 * five minutes after sign-in, and until now the refusal was a dead end: the message asked
 * the operator to confirm their identity again and nothing anywhere could. Saving M-PESA
 * credentials was impossible in practice — nobody pastes a certificate and six other fields
 * inside five minutes — and so was releasing a payment.
 *
 * Handled here rather than at each call site so that every protected action gets it, now
 * and in future, without each one remembering to.
 */
type StepUpHandler = () => Promise<boolean>;
let stepUpHandler: StepUpHandler | null = null;

export function setStepUpHandler(handler: StepUpHandler | null): void {
  stepUpHandler = handler;
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

    /*
     * Re-confirm and replay the original request once. `options.retried` stops a loop if the
     * server still refuses — better one clear error than an endless prompt. The step-up
     * endpoints themselves are excluded, or a failure inside the prompt would re-enter it.
     */
    if (
      shape?.code === 'STEP_UP_REQUIRED' &&
      stepUpHandler &&
      !options.retried &&
      !path.startsWith('/auth/step-up')
    ) {
      const confirmed = await stepUpHandler();
      if (confirmed) return request<T>(path, { ...options, retried: true });
    }

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

/**
 * Daraja credentials as the API returns them: identifiers in the clear, secrets masked.
 *
 * The API never sends a consumer secret or security credential back, at any authority
 * level — only the last four of the consumer key, which is a public identifier and exists
 * so an administrator can tell two keys apart mid-rotation.
 */
export interface DarajaConfigurationView {
  id: string;
  environment: 'sandbox' | 'production';
  shortCode: string;
  initiatorName: string;
  commandId: string;
  consumerKeyMasked: string;
  consumerSecretMasked: string;
  securityCredentialMasked: string;
  credentialVersion: number;
  credentialRotatedAt: string | null;
  /** Days since the last rotation. Safaricom expires the portal password after 90. */
  credentialAgeDays: number | null;
  resultUrl: string | null;
  queueTimeoutUrl: string | null;
  status: string;
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
}

/** The organisation's policy limits, as stored. Amounts are cents. */
export interface OrganizationPolicyView {
  maxInstructionAmountCents: number;
  maxBatchTotalCents: number;
  maxBatchInstructions: number;
  highValueThresholdCents: number;
  coolingOffSeconds: number;
  blockingRiskBand: 'NEVER' | 'HIGH' | 'CRITICAL';
  allowL1FailedExport: boolean;
  maxExportRows: number;
  dailyDisbursementCeilingCents: number;
}

/** One row of the append-only audit trail. */
export interface AuditEventView {
  event_reference: string;
  sequence: string;
  actor_id: string | null;
  actor_level: string | null;
  event_class: string;
  action: string;
  object_type: string | null;
  object_id: string | null;
  outcome: string;
  /** The API selects occurred_at; there is no created_at on this projection. */
  occurred_at: string;
  correlation_id?: string;
  detail?: Record<string, unknown> | null;
}

/** A member of the organisation, for the user-management screen. */
export interface OrganizationUserView {
  userId: string;
  email: string;
  fullName: string;
  level: 'L1' | 'L2' | 'L3';
  status: string;
  createdAt: string;
  hasAuthenticator: boolean;
  hasAuthorizationPin: boolean;
  lastLoginAt: string | null;
}

/**
 * Upload a file as multipart/form-data.
 *
 * Separate from `request` because the body is a FormData, and setting Content-Type by hand
 * would omit the multipart boundary the browser generates — the request would arrive
 * unparseable and the API would report a missing file.
 */
async function upload<T>(path: string, file: File, field = 'file'): Promise<T> {
  const form = new FormData();
  form.append(field, file);

  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'X-Solvaren-Device': deviceId(),
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    body: form,
    credentials: 'omit',
  });

  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const shape = (payload as { error?: ApiErrorShape } | null)?.error;
    throw new ApiError(
      response.status,
      shape ?? {
        code: 'UPLOAD_FAILED',
        category: 'INTERNAL',
        message: `The server returned ${response.status}.`,
      },
    );
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
  /**
   * Which deployment this is. Rendered persistently, because an operator who cannot tell a
   * sandbox from production will eventually rehearse against real money — or release a real
   * payroll into a sandbox and believe it went out.
   */
  deployment: {
    environment: 'development' | 'staging' | 'production';
    darajaEnvironment: 'sandbox' | 'production';
    movesRealMoney: boolean;
  };
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

export interface BatchDetailView {
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
    /**
     * The commands THIS caller may issue from the batch's current state, decided by the
     * server. The console renders actions from this list rather than working them out from
     * the state and the capability payload, so the screen cannot offer a button the API
     * would refuse.
     */
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
}

export interface PageInfo {
  page: number;
  pageSize: number;
  totalRows: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

/** One thing waiting for the signed-in person, computed server-side from their own authority. */
export interface ActionQueueItem {
  kind: string;
  severity: 'info' | 'warning' | 'critical';
  title: string;
  detail: string;
  count: number;
  /** The console route that acts on it, so the notification is a door and not just a notice. */
  route: string;
  oldestAt: string | null;
}

export interface ReconciliationCaseView {
  caseId: string;
  caseReference: string;
  state: string;
  openedReason: string;
  discrepancy: boolean;
  queryAttempts: number;
  nextQueryAt: string | null;
  openedAt: string;
  resolvedAt: string | null;
  resolvedBy: string | null;
  resolutionNote: string | null;
  evidence: unknown;
  transaction: {
    transactionId: string;
    status: string;
    statusTone: string;
    failureCode: string | null;
    failureReason: string | null;
    providerResultDescription: string | null;
    mpesaReceiptNumber: string | null;
    originatorConversationId: string | null;
    conversationId: string | null;
    amountCents: number;
    recipientName: string;
    msisdn: string;
    batchId: string;
    batchReference: string;
  };
}

export interface RecipientView {
  id: string;
  fullName: string;
  msisdn: string;
  status: string;
  externalReference: string | null;
  departmentId: string | null;
  departmentName: string | null;
  createdAt: string;
  updatedAt: string;
  paymentDetailsModifiedAt: string;
}

export interface RecipientPayment {
  transactionId: string;
  status: string;
  statusTone: string;
  amountCents: number;
  /** What the number was at the time of payment, which may not be the number today. */
  paidToMsisdn: string;
  batchReference: string;
  mpesaReceiptNumber: string | null;
  failureReason: string | null;
  createdAt: string;
  completedAt: string | null;
}

export interface DepartmentView {
  id: string;
  name: string;
  code: string | null;
  status: string;
  monthlyBudgetCents: number | null;
  recipientCount: number;
}

export interface SecurityEventView {
  id: string;
  eventType: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  description: string;
  ip: string | null;
  userAgent: string | null;
  detail: unknown;
  createdAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy: string | null;
  user: { name: string; email: string | null } | null;
}

export interface LiveSessionView {
  id: string;
  userName: string;
  email: string;
  authorityLevel: string;
  issuedAt: string;
  expiresAt: string;
  lastSeenAt: string;
  webauthnVerified: boolean;
  ip: string | null;
  userAgent: string | null;
  deviceLabel: string | null;
  deviceTrust: string | null;
}

export interface TrustedDeviceView {
  id: string;
  userName: string;
  email: string;
  label: string | null;
  trustStatus: string;
  firstSeenIp: string | null;
  lastSeenIp: string | null;
  userAgent: string | null;
  registeredAt: string;
  lastActivityAt: string;
}

export interface ReportColumnView {
  key: string;
  label: string;
  format?: 'money' | 'number' | 'text' | 'timestamp';
}

export interface ReportDocumentView {
  family: string;
  title: string;
  description: string;
  periodFrom: string;
  periodTo: string;
  highlights: { label: string; value: string; hint?: string }[];
  sections: {
    title: string;
    columns: ReportColumnView[];
    rows: Record<string, string | number | null>[];
  }[];
  /** Kept separate from the computed sections — spec §12.2. */
  narrative: { text: string; source: 'AI_ADVISORY'; model: string } | null;
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

    /*
     * Enrolling the FIRST authenticator on an L2/L3 account.
     *
     * Unauthenticated by necessity — those accounts cannot hold a session until a key
     * exists — so it is gated on the password plus a single-use token issued out of band.
     * It registers one credential and issues no session: sign in normally afterwards.
     */
    enrolmentOptions: (email: string, password: string, token: string) =>
      request<{ challenge: string; user: { id: string; name: string; displayName: string } }>(
        '/auth/enrolment/options',
        { method: 'POST', body: { email, password, token } },
      ),

    completeEnrolment: (
      email: string,
      password: string,
      token: string,
      response: unknown,
      friendlyName?: string,
    ) =>
      request<{ registered: boolean; credentialId: string }>('/auth/enrolment/complete', {
        method: 'POST',
        body: { email, password, token, response, friendlyName },
      }),
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

    retry: (id: string) =>
      request<{ accepted: boolean; retrySequence: number; message: string }>(
        `/payments/transactions/${id}/retry`,
        { method: 'POST' },
      ),

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
    detail: (id: string) => request<BatchDetailView>(`/batches/${id}`),
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
    hold: (id: string, reason: string) =>
      request(`/batches/${id}/hold`, { method: 'POST', body: { reason } }),
    releaseHold: (id: string, reason?: string) =>
      request<{ state: string }>(`/batches/${id}/release-hold`, {
        method: 'POST',
        body: { reason },
      }),
    cancel: (id: string, reason: string) =>
      request<{ state: string }>(`/batches/${id}/cancel`, { method: 'POST', body: { reason } }),

    /*
     * Batch preparation, the front half of the payment path.
     *
     * These four endpoints existed from the start and nothing in the console called them,
     * so a batch could be reviewed, approved and released but never created. The empty
     * state even told the operator to upload a CSV, with no control to do it.
     */
    create: (purpose: string, paymentPeriod?: string) =>
      request<{ batchId: string; batchReference: string; state: string }>('/batches', {
        method: 'POST',
        body: { purpose, ...(paymentPeriod ? { paymentPeriod } : {}) },
      }),

    uploadCsv: (id: string, file: File) =>
      upload<{
        accepted: number;
        /** Per-row rejections, using the parser's own field names (packages/core/src/csv.ts). */
        rejected: { lineNumber: number; column: string; value: string; reason: string }[];
        duplicateWarnings: {
          msisdn: string;
          amountCents: number;
          lineNumbers: number[];
          reason: string;
        }[];
        totalAmountCents: number;
        state: string;
      }>(`/batches/${id}/upload`, file),

    validate: (id: string) =>
      request<{
        state: string;
        risk: {
          score: number;
          band: 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
          signals: RiskSignalView[];
          requiresAcknowledgement: boolean;
        };
      }>(`/batches/${id}/validate`, { method: 'POST' }),

    submit: (id: string) => request<{ state: string }>(`/batches/${id}/submit`, { method: 'POST' }),
  },

  /*
   * The signed-in person's own security settings.
   *
   * The Authorization PIN is a separate credential from the password and is what the
   * release ceremony asks for. Until this was reachable, an account created by
   * scripts/create-user.mjs had no PIN and no way to set one, so an L3 could sign in and
   * still never complete a release.
   */
  /*
   * Credential recovery (§11). No SMS, no emailed reset link: a recovery code you already
   * hold, or an executive vouching for you. A ticket authorises one act — setting a new
   * password — and is never a session.
   */
  stepUp: {
    start: (password: string) =>
      request<
        | { stage: 'CONFIRMED' }
        | {
            stage: 'WEBAUTHN_REQUIRED';
            ticket: string;
            options: PublicKeyCredentialRequestOptionsJSON;
          }
      >('/auth/step-up', { method: 'POST', body: { password } }),
    verify: (ticket: string, response: unknown) =>
      request<{ stage: 'CONFIRMED' }>('/auth/step-up/verify', {
        method: 'POST',
        body: { ticket, response },
      }),
  },

  recovery: {
    start: (email: string, code: string) =>
      request<{
        ticket: string;
        expiresInMinutes: number;
        remainingCodes: number;
        level: string;
        note: string;
      }>('/auth/recovery/start', { method: 'POST', body: { email, code } }),
    complete: (ticket: string, newPassword: string) =>
      request<{ recovered: boolean; message: string }>('/auth/recovery/complete', {
        method: 'POST',
        body: { ticket, newPassword },
      }),
  },

  account: {
    setAuthorizationPin: (currentPassword: string, pin: string) =>
      request<{ updated: boolean }>('/auth/authorization-pin', {
        method: 'POST',
        body: { currentPassword, pin },
      }),

    generateRecoveryCodes: (currentPassword: string) =>
      request<{ codes: string[] }>('/auth/recovery-codes', {
        method: 'POST',
        body: { currentPassword },
      }),

    registerKeyOptions: () =>
      request<{
        challenge: string;
        user: { id: string; name: string; displayName: string };
        rp?: { id?: string; name?: string };
        excludeCredentials?: { id: string }[];
      }>('/auth/webauthn/register/options', { method: 'POST' }),

    registerKey: (response: unknown, friendlyName?: string) =>
      request<{ registered: boolean; credentialId: string }>('/auth/webauthn/register', {
        method: 'POST',
        body: { response, friendlyName },
      }),

    signOutEverywhere: () => request<{ revoked: number }>('/auth/logout-all', { method: 'POST' }),
  },

  /*
   * Organisation administration. Every endpoint here is L3-only and enforced server-side;
   * the console hides the screens from lower levels purely to avoid showing controls that
   * would be refused.
   */
  admin: {
    daraja: {
      list: () => request<{ configurations: DarajaConfigurationView[] }>('/admin/daraja'),

      save: (config: {
        environment: 'sandbox' | 'production';
        shortCode: string;
        initiatorName: string;
        commandId: 'BusinessPayment' | 'SalaryPayment' | 'PromotionPayment';
        consumerKey: string;
        consumerSecret: string;
        initiatorPasswordOrCredential: string;
        mpesaCertificatePem?: string;
      }) => request<{ configurationId: string }>('/admin/daraja', { method: 'POST', body: config }),

      /** Proves the credentials authenticate, without moving money. */
      test: (id: string) =>
        request<{ ok: boolean; message: string; latencyMs?: number }>(`/admin/daraja/${id}/test`, {
          method: 'POST',
        }),

      enable: (id: string) =>
        request<{ status: string }>(`/admin/daraja/${id}/enable`, { method: 'POST' }),
      disable: (id: string) =>
        request<{ status: string }>(`/admin/daraja/${id}/disable`, { method: 'POST' }),
    },

    policies: {
      get: () => request<{ policy: OrganizationPolicyView }>('/admin/policies'),
      update: (patch: Partial<OrganizationPolicyView>) =>
        request<{ policy: OrganizationPolicyView }>('/admin/policies', {
          method: 'PATCH',
          body: patch,
        }),
    },

    audit: {
      list: (params: URLSearchParams) =>
        request<{ events: AuditEventView[] }>(`/admin/audit?${params.toString()}`),
      /**
       * Field names come from ChainVerification in packages/core/src/audit.ts.
       * Reading a name the API does not send yields undefined, which is falsy — and a
       * falsy "valid" reads as "your audit log has been tampered with". Getting this
       * wrong raises an incident over nothing, so it is typed from the source.
       */
      verify: () =>
        request<{
          valid: boolean;
          eventsVerified: number;
          brokenAtIndex: number | null;
          brokenEventId: string | null;
          reason: string | null;
          interpretation: string;
        }>('/admin/audit/verify', { method: 'POST' }),
    },

    users: {
      list: () => request<{ users: OrganizationUserView[] }>('/admin/users'),
      create: (input: { email: string; fullName: string; level: 'L1' | 'L2' | 'L3' }) =>
        request<{ userId: string; email: string; level: string; temporaryPassword: string }>(
          '/admin/users',
          { method: 'POST', body: input },
        ),
      setStatus: (id: string, status: 'ACTIVE' | 'DISABLED') =>
        request<{ status: string }>(`/admin/users/${id}/status`, {
          method: 'PATCH',
          body: { status },
        }),
      setLevel: (id: string, level: 'L1' | 'L2' | 'L3') =>
        request<{ level: string }>(`/admin/users/${id}/level`, {
          method: 'PATCH',
          body: { level },
        }),
      resetAccess: (id: string, reason: string, revokeAuthenticators: boolean) =>
        request<{
          email: string;
          status: string;
          oneTimePassword: string;
          authenticatorsRevoked: boolean;
          note: string;
        }>(`/admin/users/${id}/reset-access`, {
          method: 'POST',
          body: { reason, revokeAuthenticators },
        }),
      issueEnrolmentToken: (id: string) =>
        request<{ token: string; expiresAt: string }>(`/admin/users/${id}/enrolment-token`, {
          method: 'POST',
        }),
    },
  },

  /*
   * The conflict-of-interest registry. `assertNoDeclaredConflict` has barred conflicted
   * approvers at every release since the first commit, against a table nothing could write
   * to — a real control that no one could actually use.
   */
  conflicts: {
    list: () =>
      request<{
        conflicts: {
          id: string;
          userName: string;
          email: string;
          scopeType: string;
          scopeId: string | null;
          scopeName: string | null;
          reason: string;
          declaredAt: string;
          declaredBy: string | null;
          withdrawnAt: string | null;
        }[];
      }>('/admin/conflicts'),
    declare: (body: {
      userId: string;
      scopeType: 'RECIPIENT' | 'DEPARTMENT' | 'ORGANIZATION';
      scopeId?: string | null;
      reason: string;
    }) => request<{ conflict: { id: string } }>('/admin/conflicts', { method: 'POST', body }),
    withdraw: (id: string, reason: string) =>
      request<{ withdrawn: boolean }>(`/admin/conflicts/${id}/withdraw`, {
        method: 'POST',
        body: { reason },
      }),
  },

  security: {
    events: (params: URLSearchParams) =>
      request<{
        events: SecurityEventView[];
        counts: { severity: string; open: number; total: number }[];
        page: PageInfo;
      }>(`/admin/security/events?${params.toString()}`),
    acknowledge: (eventIds: string[], note?: string) =>
      request<{ acknowledged: number }>('/admin/security/events/acknowledge', {
        method: 'POST',
        body: JSON.stringify({ eventIds, note }),
      }),
    sessions: () =>
      request<{ sessions: LiveSessionView[]; devices: TrustedDeviceView[] }>(
        '/admin/security/sessions',
      ),
    revokeSession: (id: string) =>
      request<{ revoked: boolean }>(`/admin/security/sessions/${id}/revoke`, { method: 'POST' }),
    revokeDevice: (id: string) =>
      request<{ revoked: boolean }>(`/admin/security/devices/${id}/revoke`, { method: 'POST' }),
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

    actionQueue: () =>
      request<{
        items: ActionQueueItem[];
        counts: { total: number; critical: number; warning: number };
      }>('/analytics/action-queue'),
  },

  reconciliation: {
    summary: () =>
      request<{
        byState: Record<string, number>;
        outstanding: number;
        discrepancies: number;
        oldestOutstandingAt: string | null;
      }>('/reconciliation/summary'),
    list: (params: URLSearchParams) =>
      request<{ cases: ReconciliationCaseView[]; page: PageInfo }>(
        `/reconciliation/cases?${params.toString()}`,
      ),
    detail: (id: string) =>
      request<{
        case: ReconciliationCaseView;
        activity: { action: string; outcome: string; occurred_at: string; detail: unknown }[];
      }>(`/reconciliation/cases/${id}`),
    query: (id: string) =>
      request<{ accepted: boolean; message: string }>(`/reconciliation/cases/${id}/query`, {
        method: 'POST',
      }),
    resolve: (
      id: string,
      body: {
        outcome: 'FAILED' | 'MANUAL';
        failureCode?: string;
        providerReceipt?: string;
        note: string;
      },
    ) =>
      request<{ resolved: boolean; state: string; message: string }>(
        `/reconciliation/cases/${id}/resolve`,
        { method: 'POST', body: JSON.stringify(body) },
      ),
  },

  recipients: {
    list: (params: URLSearchParams) =>
      request<{ recipients: RecipientView[]; page: PageInfo }>(`/recipients?${params.toString()}`),
    detail: (id: string) =>
      request<{
        recipient: RecipientView;
        totals: { successfulPayments: number; totalPaidCents: number };
        history: RecipientPayment[];
        changes: {
          action: string;
          occurred_at: string;
          previous_state: unknown;
          new_state: unknown;
        }[];
      }>(`/recipients/${id}`),
    create: (body: {
      fullName: string;
      msisdn: string;
      departmentId?: string | null;
      externalReference?: string | null;
    }) =>
      request<{ recipient: { id: string } }>('/recipients', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    update: (
      id: string,
      body: {
        fullName?: string;
        msisdn?: string;
        departmentId?: string | null;
        externalReference?: string | null;
        status?: 'ACTIVE' | 'INACTIVE' | 'BLOCKED';
        reason?: string;
      },
    ) =>
      request<{ updated: boolean; paymentDetailsChanged: boolean; message: string }>(
        `/recipients/${id}`,
        { method: 'PATCH', body: JSON.stringify(body) },
      ),
    departments: () => request<{ departments: DepartmentView[] }>('/recipients/departments'),
    createDepartment: (body: {
      name: string;
      code?: string | null;
      monthlyBudgetCents?: number | null;
    }) =>
      request<{ department: { id: string; name: string } }>('/recipients/departments', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
  },

  /*
   * The AI layer, which had four working endpoints and nothing calling any of them.
   *
   * Every response separates computed figures from generated narrative, and the console
   * must keep them apart on screen too — §11 forbids an advisory signal being mistaken for
   * a deterministic result, and a model's guess rendered like a figure is how that happens.
   */
  ai: {
    analyseBatch: (batchId: string) =>
      request<{
        deterministicFindings: RiskSignalView[];
        riskScore: number | null;
        riskBand: string | null;
        narrative: string | null;
        degraded: boolean;
        degradedReason: string | null;
        advisoryNotice: string;
      }>(`/ai/batches/${batchId}/analyse`, { method: 'POST' }),

    explainFailure: (failureCode: string, transactionId?: string) =>
      request<{
        failureCode: string;
        failureReason: string;
        failureClass: string;
        operatorAction: string;
        transient: boolean;
        mapped: boolean;
        narrative: string | null;
        advisoryNotice: string;
      }>('/ai/failures/explain', {
        method: 'POST',
        body: { failureCode, transactionId },
      }),

    askExpenditure: (question: string) =>
      request<{
        question: string;
        data: { cycles: { period: string; totalCents: number; recipientCount: number }[] };
        narrative: string | null;
        degraded: boolean;
        advisoryNotice: string;
      }>('/ai/analysis/expenditure', { method: 'POST', body: { question } }),

    briefing: () =>
      request<{
        briefing: string | null;
        degraded: boolean;
        figures: {
          monthlyDisbursements: { period: string; totalCents: number }[];
          unresolvedReconciliationCases: number;
          topFailureReasons: { reason: string; count: number }[];
        };
        advisoryNotice: string;
      }>('/ai/briefing', { method: 'POST' }),
  },

  reports: {
    catalogue: () =>
      request<{
        reports: { family: string; title: string; description: string; permission: string }[];
      }>('/reports'),
    generate: (family: string, from: string, to: string) =>
      request<{ report: ReportDocumentView; exportReference: string; generatedAt: string }>(
        `/reports/${family}?from=${from}&to=${to}`,
      ),
    downloadCsv: (family: string, from: string, to: string) =>
      downloadCsv(`/reports/${family}?from=${from}&to=${to}&format=csv`),
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
