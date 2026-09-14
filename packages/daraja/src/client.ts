/**
 * Daraja HTTP client.
 *
 * Responsibilities and the reasoning behind each:
 *
 *  - **Token lifecycle.** Daraja tokens last one hour. The client refreshes at 80% of the
 *    advertised lifetime and serialises concurrent refreshes through a single in-flight
 *    promise, so a burst of 200 queued payments produces one token request, not 200.
 *  - **No silent retries on payment submission.** A retry of a B2C request whose response
 *    we did not see risks paying twice. The client retries the *token* call and read-only
 *    queries, and never the payment call — ambiguity is escalated to reconciliation.
 *  - **Timeouts.** Every request is bounded by an AbortController. A Worker that hangs on a
 *    provider socket holds a payment in limbo, which is worse than a clean timeout.
 *  - **Errors carry no secrets.** Request bodies are never echoed into error messages; the
 *    credential fields would travel with them.
 */

import { providerError, type SolvarenError } from '@solvaren/core';
import {
  DARAJA_HOSTS,
  DARAJA_PATHS,
  ackSchema,
  gatewayErrorSchema,
  type B2cRequest,
  type DarajaAck,
  type DarajaEnvironment,
  type TransactionStatusRequest,
  type AccountBalanceRequest,
} from './types.js';

export interface DarajaCredentials {
  consumerKey: string;
  consumerSecret: string;
  /** Already-encrypted `SecurityCredential`, never the raw initiator password. */
  securityCredential: string;
  initiatorName: string;
  /** B2C shortcode (`PartyA`). */
  shortCode: string;
}

export interface DarajaClientOptions {
  environment: DarajaEnvironment;
  credentials: DarajaCredentials;
  /** Overridable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Injected clock, for deterministic token-expiry tests. */
  now?: () => number;
  /** Optional structured logger. Must never be given credential material. */
  onEvent?: (event: DarajaClientEvent) => void;
}

export interface DarajaClientEvent {
  type: 'token_refresh' | 'request' | 'response' | 'error';
  endpoint: string;
  httpStatus?: number;
  durationMs?: number;
  detail?: Record<string, unknown>;
}

interface CachedToken {
  accessToken: string;
  expiresAtMs: number;
}

const DEFAULT_TIMEOUT_MS = 20_000;
/** Refresh at 80% of lifetime so an in-flight payment never races an expiry. */
const TOKEN_REFRESH_RATIO = 0.8;

export class DarajaClient {
  private readonly host: string;
  private readonly options: Required<Pick<DarajaClientOptions, 'environment' | 'credentials'>> &
    DarajaClientOptions;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly now: () => number;
  private token: CachedToken | null = null;
  private inFlightToken: Promise<string> | null = null;

  constructor(options: DarajaClientOptions) {
    this.options = options;
    this.host = DARAJA_HOSTS[options.environment];
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.now = options.now ?? (() => Date.now());
  }

  /** The only GET endpoint on Daraja. Basic auth with consumer key and secret. */
  async getAccessToken(forceRefresh = false): Promise<string> {
    if (!forceRefresh && this.token && this.now() < this.token.expiresAtMs) {
      return this.token.accessToken;
    }
    // Collapse concurrent refreshes: a queue batch starting 200 payments at once must not
    // issue 200 token requests and trip Daraja's spike-arrest (500.003.02).
    if (this.inFlightToken) return this.inFlightToken;

    this.inFlightToken = this.refreshToken().finally(() => {
      this.inFlightToken = null;
    });
    return this.inFlightToken;
  }

  private async refreshToken(): Promise<string> {
    const { consumerKey, consumerSecret } = this.options.credentials;
    const basic = btoa(`${consumerKey}:${consumerSecret}`);
    const started = this.now();

    const response = await this.fetchWithTimeout(`${this.host}${DARAJA_PATHS.oauth}`, {
      method: 'GET',
      headers: { Authorization: `Basic ${basic}`, Accept: 'application/json' },
    });

    const bodyText = await response.text();
    if (!response.ok) {
      throw this.toProviderError(response.status, bodyText, 'oauth');
    }

    let parsed: { access_token?: string; expires_in?: string | number };
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      throw providerError(
        'DARAJA_TOKEN_MALFORMED',
        'M-PESA returned a token response that could not be parsed',
      );
    }
    if (!parsed.access_token) {
      throw providerError('DARAJA_TOKEN_MISSING', 'M-PESA did not return an access token');
    }

    const lifetimeSeconds = Number(parsed.expires_in ?? 3599);
    const safeLifetime =
      Number.isFinite(lifetimeSeconds) && lifetimeSeconds > 0 ? lifetimeSeconds : 3599;
    this.token = {
      accessToken: parsed.access_token,
      expiresAtMs: this.now() + safeLifetime * TOKEN_REFRESH_RATIO * 1000,
    };

    this.options.onEvent?.({
      type: 'token_refresh',
      endpoint: 'oauth',
      httpStatus: response.status,
      durationMs: this.now() - started,
      detail: { lifetimeSeconds: safeLifetime },
    });
    return this.token.accessToken;
  }

  /** Invalidate the cached token, e.g. after a credential rotation. */
  clearToken(): void {
    this.token = null;
  }

  /**
   * Submit a B2C payment.
   *
   * Deliberately not retried. If this throws, the caller cannot know whether M-PESA
   * received the request, and the payment executor moves the transaction into
   * reconciliation rather than resending (§9.3).
   */
  async sendB2cPayment(request: B2cRequest): Promise<DarajaAck> {
    return this.postJson(DARAJA_PATHS.b2c, request, 'b2c', { allowRetry: false });
  }

  /** Read-only status query. Safe to retry because it mutates nothing. */
  async queryTransactionStatus(request: TransactionStatusRequest): Promise<DarajaAck> {
    return this.postJson(DARAJA_PATHS.transactionStatus, request, 'transaction_status', {
      allowRetry: true,
    });
  }

  /** Read-only balance query (§21 executive balance panel). */
  async queryAccountBalance(request: AccountBalanceRequest): Promise<DarajaAck> {
    return this.postJson(DARAJA_PATHS.accountBalance, request, 'account_balance', {
      allowRetry: true,
    });
  }

  /**
   * Connection test for the L3 Daraja configuration screen (§9.1).
   * Proves the consumer key/secret are valid without moving any money.
   */
  async testConnection(): Promise<{ ok: boolean; message: string; latencyMs: number }> {
    const started = this.now();
    try {
      await this.getAccessToken(true);
      return {
        ok: true,
        /*
         * Deliberately narrow wording. This exchanges the consumer key and secret for a
         * token and proves nothing else: not the initiator name, not the SecurityCredential,
         * not the shortcode, and not whether the API user holds the ORG B2C API Initiator
         * role. Those are only exercised by a real payment. Reporting this as "connected"
         * would let an administrator enable a configuration that fails on every single
         * disbursement with 2001 or 21, which is exactly the trap this message avoids.
         */
        message: `Consumer key and secret accepted by the Daraja ${this.options.environment} environment. This proves the app credentials only — the initiator name, security credential, shortcode and B2C role are first exercised by a real payment.`,
        latencyMs: this.now() - started,
      };
    } catch (err) {
      const e = err as SolvarenError;
      return {
        ok: false,
        message: e.message ?? 'The connection test failed',
        latencyMs: this.now() - started,
      };
    }
  }

  private async postJson(
    path: string,
    body: unknown,
    endpoint: string,
    options: { allowRetry: boolean },
  ): Promise<DarajaAck> {
    const attempt = async (isRetry: boolean): Promise<DarajaAck> => {
      const token = await this.getAccessToken(isRetry);
      const started = this.now();

      const response = await this.fetchWithTimeout(`${this.host}${path}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
      });

      const text = await response.text();
      this.options.onEvent?.({
        type: 'response',
        endpoint,
        httpStatus: response.status,
        durationMs: this.now() - started,
      });

      if (!response.ok) {
        throw this.toProviderError(response.status, text, endpoint);
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw providerError(
          'DARAJA_RESPONSE_MALFORMED',
          `M-PESA returned an unparseable response from ${endpoint}`,
        );
      }

      const ack = ackSchema.safeParse(parsed);
      if (!ack.success) {
        // A 200 that is not an acknowledgement is usually a gateway error body.
        const gateway = gatewayErrorSchema.safeParse(parsed);
        if (gateway.success) {
          throw providerError(
            'DARAJA_GATEWAY_ERROR',
            gateway.data.errorMessage ?? `M-PESA rejected the request (${gateway.data.errorCode})`,
            { errorCode: gateway.data.errorCode, requestId: gateway.data.requestId, endpoint },
          );
        }
        throw providerError(
          'DARAJA_RESPONSE_UNEXPECTED',
          `M-PESA returned an unexpected response from ${endpoint}`,
        );
      }

      if (ack.data.ResponseCode !== '0') {
        throw providerError(
          'DARAJA_REQUEST_REJECTED',
          ack.data.ResponseDescription ??
            `M-PESA rejected the request with code ${ack.data.ResponseCode}`,
          { responseCode: ack.data.ResponseCode, endpoint },
        );
      }
      return ack.data;
    };

    try {
      return await attempt(false);
    } catch (err) {
      const e = err as SolvarenError;
      // One retry, only for read-only endpoints, and only for an expired/invalid token —
      // the single failure mode where retrying is both safe and likely to succeed.
      const tokenProblem =
        e.details?.errorCode === '404.001.03' ||
        e.details?.errorCode === '400.003.01' ||
        e.details?.errorCode === '401.002.01' ||
        e.code === 'DARAJA_TOKEN_MISSING';
      if (options.allowRetry && tokenProblem) {
        this.clearToken();
        return attempt(true);
      }
      throw err;
    }
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch (err) {
      const aborted = err instanceof Error && err.name === 'AbortError';
      throw providerError(
        aborted ? 'DARAJA_TIMEOUT' : 'DARAJA_UNREACHABLE',
        aborted
          ? `M-PESA did not respond within ${this.timeoutMs}ms`
          : 'SOLVAREN could not reach M-PESA',
        { url: url.replace(/\?.*$/, '') },
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /** Convert an HTTP error into a SolvarenError, preserving the provider's own code. */
  private toProviderError(status: number, body: string, endpoint: string): SolvarenError {
    let errorCode: string | undefined;
    let errorMessage: string | undefined;
    let requestId: string | undefined;
    try {
      const parsed = gatewayErrorSchema.safeParse(JSON.parse(body));
      if (parsed.success) {
        errorCode = parsed.data.errorCode;
        errorMessage = parsed.data.errorMessage;
        requestId = parsed.data.requestId;
      }
    } catch {
      // Non-JSON error body — Daraja occasionally returns HTML from its gateway.
    }

    return providerError(
      'DARAJA_HTTP_ERROR',
      errorMessage ?? `M-PESA returned HTTP ${status} from ${endpoint}`,
      { httpStatus: status, errorCode, requestId, endpoint },
    );
  }
}
