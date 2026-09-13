import { describe, it, expect, vi } from 'vitest';
import { DarajaClient, type DarajaCredentials } from './client.js';
import {
  parseB2cResult,
  parseTransactionStatusResult,
  parseAccountBalanceResult,
  parseAccountBalances,
  interpretTransactionStatus,
  parseDarajaTimestamp,
  toCents,
  normalizeResultParameters,
} from './callbacks.js';
import type { SolvarenError } from '@solvaren/core';

const credentials: DarajaCredentials = {
  consumerKey: 'ck-test',
  consumerSecret: 'cs-test',
  securityCredential: 'RC6E9WDxXR4b9X2c6z3gp0oC5Th==',
  initiatorName: 'testapi',
  shortCode: '600992',
};

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const tokenBody = { access_token: 'tok-1', expires_in: '3599' };
const ackBody = {
  ConversationID: 'AG_20240706_20106e9209f64bebd05b',
  OriginatorConversationID: '600997_Test_32et3241ed8yu',
  ResponseCode: '0',
  ResponseDescription: 'Accept the service request successfully.',
};

const b2cRequest = {
  OriginatorConversationID: '600992-INS1-ABC',
  InitiatorName: 'testapi',
  SecurityCredential: credentials.securityCredential,
  CommandID: 'BusinessPayment' as const,
  Amount: '10',
  PartyA: '600992',
  PartyB: '254705912645',
  Remarks: 'September payroll',
  QueueTimeOutURL: 'https://api.solvaren.example/integrations/daraja/timeout',
  ResultURL: 'https://api.solvaren.example/integrations/daraja/callback',
};

describe('access token lifecycle', () => {
  it('authenticates with Basic auth over GET, as Daraja requires', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(tokenBody));
    const client = new DarajaClient({ environment: 'sandbox', credentials, fetchImpl: fetchImpl });

    await client.getAccessToken();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(
      'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
    );
    expect((init as RequestInit).method).toBe('GET');
    expect((init as any).headers.Authorization).toBe(`Basic ${btoa('ck-test:cs-test')}`);
  });

  it('uses the production host when configured for production', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(tokenBody));
    const client = new DarajaClient({
      environment: 'production',
      credentials,
      fetchImpl: fetchImpl,
    });
    await client.getAccessToken();
    expect(fetchImpl.mock.calls[0]![0]).toContain('https://api.safaricom.co.ke');
  });

  it('caches the token and refreshes at 80% of its lifetime', async () => {
    let now = 1_000_000;
    const fetchImpl = vi.fn(async () => jsonResponse(tokenBody));
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl,
      now: () => now,
    });

    await client.getAccessToken();
    await client.getAccessToken();
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now += 3599 * 0.8 * 1000 - 1; // just inside the refresh window
    await client.getAccessToken();
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now += 2; // past it
    await client.getAccessToken();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('collapses concurrent refreshes into a single token request', async () => {
    // A batch releasing 200 payments at once must not trip Daraja spike arrest.
    const fetchImpl = vi.fn(async () => {
      await new Promise((r) => setTimeout(r, 5));
      return jsonResponse(tokenBody);
    });
    const client = new DarajaClient({ environment: 'sandbox', credentials, fetchImpl: fetchImpl });

    const tokens = await Promise.all(Array.from({ length: 200 }, () => client.getAccessToken()));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(new Set(tokens).size).toBe(1);
  });

  it('surfaces an authentication failure with the provider error code', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(
        { requestId: 'r1', errorCode: '401.002.01', errorMessage: 'Invalid credentials' },
        401,
      ),
    );
    const client = new DarajaClient({ environment: 'sandbox', credentials, fetchImpl: fetchImpl });
    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: 'DARAJA_HTTP_ERROR',
      details: { errorCode: '401.002.01', httpStatus: 401 },
    });
  });
});

describe('B2C submission', () => {
  const okFetch = () =>
    vi.fn(async (url: string) =>
      String(url).includes('/oauth/') ? jsonResponse(tokenBody) : jsonResponse(ackBody),
    );

  it('posts to the v3 B2C endpoint with a bearer token', async () => {
    const fetchImpl = okFetch();
    const client = new DarajaClient({
      environment: 'production',
      credentials,
      fetchImpl: fetchImpl as any,
    });
    const ack = await client.sendB2cPayment(b2cRequest);

    expect(ack.ResponseCode).toBe('0');
    const [url, init] = fetchImpl.mock.calls[1]!;
    expect(url).toBe('https://api.safaricom.co.ke/mpesa/b2c/v3/paymentrequest');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as any).headers.Authorization).toBe('Bearer tok-1');
    expect(JSON.parse((init as any).body).OriginatorConversationID).toBe('600992-INS1-ABC');
  });

  it('§9.3: NEVER retries a payment submission, even on a token error', async () => {
    // Retrying a payment whose outcome is unknown is how employees get paid twice.
    const fetchImpl = vi.fn(async (url: string) =>
      String(url).includes('/oauth/')
        ? jsonResponse(tokenBody)
        : jsonResponse(
            { requestId: 'r', errorCode: '404.001.03', errorMessage: 'Invalid Access Token' },
            404,
          ),
    );
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
    });

    await expect(client.sendB2cPayment(b2cRequest)).rejects.toMatchObject({
      code: 'DARAJA_HTTP_ERROR',
    });
    const paymentCalls = fetchImpl.mock.calls.filter((c) =>
      String(c[0]).includes('paymentrequest'),
    );
    expect(paymentCalls).toHaveLength(1);
  });

  it('rejects a non-zero ResponseCode rather than treating it as accepted', async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      String(url).includes('/oauth/')
        ? jsonResponse(tokenBody)
        : jsonResponse({ ResponseCode: '1', ResponseDescription: 'Request failed' }),
    );
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
    });
    await expect(client.sendB2cPayment(b2cRequest)).rejects.toMatchObject({
      code: 'DARAJA_REQUEST_REJECTED',
      details: { responseCode: '1' },
    });
  });

  it('recognises the duplicate-OriginatorConversationID gateway error', async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      String(url).includes('/oauth/')
        ? jsonResponse(tokenBody)
        : jsonResponse(
            {
              requestId: 'r',
              errorCode: '500.002.1001',
              errorMessage: 'Duplicate OriginatorConversationID.',
            },
            500,
          ),
    );
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
    });
    await expect(client.sendB2cPayment(b2cRequest)).rejects.toMatchObject({
      details: { errorCode: '500.002.1001' },
    });
  });

  it('times out rather than hanging a payment forever', async () => {
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/oauth/')) return jsonResponse(tokenBody);
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
      timeoutMs: 20,
    });
    await expect(client.sendB2cPayment(b2cRequest)).rejects.toMatchObject({
      code: 'DARAJA_TIMEOUT',
    });
  });

  it('never echoes credential material into an error', async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (String(url).includes('/oauth/')) return jsonResponse(tokenBody);
      throw new Error('socket hang up');
    });
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
    });
    try {
      await client.sendB2cPayment(b2cRequest);
      expect.unreachable('should have thrown');
    } catch (err) {
      const serialized = JSON.stringify((err as SolvarenError).toJSON());
      expect(serialized).not.toContain(credentials.consumerSecret);
      expect(serialized).not.toContain(credentials.securityCredential);
    }
  });
});

describe('read-only queries', () => {
  it('retries a status query once after a token rejection', async () => {
    let paymentCalls = 0;
    const fetchImpl = vi.fn(async (url: string) => {
      if (String(url).includes('/oauth/')) return jsonResponse(tokenBody);
      paymentCalls += 1;
      if (paymentCalls === 1) {
        return jsonResponse(
          { requestId: 'r', errorCode: '404.001.03', errorMessage: 'Invalid Access Token' },
          404,
        );
      }
      return jsonResponse(ackBody);
    });
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: fetchImpl as any,
    });

    const ack = await client.queryTransactionStatus({
      Initiator: 'testapi',
      SecurityCredential: credentials.securityCredential,
      CommandID: 'TransactionStatusQuery',
      TransactionID: 'NEF61H8J60',
      PartyA: '600992',
      IdentifierType: '4',
      ResultURL: 'https://x/result',
      QueueTimeOutURL: 'https://x/timeout',
      Remarks: 'reconciliation sweep',
    });
    expect(ack.ResponseCode).toBe('0');
    expect(paymentCalls).toBe(2);
  });

  it('reports a successful connection test without moving money', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(tokenBody));
    const client = new DarajaClient({ environment: 'sandbox', credentials, fetchImpl: fetchImpl });
    const result = await client.testConnection();

    expect(result.ok).toBe(true);
    expect(result.message).toMatch(/sandbox/);
    expect(fetchImpl.mock.calls.every((c) => String(c[0]).includes('/oauth/'))).toBe(true);
  });

  it('reports a failed connection test as a message, not an exception', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ errorCode: '401.002.01', errorMessage: 'bad key' }, 401),
    );
    const client = new DarajaClient({ environment: 'sandbox', credentials, fetchImpl: fetchImpl });
    const result = await client.testConnection();
    expect(result.ok).toBe(false);
    expect(result.message).toBe('bad key');
  });
});

describe('B2C result callback parsing', () => {
  const successCallback = {
    Result: {
      ResultType: 0,
      ResultCode: 0,
      ResultDesc: 'The service request is processed successfully.',
      OriginatorConversationID: '600992-INS1-ABC',
      ConversationID: 'AG_20240706_20106e9209f64bebd05b',
      TransactionID: 'SG632NMUAB',
      ResultParameters: {
        ResultParameter: [
          { Key: 'TransactionAmount', Value: 45000 },
          { Key: 'TransactionReceipt', Value: 'SG632NMUAB' },
          { Key: 'ReceiverPartyPublicName', Value: '254705912645 - Jane Doe' },
          { Key: 'TransactionCompletedDateTime', Value: '13.09.2026 11:30:45' },
          { Key: 'B2CUtilityAccountAvailableFunds', Value: 228037.0 },
          { Key: 'B2CWorkingAccountAvailableFunds', Value: 700000.0 },
          { Key: 'B2CRecipientIsRegisteredCustomer', Value: 'Y' },
          { Key: 'B2CChargesPaidAccountAvailableFunds', Value: -1540.0 },
        ],
      },
      ReferenceData: { ReferenceItem: { Key: 'QueueTimeoutURL', Value: 'https://x/timeout' } },
    },
  };

  it('extracts receipt, amount, balances and completion time', () => {
    const parsed = parseB2cResult(successCallback);
    expect(parsed.succeeded).toBe(true);
    expect(parsed.resultCode).toBe('0');
    expect(parsed.transactionReceipt).toBe('SG632NMUAB');
    expect(parsed.transactionAmountCents).toBe(45_000_00);
    expect(parsed.utilityAccountBalanceCents).toBe(228_037_00);
    expect(parsed.chargesPaidAccountBalanceCents).toBe(-1_540_00);
    expect(parsed.recipientIsRegistered).toBe(true);
    // 11:30:45 EAT is 08:30:45 UTC.
    expect(parsed.completedAt).toBe('2026-09-13T08:30:45.000Z');
  });

  it('parses a failure callback and preserves the provider description', () => {
    const parsed = parseB2cResult({
      Result: {
        ResultCode: '1',
        ResultDesc: 'The balance is insufficient for the transaction',
        OriginatorConversationID: '600992-INS9-XYZ',
        ConversationID: 'AG_1',
      },
    });
    expect(parsed.succeeded).toBe(false);
    expect(parsed.resultCode).toBe('1');
    expect(parsed.resultDescription).toBe('The balance is insufficient for the transaction');
    expect(parsed.transactionReceipt).toBeNull();
  });

  it('handles a single ResultParameter object as well as an array', () => {
    const parsed = parseB2cResult({
      Result: {
        ResultCode: 0,
        ResultDesc: 'ok',
        TransactionID: 'SG1',
        ResultParameters: { ResultParameter: { Key: 'TransactionAmount', Value: '1000' } },
      },
    });
    expect(parsed.transactionAmountCents).toBe(100_000);
  });

  it('accepts ResultCode as either a number or a string', () => {
    expect(
      parseB2cResult({ Result: { ResultCode: 0, ResultDesc: 'ok', TransactionID: 'A' } }).succeeded,
    ).toBe(true);
    expect(
      parseB2cResult({ Result: { ResultCode: '0', ResultDesc: 'ok', TransactionID: 'A' } })
        .succeeded,
    ).toBe(true);
  });

  it('rejects a structurally invalid callback rather than guessing', () => {
    expect(() => parseB2cResult({ nonsense: true })).toThrow();
    expect(() => parseB2cResult({ Result: {} })).toThrow();
  });
});

describe('transaction status parsing', () => {
  it('extracts the lifecycle status and receipt', () => {
    const parsed = parseTransactionStatusResult({
      Result: {
        ResultCode: 0,
        ResultDesc: 'The service request is processed successfully.',
        ResultParameters: {
          ResultParameter: [
            { Key: 'TransactionStatus', Value: 'Completed' },
            { Key: 'ReceiptNo', Value: 'NEF61H8J60' },
            { Key: 'Amount', Value: 45000 },
            { Key: 'InitiatedTime', Value: '20260913113045' },
            { Key: 'FinalisedTime', Value: '20260913113050' },
            { Key: 'DebitAccountType', Value: 'Utility Account' },
            { Key: 'OriginatorConversationID', Value: '600992-INS1-ABC' },
          ],
        },
      },
    });
    expect(parsed.transactionStatus).toBe('Completed');
    expect(parsed.receiptNumber).toBe('NEF61H8J60');
    expect(parsed.amountCents).toBe(45_000_00);
    expect(parsed.initiatedAt).toBe('2026-09-13T08:30:45.000Z');
    expect(parsed.debitAccountType).toBe('Utility Account');
  });

  it('maps provider lifecycle statuses onto SOLVAREN outcomes', () => {
    expect(interpretTransactionStatus('Completed')).toBe('SUCCESS');
    expect(interpretTransactionStatus('Cancelled')).toBe('FAILED');
    expect(interpretTransactionStatus('Declined')).toBe('FAILED');
    expect(interpretTransactionStatus('Expired')).toBe('FAILED');
    // Still in flight — must NOT be treated as a failure, or a paid employee shows unpaid.
    expect(interpretTransactionStatus('Initiated')).toBe('PENDING');
    expect(interpretTransactionStatus('Pending Authorized')).toBe('PENDING');
    expect(interpretTransactionStatus('Authorized')).toBe('PENDING');
    expect(interpretTransactionStatus('Something New')).toBe('UNKNOWN');
    expect(interpretTransactionStatus(null)).toBe('UNKNOWN');
  });
});

describe('account balance parsing (§21 executive panel)', () => {
  it('parses the pipe-and-ampersand delimited balance string', () => {
    const accounts = parseAccountBalances(
      'Working Account|KES|700000.00|700000.00|0.00|0.00&Float Account|KES|0.00|0.00|0.00|0.00&Utility Account|KES|228037.00|228037.00|0.00|0.00&Charges Paid Account|KES|-1540.00|-1540.00|0.00|0.00&Organization Settlement Account|KES|0.00|0.00|0.00|0.00',
    );
    expect(accounts).toHaveLength(5);
    expect(accounts[0]).toMatchObject({
      accountType: 'Working Account',
      availableBalanceCents: 700_000_00,
    });
    const utility = accounts.find((a) => a.accountType === 'Utility Account')!;
    expect(utility.availableBalanceCents).toBe(228_037_00);
    // Charges Paid always carries a negative balance — it must not be clamped to zero.
    expect(
      accounts.find((a) => a.accountType === 'Charges Paid Account')!.availableBalanceCents,
    ).toBe(-154_000);
  });

  it('parses a full balance callback', () => {
    const parsed = parseAccountBalanceResult({
      Result: {
        ResultCode: 0,
        ResultDesc: 'ok',
        ResultParameters: {
          ResultParameter: [
            { Key: 'AccountBalance', Value: 'Utility Account|KES|228037.00|228037.00|0.00|0.00' },
            { Key: 'BOCompletedTime', Value: '20260913113045' },
          ],
        },
      },
    });
    expect(parsed.accounts[0]!.availableBalanceCents).toBe(228_037_00);
    expect(parsed.completedAt).toBe('2026-09-13T08:30:45.000Z');
  });

  it('returns an empty list rather than throwing on a missing balance string', () => {
    expect(parseAccountBalances(undefined)).toEqual([]);
    expect(parseAccountBalances('')).toEqual([]);
  });
});

describe('value coercion helpers', () => {
  it('converts provider money values to cents', () => {
    expect(toCents('45000')).toBe(4_500_000);
    expect(toCents(45000.5)).toBe(4_500_050);
    expect(toCents('12,000.00')).toBe(1_200_000);
    expect(toCents(undefined)).toBeNull();
    expect(toCents('not a number')).toBeNull();
  });

  it('parses both Daraja timestamp formats and rejects junk', () => {
    expect(parseDarajaTimestamp('13.09.2026 11:30:45')).toBe('2026-09-13T08:30:45.000Z');
    expect(parseDarajaTimestamp('20260913113045')).toBe('2026-09-13T08:30:45.000Z');
    expect(parseDarajaTimestamp('nonsense')).toBeNull();
    expect(parseDarajaTimestamp(undefined)).toBeNull();
  });

  it('normalizes result parameters from both shapes and merges reference data', () => {
    const params = normalizeResultParameters({
      Result: {
        ResultCode: 0,
        ResultParameters: { ResultParameter: { Key: 'A', Value: '1' } },
        ReferenceData: { ReferenceItem: [{ Key: 'B', Value: '2' }] },
      },
    });
    expect(params).toEqual({ A: '1', B: '2' });
  });
});
