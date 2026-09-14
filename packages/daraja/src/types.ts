/**
 * Safaricom Daraja wire contracts.
 *
 * These types mirror the provider's payloads exactly, including its spellings — Daraja
 * really does send `Occassion` on B2C and `RecieverIdentifierType` on reversals. Correcting
 * a provider's typo in our own types is how integrations silently stop working, so the
 * misspellings are preserved and commented rather than tidied.
 */

import { z } from 'zod';

export type DarajaEnvironment = 'sandbox' | 'production';

export const DARAJA_HOSTS: Record<DarajaEnvironment, string> = {
  sandbox: 'https://sandbox.safaricom.co.ke',
  production: 'https://api.safaricom.co.ke',
};

export const DARAJA_PATHS = {
  oauth: '/oauth/v1/generate?grant_type=client_credentials',
  b2c: '/mpesa/b2c/v3/paymentrequest',
  transactionStatus: '/mpesa/transactionstatus/v1/query',
  accountBalance: '/mpesa/accountbalance/v1/query',
} as const;

/** B2C CommandIDs. All three pay registered customers only. */
export type B2cCommandId = 'BusinessPayment' | 'SalaryPayment' | 'PromotionPayment';

export interface B2cRequest {
  OriginatorConversationID: string;
  InitiatorName: string;
  SecurityCredential: string;
  CommandID: B2cCommandId;
  Amount: string;
  PartyA: string;
  PartyB: string;
  Remarks: string;
  QueueTimeOutURL: string;
  ResultURL: string;
  /** Provider's spelling. Optional, 1–100 characters. */
  Occassion?: string;
}

/** Synchronous acknowledgement returned by every asynchronous Daraja API. */
export const ackSchema = z.object({
  ConversationID: z.string().optional(),
  OriginatorConversationID: z.string().optional(),
  ResponseCode: z.string(),
  ResponseDescription: z.string().optional(),
});
export type DarajaAck = z.infer<typeof ackSchema>;

/** Gateway-level error body. */
export const gatewayErrorSchema = z.object({
  requestId: z.string().optional(),
  errorCode: z.string(),
  errorMessage: z.string().optional(),
});
export type DarajaGatewayError = z.infer<typeof gatewayErrorSchema>;

/** One `ResultParameters.ResultParameter` entry. */
export const resultParameterSchema = z.object({
  Key: z.string(),
  Value: z.union([z.string(), z.number()]).optional(),
});

/**
 * The Result envelope delivered to `ResultURL` and `QueueTimeOutURL`.
 *
 * Daraja is inconsistent here: `ResultParameter` arrives as an array for multi-value
 * results and as a bare object when there is exactly one, and `ReferenceData.ReferenceItem`
 * does the same. Both shapes are accepted and normalised in `callbacks.ts`.
 */
export const resultCallbackSchema = z.object({
  Result: z.object({
    ResultType: z.union([z.number(), z.string()]).optional(),
    ResultCode: z.union([z.number(), z.string()]),
    ResultDesc: z.string().optional(),
    OriginatorConversationID: z.string().optional(),
    ConversationID: z.string().optional(),
    TransactionID: z.string().optional(),
    ResultParameters: z
      .object({
        ResultParameter: z.union([resultParameterSchema, z.array(resultParameterSchema)]),
      })
      .optional(),
    ReferenceData: z
      .object({
        ReferenceItem: z.union([resultParameterSchema, z.array(resultParameterSchema)]),
      })
      .optional(),
  }),
});
export type DarajaResultCallback = z.infer<typeof resultCallbackSchema>;

export interface TransactionStatusRequest {
  Initiator: string;
  SecurityCredential: string;
  CommandID: 'TransactionStatusQuery';
  /** M-PESA receipt number. Supply this or `OriginalConversationID`. */
  TransactionID?: string;
  OriginalConversationID?: string;
  PartyA: string;
  /** `4` = organization shortcode. */
  IdentifierType: '1' | '2' | '4';
  ResultURL: string;
  QueueTimeOutURL: string;
  Remarks: string;
  Occasion?: string; // correctly spelled on this endpoint, unlike B2C
}

export interface AccountBalanceRequest {
  Initiator: string;
  SecurityCredential: string;
  CommandID: 'AccountBalance';
  PartyA: string;
  IdentifierType: '4';
  Remarks: string;
  QueueTimeOutURL: string;
  ResultURL: string;
}

/** Daraja transaction lifecycle statuses, as reported by the Transaction Status API. */
export type DarajaTransactionStatus =
  | 'Initiated'
  | 'Pending Authorized'
  | 'Authorized'
  | 'Completed'
  | 'Cancelled'
  | 'Declined'
  | 'Expired';

export interface OrganizationAccountBalance {
  accountType: string;
  currency: string;
  availableBalanceCents: number;
  unclearedBalanceCents: number;
  reservedBalanceCents: number;
}
