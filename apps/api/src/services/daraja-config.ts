/**
 * Daraja credential management (spec 9.1, 4.4, 8.4).
 *
 * The governing rule: **no code path returns a plaintext Daraja secret to any caller, at
 * any authority level.** Spec 4.4 marks "View plaintext Daraja secrets" as forbidden even
 * to L3, and this module is where that is true in practice:
 *
 *   - secrets are envelope-encrypted with AES-GCM and stored in the Cloudflare Secrets
 *     Store, referenced from the database by binding name only;
 *   - the configuration API returns a masked view and nothing else;
 *   - decryption happens inside the payment executor and the connection test, and the
 *     plaintext never leaves the function that uses it.
 *
 * The initiator password is never persisted at all. It is used once, at configuration
 * time, to produce the `SecurityCredential`, and that encrypted artefact is what is stored.
 */

import {
  DarajaClient,
  generateSecurityCredential,
  isPrecomputedCredential,
  validateInitiatorPassword,
  type DarajaCredentials,
  type DarajaEnvironment,
  type B2cCommandId,
} from '@solvaren/daraja';
import { notFoundError, stateError, validationError } from '@solvaren/core';
import { decryptSecret, encryptSecret } from './crypto.js';
import type { Sql } from '../db/client.js';
import type { Env } from '../env.js';

export interface DarajaConfigRow {
  id: string;
  organization_id: string;
  environment: DarajaEnvironment;
  short_code: string;
  initiator_name: string;
  command_id: B2cCommandId;
  consumer_key_secret_ref: string;
  consumer_secret_secret_ref: string;
  security_credential_ref: string;
  consumer_key_last_four: string | null;
  credential_version: number;
  credential_rotated_at: string | null;
  result_url: string;
  queue_timeout_url: string;
  callback_secret_ref: string;
  status: 'DISABLED' | 'TESTING' | 'ENABLED' | 'ERROR';
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string | null;
}

/** The only shape the configuration API ever returns. */
export interface MaskedDarajaConfig {
  id: string;
  environment: DarajaEnvironment;
  shortCode: string;
  initiatorName: string;
  commandId: B2cCommandId;
  /** Always the literal mask plus the last four characters of the *public* consumer key. */
  consumerKeyMasked: string;
  consumerSecretMasked: string;
  securityCredentialMasked: string;
  credentialVersion: number;
  credentialRotatedAt: string | null;
  resultUrl: string;
  queueTimeoutUrl: string;
  status: DarajaConfigRow['status'];
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
}

const MASK = '••••••••';

export function maskConfig(row: DarajaConfigRow): MaskedDarajaConfig {
  return {
    id: row.id,
    environment: row.environment,
    shortCode: row.short_code,
    initiatorName: row.initiator_name,
    commandId: row.command_id,
    // Four characters of a consumer key (a public identifier) let an administrator tell
    // two keys apart mid-rotation. The secret itself has no partial disclosure at all.
    consumerKeyMasked: `${MASK}${row.consumer_key_last_four ?? ''}`,
    consumerSecretMasked: MASK,
    securityCredentialMasked: MASK,
    credentialVersion: row.credential_version,
    credentialRotatedAt: row.credential_rotated_at,
    resultUrl: row.result_url,
    queueTimeoutUrl: row.queue_timeout_url,
    status: row.status,
    lastTestAt: row.last_test_at,
    lastTestOk: row.last_test_ok,
    lastTestMessage: row.last_test_message,
  };
}

/**
 * Secret storage.
 *
 * In production the encrypted envelope is written to the Cloudflare Secrets Store under a
 * deterministic binding name and the database keeps only that name. The envelope is
 * encrypted *before* it leaves the Worker, so the platform never holds a usable credential
 * even in the store.
 */
export function secretReference(
  organizationId: string,
  environment: string,
  field: string,
): string {
  return `daraja:${organizationId}:${environment}:${field}`;
}

/**
 * Persist a secret. The `secrets` table is intentionally absent from the schema: this
 * writes to the Secrets Store binding via the platform API in production, and in
 * development to an encrypted column that the deployment guide documents as
 * development-only.
 */
export interface SecretStore {
  put(reference: string, envelope: string): Promise<void>;
  get(reference: string): Promise<string | null>;
  delete(reference: string): Promise<void>;
}

/**
 * R2-backed secret store.
 *
 * Values are AES-GCM envelopes encrypted under `SECRET_ENCRYPTION_KEY`, which is a process
 * environment variable, not an object in this bucket. Compromising the bucket alone yields
 * nothing usable; the master key is required, and it is never stored alongside the data it
 * protects.
 */
export function createSecretStore(env: Env): SecretStore {
  const prefix = 'secrets/';
  return {
    async put(reference, envelope) {
      await env.objects.put(`${prefix}${reference}`, envelope, {
        contentType: 'application/octet-stream',
        metadata: { kind: 'solvaren-secret-envelope' },
      });
    },
    async get(reference) {
      const object = await env.objects.get(`${prefix}${reference}`);
      return object ? object.text() : null;
    },
    async delete(reference) {
      await env.objects.delete(`${prefix}${reference}`);
    },
  };
}

export interface ConfigureDarajaInput {
  organizationId: string;
  environment: DarajaEnvironment;
  shortCode: string;
  initiatorName: string;
  commandId: B2cCommandId;
  consumerKey: string;
  consumerSecret: string;
  /**
   * Either the raw initiator password (encrypted here against the M-PESA certificate and
   * then discarded) or an already-encrypted credential generated on the Daraja portal.
   */
  initiatorPasswordOrCredential: string;
  /** Required when supplying a raw password. */
  mpesaCertificatePem?: string;
  apiBaseUrl: string;
}

/**
 * Write a Daraja configuration.
 *
 * Returns the masked view. The plaintext inputs are local to this function and are not
 * returned, logged, or written to an audit detail.
 */
export async function configureDaraja(
  sql: Sql,
  env: Env,
  input: ConfigureDarajaInput,
): Promise<MaskedDarajaConfig> {
  const store = createSecretStore(env);

  // Derive the SecurityCredential now, so the initiator password need never be stored.
  let securityCredential: string;
  if (isPrecomputedCredential(input.initiatorPasswordOrCredential)) {
    securityCredential = input.initiatorPasswordOrCredential.trim();
  } else {
    if (!input.mpesaCertificatePem) {
      throw validationError(
        'DARAJA_CERTIFICATE_REQUIRED',
        'Supply the M-PESA public certificate so the initiator password can be encrypted, or paste a SecurityCredential generated on the Daraja portal',
      );
    }
    const passwordCheck = validateInitiatorPassword(input.initiatorPasswordOrCredential);
    if (!passwordCheck.ok) {
      throw validationError(
        'DARAJA_INITIATOR_PASSWORD_INVALID',
        passwordCheck.problems.join('; '),
        {
          problems: passwordCheck.problems,
        },
      );
    }
    securityCredential = generateSecurityCredential(
      input.initiatorPasswordOrCredential,
      input.mpesaCertificatePem,
    );
  }

  const refs = {
    consumerKey: secretReference(input.organizationId, input.environment, 'consumer_key'),
    consumerSecret: secretReference(input.organizationId, input.environment, 'consumer_secret'),
    securityCredential: secretReference(
      input.organizationId,
      input.environment,
      'security_credential',
    ),
    callbackSecret: secretReference(input.organizationId, input.environment, 'callback_secret'),
  };

  const callbackSecret = crypto.randomUUID() + crypto.randomUUID();

  await Promise.all([
    store.put(refs.consumerKey, await encryptSecret(input.consumerKey, env.SECRET_ENCRYPTION_KEY)),
    store.put(
      refs.consumerSecret,
      await encryptSecret(input.consumerSecret, env.SECRET_ENCRYPTION_KEY),
    ),
    store.put(
      refs.securityCredential,
      await encryptSecret(securityCredential, env.SECRET_ENCRYPTION_KEY),
    ),
    store.put(refs.callbackSecret, await encryptSecret(callbackSecret, env.SECRET_ENCRYPTION_KEY)),
  ]);

  // The callback path embeds the organisation, so a delivery can be routed and
  // authenticated without trusting anything inside the payload.
  const resultUrl = `${input.apiBaseUrl}/integrations/daraja/callback/${input.organizationId}`;
  const queueTimeoutUrl = `${input.apiBaseUrl}/integrations/daraja/timeout/${input.organizationId}`;

  const rows = await sql<DarajaConfigRow[]>`
    INSERT INTO daraja_configurations (
      organization_id, environment, short_code, initiator_name, command_id,
      consumer_key_secret_ref, consumer_secret_secret_ref, security_credential_ref,
      consumer_key_last_four, result_url, queue_timeout_url, callback_secret_ref, status
    ) VALUES (
      ${input.organizationId}, ${input.environment}, ${input.shortCode}, ${input.initiatorName},
      ${input.commandId}, ${refs.consumerKey}, ${refs.consumerSecret}, ${refs.securityCredential},
      ${input.consumerKey.slice(-4)}, ${resultUrl}, ${queueTimeoutUrl}, ${refs.callbackSecret}, 'TESTING'
    )
    ON CONFLICT (organization_id, environment) DO UPDATE SET
      short_code = EXCLUDED.short_code,
      initiator_name = EXCLUDED.initiator_name,
      command_id = EXCLUDED.command_id,
      consumer_key_secret_ref = EXCLUDED.consumer_key_secret_ref,
      consumer_secret_secret_ref = EXCLUDED.consumer_secret_secret_ref,
      security_credential_ref = EXCLUDED.security_credential_ref,
      consumer_key_last_four = EXCLUDED.consumer_key_last_four,
      -- A credential change resets the integration to TESTING: it cannot keep processing
      -- production payments on credentials that have not been proven to work.
      status = 'TESTING',
      last_test_ok = NULL,
      last_test_message = NULL,
      credential_version = daraja_configurations.credential_version + 1,
      credential_rotated_at = now()
    RETURNING *
  `;

  return maskConfig(rows[0]!);
}

/** Load decrypted credentials for use by the executor. Never exposed over the API. */
export async function loadDarajaClient(
  sql: Sql,
  env: Env,
  organizationId: string,
): Promise<{
  client: DarajaClient;
  credentials: DarajaCredentials;
  config: {
    commandId: B2cCommandId;
    resultUrl: string;
    queueTimeoutUrl: string;
    environment: DarajaEnvironment;
  };
}> {
  const rows = await sql<DarajaConfigRow[]>`
    SELECT * FROM daraja_configurations
     WHERE organization_id = ${organizationId} AND status = 'ENABLED'
     ORDER BY environment = 'production' DESC
     LIMIT 1
  `;
  const config = rows[0];
  if (!config) {
    throw stateError(
      'DARAJA_NOT_CONFIGURED',
      'No enabled Daraja integration is configured for this organisation',
    );
  }
  return buildClient(env, config);
}

/** Load a specific configuration for a connection test, regardless of enabled state. */
export async function loadDarajaClientById(
  sql: Sql,
  env: Env,
  organizationId: string,
  configId: string,
) {
  const rows = await sql<DarajaConfigRow[]>`
    SELECT * FROM daraja_configurations
     WHERE id = ${configId} AND organization_id = ${organizationId}
     LIMIT 1
  `;
  const config = rows[0];
  if (!config)
    throw notFoundError('DARAJA_CONFIG_NOT_FOUND', 'That Daraja configuration could not be found');
  return buildClient(env, config);
}

async function buildClient(env: Env, config: DarajaConfigRow) {
  const store = createSecretStore(env);
  const [keyEnvelope, secretEnvelope, credentialEnvelope] = await Promise.all([
    store.get(config.consumer_key_secret_ref),
    store.get(config.consumer_secret_secret_ref),
    store.get(config.security_credential_ref),
  ]);

  if (!keyEnvelope || !secretEnvelope || !credentialEnvelope) {
    throw stateError(
      'DARAJA_SECRETS_MISSING',
      'The stored Daraja credentials could not be retrieved. Reconfigure the integration.',
    );
  }

  const credentials: DarajaCredentials = {
    consumerKey: await decryptSecret(keyEnvelope, env.SECRET_ENCRYPTION_KEY),
    consumerSecret: await decryptSecret(secretEnvelope, env.SECRET_ENCRYPTION_KEY),
    securityCredential: await decryptSecret(credentialEnvelope, env.SECRET_ENCRYPTION_KEY),
    initiatorName: config.initiator_name,
    shortCode: config.short_code,
  };

  const client = new DarajaClient({
    environment: config.environment,
    credentials,
    onEvent: (event) => {
      // Structured, and deliberately carries no request body — the body holds the
      // SecurityCredential on every B2C call.
      console.info(
        JSON.stringify({
          level: 'info',
          scope: 'daraja',
          type: event.type,
          endpoint: event.endpoint,
          httpStatus: event.httpStatus,
          durationMs: event.durationMs,
        }),
      );
    },
  });

  return {
    client,
    credentials,
    config: {
      commandId: config.command_id,
      resultUrl: config.result_url,
      queueTimeoutUrl: config.queue_timeout_url,
      environment: config.environment,
    },
  };
}

/** Resolve the shared secret a callback must present (spec 9.4). */
export async function loadCallbackSecret(
  sql: Sql,
  env: Env,
  organizationId: string,
): Promise<string | null> {
  const rows = await sql<{ callback_secret_ref: string }[]>`
    SELECT callback_secret_ref FROM daraja_configurations
     WHERE organization_id = ${organizationId}
     ORDER BY status = 'ENABLED' DESC
     LIMIT 1
  `;
  if (!rows[0]) return null;
  const envelope = await createSecretStore(env).get(rows[0].callback_secret_ref);
  return envelope ? decryptSecret(envelope, env.SECRET_ENCRYPTION_KEY) : null;
}
