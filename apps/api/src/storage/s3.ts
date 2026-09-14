/**
 * S3-compatible object storage.
 *
 * Implements the `ObjectStore` interface over the S3 REST API using AWS Signature Version 4,
 * signed with Web Crypto. There is no AWS SDK dependency here, and that is deliberate:
 * `@aws-sdk/client-s3` and its transitive tree is tens of megabytes for four operations, and
 * every megabyte is something that ships in the image and has to be patched when it has a
 * CVE. SigV4 is a page of well-specified code, and it is exercised by the backup
 * round-trip test rather than trusted.
 *
 * Works against any S3-compatible target — Cloudflare R2, Backblaze B2, AWS S3, or MinIO
 * running alongside the app. Spec BAK-001 already required an S3-compatible target, so
 * this is the specification's own shape.
 *
 * What this module deliberately does NOT do: it never logs a URL with a signature in it,
 * never puts credentials in a query string (they go in the Authorization header), and
 * never includes the object body in an error message — a backup body is the entire
 * payment ledger.
 */

import type { ObjectStore, ObjectPutOptions, ObjectBody, ObjectMetadata } from '../env.js';

export interface S3Config {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** MinIO and some clones require path-style addressing rather than virtual-host style. */
  forcePathStyle: boolean;
}

const UNSIGNED_PAYLOAD_HEADERS = new Set([
  'host',
  'content-type',
  'x-amz-content-sha256',
  'x-amz-date',
]);

export class S3ObjectStore implements ObjectStore {
  constructor(private readonly config: S3Config) {}

  async put(key: string, body: string | Uint8Array, options: ObjectPutOptions = {}): Promise<void> {
    const payload = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    const headers: Record<string, string> = {
      'content-type': options.contentType ?? 'application/octet-stream',
      // Backups and secret envelopes must never be cached by an intermediary.
      'cache-control': 'no-store',
    };
    // S3 user metadata travels as x-amz-meta-* headers. Values must be ASCII; anything we
    // store here is a reference, a checksum or an id, so encoding is a guard rather than a
    // transformation.
    for (const [name, value] of Object.entries(options.metadata ?? {})) {
      headers[`x-amz-meta-${name.toLowerCase()}`] = encodeURIComponent(value);
    }

    const response = await this.send('PUT', key, headers, payload);
    if (!response.ok) {
      throw new Error(await this.describeFailure('store', key, response));
    }
  }

  async get(key: string): Promise<ObjectBody | null> {
    const response = await this.send('GET', key, {}, undefined);
    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(await this.describeFailure('read', key, response));
    }

    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    return {
      size: bytes.byteLength,
      async text() {
        return new TextDecoder().decode(bytes);
      },
      async bytes() {
        return bytes;
      },
    };
  }

  async head(key: string): Promise<ObjectMetadata | null> {
    const response = await this.send('HEAD', key, {}, undefined);
    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(await this.describeFailure('stat', key, response));
    }
    const length = response.headers.get('content-length');
    return {
      size: length ? Number(length) : 0,
      etag: response.headers.get('etag'),
    };
  }

  async delete(key: string): Promise<void> {
    const response = await this.send('DELETE', key, {}, undefined);
    // S3 returns 204 for a successful delete and, for most implementations, also for a key
    // that was already absent. Both are the outcome the caller wanted.
    if (!response.ok && response.status !== 404) {
      throw new Error(await this.describeFailure('delete', key, response));
    }
  }

  /**
   * Build, sign and issue one request.
   *
   * Every request is signed over its exact payload hash rather than UNSIGNED-PAYLOAD, so a
   * body altered in transit fails the signature check at the storage provider instead of
   * being written.
   */
  private async send(
    method: string,
    key: string,
    extraHeaders: Record<string, string>,
    payload: Uint8Array | undefined,
  ): Promise<Response> {
    const url = this.urlFor(key);
    const payloadHash = await sha256Hex(payload ?? new Uint8Array());
    const now = new Date();
    const amzDate = toAmzDate(now);
    const dateStamp = amzDate.slice(0, 8);

    const headers: Record<string, string> = {
      ...extraHeaders,
      host: url.host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    };

    const signedHeaderNames = Object.keys(headers)
      .map((h) => h.toLowerCase())
      .filter((h) => UNSIGNED_PAYLOAD_HEADERS.has(h) || h.startsWith('x-amz-'))
      .sort();

    const canonicalHeaders = signedHeaderNames
      .map((name) => `${name}:${(headers[name] ?? '').trim()}\n`)
      .join('');
    const signedHeaders = signedHeaderNames.join(';');

    const canonicalRequest = [
      method,
      url.pathname,
      url.search.replace(/^\?/, ''),
      canonicalHeaders,
      signedHeaders,
      payloadHash,
    ].join('\n');

    const scope = `${dateStamp}/${this.config.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      scope,
      await sha256Hex(new TextEncoder().encode(canonicalRequest)),
    ].join('\n');

    const signingKey = await deriveSigningKey(
      this.config.secretAccessKey,
      dateStamp,
      this.config.region,
    );
    const signature = toHex(await hmac(signingKey, stringToSign));

    headers['authorization'] =
      `AWS4-HMAC-SHA256 Credential=${this.config.accessKeyId}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // `host` is set by fetch itself and rejected as a forbidden header if passed through.
    const { host: _host, ...sendable } = headers;

    return fetch(url, {
      method,
      headers: sendable,
      ...(payload && method !== 'GET' && method !== 'HEAD' ? { body: payload } : {}),
    });
  }

  private urlFor(key: string): URL {
    const base = new URL(this.config.endpoint);
    // Each path segment is encoded independently: a key legitimately contains slashes
    // (`backups/<org>/<file>.json`) and encoding those would address the wrong object.
    const encodedKey = key.split('/').map(encodeURIComponent).join('/');

    if (this.config.forcePathStyle) {
      base.pathname = `/${this.config.bucket}/${encodedKey}`;
      return base;
    }
    // Virtual-host style: the bucket becomes the leading label of the hostname.
    base.hostname = `${this.config.bucket}.${base.hostname}`;
    base.pathname = `/${encodedKey}`;
    return base;
  }

  /**
   * Describe a failure without leaking the object.
   *
   * S3 error bodies are small XML documents naming the error code, which is exactly what an
   * operator needs. The object body is never included, and neither is any header — a signed
   * URL or an Authorization value in a log is a credential in a log.
   */
  private async describeFailure(action: string, key: string, response: Response): Promise<string> {
    let detail = '';
    try {
      const text = await response.text();
      const code = /<Code>([^<]+)<\/Code>/.exec(text)?.[1];
      const messageText = /<Message>([^<]+)<\/Message>/.exec(text)?.[1];
      detail = code ? ` (${code}${messageText ? `: ${messageText}` : ''})` : '';
    } catch {
      /* A failure with an unreadable body is still a failure worth reporting. */
    }
    return `Could not ${action} object ${key}: HTTP ${response.status}${detail}`;
  }
}

// ---------------------------------------------------------------------------
// SigV4 primitives
// ---------------------------------------------------------------------------

function toAmzDate(date: Date): string {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

function toHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', data));
}

async function hmac(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
}

/**
 * Derive the SigV4 signing key.
 *
 * Four chained HMACs, each narrowing the key's scope: secret → date → region → service →
 * request type. The result is only valid for one day, one region and S3, which is what
 * limits the damage if a signature is ever captured.
 */
async function deriveSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
): Promise<ArrayBuffer> {
  const kDate = await hmac(new TextEncoder().encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, 's3');
  return hmac(kService, 'aws4_request');
}
