/**
 * S3 client.
 *
 * Two classes of bug matter here, and neither shows up as an obvious failure:
 *
 *  1. **Addressing the wrong object.** A key is `backups/<org>/<file>.json`. Percent-encode
 *     those slashes and every backup lands at a single flat key, overwriting the last —
 *     which looks like a working backup system right up until the restore.
 *  2. **Leaking a credential into a log.** The Authorization header carries a signature, and
 *     an error path that echoed request headers or the object body would put the payment
 *     ledger, or a usable signature, into the application log.
 *
 * Note what is and is not covered. These tests assert the *structure* of the signature —
 * the credential scope, the signed payload hash, that the signature changes with the body,
 * that it never reaches a query string — not that it equals a known-good value from AWS's
 * published test vectors. A refactor that produced a well-formed but incorrect signature
 * would pass here and fail at the provider. Closing that would mean pinning the clock and
 * checking one signature against the vector; it has not been done, and the backup
 * round-trip test is the compensating control.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { S3ObjectStore } from './s3.js';

const CONFIG = {
  endpoint: 'https://s3.example.com',
  region: 'us-east-1',
  bucket: 'solvaren-backups',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  forcePathStyle: false,
};

let requests: { url: string; method: string; headers: Record<string, string>; body?: unknown }[];
const realFetch = globalThis.fetch;

function respondWith(status: number, body = '', headers: Record<string, string> = {}) {
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    requests.push({
      url: typeof url === 'string' ? url : url instanceof URL ? url.href : url.url,
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body,
    });
    return new Response(status === 204 ? null : body, { status, headers });
  });
}

beforeEach(() => {
  requests = [];
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('S3 addressing', () => {
  it('keeps the slashes in a key as path separators, not encoded characters', async () => {
    respondWith(200);
    const store = new S3ObjectStore(CONFIG);
    await store.put('backups/org-1/2026-01-01-snapshot.json', '{}');

    // %2F here would collapse every backup onto one key.
    expect(requests[0]!.url).toBe(
      'https://solvaren-backups.s3.example.com/backups/org-1/2026-01-01-snapshot.json',
    );
    expect(requests[0]!.url).not.toContain('%2F');
  });

  it('uses virtual-host addressing by default', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v');
    expect(requests[0]!.url).toContain('https://solvaren-backups.s3.example.com/');
  });

  it('uses path-style addressing when the target requires it (MinIO)', async () => {
    respondWith(200);
    await new S3ObjectStore({ ...CONFIG, forcePathStyle: true }).put('k', 'v');
    expect(requests[0]!.url).toBe('https://s3.example.com/solvaren-backups/k');
  });

  it('encodes a character that would otherwise change the path', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('backups/a b?c', 'v');
    expect(requests[0]!.url).toContain('a%20b%3Fc');
  });
});

describe('SigV4 signing', () => {
  it('signs with a credential scope bound to the day, region and service', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v');

    const auth = requests[0]!.headers['authorization']!;
    expect(auth).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/\d{8}\/us-east-1\/s3\/aws4_request/,
    );
    expect(auth).toContain('SignedHeaders=');
    expect(auth).toMatch(/Signature=[0-9a-f]{64}$/);
  });

  it('signs over the real payload hash, not UNSIGNED-PAYLOAD', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'hello');

    // SHA-256 of "hello".
    expect(requests[0]!.headers['x-amz-content-sha256']).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });

  it('produces a different signature for a different body', async () => {
    respondWith(200);
    const store = new S3ObjectStore(CONFIG);
    await store.put('k', 'one');
    await store.put('k', 'two');
    expect(requests[0]!.headers['authorization']).not.toBe(requests[1]!.headers['authorization']);
  });

  it('never puts the credential in the query string', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v');
    expect(requests[0]!.url).not.toContain('X-Amz-Signature');
    expect(requests[0]!.url).not.toContain(CONFIG.accessKeyId);
  });

  it('does not send a host header, which fetch forbids and would break the request', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v');
    expect(Object.keys(requests[0]!.headers).map((h) => h.toLowerCase())).not.toContain('host');
  });
});

describe('operations', () => {
  it('returns null for a missing object rather than throwing', async () => {
    respondWith(404, '<Error><Code>NoSuchKey</Code></Error>');
    const store = new S3ObjectStore(CONFIG);
    expect(await store.get('absent')).toBeNull();
    expect(await store.head('absent')).toBeNull();
  });

  it('round-trips text', async () => {
    respondWith(200, '{"hello":"world"}');
    const body = await new S3ObjectStore(CONFIG).get('k');
    expect(await body!.text()).toBe('{"hello":"world"}');
    expect(body!.size).toBe(17);
  });

  it('reports size from head, which is how a backup is verified after upload', async () => {
    respondWith(200, '', { 'content-length': '4096', etag: '"abc"' });
    const meta = await new S3ObjectStore(CONFIG).head('k');
    expect(meta).toEqual({ size: 4096, etag: '"abc"' });
  });

  it('treats deleting an absent object as success', async () => {
    respondWith(404, '<Error><Code>NoSuchKey</Code></Error>');
    await expect(new S3ObjectStore(CONFIG).delete('absent')).resolves.toBeUndefined();
  });

  it('sets no-store on writes so a backup is never cached by an intermediary', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v');
    expect(requests[0]!.headers['cache-control']).toBe('no-store');
  });

  it('carries metadata as x-amz-meta headers', async () => {
    respondWith(200);
    await new S3ObjectStore(CONFIG).put('k', 'v', { metadata: { checksumSha256: 'deadbeef' } });
    expect(requests[0]!.headers['x-amz-meta-checksumsha256']).toBe('deadbeef');
  });
});

describe('failures do not leak', () => {
  it('names the S3 error code without echoing the object', async () => {
    respondWith(403, '<Error><Code>AccessDenied</Code><Message>Forbidden</Message></Error>');
    await expect(new S3ObjectStore(CONFIG).put('k', 'THE-ENTIRE-PAYMENT-LEDGER')).rejects.toThrow(
      /AccessDenied/,
    );
  });

  it('does not put the request body in the error message', async () => {
    respondWith(500, '<Error><Code>InternalError</Code></Error>');
    const store = new S3ObjectStore(CONFIG);
    const error = await store.put('k', 'SENSITIVE-LEDGER-CONTENT').catch((e: Error) => e);
    expect(String(error)).not.toContain('SENSITIVE-LEDGER-CONTENT');
  });

  it('does not put the signature in the error message', async () => {
    respondWith(500, '<Error><Code>InternalError</Code></Error>');
    const error = await new S3ObjectStore(CONFIG).put('k', 'v').catch((e: Error) => e);
    expect(String(error)).not.toContain('AWS4-HMAC-SHA256');
    expect(String(error)).not.toContain(CONFIG.secretAccessKey);
  });

  it('still reports a failure whose body cannot be read', async () => {
    respondWith(503);
    await expect(new S3ObjectStore(CONFIG).get('k')).rejects.toThrow(/HTTP 503/);
  });
});
