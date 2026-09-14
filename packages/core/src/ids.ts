/**
 * Identifier generation.
 *
 * All randomness comes from the Web Crypto API, which is available in Cloudflare Workers
 * and in Node >= 18. `Math.random` is never used for anything that reaches a security or
 * idempotency boundary.
 */

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // no I, L, O, U — unambiguous when read aloud

/** Cryptographically random Crockford-base32 token of `length` characters. */
export function randomToken(length = 26): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < length; i++) out += CROCKFORD[bytes[i]! % CROCKFORD.length];
  return out;
}

/** RFC 4122 v4 UUID. */
export function uuid(): string {
  return crypto.randomUUID();
}

/**
 * Human-facing reference, e.g. `SLV-2026-7F3KQ9ZB`. Used for batch references, backup
 * attempt ids and export ids — things operators read out to each other.
 */
export function reference(prefix: string, year = new Date().getUTCFullYear()): string {
  return `${prefix}-${year}-${randomToken(8)}`;
}

/**
 * Daraja `OriginatorConversationID`. Safaricom rejects duplicates (`500.002.1001`), so
 * this must be globally unique per *submission attempt*, while remaining traceable back to
 * the instruction. Format: `<shortcode>-<instructionId short>-<random>`; Daraja permits up
 * to 128 characters.
 */
export function originatorConversationId(shortCode: string, instructionId: string): string {
  const short = instructionId.replace(/-/g, '').slice(0, 12).toUpperCase();
  return `${shortCode}-${short}-${randomToken(12)}`;
}

/** Correlation id threaded through request -> queue -> provider -> callback -> audit. */
export function correlationId(): string {
  return `cor_${randomToken(20)}`;
}
