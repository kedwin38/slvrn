/**
 * Issue a single-use token that lets one account enrol its FIRST authenticator.
 *
 * Why this exists: L2 and L3 cannot hold a session without a verified WebAuthn assertion,
 * and the endpoint that enrols an authenticator requires a session. Without a way in, the
 * first privileged account can never sign in — and L3 is the only level that can release a
 * payment.
 *
 * Why it is a script and not a button: the token is the second factor for enrolment. The
 * first is the account password. Requiring both means a stolen password cannot be turned
 * into an L3 who moves money, which is the whole point of the WebAuthn requirement. Running
 * this needs database access, so the person issuing it is already trusted with far more.
 *
 * The token is shown ONCE. Only its SHA-256 hash is stored, so it cannot be recovered from
 * the database, by anyone, including whoever runs this.
 *
 * Usage:
 *   node scripts/issue-enrolment-token.mjs --email ceo@acme.example
 *   node scripts/issue-enrolment-token.mjs --email ceo@acme.example --minutes 60
 *   node scripts/issue-enrolment-token.mjs --email ceo@acme.example --revoke
 */

import postgres from 'postgres';
import { webcrypto } from 'node:crypto';
import { createHash, randomBytes } from 'node:crypto';

const crypto = globalThis.crypto ?? webcrypto;
void crypto;

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? undefined : args[i + 1];
};

const email = flag('email')?.trim().toLowerCase();
const minutes = Number(flag('minutes') ?? 30);
const revoke = args.includes('--revoke');

if (!email) {
  console.error('');
  console.error('  Usage: node scripts/issue-enrolment-token.mjs --email <address>');
  console.error('         [--minutes <n>]   how long the token is valid (default 30)');
  console.error('         [--revoke]        cancel any outstanding token instead');
  console.error('');
  process.exit(1);
}

if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
  console.error('--minutes must be a whole number of minutes between 1 and 1440.');
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

function sslOption(url) {
  try {
    const { hostname, searchParams } = new URL(url);
    const sslmode = searchParams.get('sslmode');
    if (sslmode === 'disable') return {};
    if (sslmode && sslmode !== 'prefer') return { ssl: { rejectUnauthorized: false } };
    if (hostname === 'localhost' || hostname === '127.0.0.1') return {};
    if (hostname.endsWith('.railway.internal')) return {};
    return { ssl: { rejectUnauthorized: false } };
  } catch {
    return {};
  }
}

const sql = postgres(databaseUrl, { max: 1, onnotice: () => {}, ...sslOption(databaseUrl) });

/** Base64url, so the token survives being pasted into a form or a terminal unchanged. */
function generateToken() {
  return randomBytes(32).toString('base64url');
}

const sha256Hex = (value) => createHash('sha256').update(value).digest('hex');

try {
  const users = await sql`
    SELECT u.id, u.organization_id, u.email, u.full_name, u.authority_level, u.status
      FROM users u JOIN organizations o ON o.id = u.organization_id
     WHERE u.email = ${email} AND o.status = 'ACTIVE'
     LIMIT 1
  `;
  const user = users[0];
  if (!user) {
    console.error(`No active user with email "${email}".`);
    process.exit(1);
  }

  if (revoke) {
    const removed = await sql`
      DELETE FROM enrolment_tokens WHERE user_id = ${user.id} AND consumed_at IS NULL
      RETURNING id
    `;
    console.log(`  Revoked ${removed.length} outstanding enrolment token(s) for ${email}.`);
    process.exit(0);
  }

  // An account that already has a working authenticator must not be enrolable this way:
  // adding a key to a live account is an authenticated action, and letting a token do it
  // would make this an account-takeover primitive rather than a bootstrap.
  const credentials = await sql`
    SELECT 1 FROM webauthn_credentials WHERE user_id = ${user.id} AND status = 'ACTIVE' LIMIT 1
  `;
  if (credentials.length > 0) {
    console.error('');
    console.error(`  ${email} already has an active authenticator.`);
    console.error('');
    console.error('  Enrolment tokens exist only to register the FIRST key on an account that');
    console.error('  has none. To add another key, sign in and enrol it from the console; to');
    console.error('  replace a lost one, revoke the old credential first.');
    console.error('');
    process.exit(1);
  }

  const token = generateToken();

  // Replace rather than accumulate: a token glimpsed over a shoulder and a token issued
  // five minutes later must not both work.
  await sql.begin(async (tx) => {
    await tx`DELETE FROM enrolment_tokens WHERE user_id = ${user.id} AND consumed_at IS NULL`;
    await tx`
      INSERT INTO enrolment_tokens (organization_id, user_id, token_hash, expires_at)
      VALUES (${user.organization_id}, ${user.id}, ${sha256Hex(token)},
              now() + (${minutes} * interval '1 minute'))
    `;
  });

  console.log('');
  console.log('  Enrolment token issued');
  console.log('  ─────────────────────────────────────────────────────────────');
  console.log(`  Account        ${user.email}`);
  console.log(`  Name           ${user.full_name}`);
  console.log(`  Authority      ${user.authority_level}`);
  console.log(`  Status         ${user.status}`);
  console.log(`  Valid for      ${minutes} minute(s)`);
  console.log('');
  console.log(`  TOKEN          ${token}`);
  console.log('');
  console.log('  Shown once. Only its hash is stored, so it cannot be recovered.');
  console.log('');
  console.log('  To use it: open the console, choose "Enrol a security key" on the sign-in');
  console.log('  page, and supply the email, password and this token. It registers one');
  console.log('  authenticator and is then spent. It never issues a session by itself —');
  console.log('  sign in normally afterwards with the password and the new key.');
  console.log('');
  console.log('  Hand it over out of band. Anyone holding both this token and the account');
  console.log('  password can enrol their own authenticator on this account.');
  console.log('');
} catch (error) {
  console.error('');
  console.error(`  Failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  await sql.end({ timeout: 10 });
}
