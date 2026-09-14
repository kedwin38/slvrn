/**
 * Seed demo accounts with known, fixed passwords.
 *
 * This exists so the console can be opened and looked at without running the bootstrap
 * script and capturing a one-time passphrase. The passwords below are published in the
 * README and in this file: they are not secret and are not meant to be.
 *
 * ──────────────────────────────────────────────────────────────────────────────
 * WHY THIS REFUSES TO RUN IN PRODUCTION
 *
 * Known credentials on a system that disburses money is the single most reliable way for
 * one to be emptied. Not "a risk to weigh" — the actual, common, first thing an attacker
 * tries against any deployment whose source is public, and this repository is.
 *
 * So the account set is real and complete, and the guard is the environment: this script
 * exits non-zero when ENVIRONMENT=production. That keeps the convenience for staging and
 * local work, where it is genuinely useful, and keeps it out of the one place where it
 * would be indefensible.
 *
 * Overriding the guard takes an explicit I_UNDERSTAND_THIS_IS_INSECURE=yes, which is
 * deliberately awkward to type and impossible to set by accident.
 * ──────────────────────────────────────────────────────────────────────────────
 *
 * WHAT ACTUALLY SIGNS IN, AND WHAT DOES NOT
 *
 * L1 works immediately with its password. That is the account to use for a look around.
 *
 * L2 and L3 do NOT, and no seed can change that: `issueSession` refuses a session for any
 * account above L1 without a verified WebAuthn assertion (services/auth.ts). It is a gate
 * in the application, not a column in the database, so seeding cannot bypass it. Both are
 * seeded ACTIVE with a PIN set, so the moment a security key is enrolled they work — but
 * until then the password alone gets you a refusal, by design.
 *
 * Usage:
 *   node scripts/seed-demo.mjs                 # create or refresh the demo accounts
 *   node scripts/seed-demo.mjs --remove        # delete them again
 */

import postgres from 'postgres';
import { argon2id } from 'hash-wasm';
import { webcrypto } from 'node:crypto';

const crypto = globalThis.crypto ?? webcrypto;

// Must match apps/api/src/services/crypto.ts exactly, or these hashes will not verify.
const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 19_456,
  hashLength: 32,
  outputType: 'encoded',
};

const ORGANIZATION = { slug: 'demo', name: 'Demo Organisation' };

/**
 * The demo accounts.
 *
 * Passwords are long enough to survive the login form's own length checks and obvious
 * enough that nobody mistakes one for a real credential. The PIN is what the release
 * ceremony asks for; it is a separate credential from the password by design (§7.4).
 */
const ACCOUNTS = [
  {
    email: 'l1@demo.solvaren',
    name: 'Demo Operations Officer',
    level: 'L1',
    password: 'demo-L1-operations-2026',
    pin: null,
  },
  {
    email: 'l2@demo.solvaren',
    name: 'Demo Finance Controller',
    level: 'L2',
    password: 'demo-L2-controller-2026',
    pin: '246813',
  },
  {
    email: 'l3@demo.solvaren',
    name: 'Demo Executive Authority',
    level: 'L3',
    password: 'demo-L3-executive-2026',
    pin: '135792',
  },
];

const remove = process.argv.includes('--remove');

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

// ---- The guard -------------------------------------------------------------
const environment = (process.env.ENVIRONMENT ?? 'development').trim();
const override = process.env.I_UNDERSTAND_THIS_IS_INSECURE === 'yes';

if (environment === 'production' && !override) {
  console.error('');
  console.error('  Refusing to seed demo accounts: ENVIRONMENT=production.');
  console.error('');
  console.error('  These passwords are published in the repository. Creating them on a');
  console.error('  production deployment would hand anyone who reads the source a working');
  console.error('  login to a system that moves money.');
  console.error('');
  console.error('  If this really is what you want, set:');
  console.error('      I_UNDERSTAND_THIS_IS_INSECURE=yes');
  console.error('');
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

async function hash(value) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return argon2id({ password: value, salt, ...ARGON2_PARAMS });
}

try {
  if (remove) {
    const deleted = await sql`
      DELETE FROM users
       WHERE email = ANY(
         SELECT jsonb_array_elements_text(${sql.json(ACCOUNTS.map((a) => a.email))}::jsonb)
       )
      RETURNING email
    `;
    console.log(`  Removed ${deleted.length} demo account(s).`);
    // The organisation is left in place: it may own batches or audit events by now, and
    // audit_events cannot be deleted by anyone (§4.3).
    process.exit(0);
  }

  const organizations = await sql`
    INSERT INTO organizations (name, slug)
    VALUES (${ORGANIZATION.name}, ${ORGANIZATION.slug})
    ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
    RETURNING id
  `;
  const organizationId = organizations[0].id;

  await sql`
    INSERT INTO policies (organization_id) VALUES (${organizationId})
    ON CONFLICT (organization_id) DO NOTHING
  `;

  for (const account of ACCOUNTS) {
    const passwordHash = await hash(account.password);
    const pinHash = account.pin ? await hash(account.pin) : null;

    // ACTIVE for every level: users_privileged_requires_pin is satisfied because L2 and L3
    // both carry a PIN here. The WebAuthn requirement is enforced in the application at
    // session issue, not by this row, so these accounts are correct-but-not-yet-usable
    // above L1 rather than wrongly marked.
    await sql`
      INSERT INTO users (
        organization_id, email, full_name, authority_level,
        password_hash, authorization_pin_hash, authorization_pin_updated_at, status
      ) VALUES (
        ${organizationId}, ${account.email}, ${account.name}, ${account.level},
        ${passwordHash}, ${pinHash}, ${pinHash ? new Date() : null}, 'ACTIVE'
      )
      ON CONFLICT (organization_id, email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            authorization_pin_hash = EXCLUDED.authorization_pin_hash,
            authorization_pin_updated_at = EXCLUDED.authorization_pin_updated_at,
            full_name = EXCLUDED.full_name,
            authority_level = EXCLUDED.authority_level,
            status = 'ACTIVE'
    `;
  }

  console.log('');
  console.log('  Demo accounts seeded');
  console.log('  ─────────────────────────────────────────────────────────────');
  console.log(`  Organisation   ${ORGANIZATION.name} (${ORGANIZATION.slug})`);
  console.log(`  Environment    ${environment}`);
  console.log('');
  for (const account of ACCOUNTS) {
    console.log(`  ${account.level}  ${account.email}`);
    console.log(`      password   ${account.password}`);
    if (account.pin) console.log(`      PIN        ${account.pin}`);
    console.log(
      account.level === 'L1'
        ? '      signs in   yes, with the password alone'
        : '      signs in   NOT until a security key is enrolled (WebAuthn is required above L1)',
    );
    console.log('');
  }
  console.log('  These credentials are published in the repository. Never seed them on a');
  console.log('  deployment that holds real payment data.');
  console.log('');
} catch (error) {
  console.error('');
  console.error(`  Seeding failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  await sql.end({ timeout: 10 });
}
