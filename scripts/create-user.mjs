/**
 * Bootstrap a SOLVAREN user directly against the database.
 *
 * There is deliberately no self-service signup — SOLVAREN is a controlled-tenancy
 * platform — so the first Level 3 account for an organisation has to be created out of
 * band. After that, L3 creates users through the console.
 *
 * The account is created PENDING_ENROLMENT and cannot sign in until:
 *   - a WebAuthn authenticator is registered (mandatory for L2/L3, spec §7.3), and
 *   - an authorization PIN is set (the schema refuses to mark an L2/L3 account ACTIVE
 *     without one).
 *
 * The generated password is printed once, to stdout, and is not stored anywhere by this
 * script. Hand it over out of band and have the user change it at first sign-in.
 *
 * Usage:
 *   node --experimental-strip-types scripts/create-user.mjs \
 *     --organization acme --email ceo@acme.test --name "Amina Njeri" --level L3
 */

import postgres from 'postgres';
import { argon2id } from 'hash-wasm';
import { webcrypto } from 'node:crypto';

const crypto = globalThis.crypto ?? webcrypto;

// Must match apps/api/src/services/crypto.ts exactly, or the hash this writes will not
// verify against the one the Worker computes.
const ARGON2_PARAMS = {
  parallelism: 1,
  iterations: 2,
  memorySize: 19_456,
  hashLength: 32,
  outputType: 'encoded',
};

function parseArguments(argv) {
  const options = {};
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '');
    const value = argv[i + 1];
    if (!key || value === undefined) continue;
    options[key] = value;
  }
  return options;
}

/**
 * Generate a passphrase from a word list rather than a random character string.
 * It has to be read aloud or typed from a note during onboarding, and a 20-character
 * mixed-symbol string gets written on a sticky note; four words do not.
 */
function generatePassphrase() {
  const words = [
    'harbour', 'lantern', 'meridian', 'quartz', 'thistle', 'vellum', 'cobalt', 'juniper',
    'saffron', 'obsidian', 'kestrel', 'marigold', 'pewter', 'tamarind', 'zephyr', 'alcove',
    'bramble', 'cardamom', 'dovetail', 'ember', 'fathom', 'granite', 'hollow', 'ivory',
  ];
  const bytes = new Uint8Array(5);
  crypto.getRandomValues(bytes);
  const chosen = Array.from(bytes.slice(0, 4), (b) => words[b % words.length]);
  return `${chosen.join('-')}-${(bytes[4] % 90) + 10}`;
}

const options = parseArguments(process.argv);
const required = ['organization', 'email', 'name', 'level'];
const missing = required.filter((key) => !options[key]);

if (missing.length > 0) {
  console.error(`Missing required arguments: ${missing.join(', ')}`);
  console.error(
    '\nUsage:\n  node --experimental-strip-types scripts/create-user.mjs \\\n' +
      '    --organization <slug> --email <email> --name "<full name>" --level <L1|L2|L3>\n',
  );
  process.exit(1);
}

if (!['L1', 'L2', 'L3'].includes(options.level)) {
  console.error(`Invalid level "${options.level}". Must be L1, L2 or L3.`);
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 1, onnotice: () => {} });

try {
  const organizations = await sql`
    SELECT id, name FROM organizations WHERE slug = ${options.organization} LIMIT 1
  `;
  const organization = organizations[0];
  if (!organization) {
    console.error(`No organization with slug "${options.organization}".`);
    process.exit(1);
  }

  const passphrase = generatePassphrase();
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const passwordHash = await argon2id({ password: passphrase, salt, ...ARGON2_PARAMS });

  const inserted = await sql`
    INSERT INTO users (organization_id, email, full_name, authority_level, password_hash, status)
    VALUES (
      ${organization.id}, ${options.email.toLowerCase()}, ${options.name},
      ${options.level}, ${passwordHash},
      -- L2 and L3 accounts cannot be ACTIVE without an authorization PIN (schema
      -- constraint users_privileged_requires_pin), so they start PENDING_ENROLMENT.
      ${options.level === 'L1' ? 'ACTIVE' : 'PENDING_ENROLMENT'}
    )
    RETURNING id, email, authority_level, status
  `;

  const user = inserted[0];

  console.log('');
  console.log('  User created');
  console.log('  ─────────────────────────────────────────────');
  console.log(`  Organization   ${organization.name} (${options.organization})`);
  console.log(`  Email          ${user.email}`);
  console.log(`  Authority      ${user.authority_level}`);
  console.log(`  Status         ${user.status}`);
  console.log('');
  console.log(`  Password       ${passphrase}`);
  console.log('');
  console.log('  This password is shown once and is not stored by this script.');
  console.log('  Hand it over out of band, not by email.');
  console.log('');

  if (options.level !== 'L1') {
    console.log('  Before this account can sign in:');
    console.log('    1. Register a WebAuthn authenticator (mandatory for L2 and L3)');
    console.log('    2. Set a SOLVAREN Authorization PIN');
    console.log('    3. An existing L3 sets the account ACTIVE');
    console.log('');
    if (options.level === 'L3') {
      console.log('  Register TWO authenticators. An L3 account is the only thing that can');
      console.log('  release a payment, and recovery from a single lost key is deliberately slow.');
      console.log('');
    }
  }
} catch (error) {
  if (error?.code === '23505') {
    console.error(`A user with email "${options.email}" already exists in this organization.`);
  } else if (error?.code === '23514') {
    console.error(`The database refused this user: ${error.constraint_name ?? error.message}`);
  } else {
    console.error(`Failed to create the user: ${error?.message ?? error}`);
  }
  process.exitCode = 1;
} finally {
  await sql.end({ timeout: 5 });
}
