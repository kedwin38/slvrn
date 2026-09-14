/**
 * Prove a deployed SOLVAREN actually works, from inside the deployment.
 *
 * A deploy that reports SUCCESS has proved that a container started. It has not proved that
 * anybody can sign in. The failure that prompted this script passed every check Railway
 * makes — both services green, the API answering /health — while the console could not
 * reach the API at all, because its Content-Security-Policy pinned connect-src to 'self'
 * and the API is a different origin. The browser refused each request before sending it, so
 * there was nothing in the API's logs and no CORS error either.
 *
 * So the checks here are the ones that would have caught it: not "is the process up" but
 * "can the console's own policy reach the API", and "does a real credential produce a real
 * session".
 *
 * Run it anywhere:
 *   node scripts/deploy-check.mjs                     # uses API_BASE_URL and APP_ORIGIN
 *   node scripts/deploy-check.mjs --strict            # exit non-zero on failure (CI)
 *   node scripts/deploy-check.mjs --demo              # also exercise a real sign-in
 *
 * It is wired as a pre-deploy command, where it runs against the deployment that is still
 * live. It exits 0 there even when a check fails: a smoke test that can block every future
 * deploy is a smoke test that gets deleted the first time it is wrong. Pass --strict when
 * you want the exit code to mean something.
 */

import { spawn } from 'node:child_process';

const strict = process.argv.includes('--strict');
const demo = process.argv.includes('--demo') || process.env.CHECK_DEMO_LOGIN === 'true';

const apiBase = (process.env.API_BASE_URL ?? '').replace(/\/$/, '');
const appOrigin = (process.env.APP_ORIGIN ?? '').replace(/\/$/, '');

const results = [];
const record = (ok, name, detail) => {
  results.push({ ok, name, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
};

async function fetchWithTimeout(url, options = {}, ms = 15_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Run the demo seed as a child process, so its own production guard still applies. */
async function seedDemoAccounts() {
  console.log('');
  console.log('Seeding demo accounts (SEED_DEMO_ACCOUNTS=true)');
  await new Promise((resolve) => {
    const child = spawn(process.execPath, ['scripts/seed-demo.mjs'], { stdio: 'inherit' });
    child.on('close', (code) => {
      if (code !== 0) {
        console.log(`  seed-demo exited ${code} — see its output above for the reason.`);
      }
      resolve();
    });
    child.on('error', (error) => {
      console.log(`  could not run seed-demo: ${error.message}`);
      resolve();
    });
  });
}

async function main() {
  console.log('');
  console.log('SOLVAREN deployment check');
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`  API      ${apiBase || '(API_BASE_URL not set)'}`);
  console.log(`  Console  ${appOrigin || '(APP_ORIGIN not set)'}`);
  console.log('');

  if (process.env.SEED_DEMO_ACCOUNTS === 'true') await seedDemoAccounts();

  console.log('');
  if (!apiBase) {
    record(false, 'API_BASE_URL is set', 'cannot check anything without it');
  } else {
    // --- The API is alive and has a usable database -------------------------
    try {
      const res = await fetchWithTimeout(`${apiBase}/health`);
      const body = await res.text();
      record(res.ok && body.includes('"ok"'), 'GET /health', `${res.status} ${body.slice(0, 80)}`);
    } catch (error) {
      record(false, 'GET /health', error.message);
    }

    try {
      const res = await fetchWithTimeout(`${apiBase}/health/ready`);
      const body = await res.text();
      record(res.ok, 'GET /health/ready', `${res.status} ${body.slice(0, 120)}`);
    } catch (error) {
      record(false, 'GET /health/ready', error.message);
    }

    // --- Authentication is actually enforced --------------------------------
    try {
      const res = await fetchWithTimeout(`${apiBase}/batches`);
      record(res.status === 401, 'GET /batches without a session is refused', `${res.status}`);
    } catch (error) {
      record(false, 'GET /batches without a session is refused', error.message);
    }

    // --- CORS lets the console through, and only the console ----------------
    if (appOrigin) {
      try {
        const res = await fetchWithTimeout(`${apiBase}/auth/login`, {
          method: 'OPTIONS',
          headers: {
            Origin: appOrigin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'content-type',
          },
        });
        const allowed = res.headers.get('access-control-allow-origin');
        record(
          allowed === appOrigin,
          'CORS preflight allows the console origin',
          `allow-origin: ${allowed ?? '(none)'}`,
        );
      } catch (error) {
        record(false, 'CORS preflight allows the console origin', error.message);
      }

      try {
        const res = await fetchWithTimeout(`${apiBase}/auth/login`, {
          method: 'OPTIONS',
          headers: {
            Origin: 'https://not-the-console.example',
            'Access-Control-Request-Method': 'POST',
          },
        });
        const allowed = res.headers.get('access-control-allow-origin');
        record(
          allowed !== 'https://not-the-console.example' && allowed !== '*',
          'CORS refuses an unknown origin',
          `allow-origin: ${allowed ?? '(none)'}`,
        );
      } catch (error) {
        record(false, 'CORS refuses an unknown origin', error.message);
      }
    }
  }

  // --- The console's own policy permits talking to the API ------------------
  if (!appOrigin) {
    record(false, 'APP_ORIGIN is set', 'cannot check the console without it');
  } else {
    try {
      const res = await fetchWithTimeout(appOrigin);
      const html = await res.text();
      const meta = html
        .replace(/\n/g, ' ')
        .match(/<meta\b[^>]*http-equiv="Content-Security-Policy"[^>]*content="([^"]*)"/i);
      const connectSrc = meta ? (meta[1].match(/connect-src[^;]*/) ?? [''])[0] : '';

      record(res.ok, 'GET the console', `${res.status}`);

      if (!apiBase) {
        record(false, 'the console CSP permits the API origin', 'API_BASE_URL not set');
      } else {
        const apiOrigin = new URL(apiBase).origin;
        record(
          connectSrc.includes(apiOrigin),
          'the console CSP permits the API origin',
          connectSrc || '(no connect-src found)',
        );
      }
    } catch (error) {
      record(false, 'GET the console', error.message);
    }
  }

  // --- A real credential produces a real session ---------------------------
  if (demo && apiBase) {
    const login = (email, password) =>
      fetchWithTimeout(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email, password, deviceId: 'deploy-check' }),
      });

    try {
      const res = await login('l1@demo.solvaren', 'demo-L1-operations-2026');
      const body = await res.json().catch(() => null);
      record(
        res.ok && body?.stage === 'AUTHENTICATED' && typeof body?.token === 'string',
        'L1 demo account signs in',
        `${res.status} stage=${body?.stage ?? '(none)'}`,
      );

      // Prove the session token is actually accepted, not merely issued.
      if (body?.token) {
        const session = await fetchWithTimeout(`${apiBase}/auth/session`, {
          headers: { Authorization: `Bearer ${body.token}`, Accept: 'application/json' },
        });
        const who = await session.json().catch(() => null);
        record(
          session.ok && who?.user?.email === 'l1@demo.solvaren',
          'the issued session token is accepted',
          `${session.status} ${who?.user?.level ?? ''}`,
        );
      }
    } catch (error) {
      record(false, 'L1 demo account signs in', error.message);
    }

    // Above L1, a password alone must not be enough. This is the separation-of-duties
    // guarantee the whole system rests on, so it is checked against the deployment rather
    // than trusted because a unit test passed.
    try {
      const res = await login('l3@demo.solvaren', 'demo-L3-executive-2026');
      const body = await res.json().catch(() => null);
      const authenticated = body?.stage === 'AUTHENTICATED';
      record(
        !authenticated,
        'L3 is NOT signed in by a password alone',
        `${res.status} stage=${body?.stage ?? body?.error?.code ?? '(none)'}`,
      );
    } catch (error) {
      record(false, 'L3 is NOT signed in by a password alone', error.message);
    }

    try {
      const res = await login('l1@demo.solvaren', 'not-the-password');
      const body = await res.json().catch(() => null);
      record(
        body?.stage !== 'AUTHENTICATED',
        'a wrong password is refused',
        `${res.status} ${body?.error?.code ?? ''}`,
      );
    } catch (error) {
      record(false, 'a wrong password is refused', error.message);
    }
  }

  const failed = results.filter((r) => !r.ok);
  console.log('');
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`  ${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) {
    console.log('');
    for (const f of failed) console.log(`  FAILED: ${f.name} — ${f.detail}`);
  }
  console.log('');

  if (strict && failed.length > 0) process.exit(1);
}

await main();
