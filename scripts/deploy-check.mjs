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
 * scripts/predeploy.mjs runs it as part of the pre-deploy step, against the deployment that
 * is still live. It exits 0 there even when a check fails: a smoke test that can block every future
 * deploy is a smoke test that gets deleted the first time it is wrong. Pass --strict when
 * you want the exit code to mean something.
 */

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

async function main() {
  console.log('');
  console.log('SOLVAREN deployment check');
  console.log('─────────────────────────────────────────────────────────────');
  console.log(`  API      ${apiBase || '(API_BASE_URL not set)'}`);
  console.log(`  Console  ${appOrigin || '(APP_ORIGIN not set)'}`);
  console.log('');

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

  /*
   * --- The modules the console offers are actually deployed -----------------
   *
   * A 401 proves the route exists and is guarded. A 404 would mean the console renders a
   * screen whose endpoint was never deployed — which looks like a broken feature to the
   * operator and like a successful deploy to everyone else. Checking for "guarded" rather
   * than "reachable" is the point: these must never answer an unauthenticated caller.
   */
  if (apiBase) {
    const guarded = [
      ['/admin/users', 'user management'],
      ['/admin/daraja', 'M-PESA credentials'],
      ['/admin/policies', 'policy settings'],
      ['/admin/audit', 'audit trail'],
      ['/batches', 'batch preparation'],
      ['/recipients', 'recipient master data'],
      ['/reconciliation/cases', 'reconciliation'],
      ['/reports', 'reporting'],
      ['/admin/security/events', 'security centre'],
      ['/analytics/action-queue', 'the action queue'],
      ['/admin/conflicts', 'the conflict-of-interest registry'],
      ['/ai/briefing', 'the intelligence layer'],
    ];

    for (const [path, label] of guarded) {
      try {
        const res = await fetchWithTimeout(`${apiBase}${path}`);
        record(res.status === 401, `${label} is deployed and guarded`, `${path} -> ${res.status}`);
      } catch (error) {
        record(false, `${label} is deployed and guarded`, error.message);
      }
    }
  }

  /*
   * --- The console actually ships those screens -----------------------------
   *
   * The API having an endpoint and the console having a screen for it are independent
   * facts, and the gap between them is exactly what made this system undeployable: every
   * one of these endpoints existed for weeks with nothing calling them. Checking the served
   * bundle for the screens' own text is the cheapest way to notice that gap reappearing.
   */
  if (appOrigin) {
    try {
      /*
       * The API and the console deploy concurrently, so this can reach the console origin
       * while its nginx is still coming up and the old bundle is still being served. That
       * produced a FAILED line for a screen that was in fact deployed — and a deploy gate
       * that cries wolf is one people learn to ignore, which is worse than not having it.
       *
       * So the newest assertion is retried briefly. This waits for the console to settle;
       * it does not paper over a genuinely missing screen, because the loop still ends in
       * the same assertions against whatever is actually being served.
       */
      const settleFor = Number(process.env.CONSOLE_SETTLE_ATTEMPTS ?? '10');
      let all = '';
      for (let attempt = 1; attempt <= settleFor; attempt++) {
        const html = await (await fetchWithTimeout(appOrigin)).text();
        const scripts = [...html.matchAll(/src="([^"]+\.js)"/g)].map((m) => m[1]);
        const bundles = await Promise.all(
          scripts.map(async (src) => (await fetchWithTimeout(new URL(src, appOrigin))).text()),
        );
        all = bundles.join('');
        // `Confirm it is you` is the most recently added screen; when it is present the
        // console has finished swapping and every older assertion is settled too.
        if (all.includes('Confirm it is you') || attempt === settleFor) break;
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }

      for (const [needle, label] of [
        ['New payment batch', 'batch creation'],
        ['Authorization PIN', 'account security'],
        ['M-PESA credentials', 'M-PESA credentials'],
        ['Audit trail', 'audit trail'],
        ['Members', 'member management'],
        ['Reconciliation', 'reconciliation'],
        ['Recipients', 'recipient master data'],
        ['Security centre', 'security centre'],
        ['Reports', 'reporting'],
        ['Intelligence', 'the intelligence screen'],
        ['Conflicts of interest', 'the conflict registry'],
        // The gap that made the whole hierarchy undeliverable: a draft with no way to
        // resume it, and no Level 2 decision anywhere in the console.
        ['Submit to Finance Control', 'draft resumption'],
        ['Approve for release', 'the Level 2 review stage'],
        // §11 recovery: the codes were write-only and there was no reset at all.
        ['Use a recovery code', 'credential recovery'],
        ['Reset access', 'administrative recovery'],
        // Without this, every step-up-protected action is a dead end.
        ['Confirm it is you', 'step-up confirmation'],
      ]) {
        record(all.includes(needle), `the console ships the ${label} screen`, needle);
      }
    } catch (error) {
      record(false, 'the console ships its admin screens', error.message);
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
