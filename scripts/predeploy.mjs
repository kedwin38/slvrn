/**
 * The pre-deploy step, as one process.
 *
 * Railway does not run `preDeployCommand` through a shell. A value like
 *
 *     node scripts/migrate.mjs && node scripts/deploy-check.mjs
 *
 * is not two commands: it is `node` invoked with `scripts/migrate.mjs` and three arguments
 * it ignores. The migration ran, printed, and looked fine — and the second half silently
 * never existed. That is a bad failure to inherit in a step whose whole job is catching bad
 * deploys, so the sequence lives here, in JavaScript, where it is explicit.
 *
 * Order and failure behaviour are deliberate and not the same for each step:
 *
 *   1. Migrations MUST succeed. A failure exits non-zero and Railway abandons the deploy,
 *      leaving the previous version serving. Every guarantee this system makes about
 *      immutable audit rows and refusing a SUCCESS without a receipt is a constraint in the
 *      schema, so a half-migrated database must never take traffic.
 *
 *   2. Seeding is opt-in (SEED_DEMO_ACCOUNTS=true) and never blocks. seed-demo has its own
 *      refusal to run under ENVIRONMENT=production; running it as a child process keeps that
 *      guard in force rather than reimplementing it here.
 *
 *   3. The checks report and never block. They run against the deployment still serving
 *      traffic, so a failure is information about what is live, not a reason to stop
 *      replacing it — and a smoke test that can wedge every future deploy gets deleted the
 *      first time it is wrong.
 */

import { spawn } from 'node:child_process';

function run(script, args = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { stdio: 'inherit' });
    child.on('close', (code) => resolve(code ?? 1));
    child.on('error', (error) => {
      console.error(`  could not run ${script}: ${error.message}`);
      resolve(1);
    });
  });
}

const migrated = await run('scripts/migrate.mjs');
if (migrated !== 0) {
  console.error('');
  console.error('  Migrations failed; refusing to deploy against this database.');
  console.error('');
  process.exit(migrated);
}

if (process.env.SEED_DEMO_ACCOUNTS === 'true') {
  console.log('');
  console.log('  SEED_DEMO_ACCOUNTS=true — seeding demo accounts');
  await run('scripts/seed-demo.mjs');
}

await run('scripts/deploy-check.mjs');
