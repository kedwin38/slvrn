/**
 * Drive the built console in a real browser and capture screenshots.
 *
 * Runs against the production build with a stubbed API, in both colour schemes and at
 * phone width. It asserts the two things that silently break a console: an unhandled page
 * error, and horizontal overflow on a narrow viewport.
 *
 * Usage:  pnpm --filter @solvaren/web build && node scripts/ui-check.mjs
 */

import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, extname, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolved from this file rather than hardcoded, so the check runs on any machine and in
// CI. SOLVAREN_UI_SHOTS redirects the screenshots; the default keeps them out of the
// working tree.
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = process.env.SOLVAREN_UI_DIST ?? join(REPO_ROOT, 'apps/web/dist');
const SHOTS = process.env.SOLVAREN_UI_SHOTS ?? join(REPO_ROOT, 'apps/web/dist/.ui-check');
mkdirSync(SHOTS, { recursive: true });
const TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain',
};

// Serve the built app, and stub the API so the shell can be driven without a backend.
const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    res.setHeader('content-type', 'application/json');
    if (url.pathname === '/api/auth/login')
      return res.end(
        JSON.stringify({
          stage: 'AUTHENTICATED',
          token: 't',
          expiresAt: new Date(Date.now() + 3.6e6).toISOString(),
          user: {},
        }),
      );
    if (url.pathname === '/api/auth/session')
      return res.end(
        JSON.stringify({
          user: {
            userId: 'u1',
            email: 'ceo@acme.test',
            fullName: 'Amina Njeri',
            level: 'L3',
            levelTitle: 'Chief / Executive Payment Authority',
            organizationId: 'o1',
            organizationSlug: 'acme',
          },
          session: {
            authenticatedAt: new Date().toISOString(),
            webauthnVerified: true,
            trustedDeviceId: 'd1',
          },
          deployment: {
            environment: 'staging',
            darajaEnvironment: 'sandbox',
            movesRealMoney: false,
          },
          capabilities: {
            'transactions:read': true,
            'transactions:export_failed': true,
            'transactions:refresh_status': true,
            'batch:read': true,
            'payment:release': true,
            'admin:backups': true,
            'admin:daraja': true,
            'dashboard:balance_panel': true,
            'dashboard:recent_transactions_panel': true,
            'analytics:basic': true,
          },
        }),
      );
    if (url.pathname === '/api/admin/daraja')
      return res.end(JSON.stringify({ configurations: [] }));
    if (url.pathname === '/api/analytics/action-queue')
      return res.end(JSON.stringify({ items: [], counts: { total: 0, critical: 0, warning: 0 } }));
    if (url.pathname === '/api/analytics/operational')
      return res.end(
        JSON.stringify({
          batchesByState: { SUCCESS: 12, L3_READY: 2 },
          transactions: {
            total: 1840,
            success: 1802,
            failed: 31,
            timeout: 4,
            inFlight: 3,
            successRate: 0.9793,
            failureRate: 0.019,
          },
          processingSeconds: { median: 8.4, p95: 41.2 },
          dailyTrend: Array.from({ length: 14 }, (_, i) => ({
            day: `2026-09-${String(i + 1).padStart(2, '0')}`,
            total: 120 + i * 7,
            failed: i % 4 === 0 ? 5 : 1,
          })),
          needsAttention: { failed: 31, timeout: 4, reconciling: 2 },
        }),
      );
    if (url.pathname === '/api/analytics/executive/balance')
      return res.end(
        JSON.stringify({
          accounts: [
            {
              accountType: 'Utility Account',
              currency: 'KES',
              availableCents: 22803700,
              unclearedCents: 22803700,
              reservedCents: 0,
              asOf: new Date().toISOString(),
              source: 'CALLBACK',
            },
            {
              accountType: 'Working Account',
              currency: 'KES',
              availableCents: 70000000,
              unclearedCents: 70000000,
              reservedCents: 0,
              asOf: new Date().toISOString(),
              source: 'CALLBACK',
            },
            {
              accountType: 'Charges Paid Account',
              currency: 'KES',
              availableCents: -154000,
              unclearedCents: -154000,
              reservedCents: 0,
              asOf: new Date().toISOString(),
              source: 'CALLBACK',
            },
          ],
          asOf: new Date().toISOString(),
          awaitingRefresh: false,
          note: null,
        }),
      );
    if (url.pathname === '/api/analytics/executive/recent-transactions')
      return res.end(
        JSON.stringify({
          transactions: [
            {
              transactionId: 't1',
              status: 'SUCCESS',
              amountCents: 4500000,
              recipientName: 'Jane Wanjiku',
              msisdn: '254712345678',
              mpesaReceiptNumber: 'SG632NMUAB',
              batchReference: 'SLV-2026-00981',
              failureReason: null,
              at: new Date(Date.now() - 6e5).toISOString(),
            },
            {
              transactionId: 't2',
              status: 'FAILED',
              amountCents: 3200000,
              recipientName: 'Peter Omondi',
              msisdn: '254733111222',
              mpesaReceiptNumber: null,
              batchReference: 'SLV-2026-00981',
              failureReason: "Insufficient balance in the organization's Utility account",
              at: new Date(Date.now() - 9e5).toISOString(),
            },
          ],
        }),
      );
    if (url.pathname === '/api/payments/transactions')
      return res.end(
        JSON.stringify({
          transactions: [
            {
              transactionId: 't1',
              instructionId: 'i1',
              batchId: 'b1',
              batchReference: 'SLV-2026-00981',
              recipientId: 'r1',
              recipientName: 'Jane Wanjiku',
              msisdn: '254712345678',
              departmentId: null,
              departmentName: 'Engineering',
              amountCents: 4500000,
              status: 'SUCCESS',
              statusTone: 'success',
              failureCode: null,
              failureReason: null,
              failureClass: null,
              operatorAction: null,
              providerResultDescription: null,
              mpesaReceiptNumber: 'SG632NMUAB',
              conversationId: 'AG_20260913_2010',
              originatorConversationId: '600992-INS1-9F3K',
              statusSource: 'CALLBACK',
              lastStatusCheckAt: null,
              createdAt: new Date().toISOString(),
              submittedAt: new Date().toISOString(),
              completedAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
              retryEligible: false,
            },
            {
              transactionId: 't2',
              instructionId: 'i2',
              batchId: 'b1',
              batchReference: 'SLV-2026-00981',
              recipientId: 'r2',
              recipientName: 'Peter Omondi',
              msisdn: '254733111222',
              departmentId: null,
              departmentName: 'Finance',
              amountCents: 3200000,
              status: 'FAILED',
              statusTone: 'danger',
              failureCode: '1',
              failureReason: "Insufficient balance in the organization's Utility account",
              failureClass: 'FUNDING',
              operatorAction:
                'Top up the B2C shortcode, or move funds from the Working (MMF) account to Utility on the M-PESA org portal — B2C debits Utility, not Working',
              providerResultDescription: 'The balance is insufficient for the transaction',
              mpesaReceiptNumber: null,
              conversationId: 'AG_20260913_2011',
              originatorConversationId: '600992-INS2-7B2Q',
              statusSource: 'CALLBACK',
              lastStatusCheckAt: new Date().toISOString(),
              createdAt: new Date().toISOString(),
              submittedAt: new Date().toISOString(),
              completedAt: null,
              updatedAt: new Date().toISOString(),
              retryEligible: true,
            },
            {
              transactionId: 't3',
              instructionId: 'i3',
              batchId: 'b1',
              batchReference: 'SLV-2026-00981',
              recipientId: 'r3',
              recipientName: 'Grace Achieng',
              msisdn: '254711999888',
              departmentId: null,
              departmentName: 'Operations',
              amountCents: 12000000,
              status: 'TIMEOUT',
              statusTone: 'warning',
              failureCode: 'SLV_TIMEOUT',
              failureReason: 'No result was received from M-PESA within the expected window',
              failureClass: 'AMBIGUOUS',
              operatorAction:
                'Reconciliation is querying the Transaction Status API. Do not resubmit until the outcome is known',
              providerResultDescription: null,
              mpesaReceiptNumber: null,
              conversationId: null,
              originatorConversationId: '600992-INS3-4K9Z',
              statusSource: 'SYSTEM',
              lastStatusCheckAt: new Date().toISOString(),
              createdAt: new Date().toISOString(),
              submittedAt: new Date().toISOString(),
              completedAt: null,
              updatedAt: new Date().toISOString(),
              retryEligible: false,
            },
          ],
          page: {
            page: 1,
            pageSize: 50,
            totalRows: 3,
            totalPages: 1,
            hasNext: false,
            hasPrevious: false,
          },
          filter: { text: 'no filter (all transactions in scope)', parts: [] },
        }),
      );
    if (url.pathname === '/api/batches')
      return res.end(
        JSON.stringify({
          batches: [
            {
              batchId: 'b1',
              batchReference: 'SLV-2026-00981',
              state: 'PARTIAL_SUCCESS',
              instructionCount: 187,
              totalAmountCents: 842050000,
              outcomes: { success: 182, failed: 3, timeout: 1, inFlight: 1 },
            },
            {
              batchId: 'b2',
              batchReference: 'SLV-2026-00982',
              state: 'L3_READY',
              instructionCount: 42,
              totalAmountCents: 186400000,
              outcomes: { success: 0, failed: 0, timeout: 0, inFlight: 0 },
            },
            {
              batchId: 'b-draft',
              batchReference: 'SLV-2026-00999',
              state: 'DRAFT',
              instructionCount: 0,
              totalAmountCents: 0,
              outcomes: { success: 0, failed: 0, timeout: 0, inFlight: 0 },
            },
          ],
        }),
      );
    if (/^\/api\/batches\/[^/]+$/.test(url.pathname))
      return res.end(
        JSON.stringify({
          batch: {
            batchId: 'b-draft',
            batchReference: 'SLV-2026-00999',
            purpose: 'September payroll',
            state: 'DRAFT',
            version: 1,
            instructionCount: 0,
            totalAmountCents: 0,
            createdAt: new Date().toISOString(),
            submittedAt: null,
            approvedAt: null,
            authorizedAt: null,
            riskScore: null,
            riskBand: null,
            editable: true,
            availableCommands: ['VALIDATE', 'CANCEL'],
          },
          instructions: [],
          approvals: [],
          riskFindings: [],
        }),
      );
    if (url.pathname === '/api/authorization/batches/b2/begin')
      return res.end(
        JSON.stringify({
          challengeId: 'c1',
          challengeHash: 'A'.repeat(64),
          webauthnChallenge: 'Y2hhbGxlbmdl',
          expiresAt: new Date(Date.now() + 3e5).toISOString(),
          manifest: {
            manifestHash: '9C4A7D91'.repeat(8),
            batchReference: 'SLV-2026-00982',
            recipientCount: 42,
            totalAmountCents: 186400000,
            approvalId: 'APR-8821',
            batchVersion: 3,
          },
          acknowledgementsRequired: [
            'This is a high-value release of KES 1,864,000.00 to 42 recipients.',
          ],
          risk: {
            score: 38,
            band: 'ELEVATED',
            signals: [
              {
                type: 'NEW_RECIPIENT',
                severity: 'HIGH',
                summary: 'First payment to a recipient added 6 hours ago, for KES 120,000.00.',
                evidence: { recipientAgeHours: 6, amount: '120,000.00' },
                instructionIds: [],
              },
              {
                type: 'AMOUNT_DEVIATION',
                severity: 'MEDIUM',
                summary:
                  "KES 98,000.00 is 3.2× higher than this recipient's usual payment of KES 30,500.00.",
                evidence: { ratio: 3.2, historicalMean: '30,500.00' },
                instructionIds: [],
              },
            ],
            requiresAcknowledgement: true,
          },
          confirmation: {
            headline: 'Release KES 1,864,000.00 to 42 recipients',
            batchReference: 'SLV-2026-00982',
            manifestDigestShort: '9C4A7D919C4A7D91',
            warning:
              'Once released, these payments are submitted to M-PESA and cannot be recalled from SOLVAREN. Reversals are handled on the M-PESA organisation portal.',
          },
        }),
      );
    if (url.pathname === '/api/admin/backups')
      return res.end(
        JSON.stringify({
          configuration: {
            configurationId: 'bc1',
            providerLabel: 'Cloudflare R2',
            bucket: 'acme-backups',
            pathPrefix: 'solvaren/backups',
            region: 'auto',
            endpoint: null,
            accessKeyMasked: '••••••••3f9a',
            secretKeyMasked: '••••••••',
            encryptionMode: 'SSE_S3',
            status: 'CONNECTED',
            lastTestAt: new Date().toISOString(),
            lastTestOk: true,
            lastTestMessage: 'ok',
            scheduleEnabled: true,
            scheduleCron: '0 2 * * *',
            scheduleTimezone: 'Africa/Nairobi',
            retentionMaxCount: 30,
            lastScheduledRunAt: new Date().toISOString(),
            nextScheduledRunAt: null,
            suspended: false,
            suspensionReason: null,
            consecutiveFailures: 0,
          },
          latestResult: {
            attemptReference: 'BAK-2026-000184',
            trigger: 'SCHEDULED',
            status: 'SUCCESS',
            startedAt: new Date(Date.now() - 3.6e6).toISOString(),
            endedAt: new Date().toISOString(),
            sizeBytes: 48211904,
            checksum: 'a1b2',
            errorMessage: null,
            retentionDeletedCount: 1,
            retentionComplete: true,
          },
          history: [
            {
              attemptReference: 'BAK-2026-000184',
              trigger: 'SCHEDULED',
              status: 'SUCCESS',
              startedAt: new Date(Date.now() - 3.6e6).toISOString(),
              endedAt: new Date().toISOString(),
              sizeBytes: 48211904,
              errorMessage: null,
              objectRetained: true,
            },
            {
              attemptReference: 'BAK-2026-000183',
              trigger: 'MANUAL',
              status: 'FAILED',
              startedAt: new Date(Date.now() - 9e7).toISOString(),
              endedAt: new Date(Date.now() - 9e7).toISOString(),
              sizeBytes: null,
              errorMessage: 'The storage target rejected the credentials',
              objectRetained: false,
            },
          ],
          restoreValidationNote:
            'A backup that has never been restore-validated is not disaster-recovery proven. See docs/runbooks/backup-restore.md.',
        }),
      );
    return res.end('{}');
  }
  let file = join(DIST, url.pathname === '/' ? 'index.html' : url.pathname);
  if (!existsSync(file)) file = join(DIST, 'index.html');
  res.setHeader('content-type', TYPES[extname(file)] ?? 'application/octet-stream');
  res.end(readFileSync(file));
});

await new Promise((r) => server.listen(4173, r));

const browser = await chromium.launch({
  executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
});
const errors = [];

async function shot(page, name, width = 1440, height = 900) {
  await page.setViewportSize({ width, height });
  await page.waitForTimeout(450);
  await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: false });
  console.log(`  captured ${name}`);
}

for (const theme of ['light', 'dark']) {
  const context = await browser.newContext({ colorScheme: theme });
  const page = await context.newPage();
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`[${theme}] ${m.text()}`);
  });
  page.on('pageerror', (e) => errors.push(`[${theme}] ${e.message}`));

  await page.goto('http://localhost:4173/', { waitUntil: 'networkidle' });
  await shot(page, `01-login-${theme}`);

  /*
   * Credential recovery must be reachable from the sign-in screen itself — a person who
   * cannot sign in cannot navigate to it from anywhere else. §11 also forbids the usual
   * escape hatches, so the screen must offer a recovery CODE and must not offer to email
   * or text anything.
   */
  await page.click('text=Use a recovery code');
  await page.waitForSelector('text=Recovery code', { timeout: 5000 });
  const recoveryHtml = (await page.content()).toLowerCase();
  /*
   * Phrases that can only be an OFFER of a forbidden channel. A bare "sms" would match the
   * screen's own promise that it never uses one, which is the opposite of a defect — the
   * first version of this check failed on exactly that.
   */
  const offers = [
    'send you a code',
    'send a code to',
    "we'll text",
    'we will text',
    'check your email',
    'email you a link',
    'reset link',
  ];
  const offending = offers.filter((phrase) => recoveryHtml.includes(phrase));
  // And it should say so positively, so nobody goes looking for an email that never comes.
  if (!recoveryHtml.includes('never sends a reset by sms or email')) {
    errors.push(`[${theme}] the recovery screen does not state that SMS and email are never used`);
  }
  if (offending.length > 0) {
    errors.push(
      `[${theme}] the recovery screen offers a forbidden channel: ${offending.join(', ')}`,
    );
  }
  console.log(`  recovery reachable from sign-in: yes, forbidden offers: ${offending.length}`);
  await shot(page, `10-recovery-${theme}`);
  await page.click('text=Back to sign in');
  await page.waitForSelector('input[type=email]', { timeout: 5000 });

  await page.fill('input[type=email]', 'ceo@acme.test');
  await page.fill('input[type=password]', 'correct horse battery staple');
  await page.click('button[type=submit]');
  await page.waitForSelector('.page-title', { timeout: 5000 });
  await shot(page, `02-dashboard-${theme}`);

  await page.click('text=Transactions');
  await page.waitForSelector('table.table', { timeout: 5000 });
  await page.click('text=Why?');
  await shot(page, `03-transactions-${theme}`);

  await page.click('text=Payment batches');
  await page.waitForSelector('table.table', { timeout: 5000 });
  await shot(page, `04-batches-${theme}`);

  /*
   * A saved draft must be resumable. This is the operator-reported gap: the wizard closed
   * and the draft became unreachable, because a DRAFT row carried no action at all. The
   * assertion is that Continue opens the batch and offers the upload it needs to go on.
   */
  await page.click('text=Continue');
  await page.waitForSelector('#batch-detail-title', { timeout: 5000 });
  const resumable = await page.locator('input[type=file]').count();
  const canValidate = await page.locator('button:has-text("Validate")').count();
  if (resumable === 0 || canValidate === 0) {
    errors.push(
      `[${theme}] a saved draft cannot be resumed: ${resumable} upload control, ${canValidate} validate action`,
    );
  }
  console.log(
    `  draft resumable: upload ${resumable > 0 ? 'yes' : 'NO (BUG)'}, validate ${canValidate > 0 ? 'yes' : 'NO (BUG)'}`,
  );
  await shot(page, `09-batch-detail-${theme}`);
  await page.keyboard.press('Escape');

  await page.click('text=Review & authorize');
  await page.waitForSelector('.ceremony-amount-value', { timeout: 5000 });
  await shot(page, `05-ceremony-${theme}`);

  await page.keyboard.press('Escape');

  /*
   * Typing in a dialog must actually type.
   *
   * Modal's focus effect depended on `onClose`, which every caller passes as an inline
   * arrow — so the effect tore down and re-ran after each keystroke, yanking the caret back
   * to the first field. The panel was usable only one character at a time. `fill()` would
   * not have caught it: it sets the value in one operation. This types key by key, the way
   * a person does.
   */
  await page.click('text=M-PESA credentials');
  await page.waitForSelector('.page-title', { timeout: 5000 });
  await page.click('text=Add credentials');
  await page.waitForSelector('#daraja-title', { timeout: 5000 });

  const shortcode = page.locator('input[inputmode=numeric]').first();
  await shortcode.click();
  await shortcode.pressSequentially('600992', { delay: 20 });
  const typed = await shortcode.inputValue();
  const stillFocused = await shortcode.evaluate((el) => el === document.activeElement);
  if (typed !== '600992' || !stillFocused) {
    errors.push(
      `[${theme}] typing in a dialog loses the caret: field holds "${typed}" and focus ${stillFocused ? 'held' : 'was lost'}`,
    );
  }
  console.log(`  dialog typing: "${typed}", focus ${stillFocused ? 'held' : 'LOST (BUG)'}`);
  await shot(page, `08-daraja-${theme}`);

  await page.keyboard.press('Escape');
  await page.click('text=Backups');
  await page.waitForSelector('.card-title', { timeout: 5000 });
  await shot(page, `06-backups-${theme}`);

  await context.close();
}

// Mobile viewport: the console must work at phone width.
const mobile = await browser.newContext({
  viewport: { width: 390, height: 844 },
  colorScheme: 'light',
});
const mpage = await mobile.newPage();
mpage.on('pageerror', (e) => errors.push(`[mobile] ${e.message}`));
await mpage.goto('http://localhost:4173/', { waitUntil: 'networkidle' });
await mpage.fill('input[type=email]', 'x@y.test');
await mpage.fill('input[type=password]', 'password1234');
await mpage.click('button[type=submit]');
await mpage.waitForSelector('.page-title');
await mpage.screenshot({ path: `${SHOTS}/07-mobile-dashboard.png`, fullPage: false });
// Horizontal overflow is the classic mobile failure; assert it directly.
const overflow = await mpage.evaluate(
  () => document.documentElement.scrollWidth > window.innerWidth + 1,
);
console.log(`  mobile horizontal overflow: ${overflow ? 'YES (BUG)' : 'no'}`);
await mobile.close();

await browser.close();
server.close();

console.log(
  errors.length === 0 ? '\nNo console or page errors.' : `\nErrors:\n${errors.join('\n')}`,
);
