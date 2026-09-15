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
            'reports:operational': true,
            'reports:management': true,
            'reports:executive': true,
            'reconciliation:read': true,
            'reconciliation:resolve': true,
            'recipients:read': true,
            'recipients:write': true,
            'departments:read': true,
            'departments:write': true,
            'admin:users': true,
            'admin:policies': true,
            'admin:security': true,
            'audit:read_full': true,
            'audit:read_org': true,
            'analytics:advanced': true,
            'analytics:executive': true,
            'ai:batch_analysis': true,
            'ai:financial_analysis': true,
            'ai:executive_intelligence': true,
          },
        }),
      );
    if (url.pathname === '/api/admin/daraja')
      return res.end(JSON.stringify({ configurations: [] }));
    /*
     * Fixtures for the remaining authenticated screens. These existed as routes and were
     * never captured, so eight of the console's fifteen screens had never been looked at in
     * a browser at all — which is how an unstyled control or a broken empty state survives.
     */
    if (url.pathname === '/api/reconciliation/summary')
      return res.end(
        JSON.stringify({
          open: 2,
          discrepancies: 1,
          resolvedToday: 4,
          oldestOpenedAt: '2026-09-13T06:20:00.000Z',
        }),
      );
    if (url.pathname === '/api/reconciliation/cases')
      return res.end(
        JSON.stringify({
          cases: [
            {
              caseId: 'rc1',
              caseReference: 'REC-2026-0041',
              state: 'OPEN',
              openedReason: 'The provider did not answer within the timeout window',
              discrepancy: true,
              queryAttempts: 3,
              nextQueryAt: '2026-09-15T10:00:00.000Z',
              openedAt: '2026-09-13T06:20:00.000Z',
              resolvedAt: null,
              resolvedBy: null,
              resolutionNote: null,
              evidence: null,
              transaction: {
                transactionId: 't1',
                status: 'TIMEOUT',
                statusTone: 'warning',
                failureCode: null,
                failureReason: null,
                providerResultDescription: null,
                mpesaReceiptNumber: null,
                originatorConversationId: '600992-INS2-7B2Q',
                conversationId: 'AG_20260913_2011',
                amountCents: 12000000,
                recipientName: 'Grace Achieng',
                msisdn: '254799889888',
                batchId: 'b1',
                batchReference: 'SLV-2026-00981',
              },
            },
          ],
          nextCursor: null,
        }),
      );
    if (url.pathname === '/api/recipients/departments')
      return res.end(
        JSON.stringify({
          departments: [
            {
              id: 'd1',
              name: 'Engineering',
              code: 'ENG',
              status: 'ACTIVE',
              monthlyBudgetCents: 400000000,
              recipientCount: 24,
            },
            {
              id: 'd2',
              name: 'Operations',
              code: 'OPS',
              status: 'ACTIVE',
              monthlyBudgetCents: null,
              recipientCount: 11,
            },
          ],
        }),
      );
    if (url.pathname === '/api/recipients')
      return res.end(
        JSON.stringify({
          recipients: [
            {
              id: 'r1',
              fullName: 'Jane Wanjiku',
              msisdn: '254790005678',
              status: 'ACTIVE',
              externalReference: 'EMP-0041',
              departmentId: 'd1',
              departmentName: 'Engineering',
              createdAt: '2026-04-02T08:00:00.000Z',
              updatedAt: '2026-09-01T08:00:00.000Z',
              paymentDetailsModifiedAt: '2026-09-01T08:00:00.000Z',
            },
            {
              id: 'r2',
              fullName: 'Peter Omondi',
              msisdn: '254790001222',
              status: 'ACTIVE',
              externalReference: 'EMP-0042',
              departmentId: 'd2',
              departmentName: 'Operations',
              createdAt: '2026-04-02T08:00:00.000Z',
              updatedAt: '2026-08-20T08:00:00.000Z',
              paymentDetailsModifiedAt: '2026-08-20T08:00:00.000Z',
            },
          ],
          nextCursor: null,
        }),
      );
    if (url.pathname === '/api/admin/users')
      return res.end(
        JSON.stringify({
          users: [
            {
              userId: 'u1',
              email: 'ceo@acme.test',
              fullName: 'Amina Njeri',
              level: 'L3',
              status: 'ACTIVE',
              createdAt: '2026-01-04T08:00:00.000Z',
              hasAuthenticator: true,
              hasAuthorizationPin: true,
              lastLoginAt: '2026-09-15T07:40:00.000Z',
            },
            {
              userId: 'u2',
              email: 'finance@acme.test',
              fullName: 'Otieno Were',
              level: 'L2',
              status: 'ACTIVE',
              createdAt: '2026-01-04T08:00:00.000Z',
              hasAuthenticator: true,
              hasAuthorizationPin: false,
              lastLoginAt: '2026-09-15T06:10:00.000Z',
            },
            {
              userId: 'u3',
              email: 'ops@acme.test',
              fullName: 'Wanjiku Kamau',
              level: 'L1',
              status: 'SUSPENDED',
              createdAt: '2026-02-11T08:00:00.000Z',
              hasAuthenticator: false,
              hasAuthorizationPin: false,
              lastLoginAt: null,
            },
          ],
        }),
      );
    if (url.pathname === '/api/admin/security/events')
      return res.end(
        JSON.stringify({
          events: [
            {
              id: 'se1',
              eventType: 'AUTHORIZATION_PIN_FAILED',
              severity: 'CRITICAL',
              description: 'Three consecutive wrong authorization PINs during a release',
              ip: '41.90.12.8',
              userAgent: 'Mozilla/5.0',
              detail: null,
              createdAt: '2026-09-15T07:10:00.000Z',
              acknowledgedAt: null,
              acknowledgedBy: null,
              user: { name: 'Amina Njeri', email: 'ceo@acme.test' },
            },
            {
              id: 'se2',
              eventType: 'NEW_DEVICE',
              severity: 'WARNING',
              description: 'Sign-in from a device not seen before',
              ip: '197.232.4.11',
              userAgent: 'Mozilla/5.0',
              detail: null,
              createdAt: '2026-09-14T16:02:00.000Z',
              acknowledgedAt: '2026-09-14T16:30:00.000Z',
              acknowledgedBy: 'Amina Njeri',
              user: { name: 'Otieno Were', email: 'finance@acme.test' },
            },
          ],
          counts: [
            { severity: 'CRITICAL', open: 1, total: 3 },
            { severity: 'WARNING', open: 0, total: 6 },
            { severity: 'INFO', open: 0, total: 41 },
          ],
          page: { pageSize: 100, nextCursor: null },
        }),
      );
    if (url.pathname === '/api/admin/security/sessions')
      return res.end(
        JSON.stringify({
          sessions: [
            {
              id: 'sess1',
              userName: 'Amina Njeri',
              email: 'ceo@acme.test',
              authorityLevel: 'L3',
              issuedAt: '2026-09-15T07:40:00.000Z',
              expiresAt: '2026-09-15T15:40:00.000Z',
              lastSeenAt: '2026-09-15T08:02:00.000Z',
              webauthnVerified: true,
              ip: '41.90.12.8',
              userAgent: 'Mozilla/5.0',
              deviceLabel: 'Office MacBook',
              deviceTrust: 'TRUSTED',
            },
          ],
          devices: [
            {
              id: 'dev1',
              userName: 'Amina Njeri',
              email: 'ceo@acme.test',
              label: 'Office MacBook',
              trustStatus: 'TRUSTED',
              firstSeenIp: '41.90.12.8',
              lastSeenIp: '41.90.12.8',
              userAgent: 'Mozilla/5.0',
              registeredAt: '2026-03-02T08:00:00.000Z',
              lastActivityAt: '2026-09-15T08:02:00.000Z',
            },
          ],
        }),
      );
    if (url.pathname === '/api/admin/conflicts')
      return res.end(
        JSON.stringify({
          registrations: [
            {
              id: 'cf1',
              userName: 'Otieno Were',
              scopeType: 'RECIPIENT',
              scopeLabel: 'Jane Wanjiku',
              reason: 'Family member',
              declaredAt: '2026-08-02T08:00:00.000Z',
              declaredBy: 'Amina Njeri',
              withdrawnAt: null,
            },
          ],
        }),
      );
    if (url.pathname === '/api/admin/policies')
      return res.end(
        JSON.stringify({
          policy: {
            perPaymentLimitCents: 15000000,
            dailyLimitCents: 500000000,
            batchLimitCents: 200000000,
            coolingOffSeconds: 300,
            riskGateBand: 'ELEVATED',
            allowL1FailedExport: true,
            requireDualApprovalAboveCents: 100000000,
          },
        }),
      );
    if (url.pathname === '/api/admin/audit')
      return res.end(
        JSON.stringify({
          events: [
            {
              event_reference: 'EVT-2026-004411',
              sequence: '4411',
              actor_id: 'u1',
              actor_level: 'L3',
              event_class: 'PAYMENT',
              action: 'batch.released',
              object_type: 'PaymentBatch',
              object_id: 'b1',
              outcome: 'SUCCESS',
              occurred_at: '2026-09-15T07:45:00.000Z',
              correlation_id: 'cor_A7NB750EH9654WJM',
              detail: { batchVersion: 3, instructionCount: 42 },
            },
            {
              event_reference: 'EVT-2026-004410',
              sequence: '4410',
              actor_id: 'u2',
              actor_level: 'L2',
              event_class: 'PAYMENT',
              action: 'batch.approved',
              object_type: 'PaymentBatch',
              object_id: 'b1',
              outcome: 'SUCCESS',
              occurred_at: '2026-09-15T07:31:00.000Z',
              correlation_id: 'cor_A7NB750EH9654WJM',
              detail: null,
            },
          ],
          nextCursor: null,
        }),
      );
    if (url.pathname === '/api/payments/failure-summary')
      return res.end(
        JSON.stringify({
          reasons: [
            { failureCode: '2001', failureReason: 'Insufficient balance', count: 18 },
            { failureCode: '2040', failureReason: 'Unregistered recipient', count: 9 },
          ],
        }),
      );
    if (url.pathname === '/api/reports')
      return res.end(
        JSON.stringify({
          reports: [
            {
              family: 'EXECUTIVE_SUMMARY',
              title: 'Executive summary',
              description: 'Disbursement totals and exceptions for the period.',
            },
          ],
        }),
      );
    /*
     * A report wide enough to overflow the viewport, on purpose: .table-scroll clips on
     * paper rather than scrolling, so a narrow fixture would pass a printout that silently
     * drops its right-hand columns.
     */
    if (url.pathname.startsWith('/api/reports/'))
      return res.end(
        JSON.stringify({
          generatedAt: '2026-09-15T09:12:00.000Z',
          exportReference: 'RPT-2026-09-0041',
          report: {
            family: 'EXECUTIVE_SUMMARY',
            title: 'Executive summary',
            description: 'Disbursement totals and exceptions for the period.',
            periodFrom: '2026-09-01T00:00:00.000Z',
            periodTo: '2026-09-15T00:00:00.000Z',
            highlights: [
              { label: 'Disbursed', value: 'KES 5,960,000', hint: '412 payments' },
              { label: 'Failed', value: '31', hint: '1.9% of attempts' },
              { label: 'Awaiting release', value: '2 batches' },
            ],
            sections: [
              {
                title: 'Batches in the period',
                columns: [
                  { key: 'reference', label: 'Reference', format: 'text' },
                  { key: 'prepared', label: 'Prepared by', format: 'text' },
                  { key: 'approved', label: 'Approved by', format: 'text' },
                  { key: 'released', label: 'Released by', format: 'text' },
                  { key: 'count', label: 'Payments', format: 'number' },
                  { key: 'gross', label: 'Gross', format: 'money' },
                  { key: 'charges', label: 'Charges', format: 'money' },
                  { key: 'net', label: 'Net settled', format: 'money' },
                  { key: 'releasedAt', label: 'Released at', format: 'timestamp' },
                ],
                rows: Array.from({ length: 24 }, (_, i) => ({
                  reference: `BATCH-2026-09-${String(i + 1).padStart(3, '0')}`,
                  prepared: 'Wanjiku Kamau',
                  approved: 'Otieno Were',
                  released: 'Amina Njeri',
                  count: 12 + i,
                  gross: 59600000 + i * 100000,
                  charges: 33000,
                  net: 59567000 + i * 100000,
                  releasedAt: `2026-09-${String((i % 28) + 1).padStart(2, '0')}T14:05:00.000Z`,
                })),
              },
            ],
            narrative: {
              text: 'Failure concentration rose in the second week, driven by unregistered recipients.',
              source: 'AI_ADVISORY',
              model: 'advisory-1',
            },
          },
        }),
      );
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

  /*
   * Reports, then the same page under print media.
   *
   * A report is a real output of this product — it goes into a board file or an audit
   * response — so the printed page is checked the way a screen is. Two failures are
   * asserted because both look fine on screen and ruin the document: .table-scroll is
   * `overflow-x: auto`, which CLIPS on paper rather than scrolling, so wide columns
   * vanish from a printout that still looks complete; and the sidebar taking a third of
   * the sheet.
   */
  await page.click('.nav-item >> text=Reports');
  await page.waitForSelector('.page-title', { timeout: 5000 });
  await page.getByRole('button', { name: 'Generate', exact: true }).click();
  await page.waitForSelector('.report-document table.table', { timeout: 5000 });
  await shot(page, `11-reports-${theme}`);

  /*
   * A4 at 96dpi less the @page margins. emulateMedia alone keeps the 1440px viewport, at
   * which a nine-column table fits and the clipping assertion below measures nothing —
   * which is exactly what it did until this line was added.
   */
  await page.emulateMedia({ media: 'print' });
  await page.setViewportSize({ width: 688, height: 1056 });
  await page.waitForTimeout(250);
  const printed = await page.evaluate(() => {
    const scroller = document.querySelector('.report-document .table-scroll');
    const table = scroller?.querySelector('table.table');
    const masthead = document.querySelector('.print-masthead');
    const style = scroller ? getComputedStyle(scroller) : null;
    return {
      // Clipped if the table is wider than the box that is meant to hold it on paper.
      clipped: Boolean(table && scroller && table.scrollWidth > scroller.clientWidth + 1),
      overflowX: style?.overflowX ?? 'none',
      mastheadShown: Boolean(masthead && getComputedStyle(masthead).display !== 'none'),
      chromeShown: ['.sidebar', '.topbar', '.button'].some((sel) => {
        const el = document.querySelector(sel);
        return Boolean(el && getComputedStyle(el).display !== 'none');
      }),
      headerRepeats:
        getComputedStyle(document.querySelector('.report-document table.table thead')).display ===
        'table-header-group',
    };
  });
  if (printed.clipped) {
    errors.push(`[${theme}] printed report clips its table (overflow-x: ${printed.overflowX})`);
  }
  if (!printed.mastheadShown) errors.push(`[${theme}] printed report has no masthead`);
  if (printed.chromeShown) errors.push(`[${theme}] printed report still shows console chrome`);
  if (!printed.headerRepeats) {
    errors.push(`[${theme}] printed table headers do not repeat across pages`);
  }
  console.log(
    `  print: clipped ${printed.clipped ? 'YES (BUG)' : 'no'}, masthead ${
      printed.mastheadShown ? 'yes' : 'MISSING'
    }, chrome ${printed.chromeShown ? 'SHOWN (BUG)' : 'hidden'}, repeating headers ${
      printed.headerRepeats ? 'yes' : 'NO'
    }`,
  );
  if (theme === 'light') {
    await page.pdf({ path: `${SHOTS}/12-report-print.pdf`, format: 'A4', printBackground: true });
    // A PNG of the same thing, because the PDF is not reviewable without a renderer.
    await page.screenshot({ path: `${SHOTS}/12-report-print.png`, fullPage: true });
    console.log('  captured 12-report-print.pdf and .png');
  }
  await page.emulateMedia({ media: 'screen' });
  // The print check narrowed the viewport to A4; put it back, or the taller sidebar puts
  // later nav entries below the fold and every click below times out.
  await page.setViewportSize({ width: 1440, height: 900 });

  /*
   * The rest of the authenticated console.
   *
   * Eight of the fifteen screens had never been captured, so nobody had looked at them in a
   * browser. A page renders or it does not; a screenshot is the only thing that says which.
   */
  // Exact labels, anchored: `hasText: 'Security'` also matches 'Security centre', which
  // would capture the wrong screen twice and never visit the account one.
  for (const [label, nav] of [
    ['13-reconciliation', 'Reconciliation'],
    ['14-recipients', 'Recipients'],
    ['15-intelligence', 'Intelligence'],
    ['16-members', 'Members'],
    ['17-policy', 'Policy'],
    ['18-security-centre', 'Security centre'],
    ['19-audit', 'Audit trail'],
    ['20-account-security', 'Security'],
  ]) {
    const item = page.locator('.nav-item', { hasText: new RegExp(`^${nav}$`) }).first();
    if ((await item.count()) === 0) {
      errors.push(`[${theme}] no navigation entry for ${nav}`);
      continue;
    }
    await item.click();
    await page.waitForSelector('.page-title', { timeout: 5000 });

    /*
     * The heading must not end up underneath the sticky top bar.
     *
     * Navigating focuses #main-content so a keyboard user lands on the page rather than the
     * nav item they just left. The browser scrolls that into view — and on a tall page it
     * scrolled the heading straight under the sticky bar, so the screen a person arrived at
     * opened with its own title half hidden.
     */
    const covered = await page.evaluate(() => {
      const title = document.querySelector('.page-title');
      const bar = document.querySelector('.topbar');
      if (!title || !bar) return null;
      const t = title.getBoundingClientRect();
      const b = bar.getBoundingClientRect();
      return { overlap: Math.round(b.bottom - t.top), title: Math.round(t.top) };
    });
    if (covered && covered.overlap > 0) {
      errors.push(
        `[${theme}] ${label}: the sticky top bar covers the page heading by ${covered.overlap}px`,
      );
    }
    await shot(page, `${label}-${theme}`);
  }

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

/*
 * The navigation must not be the first screen on a phone. Asserted by position rather than
 * by a class name: what matters is that the page heading is visible without scrolling and
 * that the nav is off-screen until asked for.
 */
const mobileNav = await mpage.evaluate(() => {
  const title = document.querySelector('.page-title');
  const sidebar = document.querySelector('.sidebar');
  return {
    titleTop: Math.round(title.getBoundingClientRect().top),
    sidebarLeft: Math.round(sidebar.getBoundingClientRect().left),
    viewport: window.innerHeight,
  };
});
if (mobileNav.titleTop > mobileNav.viewport) {
  errors.push(
    `[mobile] the page heading is below the fold (${mobileNav.titleTop}px) — navigation is pushing content down`,
  );
}
if (mobileNav.sidebarLeft >= 0) {
  errors.push(`[mobile] the navigation drawer is not stowed (left ${mobileNav.sidebarLeft}px)`);
}
await mpage.click('.nav-toggle');
await mpage.waitForTimeout(300);
const opened = await mpage.evaluate(() =>
  Math.round(document.querySelector('.sidebar').getBoundingClientRect().left),
);
if (opened !== 0) errors.push(`[mobile] the drawer did not open (left ${opened}px)`);
await mpage.screenshot({ path: `${SHOTS}/07-mobile-nav-open.png`, fullPage: false });
// Escape closes it, and the drawer closes itself once a route is chosen.
await mpage.click('.nav-item >> text=Transactions');
await mpage.waitForTimeout(300);
const afterNavigate = await mpage.evaluate(() =>
  Math.round(document.querySelector('.sidebar').getBoundingClientRect().left),
);
if (afterNavigate >= 0) {
  errors.push(`[mobile] the drawer stayed open after navigating (left ${afterNavigate}px)`);
}
console.log(
  `  mobile nav: heading at ${mobileNav.titleTop}px, drawer stowed at ${mobileNav.sidebarLeft}px, opens to ${opened}px, closes on navigate ${afterNavigate < 0 ? 'yes' : 'NO (BUG)'}`,
);
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
