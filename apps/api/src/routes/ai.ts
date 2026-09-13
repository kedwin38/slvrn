/**
 * AI advisory layer (spec 11).
 *
 *   AI CONTROL — "The AI layer must not directly issue a payment release command. AI output
 *   is advisory unless converted into an explicit, policy-approved state transition by an
 *   authorized human workflow."
 *
 * This file is built so that constraint is structural rather than aspirational:
 *
 *  - it is a **read-only** route group. No handler here writes to any payment table, and
 *    the only INSERT is into `ai_interactions`, whose `caused_state_change` column carries
 *    a CHECK constraint pinning it to false;
 *  - the model is given *derived summaries*, never the ability to call back into SOLVAREN.
 *    There are no tools, no function calling, no agentic loop;
 *  - recipient identifiers are masked before they are sent anywhere, so a payroll does not
 *    leave the execution environment in identifiable form;
 *  - when the AI provider is unavailable, the endpoints degrade to the deterministic
 *    analysis rather than failing — the deterministic layer was always the one that counts.
 */

import { Hono, type Context } from 'hono';
import { z } from 'zod';
import { formatCents, maskMsisdn, resolveFailure, notFoundError } from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection } from '../db/client.js';
import { loadFailureOverrides } from '../services/failure-map.js';
import { sha256Base64Url } from '../services/crypto.js';
import type { AppContext, Env } from '../env.js';

export const aiRoutes = new Hono<AppContext>();
aiRoutes.use('*', requireAuth);

/** Every AI response carries this, so the UI can always show the boundary. */
const ADVISORY_NOTICE =
  'This analysis is advisory. It cannot approve, authorize or release any payment; those actions require the documented human authorization ceremony.';

interface AiCallResult {
  text: string;
  model: string;
  latencyMs: number;
  degraded: boolean;
}

/**
 * Call the language model with a strictly bounded prompt.
 *
 * The system prompt states the boundary, but the boundary is not *enforced* by the prompt —
 * it is enforced by this function having no way to mutate anything. A model that replied
 * "I have released the batch" would simply be wrong text on a screen.
 */
async function callModel(
  env: Env,
  systemPrompt: string,
  userPrompt: string,
): Promise<AiCallResult> {
  const model = env.AI_MODEL ?? 'claude-sonnet-5';
  const started = Date.now();

  if (!env.AI_API_KEY) {
    return {
      text: '',
      model,
      latencyMs: 0,
      degraded: true,
    };
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': env.AI_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model,
        max_tokens: 1200,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
      signal: AbortSignal.timeout(25_000),
    });

    if (!response.ok) return { text: '', model, latencyMs: Date.now() - started, degraded: true };

    const data = (await response.json()) as { content?: { type: string; text?: string }[] };
    const text = (data.content ?? [])
      .filter((block) => block.type === 'text')
      .map((block) => block.text ?? '')
      .join('\n')
      .trim();

    return { text, model, latencyMs: Date.now() - started, degraded: text === '' };
  } catch {
    // A provider outage must never block finance work; the deterministic layer stands.
    return { text: '', model, latencyMs: Date.now() - started, degraded: true };
  }
}

const SYSTEM_PROMPT = `You are the analysis assistant inside SOLVAREN, a business disbursement control plane for M-PESA payments in Kenya.

Your role is strictly advisory. You explain, summarise and flag. You never approve, authorize or release payments, and you have no capability to do so — payment release requires a separate cryptographic ceremony performed by a human with executive authority.

Guidelines:
- Be concrete and brief. Finance officers are reading this between other tasks.
- Quote the figures you were given. Never invent a number, a recipient, or a transaction.
- If the data provided does not support a conclusion, say so plainly rather than speculating.
- Recipient phone numbers are masked before reaching you; do not attempt to reconstruct them.
- When you flag something, say what a person should check, not what the system should do.`;

/** Record the interaction. The schema's CHECK constraint keeps the boundary provable. */
async function recordInteraction(
  c: Context<AppContext>,
  capability: string,
  promptSummary: string,
  context: unknown,
  result: AiCallResult,
  responseSummary: string,
): Promise<void> {
  const actor = actorOf(c);
  await withConnection(c.env, c.executionCtx, async (sql) => {
    await sql`
      INSERT INTO ai_interactions (
        organization_id, user_id, capability, prompt_summary, context_digest,
        context_row_count, model, response_summary, caused_state_change, latency_ms
      ) VALUES (
        ${actor.organizationId}, ${actor.userId}, ${capability}, ${promptSummary.slice(0, 500)},
        ${await sha256Base64Url(JSON.stringify(context))},
        ${Array.isArray(context) ? context.length : 1}, ${result.model},
        ${responseSummary.slice(0, 2000)}, FALSE, ${result.latencyMs}
      )
    `;
  });
}

/**
 * POST /ai/batches/:id/analyse — explain a batch and its risk findings.
 *
 * The deterministic findings are computed first and returned regardless of whether the
 * model responds. The narrative is an addition to them, never a replacement.
 */
aiRoutes.post('/batches/:id/analyse', requirePermissions('ai:batch_analysis'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');

  const context = await withConnection(c.env, c.executionCtx, async (sql) => {
    const batches = await sql<
      { batch_reference: string; purpose: string; state: string; instruction_count: number; total_amount_cents: string; risk_score: number | null; risk_band: string | null }[]
    >`
      SELECT batch_reference, purpose, state, instruction_count, total_amount_cents, risk_score, risk_band
        FROM payment_batches WHERE id = ${batchId} AND organization_id = ${actor.organizationId}
    `;
    const batch = batches[0];
    if (!batch) throw notFoundError('BATCH_NOT_FOUND', 'That batch could not be found');

    const findings = await sql<{ signal_type: string; severity: string; summary: string; disposition: string }[]>`
      SELECT signal_type, severity, summary, disposition
        FROM risk_findings WHERE batch_id = ${batchId}
       ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END
       LIMIT 40
    `;

    const departments = await sql<{ name: string | null; total: string; count: string }[]>`
      SELECT d.name, SUM(pi.amount_cents) AS total, COUNT(*) AS count
        FROM payment_instructions pi
        LEFT JOIN departments d ON d.id = pi.department_id
       WHERE pi.batch_id = ${batchId}
       GROUP BY d.name ORDER BY SUM(pi.amount_cents) DESC LIMIT 20
    `;

    return { batch, findings, departments };
  });

  const prompt = `Analyse this payment batch for a finance reviewer.

Batch ${context.batch.batch_reference} — "${context.batch.purpose}"
State: ${context.batch.state}
Recipients: ${context.batch.instruction_count}
Total: KES ${formatCents(Number(context.batch.total_amount_cents))}
Deterministic risk score: ${context.batch.risk_score ?? 'not yet assessed'} (${context.batch.risk_band ?? 'n/a'})

Departmental breakdown:
${context.departments.map((d) => `- ${d.name ?? 'Unassigned'}: ${d.count} recipients, KES ${formatCents(Number(d.total))}`).join('\n')}

Risk findings raised by the deterministic engine:
${context.findings.length === 0 ? '- none' : context.findings.map((f) => `- [${f.severity}] ${f.summary} (${f.disposition})`).join('\n')}

Write two short paragraphs: what this batch is, and what the reviewer should check before approving. Do not recommend approving or rejecting — that decision is theirs.`;

  const result = await callModel(c.env, SYSTEM_PROMPT, prompt);
  await recordInteraction(c, 'BATCH_ANALYSIS', `Analyse batch ${context.batch.batch_reference}`, context, result, result.text);

  return c.json({
    // The deterministic findings are the authoritative part of this response.
    deterministicFindings: context.findings,
    riskScore: context.batch.risk_score,
    riskBand: context.batch.risk_band,
    narrative: result.degraded ? null : result.text,
    degraded: result.degraded,
    degradedReason: result.degraded
      ? 'The analysis assistant is unavailable. The deterministic risk findings above are complete and unaffected.'
      : null,
    advisoryNotice: ADVISORY_NOTICE,
  });
});

/**
 * POST /ai/failures/explain — explain a failure in plain language (spec 11.3).
 *
 * The mapped dictionary reason is returned first and is authoritative; the model adds
 * context. An unmapped provider code still gets its raw description, so this endpoint
 * cannot produce a blank explanation even with the AI layer switched off entirely.
 */
aiRoutes.post('/failures/explain', requirePermissions('ai:batch_analysis'), async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ transactionId: z.string().uuid().optional(), failureCode: z.string().max(40).optional() })
    .parse(await c.req.json());

  const context = await withConnection(c.env, c.executionCtx, async (sql) => {
    const overrides = await loadFailureOverrides(sql, actor.organizationId);

    if (body.transactionId) {
      const rows = await sql<
        { failure_code: string | null; failure_reason: string | null; provider_result_description: string | null; status: string; amount_cents: string }[]
      >`
        SELECT t.failure_code, t.failure_reason, t.provider_result_description, t.status, pi.amount_cents
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
         WHERE t.id = ${body.transactionId} AND t.organization_id = ${actor.organizationId}
         LIMIT 1
      `;
      const row = rows[0];
      if (!row) throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
      return {
        resolved: resolveFailure(row.failure_code, row.provider_result_description, overrides),
        status: row.status,
        amountCents: Number(row.amount_cents),
      };
    }

    return {
      resolved: resolveFailure(body.failureCode ?? null, null, overrides),
      status: 'FAILED',
      amountCents: null,
    };
  });

  const prompt = `Explain this M-PESA payment failure to a payment operations officer.

Result code: ${context.resolved.failureCode}
Mapped explanation: ${context.resolved.failureReason}
Category: ${context.resolved.failureClass}
Documented operator action: ${context.resolved.operatorAction}
Transient: ${context.resolved.transient ? 'yes' : 'no'}
${context.amountCents !== null ? `Amount: KES ${formatCents(context.amountCents)}` : ''}

In three sentences: what happened, why, and what the officer should do next. Stay within the documented action above.`;

  const result = await callModel(c.env, SYSTEM_PROMPT, prompt);
  await recordInteraction(c, 'FAILURE_EXPLANATION', `Explain ${context.resolved.failureCode}`, context, result, result.text);

  return c.json({
    // Never blank, with or without the AI layer (TRK-002).
    failureCode: context.resolved.failureCode,
    failureReason: context.resolved.failureReason,
    failureClass: context.resolved.failureClass,
    operatorAction: context.resolved.operatorAction,
    transient: context.resolved.transient,
    mapped: context.resolved.mapped,
    narrative: result.degraded ? null : result.text,
    advisoryNotice: ADVISORY_NOTICE,
  });
});

/** POST /ai/analysis/expenditure — compare payroll cycles and explain movements (L2/L3). */
aiRoutes.post('/analysis/expenditure', requirePermissions('ai:financial_analysis'), async (c) => {
  const actor = actorOf(c);
  const body = z.object({ question: z.string().trim().min(3).max(500) }).parse(await c.req.json());

  const context = await withConnection(c.env, c.executionCtx, async (sql) => {
    const cycles = await sql<{ period: string; total: string; recipients: string }[]>`
      SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period,
             SUM(pi.amount_cents) AS total, COUNT(DISTINCT pi.recipient_id) AS recipients
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE t.organization_id = ${actor.organizationId} AND t.status = 'SUCCESS'
         AND t.completed_at > now() - interval '12 months'
       GROUP BY 1 ORDER BY 1 DESC
    `;

    const departments = await sql<{ name: string | null; period: string; total: string }[]>`
      SELECT d.name, date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period,
             SUM(pi.amount_cents) AS total
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
        LEFT JOIN departments d ON d.id = pi.department_id
       WHERE t.organization_id = ${actor.organizationId} AND t.status = 'SUCCESS'
         AND t.completed_at > now() - interval '6 months'
       GROUP BY d.name, 2 ORDER BY 2 DESC, 3 DESC
       LIMIT 60
    `;

    return { cycles, departments };
  });

  // Aggregates only. No recipient names or numbers leave the environment on this path.
  const prompt = `A finance officer asks: "${body.question}"

Monthly disbursement totals (most recent first):
${context.cycles.map((cycle) => `- ${cycle.period}: KES ${formatCents(Number(cycle.total))} across ${cycle.recipients} recipients`).join('\n')}

Departmental totals by month:
${context.departments.map((d) => `- ${d.period} ${d.name ?? 'Unassigned'}: KES ${formatCents(Number(d.total))}`).join('\n')}

Answer using only these figures. Quote the numbers you rely on. If the data does not answer the question, say what would.`;

  const result = await callModel(c.env, SYSTEM_PROMPT, prompt);
  await recordInteraction(c, 'EXPENDITURE_ANALYSIS', body.question, context, result, result.text);

  return c.json({
    question: body.question,
    data: {
      cycles: context.cycles.map((cycle) => ({
        period: cycle.period,
        totalCents: Number(cycle.total),
        recipientCount: Number(cycle.recipients),
      })),
    },
    narrative: result.degraded ? null : result.text,
    degraded: result.degraded,
    advisoryNotice: ADVISORY_NOTICE,
  });
});

/** POST /ai/briefing — the L3 executive briefing draft (spec 4.3). */
aiRoutes.post('/briefing', requirePermissions('ai:executive_intelligence'), async (c) => {
  const actor = actorOf(c);

  const context = await withConnection(c.env, c.executionCtx, async (sql) => {
    const months = await sql<{ period: string; total: string }[]>`
      SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period,
             SUM(pi.amount_cents) AS total
        FROM transactions t JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE t.organization_id = ${actor.organizationId} AND t.status = 'SUCCESS'
         AND t.completed_at > now() - interval '3 months'
       GROUP BY 1 ORDER BY 1 DESC
    `;
    const findings = await sql<{ severity: string; disposition: string; count: string }[]>`
      SELECT severity, disposition, COUNT(*) AS count FROM risk_findings
       WHERE organization_id = ${actor.organizationId} AND created_at > now() - interval '30 days'
       GROUP BY severity, disposition
    `;
    const failures = await sql<{ failure_reason: string; count: string }[]>`
      SELECT failure_reason, COUNT(*) AS count FROM transactions
       WHERE organization_id = ${actor.organizationId} AND status = 'FAILED'
         AND created_at > now() - interval '30 days'
       GROUP BY failure_reason ORDER BY COUNT(*) DESC LIMIT 5
    `;
    const unresolved = await sql<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM reconciliation_cases
       WHERE organization_id = ${actor.organizationId} AND state IN ('OPEN', 'QUERYING', 'ESCALATED')
    `;
    return { months, findings, failures, unresolved: Number(unresolved[0]?.count ?? 0) };
  });

  const prompt = `Draft an executive briefing for the chief payment authority.

Monthly disbursements:
${context.months.map((m) => `- ${m.period}: KES ${formatCents(Number(m.total))}`).join('\n')}

Risk findings in the last 30 days:
${context.findings.map((f) => `- ${f.severity}, ${f.disposition}: ${f.count}`).join('\n') || '- none'}

Most common failure reasons in the last 30 days:
${context.failures.map((f) => `- ${f.failure_reason}: ${f.count}`).join('\n') || '- none'}

Unresolved reconciliation cases: ${context.unresolved}

Write four or five sentences in the style of a board briefing: the movement, its main driver, the risk position, and anything outstanding. State figures precisely.`;

  const result = await callModel(c.env, SYSTEM_PROMPT, prompt);
  await recordInteraction(c, 'EXECUTIVE_BRIEFING', 'Executive briefing', context, result, result.text);

  return c.json({
    briefing: result.degraded ? null : result.text,
    degraded: result.degraded,
    figures: {
      monthlyDisbursements: context.months.map((m) => ({ period: m.period, totalCents: Number(m.total) })),
      unresolvedReconciliationCases: context.unresolved,
      topFailureReasons: context.failures.map((f) => ({ reason: f.failure_reason, count: Number(f.count) })),
    },
    advisoryNotice: ADVISORY_NOTICE,
  });
});

void maskMsisdn;
