/**
 * Intelligence (spec §11, and the AI sections of all three authority levels).
 *
 * The AI layer had four working endpoints and no client method called any of them, so every
 * "ask the assistant", "explain this failure" and "executive briefing" in the specification
 * was unreachable. This is that screen.
 *
 * The organising rule is §11's, and it shapes every block here: **computed figures and
 * generated narrative are never mixed**. The deterministic findings, the mapped failure
 * reason and the monthly totals are authoritative and come from the ledger; the narrative is
 * labelled as advisory wherever it appears, and when the model is unavailable the page still
 * shows the figures rather than an error. A briefing that quietly omits its numbers because
 * a model timed out is worse than no briefing.
 *
 * What is offered depends on authority, as the specification sets out: batch analysis and
 * failure explanation for operations, expenditure questions for finance control, the
 * executive briefing for the chief alone. The server refuses the rest regardless.
 */

import { useState } from 'react';
import { api, ApiError, type SessionResponse, type RiskSignalView } from '../lib/api.js';
import { Amount, Notice, Field, EmptyState } from '../components/primitives.js';

export function IntelligencePage({
  capabilities,
}: {
  capabilities: SessionResponse['capabilities'];
}) {
  const canAnalyseBatch = Boolean(capabilities['ai:batch_analysis']);
  const canAnalyseFinance = Boolean(capabilities['ai:financial_analysis']);
  const canBrief = Boolean(capabilities['ai:executive_intelligence']);

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Intelligence</h1>
          <p className="page-subtitle">
            Analysis of your own payment data. Figures come from the ledger; anything written in
            prose is a model's suggestion and is labelled as such.
          </p>
        </div>
      </div>

      <Notice tone="info">
        The assistant cannot authorize, release, alter or retry a payment. It reads; people decide.
      </Notice>

      {canAnalyseBatch && <FailureExplainer />}
      {canAnalyseBatch && <BatchAnalyser />}
      {canAnalyseFinance && <ExpenditureAssistant />}
      {canBrief && <ExecutiveBriefing />}

      {!canAnalyseBatch && !canAnalyseFinance && !canBrief && (
        <EmptyState title="No analysis is available to you">
          Intelligence is granted by authority level.
        </EmptyState>
      )}
    </div>
  );
}

/** A labelled block of model-written prose. Never rendered as though it were a figure. */
function Advisory({ text, notice }: { text: string | null; notice: string }) {
  if (!text) return null;
  return (
    <div className="card" style={{ borderStyle: 'dashed' }}>
      <div className="card-body stack">
        <div className="small strong">AI advisory — not a computed figure</div>
        <p style={{ whiteSpace: 'pre-wrap' }}>{text}</p>
        <p className="small muted">{notice}</p>
      </div>
    </div>
  );
}

function Degraded({ reason }: { reason: string | null }) {
  return (
    <Notice tone="warning">
      {reason ??
        'The assistant is unavailable. The figures above are complete and unaffected by that.'}
    </Notice>
  );
}

function useAsk<T>() {
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function ask(operation: () => Promise<T>) {
    setBusy(true);
    setError(null);
    try {
      setResult(await operation());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That analysis could not be produced.');
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  return { result, error, busy, ask };
}

/** Why did this payment fail, in plain language (spec §11.3). */
function FailureExplainer() {
  const [code, setCode] = useState('');
  const { result, error, busy, ask } = useAsk<Awaited<ReturnType<typeof api.ai.explainFailure>>>();

  return (
    <div className="card">
      <div className="card-body stack">
        <h2 className="section-title">Explain a failure</h2>
        <p className="small muted">
          Enter the provider code from the transactions list. The mapped reason is authoritative and
          appears with or without the assistant.
        </p>

        <form
          className="row"
          style={{ gap: 'var(--s2)', alignItems: 'end', flexWrap: 'wrap' }}
          onSubmit={(event) => {
            event.preventDefault();
            void ask(() => api.ai.explainFailure(code.trim()));
          }}
        >
          <div style={{ flex: '0 1 20rem' }}>
            <Field label="Provider failure code" hint="For example 1, 2001 or 2040">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  required
                  maxLength={32}
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                />
              )}
            </Field>
          </div>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Explaining…' : 'Explain'}
          </button>
        </form>

        {error && (
          <Notice tone="danger" live="assertive">
            {error}
          </Notice>
        )}

        {result && (
          <>
            <dl className="finding-evidence">
              <div>
                <dt>Reason&nbsp;</dt>
                <dd>{result.failureReason}</dd>
              </div>
              <div>
                <dt>What to do&nbsp;</dt>
                <dd>{result.operatorAction}</dd>
              </div>
              <div>
                <dt>Class&nbsp;</dt>
                <dd>{result.failureClass}</dd>
              </div>
              <div>
                <dt>Retryable&nbsp;</dt>
                <dd>{result.transient ? 'yes — another attempt may succeed' : 'no'}</dd>
              </div>
            </dl>
            {!result.mapped && (
              <Notice tone="warning">
                This code is not in the failure dictionary, so the reason above is the provider's
                own wording.
              </Notice>
            )}
            <Advisory text={result.narrative} notice={result.advisoryNotice} />
          </>
        )}
      </div>
    </div>
  );
}

/** Screen a prepared batch before it goes for review. */
function BatchAnalyser() {
  const [batchId, setBatchId] = useState('');
  const { result, error, busy, ask } = useAsk<Awaited<ReturnType<typeof api.ai.analyseBatch>>>();

  return (
    <div className="card">
      <div className="card-body stack">
        <h2 className="section-title">Analyse a batch</h2>
        <p className="small muted">
          Duplicates, unusual amounts, recently changed payment details. The findings are computed
          by the risk engine, not written by the model.
        </p>

        <form
          className="row"
          style={{ gap: 'var(--s2)', alignItems: 'end', flexWrap: 'wrap' }}
          onSubmit={(event) => {
            event.preventDefault();
            void ask(() => api.ai.analyseBatch(batchId.trim()));
          }}
        >
          <div style={{ flex: '0 1 28rem' }}>
            <Field label="Batch id" hint="Copy it from the batch you want screened.">
              {(props) => (
                <input
                  {...props}
                  className="input"
                  required
                  value={batchId}
                  onChange={(event) => setBatchId(event.target.value)}
                />
              )}
            </Field>
          </div>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Analysing…' : 'Analyse'}
          </button>
        </form>

        {error && (
          <Notice tone="danger" live="assertive">
            {error}
          </Notice>
        )}

        {result && (
          <>
            {result.riskBand && (
              <p className="small">
                Risk <strong>{result.riskBand.toLowerCase()}</strong> ({result.riskScore})
              </p>
            )}
            {result.deterministicFindings.length === 0 ? (
              <Notice tone="success">The risk engine raised no findings on this batch.</Notice>
            ) : (
              result.deterministicFindings.map((finding: RiskSignalView, index) => (
                <Notice
                  key={`${finding.type}-${index}`}
                  tone={
                    finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                      ? 'danger'
                      : 'warning'
                  }
                >
                  <strong>{finding.severity}</strong> · {finding.summary}
                </Notice>
              ))
            )}
            {result.degraded && <Degraded reason={result.degradedReason} />}
            <Advisory text={result.narrative} notice={result.advisoryNotice} />
          </>
        )}
      </div>
    </div>
  );
}

/** "Why did payroll increase this month?" — the L2 financial assistant. */
function ExpenditureAssistant() {
  const [question, setQuestion] = useState('');
  const { result, error, busy, ask } = useAsk<Awaited<ReturnType<typeof api.ai.askExpenditure>>>();

  const suggestions = [
    'Why did payroll increase this month?',
    'Which department had the largest increase?',
    'Compare the last six payroll cycles.',
  ];

  return (
    <div className="card">
      <div className="card-body stack">
        <h2 className="section-title">Ask about expenditure</h2>
        <p className="small muted">
          Answered against your own payment cycles. The monthly totals below are the ledger's; the
          prose is the model's reading of them.
        </p>

        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void ask(() => api.ai.askExpenditure(question.trim()));
          }}
        >
          <Field label="Your question">
            {(props) => (
              <input
                {...props}
                className="input"
                required
                minLength={3}
                maxLength={500}
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
              />
            )}
          </Field>
          <div className="row" style={{ gap: 'var(--s2)', flexWrap: 'wrap' }}>
            {suggestions.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                className="button button-sm"
                data-variant="ghost"
                onClick={() => setQuestion(suggestion)}
              >
                {suggestion}
              </button>
            ))}
          </div>
          <button className="button" data-variant="primary" type="submit" disabled={busy}>
            {busy ? 'Thinking…' : 'Ask'}
          </button>
        </form>

        {error && (
          <Notice tone="danger" live="assertive">
            {error}
          </Notice>
        )}

        {result && (
          <>
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Period</th>
                    <th scope="col">Recipients</th>
                    <th scope="col">Disbursed</th>
                  </tr>
                </thead>
                <tbody>
                  {result.data.cycles.map((cycle) => (
                    <tr key={cycle.period}>
                      <td>{cycle.period}</td>
                      <td className="numeric">{cycle.recipientCount.toLocaleString('en-KE')}</td>
                      <td className="numeric">
                        <Amount cents={cycle.totalCents} showCurrency={false} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {result.degraded && <Degraded reason={null} />}
            <Advisory text={result.narrative} notice={result.advisoryNotice} />
          </>
        )}
      </div>
    </div>
  );
}

/** The executive brief of spec §12.2 — L3 only, and refused to everyone else server-side. */
function ExecutiveBriefing() {
  const { result, error, busy, ask } = useAsk<Awaited<ReturnType<typeof api.ai.briefing>>>();

  return (
    <div className="card">
      <div className="card-body stack">
        <h2 className="section-title">Executive briefing</h2>
        <p className="small muted">
          The organisation-wide picture, drafted from the last months of disbursements and the
          outstanding control items.
        </p>

        <button
          className="button"
          data-variant="primary"
          disabled={busy}
          onClick={() => void ask(() => api.ai.briefing())}
        >
          {busy ? 'Drafting…' : 'Draft the briefing'}
        </button>

        {error && (
          <Notice tone="danger" live="assertive">
            {error}
          </Notice>
        )}

        {result && (
          <>
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Month</th>
                    <th scope="col">Disbursed</th>
                  </tr>
                </thead>
                <tbody>
                  {result.figures.monthlyDisbursements.map((month) => (
                    <tr key={month.period}>
                      <td>{month.period}</td>
                      <td className="numeric">
                        <Amount cents={month.totalCents} showCurrency={false} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {result.figures.unresolvedReconciliationCases > 0 && (
              <Notice tone="warning">
                {result.figures.unresolvedReconciliationCases} payment
                {result.figures.unresolvedReconciliationCases === 1 ? '' : 's'} still have no
                confirmed outcome.
              </Notice>
            )}

            {result.figures.topFailureReasons.length > 0 && (
              <div>
                <h3 className="section-title">Most common failures</h3>
                <ul className="small">
                  {result.figures.topFailureReasons.map((failure) => (
                    <li key={failure.reason}>
                      {failure.reason} — {failure.count}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {result.degraded && <Degraded reason={null} />}
            <Advisory text={result.briefing} notice={result.advisoryNotice} />
          </>
        )}
      </div>
    </div>
  );
}
