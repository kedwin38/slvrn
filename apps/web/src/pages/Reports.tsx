/**
 * Reports (spec §12).
 *
 * The catalogue comes from the server, already filtered to what this person may generate.
 * The console does not decide what to show: an L2 asking for the executive report is refused
 * by the endpoint, and hiding the tile is only a courtesy on top of that.
 *
 * Two things are deliberate in the rendering. The period is always printed on the report,
 * because a table headed "September" with no year is useless as evidence. And AI narrative,
 * where a report has any, is rendered in its own marked block — §12.2 requires computed facts
 * and generated narrative to be distinguishable, and a model's guess formatted like a figure
 * is exactly how it ends up quoted in a board pack as one.
 */

import { useCallback, useEffect, useState } from 'react';
import { formatCents } from '@solvaren/core';
import { api, ApiError, type ReportDocumentView } from '../lib/api.js';
import { Notice, EmptyState, Field, Stat } from '../components/primitives.js';

/** Default period: the calendar month up to today, which is what month-end reporting asks for. */
function defaultPeriod(): { from: string; to: string } {
  const now = new Date();
  const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  return { from: from.toISOString().slice(0, 10), to: now.toISOString().slice(0, 10) };
}

export function ReportsPage() {
  const [catalogue, setCatalogue] = useState<
    { family: string; title: string; description: string }[] | null
  >(null);
  const [family, setFamily] = useState<string>('');
  const [period, setPeriod] = useState(defaultPeriod);
  const [report, setReport] = useState<ReportDocumentView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.reports
      .catalogue()
      .then((result) => {
        setCatalogue(result.reports);
        setFamily((current) => current || (result.reports[0]?.family ?? ''));
      })
      .catch((err: unknown) =>
        setError(err instanceof ApiError ? err.message : 'The report list could not be loaded.'),
      );
  }, []);

  const generate = useCallback(async () => {
    if (!family) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.reports.generate(family, period.from, period.to);
      setReport(result.report);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The report could not be generated.');
      setReport(null);
    } finally {
      setBusy(false);
    }
  }, [family, period]);

  const selected = catalogue?.find((entry) => entry.family === family);

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">
            Every figure is computed from the payment ledger for the period you choose. Who
            generated a report, and when, is recorded — these carry salary data.
          </p>
        </div>
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      <div className="card">
        <div className="card-body stack">
          <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'end' }}>
            <div style={{ flex: '1 1 260px' }}>
              <Field label="Report">
                {(props) => (
                  <select
                    {...props}
                    className="input"
                    value={family}
                    onChange={(event) => {
                      setFamily(event.target.value);
                      setReport(null);
                    }}
                  >
                    {(catalogue ?? []).map((entry) => (
                      <option key={entry.family} value={entry.family}>
                        {entry.title}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            </div>
            <div>
              <Field label="From">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="date"
                    value={period.from}
                    onChange={(event) => setPeriod({ ...period, from: event.target.value })}
                  />
                )}
              </Field>
            </div>
            <div>
              <Field label="To" hint="Inclusive — the last day counts.">
                {(props) => (
                  <input
                    {...props}
                    className="input"
                    type="date"
                    value={period.to}
                    onChange={(event) => setPeriod({ ...period, to: event.target.value })}
                  />
                )}
              </Field>
            </div>
            <button
              className="button"
              data-variant="primary"
              disabled={busy || !family}
              onClick={() => void generate()}
            >
              {busy ? 'Generating…' : 'Generate'}
            </button>
            <button
              className="button"
              data-variant="ghost"
              disabled={busy || !family}
              onClick={() => {
                void api.reports
                  .downloadCsv(family, period.from, period.to)
                  .catch((err: unknown) =>
                    setError(err instanceof ApiError ? err.message : 'The download failed.'),
                  );
              }}
            >
              Download CSV
            </button>
          </div>
          {selected && <p className="small muted">{selected.description}</p>}
        </div>
      </div>

      {catalogue !== null && catalogue.length === 0 && (
        <EmptyState title="No reports available to you">
          Reporting is granted by authority level. Ask an administrator if you expect to see
          something here.
        </EmptyState>
      )}

      {report && <RenderedReport report={report} />}
    </div>
  );
}

function RenderedReport({ report }: { report: ReportDocumentView }) {
  return (
    <div className="stack">
      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title">{report.title}</h2>
          <p className="small muted">
            {report.periodFrom.slice(0, 10)} to {report.periodTo.slice(0, 10)} ·{' '}
            {report.description}
          </p>
          <div className="grid">
            {report.highlights.map((highlight) => (
              <Stat
                key={highlight.label}
                label={highlight.label}
                value={highlight.value}
                detail={highlight.hint}
              />
            ))}
          </div>
        </div>
      </div>

      {report.narrative && (
        <Notice tone="info">
          <strong>AI advisory, not a computed figure</strong> ({report.narrative.model}):{' '}
          {report.narrative.text}
        </Notice>
      )}

      {report.sections.map((section) => (
        <div className="card" key={section.title}>
          <div className="card-body">
            <h3 className="section-title">{section.title}</h3>
          </div>
          {section.rows.length === 0 ? (
            <div className="card-body">
              <p className="small muted">Nothing in this period.</p>
            </div>
          ) : (
            <div className="table-scroll">
              <table className="table">
                <thead>
                  <tr>
                    {section.columns.map((column) => (
                      <th key={column.key} scope="col">
                        {column.label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {section.rows.map((row, index) => (
                    <tr key={index}>
                      {section.columns.map((column) => (
                        <td
                          key={column.key}
                          className={column.format === 'money' ? 'numeric' : undefined}
                        >
                          {formatCell(row[column.key], column.format)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function formatCell(
  value: string | number | null | undefined,
  format: 'money' | 'number' | 'text' | 'timestamp' | undefined,
): string {
  if (value === null || value === undefined || value === '') return '—';
  if (format === 'money') return formatCents(typeof value === 'number' ? value : Number(value));
  // An ISO timestamp is unreadable in a table; the date alone is what a reader scans for.
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    return value.slice(0, 16).replace('T', ' ');
  }
  return String(value);
}
