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
import {
  api,
  ApiError,
  type ReportColumnView,
  type ReportDocumentView,
  type SessionResponse,
} from '../lib/api.js';
import { Notice, EmptyState, Field, Stat } from '../components/primitives.js';

/** Default period: the calendar month up to today, which is what month-end reporting asks for. */
function defaultPeriod(): { from: string; to: string } {
  const now = new Date();
  const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  return { from: from.toISOString().slice(0, 10), to: now.toISOString().slice(0, 10) };
}

export function ReportsPage({ user }: { user: SessionResponse['user'] }) {
  const [catalogue, setCatalogue] = useState<
    { family: string; title: string; description: string }[] | null
  >(null);
  const [family, setFamily] = useState<string>('');
  const [period, setPeriod] = useState(defaultPeriod);
  const [report, setReport] = useState<ReportDocumentView | null>(null);
  /*
   * The server already returns who generated this and under what export reference, and the
   * page was discarding both. On screen they are a nicety; on a printed page they are the
   * difference between evidence and an unattributable table of salary figures.
   */
  const [provenance, setProvenance] = useState<{
    generatedAt: string;
    exportReference: string;
  } | null>(null);
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
      setProvenance({
        generatedAt: result.generatedAt,
        exportReference: result.exportReference,
      });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The report could not be generated.');
      setReport(null);
      setProvenance(null);
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

      <div className="card screen-only">
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
                      setProvenance(null);
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
            {report && (
              <button className="button" data-variant="ghost" onClick={() => window.print()}>
                Print
              </button>
            )}
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

      {report && <RenderedReport report={report} provenance={provenance} user={user} />}
    </div>
  );
}

function RenderedReport({
  report,
  provenance,
  user,
}: {
  report: ReportDocumentView;
  provenance: { generatedAt: string; exportReference: string } | null;
  user: SessionResponse['user'];
}) {
  return (
    <div className="stack report-document">
      {/*
       * The printed masthead. It exists only on paper, because on screen the same facts are
       * carried by the top bar and the controls above. A report that leaves the building as a
       * PDF has none of that context, and a page of salary totals with no period, no
       * organisation and nobody's name on it is not evidence of anything.
       */}
      <div className="print-masthead" aria-hidden="true">
        <div className="print-masthead-row">
          <strong>SOLVAREN</strong>
          <span>{user.organizationSlug}</span>
        </div>
        <h1>{report.title}</h1>
        <p>
          Period {report.periodFrom.slice(0, 10)} to {report.periodTo.slice(0, 10)} (inclusive)
        </p>
        <p>
          Generated by {user.fullName} ({user.levelTitle})
          {provenance ? ` on ${provenance.generatedAt.slice(0, 16).replace('T', ' ')} UTC` : ''}
          {provenance ? ` · Export ${provenance.exportReference}` : ''}
        </p>
        <p>Contains payroll data. Handle under your organisation&rsquo;s data policy.</p>
      </div>

      <div className="card">
        <div className="card-body stack">
          <h2 className="section-title screen-only">{report.title}</h2>
          <p className="small muted screen-only">
            {report.periodFrom.slice(0, 10)} to {report.periodTo.slice(0, 10)} ·{' '}
            {report.description}
          </p>
          {provenance && (
            <p className="small muted screen-only">
              Export {provenance.exportReference} · generated{' '}
              {provenance.generatedAt.slice(0, 16).replace('T', ' ')} UTC by {user.fullName}
            </p>
          )}
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
                <colgroup>
                  {section.columns.map((column) => (
                    <col
                      key={column.key}
                      style={{ width: `${columnShare(section.columns, section.rows, column)}%` }}
                    />
                  ))}
                </colgroup>
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

/*
 * Proportional column widths, measured from the rendered content.
 *
 * Printing uses `table-layout: fixed`, so a wide table cannot run off the sheet — but fixed
 * layout gives every column an equal share, which spent as much width on "Charges" as on a
 * batch reference and wrapped the reference across three lines. Weighting by declared
 * format instead went too far the other way and broke "596,000.00" over two lines, which is
 * the one thing this product's typography exists to prevent: a wrapped figure reads as two
 * figures. The print stylesheet now forbids a figure from wrapping at all, so its column
 * has to be wide enough or the table overflows and the ui:check print assertion fails.
 *
 * Neither guess was needed. The rows are already in hand, formatted exactly as they will be
 * rendered, so a column is sized by the widest thing it actually has to show — heading
 * included, since a column must at least fit its own label. Character count is a crude
 * proxy for width, but with tabular figures in the numeric columns it is a good one, and it
 * needs no measurement pass and no hand-tuned table per report.
 *
 * The cap keeps one pathological value (a pasted note in a text column) from starving the
 * rest; the floor keeps a column of "12" from collapsing to a slit.
 *
 * On screen these are only hints — auto layout overrides them where content needs more.
 */
function columnShare(
  columns: ReportColumnView[],
  rows: Record<string, string | number | null>[],
  column: ReportColumnView,
): number {
  const weight = (c: ReportColumnView) => {
    const widest = rows.reduce(
      (max, row) => Math.max(max, formatCell(row[c.key], c.format).length),
      c.label.length,
    );
    /*
     * The +4 stands in for cell padding, which is a fixed cost per column rather than a
     * proportional one. Without it a narrow column pays the same padding out of a much
     * smaller share, and "Charges" — seven characters against a six-character value — came
     * out too narrow to print its own heading on one line.
     */
    return Math.min(Math.max(widest, 6), 20) + 4;
  };
  const total = columns.reduce((sum, c) => sum + weight(c), 0);
  return Math.round((weight(column) / total) * 10000) / 100;
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
