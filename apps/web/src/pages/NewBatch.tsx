/**
 * Preparing a batch (spec §5.1, §5.2).
 *
 * This is the front half of the payment path, and it was missing entirely. The API had
 * create, upload, validate and submit from the beginning; nothing in the console called any
 * of them, so a batch could be reviewed, approved and released but never brought into
 * existence. The empty state on the batches page even instructed the operator to upload a
 * CSV, with no control anywhere to do it.
 *
 * The flow follows the spec's order because each step's result changes what the next one
 * should say:
 *
 *   1. Create a draft, so there is something to attach rows to and to audit against.
 *   2. Upload the CSV. Bad rows are REPORTED, not fatal — a payroll of two thousand with six
 *      malformed numbers should let the operator fix six lines, not re-export the file.
 *   3. Validate, which runs risk screening and returns findings.
 *   4. Submit to Finance Control. From here the preparer is out of the loop: they cannot
 *      approve their own batch, which is the whole point of the separation.
 */

import { useState } from 'react';
import { api, ApiError, type RiskSignalView } from '../lib/api.js';
import { Notice, Field, Amount } from '../components/primitives.js';

type Stage = 'details' | 'upload' | 'review' | 'submitted';

interface UploadResult {
  accepted: number;
  /**
   * The parser names these lineNumber/reason. Reading them as line/message renders a blank
   * explanation, which turns a correct and precisely-worded rejection ("M-PESA B2C pays
   * whole shillings only; remove the cents component") into an unexplained failure — and
   * makes the upload itself look broken when it is working exactly as intended.
   */
  rejected: { lineNumber: number; column: string; value: string; reason: string }[];
  duplicateWarnings: {
    msisdn: string;
    amountCents: number;
    lineNumbers: number[];
    reason: string;
  }[];
  totalAmountCents: number;
}

interface ValidationResult {
  state: string;
  risk: {
    score: number;
    band: 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
    signals: RiskSignalView[];
    requiresAcknowledgement: boolean;
  };
}

export function NewBatch({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [stage, setStage] = useState<Stage>('details');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [purpose, setPurpose] = useState('');
  const [paymentPeriod, setPaymentPeriod] = useState('');

  const [batch, setBatch] = useState<{ batchId: string; batchReference: string } | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploaded, setUploaded] = useState<UploadResult | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);

  async function run(operation: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'That did not work.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      {batch && <div className="small muted">Batch {batch.batchReference}</div>}

      {/* ---- 1. Details ---- */}
      {stage === 'details' && (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void run(async () => {
              const created = await api.batches.create(purpose, paymentPeriod || undefined);
              setBatch({ batchId: created.batchId, batchReference: created.batchReference });
              setStage('upload');
            });
          }}
        >
          <Field
            label="What is this batch for?"
            hint="For example: September payroll, supplier run"
          >
            {(props) => (
              <input
                {...props}
                className="input"
                required
                minLength={3}
                maxLength={200}
                value={purpose}
                onChange={(event) => setPurpose(event.target.value)}
              />
            )}
          </Field>

          <Field label="Payment period (optional)" hint="For example: 2026-09">
            {(props) => (
              <input
                {...props}
                className="input"
                maxLength={60}
                value={paymentPeriod}
                onChange={(event) => setPaymentPeriod(event.target.value)}
              />
            )}
          </Field>

          <div style={{ display: 'flex', gap: 'var(--s3)' }}>
            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Creating…' : 'Create draft'}
            </button>
            <button className="button" data-variant="ghost" type="button" onClick={onClose}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* ---- 2. Upload ---- */}
      {stage === 'upload' && batch && (
        <div className="stack">
          <Notice tone="info">
            A CSV with one row per recipient. Expected columns: recipient name, M-PESA number,
            amount. Rows that cannot be read are listed back to you rather than rejecting the whole
            file.
          </Notice>

          <Field label="CSV file" hint="Up to 8 MB">
            {(props) => (
              <input
                {...props}
                className="input"
                type="file"
                accept=".csv,text/csv"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              />
            )}
          </Field>

          {uploaded && (
            <div className="card">
              <div className="card-body stack">
                <div style={{ display: 'flex', gap: 'var(--s5)', flexWrap: 'wrap' }}>
                  <div>
                    <div className="small muted">Rows accepted</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>{uploaded.accepted}</div>
                  </div>
                  <div>
                    <div className="small muted">Total</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                      <Amount cents={uploaded.totalAmountCents} />
                    </div>
                  </div>
                  <div>
                    <div className="small muted">Rows rejected</div>
                    <div
                      style={{
                        fontSize: '1.4rem',
                        fontWeight: 700,
                        color: uploaded.rejected.length ? 'var(--danger)' : undefined,
                      }}
                    >
                      {uploaded.rejected.length}
                    </div>
                  </div>
                </div>

                {uploaded.rejected.length > 0 && (
                  <div className="table-scroll" style={{ maxHeight: 260 }}>
                    <table className="table">
                      <thead>
                        <tr>
                          <th scope="col">Line</th>
                          <th scope="col">Column</th>
                          <th scope="col">Value</th>
                          <th scope="col">Why</th>
                        </tr>
                      </thead>
                      <tbody>
                        {uploaded.rejected.map((row, index) => (
                          <tr key={`${row.lineNumber}-${row.column}-${index}`}>
                            <td>{row.lineNumber}</td>
                            <td>{row.column}</td>
                            <td className="small">{row.value}</td>
                            <td className="small">{row.reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {uploaded.duplicateWarnings.length > 0 && (
                  <Notice tone="warning">
                    <div className="stack">
                      <div>
                        {uploaded.duplicateWarnings.length} possible duplicate recipient
                        {uploaded.duplicateWarnings.length === 1 ? '' : 's'}. Review before
                        submitting — paying someone twice is not something the provider undoes.
                      </div>
                      <ul className="small">
                        {uploaded.duplicateWarnings.map((warning) => (
                          <li key={`${warning.msisdn}-${warning.lineNumbers.join('-')}`}>
                            {warning.reason} (lines {warning.lineNumbers.join(', ')})
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Notice>
                )}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
            <button
              className="button"
              data-variant={uploaded ? 'ghost' : 'primary'}
              disabled={busy || !file}
              onClick={() =>
                void run(async () => {
                  const result = await api.batches.uploadCsv(batch.batchId, file!);
                  setUploaded(result);
                })
              }
            >
              {busy ? 'Uploading…' : uploaded ? 'Upload another file' : 'Upload CSV'}
            </button>

            {uploaded && uploaded.accepted > 0 && (
              <button
                className="button"
                data-variant="primary"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const result = await api.batches.validate(batch.batchId);
                    setValidation(result);
                    setStage('review');
                  })
                }
              >
                Validate and screen
              </button>
            )}

            <button className="button" data-variant="ghost" onClick={onClose} disabled={busy}>
              Finish later
            </button>
          </div>
        </div>
      )}

      {/* ---- 3. Review ---- */}
      {stage === 'review' && batch && validation && (
        <div className="stack">
          <div className="card">
            <div className="card-body stack">
              <div style={{ display: 'flex', gap: 'var(--s5)', flexWrap: 'wrap' }}>
                <div>
                  <div className="small muted">Recipients</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    {uploaded?.accepted ?? 0}
                  </div>
                </div>
                <div>
                  <div className="small muted">Total</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    <Amount cents={uploaded?.totalAmountCents ?? 0} />
                  </div>
                </div>
                <div>
                  <div className="small muted">Risk</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    {validation.risk.band}
                    <span className="small muted"> ({validation.risk.score})</span>
                  </div>
                </div>
              </div>

              {validation.risk.signals.length > 0 ? (
                <div className="stack">
                  <h3 className="section-title">Risk findings</h3>
                  {validation.risk.signals.map((finding) => (
                    <Notice
                      key={`${finding.type}-${finding.summary}`}
                      tone={
                        finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                          ? 'warning'
                          : 'info'
                      }
                    >
                      {finding.summary}
                    </Notice>
                  ))}
                  <p className="small muted">
                    Findings do not block submission. Finance Control and the authorizer see them,
                    and each must be dispositioned before a release at or above the organisation's
                    blocking band.
                  </p>
                </div>
              ) : (
                <Notice tone="success">Screening raised no findings.</Notice>
              )}
            </div>
          </div>

          <Notice tone="info">
            Submitting hands this to Finance Control. You will not be able to approve it yourself —
            the same person cannot prepare and approve the same payment.
          </Notice>

          <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
            <button
              className="button"
              data-variant="primary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await api.batches.submit(batch.batchId);
                  setStage('submitted');
                })
              }
            >
              {busy ? 'Submitting…' : 'Submit for review'}
            </button>
            <button
              className="button"
              data-variant="ghost"
              disabled={busy}
              onClick={() => setStage('upload')}
            >
              Back to the file
            </button>
          </div>
        </div>
      )}

      {/* ---- 4. Done ---- */}
      {stage === 'submitted' && batch && (
        <div className="stack">
          <Notice tone="success">
            {batch.batchReference} has been submitted to Finance Control for review.
          </Notice>
          <button
            className="button"
            data-variant="primary"
            onClick={() => {
              onDone();
              onClose();
            }}
          >
            Done
          </button>
        </div>
      )}
    </div>
  );
}
