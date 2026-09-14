/**
 * Payment batches (spec §5, §21).
 *
 * The list is organised by what the actor can do next, not by creation date: an L2 officer
 * opening this page wants the queue awaiting review, and an L3 officer wants the batches
 * ready to authorize. Everything else is secondary.
 *
 * The release control appears on the batch detail panel only, and only when the batch is
 * genuinely ready — never as a button in a list row, where a mis-click is one pixel away
 * from a KES 8.4 million disbursement.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, type BatchSummary } from '../lib/api.js';
import {
  Amount,
  BatchStateChip,
  Notice,
  EmptyState,
  TableSkeleton,
} from '../components/primitives.js';
import { AuthorizationCeremony } from './AuthorizationCeremony.js';
import { NewBatch } from './NewBatch.js';
import { Modal } from '../components/primitives.js';

interface Props {
  capabilities: Record<string, boolean>;
  onReleased: (summary: {
    batchReference: string;
    instructionsQueued: number;
    message: string;
  }) => void;
  onViewTransactions: (batchId: string) => void;
}

/** Lifecycle states in the order they occur, for the filter control. */
const STATE_FILTERS = [
  { value: '', label: 'All' },
  { value: 'DRAFT', label: 'Draft' },
  { value: 'SUBMITTED_TO_L2', label: 'Awaiting review' },
  { value: 'L3_READY', label: 'Awaiting authorization' },
  { value: 'PROCESSING', label: 'Processing' },
  { value: 'PARTIAL_SUCCESS', label: 'Settled with failures' },
  { value: 'SUCCESS', label: 'Paid' },
];

export function BatchesPage({ capabilities, onReleased, onViewTransactions }: Props) {
  const [batches, setBatches] = useState<BatchSummary[]>([]);
  const [stateFilter, setStateFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [ceremonyBatchId, setCeremonyBatchId] = useState<string | null>(null);
  const [preparing, setPreparing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.batches.list(stateFilter || undefined);
      setBatches(result.batches);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Payment batches could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [stateFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const canAuthorize = capabilities['payment:release'];

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Payment batches</h1>
          <p className="page-subtitle">
            Every batch and where it stands in the approval chain. A batch edited after approval
            returns for re-review automatically — its previous approval no longer covers it.
          </p>
        </div>
      </div>

      <div className="filter-bar">
        <div className="filter-field" style={{ maxWidth: 260 }}>
          <label className="label" htmlFor="batch-state">
            Lifecycle state
          </label>
          <select
            id="batch-state"
            className="select"
            value={stateFilter}
            onChange={(event) => setStateFilter(event.target.value)}
          >
            {STATE_FILTERS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="filter-actions">
          {capabilities['batch:create'] && (
            <button
              className="button"
              data-variant="primary"
              onClick={() => setPreparing(true)}
              disabled={loading}
            >
              New batch
            </button>
          )}
          <button className="button" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      <div className="card">
        {loading ? (
          <TableSkeleton rows={5} columns={5} />
        ) : batches.length === 0 ? (
          <EmptyState title="No batches in this state">
            {capabilities['batch:create']
              ? 'Choose "New batch" to create one and upload a CSV of recipients and amounts.'
              : 'Payment Operations creates a batch by uploading a CSV of recipients and amounts.'}
          </EmptyState>
        ) : (
          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Batch</th>
                  <th scope="col">State</th>
                  <th scope="col" className="numeric">
                    Recipients
                  </th>
                  <th scope="col" className="numeric">
                    Total
                  </th>
                  <th scope="col">Outcome</th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {batches.map((batch) => (
                  <tr key={batch.batchId}>
                    <td>
                      <div className="mono small strong">{batch.batchReference}</div>
                    </td>
                    <td>
                      <BatchStateChip state={batch.state} />
                    </td>
                    <td className="numeric">{batch.instructionCount.toLocaleString('en-KE')}</td>
                    <td className="numeric">
                      <Amount cents={batch.totalAmountCents} showCurrency={false} />
                    </td>
                    <td>
                      {/* The roll-up of §6.1 — "182 SUCCESS / 3 FAILED / 1 TIMEOUT" — with
                          the failure count as a link to the filtered explorer. */}
                      {batch.outcomes.success + batch.outcomes.failed + batch.outcomes.timeout ===
                      0 ? (
                        <span className="muted small">Not yet executed</span>
                      ) : (
                        <div className="row small" style={{ gap: 'var(--s2)' }}>
                          {batch.outcomes.success > 0 && (
                            <span className="chip" data-tone="success">
                              {batch.outcomes.success} paid
                            </span>
                          )}
                          {batch.outcomes.failed > 0 && (
                            <button
                              className="chip"
                              data-tone="danger"
                              onClick={() => onViewTransactions(batch.batchId)}
                              style={{ cursor: 'pointer' }}
                            >
                              {batch.outcomes.failed} failed
                            </button>
                          )}
                          {batch.outcomes.timeout > 0 && (
                            <button
                              className="chip"
                              data-tone="warning"
                              onClick={() => onViewTransactions(batch.batchId)}
                              style={{ cursor: 'pointer' }}
                            >
                              {batch.outcomes.timeout} unresolved
                            </button>
                          )}
                          {batch.outcomes.inFlight > 0 && (
                            <span className="chip" data-tone="info">
                              {batch.outcomes.inFlight} in flight
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="right">
                      {/* The release entry point exists only on a batch that is genuinely
                          ready, and only for an actor with release authority. */}
                      {canAuthorize && batch.state === 'L3_READY' && (
                        <button
                          className="button button-sm"
                          data-variant="primary"
                          onClick={() => setCeremonyBatchId(batch.batchId)}
                        >
                          Review &amp; authorize
                        </button>
                      )}
                      {batch.state === 'AUTHORIZATION_PENDING' && canAuthorize && (
                        <button
                          className="button button-sm"
                          onClick={() => setCeremonyBatchId(batch.batchId)}
                        >
                          Resume authorization
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {preparing && (
        <Modal open onClose={() => setPreparing(false)} labelledBy="new-batch-title">
          <h2 id="new-batch-title" className="page-title">
            New payment batch
          </h2>
          <NewBatch onClose={() => setPreparing(false)} onDone={() => void load()} />
        </Modal>
      )}

      {ceremonyBatchId && (
        <AuthorizationCeremony
          batchId={ceremonyBatchId}
          onClose={() => {
            setCeremonyBatchId(null);
            void load();
          }}
          onReleased={(summary) => {
            setCeremonyBatchId(null);
            onReleased(summary);
            void load();
          }}
        />
      )}
    </div>
  );
}
