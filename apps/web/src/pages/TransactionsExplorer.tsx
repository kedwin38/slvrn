/**
 * Transactions Explorer (spec §6.3, TRK-001/003/004, AC-16/17/18).
 *
 * The screen that makes "no failed payment is ever invisible or unexplained" true for the
 * person actually doing the work. Design decisions that matter here:
 *
 *  - **Failure reasons expand inline**, not in a modal. A finance officer triaging thirty
 *    failures needs to read thirty reasons in sequence; a modal per row would be thirty
 *    open-and-close cycles.
 *  - **Sorting and paging are server-side**, so the screen stays responsive at hundreds of
 *    thousands of rows (NFR-OPS-002) and a sort means "sort everything", not "sort this
 *    page", which would be quietly wrong.
 *  - **The export honours the current filter** and says so, because a CSV that silently
 *    contains something other than what is on screen is worse than no CSV.
 *  - **Status counts are the filter.** Clicking "3 failed" filters to those three; the
 *    roll-up and the control are the same object, which removes a whole class of "I
 *    filtered but the number did not change" confusion.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  SORT_COLUMNS,
  TXN_STATES,
  formatCents,
  maskMsisdn,
  type TxnState,
  type SortColumn,
} from '@solvaren/core';
import { api, ApiError, type ExplorerResponse, type TransactionRow } from '../lib/api.js';
import {
  Amount,
  StatusChip,
  Notice,
  EmptyState,
  TableSkeleton,
  Reference,
  RelativeTime,
} from '../components/primitives.js';

interface Props {
  capabilities: Record<string, boolean>;
  /** Pre-applied filter, set when arriving from a dashboard drill-down. */
  initialStatuses?: TxnState[];
  initialBatchId?: string;
}

const COLUMN_LABELS: Record<SortColumn, string> = {
  date: 'Created',
  submitted: 'Submitted',
  updated: 'Updated',
  amount: 'Amount',
  recipient: 'Recipient',
  status: 'Status',
  batch: 'Batch',
  failure: 'Failure code',
};

/** The statuses offered as quick filters, in the order an operator triages them. */
const FILTER_STATUSES: TxnState[] = [
  'FAILED',
  'TIMEOUT',
  'RECONCILING',
  'AWAITING_CALLBACK',
  'PROCESSING',
  'SUCCESS',
];

export function TransactionsExplorer({ capabilities, initialStatuses, initialBatchId }: Props) {
  const [statuses, setStatuses] = useState<TxnState[]>(initialStatuses ?? []);
  const [search, setSearch] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sort, setSort] = useState<SortColumn>('date');
  const [direction, setDirection] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);

  const [data, setData] = useState<ExplorerResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);
  const [includeAmbiguous, setIncludeAmbiguous] = useState(true);

  // Debounced free-text search: a request per keystroke against a large ledger is a
  // self-inflicted denial of service.
  const [debouncedSearch, setDebouncedSearch] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(timer);
  }, [search]);

  const params = useMemo(() => {
    const query = new URLSearchParams();
    for (const status of statuses) query.append('status', status);
    if (debouncedSearch.trim()) query.set('search', debouncedSearch.trim());
    if (dateFrom) query.set('dateFrom', new Date(dateFrom).toISOString());
    if (dateTo) query.set('dateTo', new Date(`${dateTo}T23:59:59`).toISOString());
    if (initialBatchId) query.set('batchId', initialBatchId);
    query.set('sort', sort);
    query.set('direction', direction);
    query.set('page', String(page));
    query.set('pageSize', '50');
    return query;
  }, [statuses, debouncedSearch, dateFrom, dateTo, sort, direction, page, initialBatchId]);

  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError(null);
    try {
      setData(await api.transactions.list(params, controller.signal));
    } catch (err) {
      if (controller.signal.aborted) return;
      setError(
        err instanceof ApiError
          ? err
          : new ApiError(0, {
              code: 'NETWORK',
              category: 'INTERNAL',
              message: 'Could not reach SOLVAREN. Check your connection and try again.',
            }),
      );
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    void load();
    return () => abortRef.current?.abort();
  }, [load]);

  function toggleStatus(status: TxnState) {
    setPage(1);
    setStatuses((current) =>
      current.includes(status) ? current.filter((s) => s !== status) : [...current, status],
    );
  }

  function applySort(column: SortColumn) {
    setPage(1);
    if (sort === column) {
      setDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSort(column);
      setDirection('desc');
    }
  }

  async function exportFailed() {
    setExporting(true);
    setExportNotice(null);
    try {
      const exportParams = new URLSearchParams(params);
      exportParams.delete('page');
      exportParams.delete('pageSize');
      exportParams.set('includeAmbiguous', String(includeAmbiguous));

      const { blob, filename, truncated } = await api.exports.failedTransactions(exportParams);

      // Object URL rather than a data: URL, so a large export does not have to fit in a
      // string, and revoked immediately so it does not linger in memory.
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);

      setExportNotice(
        truncated
          ? `${filename} downloaded. The result set was larger than the export limit, so the file is truncated — narrow the filter and export again to capture the rest.`
          : `${filename} downloaded. This export has been recorded in the audit log.`,
      );
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setExporting(false);
    }
  }

  const canExport = capabilities['transactions:export_failed'] === true;
  const canRefresh = capabilities['transactions:refresh_status'] === true;
  const rows = data?.transactions ?? [];

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Transactions</h1>
          <p className="page-subtitle">
            Every payment outcome, with the reason for each failure. Filter and sort to isolate what
            needs attention, then export the failures for follow-up.
          </p>
        </div>
      </div>

      {/* ---- Status filters, which double as the roll-up ------------------ */}
      <div className="filter-bar">
        <fieldset style={{ border: 'none', padding: 0, margin: 0, flex: '1 1 100%' }}>
          <legend className="label" style={{ padding: 0, marginBlockEnd: 'var(--s2)' }}>
            Status
          </legend>
          <div className="status-toggles">
            {FILTER_STATUSES.map((status) => (
              <button
                key={status}
                className="status-toggle"
                aria-pressed={statuses.includes(status)}
                onClick={() => toggleStatus(status)}
              >
                <StatusChip status={status} />
              </button>
            ))}
            {statuses.length > 0 && (
              <button
                className="button button-sm"
                data-variant="ghost"
                onClick={() => {
                  setStatuses([]);
                  setPage(1);
                }}
              >
                Clear
              </button>
            )}
          </div>
        </fieldset>

        <div className="filter-field">
          <label className="label" htmlFor="txn-search">
            Search
          </label>
          <input
            id="txn-search"
            className="input"
            type="search"
            placeholder="Name, receipt, conversation id"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="filter-field">
          <label className="label" htmlFor="txn-from">
            From
          </label>
          <input
            id="txn-from"
            className="input"
            type="date"
            value={dateFrom}
            onChange={(event) => {
              setDateFrom(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="filter-field">
          <label className="label" htmlFor="txn-to">
            To
          </label>
          <input
            id="txn-to"
            className="input"
            type="date"
            value={dateTo}
            onChange={(event) => {
              setDateTo(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="filter-actions">
          {canExport && (
            <>
              <label className="row small muted" style={{ gap: 'var(--s2)' }}>
                <input
                  type="checkbox"
                  checked={includeAmbiguous}
                  onChange={(event) => setIncludeAmbiguous(event.target.checked)}
                />
                Include unresolved
              </label>
              <button
                className="button"
                data-variant="primary"
                onClick={exportFailed}
                disabled={exporting}
              >
                {exporting ? 'Preparing…' : 'Export failed transactions (CSV)'}
              </button>
            </>
          )}
        </div>
      </div>

      {exportNotice && (
        <Notice tone="success" live="polite">
          {exportNotice}
        </Notice>
      )}

      {error && (
        <Notice tone="danger" title={error.code} live="assertive">
          {error.message}
          {error.correlationId && (
            <div className="small muted mt-4">Reference: {error.correlationId}</div>
          )}
        </Notice>
      )}

      {/* ---- Results ----------------------------------------------------- */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            {data ? `${data.page.totalRows.toLocaleString('en-KE')} transactions` : 'Transactions'}
          </span>
          {data && <span className="small muted">{data.filter.text}</span>}
        </div>

        {loading && !data ? (
          <TableSkeleton rows={8} columns={6} />
        ) : rows.length === 0 ? (
          <EmptyState title="No transactions match this filter">
            {statuses.length > 0
              ? 'Try clearing the status filter or widening the date range.'
              : 'Transactions appear here once a batch has been authorized and submitted to M-PESA.'}
          </EmptyState>
        ) : (
          <>
            <div className="table-scroll">
              <table className="table">
                <caption className="visually-hidden">
                  Transactions, sorted by {COLUMN_LABELS[sort]}{' '}
                  {direction === 'asc' ? 'ascending' : 'descending'}
                </caption>
                <thead>
                  <tr>
                    {(['recipient', 'batch', 'amount', 'status', 'date'] as SortColumn[]).map(
                      (column) => (
                        <th
                          key={column}
                          scope="col"
                          className={column === 'amount' ? 'numeric' : undefined}
                          aria-sort={
                            sort === column
                              ? direction === 'asc'
                                ? 'ascending'
                                : 'descending'
                              : 'none'
                          }
                        >
                          <button
                            className="sort-button"
                            data-active={sort === column}
                            onClick={() => applySort(column)}
                          >
                            {COLUMN_LABELS[column]}
                            <span className="sort-indicator" aria-hidden="true">
                              {sort === column ? (direction === 'asc' ? '↑' : '↓') : '↕'}
                            </span>
                          </button>
                        </th>
                      ),
                    )}
                    <th scope="col">Receipt</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <TransactionRowView
                      key={row.transactionId}
                      row={row}
                      expanded={expanded === row.transactionId}
                      onToggle={() =>
                        setExpanded((current) =>
                          current === row.transactionId ? null : row.transactionId,
                        )
                      }
                      canRefresh={canRefresh}
                      onRefreshed={load}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            {data && (
              <div className="pagination">
                <span className="pagination-summary">
                  Page {data.page.page} of {data.page.totalPages} ·{' '}
                  {data.page.totalRows.toLocaleString('en-KE')} rows
                </span>
                <div className="row">
                  <button
                    className="button button-sm"
                    disabled={!data.page.hasPrevious || loading}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    Previous
                  </button>
                  <button
                    className="button button-sm"
                    disabled={!data.page.hasNext || loading}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* The sort allowlist is the same object the server validates against; rendering it
          here keeps the two visibly in step for anyone reading the code. */}
      <p className="visually-hidden">
        Sortable columns: {Object.keys(SORT_COLUMNS).join(', ')}. Statuses: {TXN_STATES.join(', ')}.
      </p>
    </div>
  );
}

function TransactionRowView({
  row,
  expanded,
  onToggle,
  canRefresh,
  onRefreshed,
}: {
  row: TransactionRow;
  expanded: boolean;
  onToggle: () => void;
  canRefresh: boolean;
  onRefreshed: () => void;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState<string | null>(null);

  const hasFailure = row.status === 'FAILED' || row.status === 'TIMEOUT';
  const detailId = `detail-${row.transactionId}`;

  async function refresh() {
    setRefreshing(true);
    try {
      const result = await api.transactions.refresh(row.transactionId);
      setRefreshMessage(result.message);
      onRefreshed();
    } catch (err) {
      setRefreshMessage(
        err instanceof ApiError ? err.message : 'The refresh could not be requested.',
      );
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <>
      <tr>
        <td>
          <div className="strong">{row.recipientName}</div>
          {/* Masked in the list: a screen of full phone numbers is an unnecessary
              exposure over a shoulder. The detail view shows the full number. */}
          <div className="small muted mono">{maskMsisdn(row.msisdn)}</div>
        </td>
        <td>
          <div className="small mono">{row.batchReference}</div>
          {row.departmentName && <div className="small muted">{row.departmentName}</div>}
        </td>
        <td className="numeric">
          <Amount cents={row.amountCents} showCurrency={false} />
        </td>
        <td>
          <StatusChip status={row.status} />
        </td>
        <td>
          <RelativeTime value={row.completedAt ?? row.submittedAt ?? row.createdAt} />
        </td>
        <td>
          {row.mpesaReceiptNumber ? (
            <code className="reference">{row.mpesaReceiptNumber}</code>
          ) : (
            <span className="muted small">—</span>
          )}
        </td>
        <td className="right">
          {hasFailure && (
            <button
              className="button button-sm"
              onClick={onToggle}
              aria-expanded={expanded}
              aria-controls={detailId}
            >
              {expanded ? 'Hide reason' : 'Why?'}
            </button>
          )}
        </td>
      </tr>

      {expanded && hasFailure && (
        <tr className="reason-row" id={detailId}>
          <td colSpan={7}>
            <div className="reason-block">
              <div className="reason-headline">
                {/* The provider code is set apart rather than run into the sentence: it is
                    the token an operator quotes to Safaricom support, and "1 Insufficient
                    balance" reads as a quantity. */}
                {row.failureCode && <span className="failure-code">{row.failureCode}</span>}
                {/* TRK-002: never blank. If the dictionary has no entry, the server
                    supplies the provider's own description instead. */}
                <span>{row.failureReason ?? 'No reason was recorded for this failure.'}</span>
              </div>

              {row.operatorAction && <div className="reason-action">{row.operatorAction}</div>}

              {row.providerResultDescription && (
                <div className="small muted">
                  M-PESA reported: “{row.providerResultDescription}”
                </div>
              )}

              <dl className="finding-evidence">
                <div>
                  <dt>Conversation&nbsp;</dt>
                  <dd>
                    <Reference value={row.conversationId} label="conversation id" />
                  </dd>
                </div>
                <div>
                  <dt>Originator&nbsp;</dt>
                  <dd>
                    <Reference
                      value={row.originatorConversationId}
                      label="originator conversation id"
                    />
                  </dd>
                </div>
                <div>
                  <dt>Last checked&nbsp;</dt>
                  <dd>
                    <RelativeTime value={row.lastStatusCheckAt} />
                    {row.statusSource && <span className="muted"> via {row.statusSource}</span>}
                  </dd>
                </div>
                <div>
                  <dt>Amount&nbsp;</dt>
                  <dd>KES {formatCents(row.amountCents)}</dd>
                </div>
              </dl>

              {canRefresh && row.status !== 'FAILED' && (
                <div className="row">
                  <button className="button button-sm" onClick={refresh} disabled={refreshing}>
                    {refreshing ? 'Requesting…' : 'Check status with M-PESA'}
                  </button>
                  {refreshMessage && (
                    <span className="small muted" role="status">
                      {refreshMessage}
                    </span>
                  )}
                </div>
              )}

              {row.status === 'TIMEOUT' && (
                <Notice tone="warning">
                  The outcome of this payment is not yet known. SOLVAREN will not resubmit it —
                  doing so could pay the recipient twice. Reconciliation is querying M-PESA.
                </Notice>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
