/**
 * Dashboards (spec §12, §21).
 *
 * Three views behind one component, selected by what the actor is actually permitted to
 * see. The rule this follows: **the UI renders from the capability payload, and the server
 * enforces**. If the two ever disagree, the worst outcome is a panel that fails to load —
 * never a panel that shows data the actor should not have.
 *
 * The L3 balance and recent-transactions panels are the sharpest case (AC-19). They are
 * hidden here *and* rejected by the API for non-L3 callers; this file is the convenience,
 * `routes/dashboard.ts` is the control.
 */

import { useEffect, useState } from 'react';
import { formatCents, maskMsisdn } from '@solvaren/core';
import {
  api,
  ApiError,
  type BalancePanel,
  type OperationalDashboard,
} from '../lib/api.js';
import { Amount, Stat, Notice, EmptyState, RelativeTime, StatusChip } from '../components/primitives.js';
import type { TxnState } from '@solvaren/core';

interface Props {
  capabilities: Record<string, boolean>;
  level: 'L1' | 'L2' | 'L3';
  fullName: string;
  /** Drill-down into the explorer, pre-filtered (spec §6.3). */
  onDrillDown: (statuses: TxnState[]) => void;
}

export function Dashboard({ capabilities, level, fullName, onDrillDown }: Props) {
  const [operational, setOperational] = useState<OperationalDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.analytics.operational();
        if (!cancelled) setOperational(data);
      } catch (err) {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Could not load the dashboard.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const attention = operational?.needsAttention;
  const needsAttention = (attention?.failed ?? 0) + (attention?.timeout ?? 0) > 0;

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            {greeting()}, {fullName.split(' ')[0]}
          </h1>
          <p className="page-subtitle">
            {level === 'L3'
              ? 'Executive payment authority. Organisation-wide position and outstanding authorizations.'
              : level === 'L2'
                ? 'Finance control. Batches awaiting review and the current reconciliation position.'
                : 'Payment operations. Batch preparation and the outcome of what has been submitted.'}
          </p>
        </div>
      </div>

      {error && (
        <Notice tone="danger" live="assertive">
          {error}
        </Notice>
      )}

      {/* ---- Attention first ---------------------------------------------
          The most important thing a payment console can do on load is say what
          went wrong, with one click to the affected rows. */}
      {needsAttention && attention && (
        <Notice tone="danger" title="Payments need attention">
          <div className="row" style={{ marginBlockStart: 'var(--s2)' }}>
            {attention.failed > 0 && (
              <button className="button button-sm" onClick={() => onDrillDown(['FAILED'])}>
                {attention.failed} failed
              </button>
            )}
            {attention.timeout > 0 && (
              <button className="button button-sm" onClick={() => onDrillDown(['TIMEOUT'])}>
                {attention.timeout} unresolved
              </button>
            )}
            {attention.reconciling > 0 && (
              <button className="button button-sm" onClick={() => onDrillDown(['RECONCILING'])}>
                {attention.reconciling} reconciling
              </button>
            )}
          </div>
        </Notice>
      )}

      {/* ---- Operational statistics --------------------------------------- */}
      <div className="grid">
        <Stat
          label="Paid (30 days)"
          value={loading ? '—' : (operational?.transactions.success ?? 0).toLocaleString('en-KE')}
          detail={
            operational?.transactions.successRate !== null && operational?.transactions.successRate !== undefined
              ? `${(operational.transactions.successRate * 100).toFixed(1)}% success rate`
              : 'No transactions yet'
          }
          tone="success"
          onClick={() => onDrillDown(['SUCCESS'])}
        />
        <Stat
          label="Failed (30 days)"
          value={loading ? '—' : (operational?.transactions.failed ?? 0).toLocaleString('en-KE')}
          detail="Every failure has a recorded reason"
          tone={(operational?.transactions.failed ?? 0) > 0 ? 'danger' : undefined}
          onClick={() => onDrillDown(['FAILED'])}
        />
        <Stat
          label="In flight"
          value={loading ? '—' : (operational?.transactions.inFlight ?? 0).toLocaleString('en-KE')}
          detail="Submitted, awaiting an outcome from M-PESA"
          onClick={() => onDrillDown(['SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING'])}
        />
        <Stat
          label="Median settlement"
          value={
            operational?.processingSeconds.median
              ? `${Math.round(operational.processingSeconds.median)}s`
              : '—'
          }
          detail={
            operational?.processingSeconds.p95
              ? `95th percentile ${Math.round(operational.processingSeconds.p95)}s`
              : 'Measured from submission to result'
          }
        />
      </div>

      {/* ---- L3-only panels (spec §21, AC-19) ----------------------------- */}
      {capabilities['dashboard:balance_panel'] && <BalancePanelView />}
      {capabilities['dashboard:recent_transactions_panel'] && <RecentTransactionsPanel />}

      {/* ---- Failure trend ------------------------------------------------ */}
      {operational && operational.dailyTrend.length > 1 && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Daily volume and failures</span>
            <span className="small muted">Last 30 days</span>
          </div>
          <div className="card-body">
            <FailureTrend data={operational.dailyTrend} onDrillDown={() => onDrillDown(['FAILED'])} />
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * The L3 balance panel.
 *
 * Always shows an "as of" timestamp. A balance figure without one invites an authorizer to
 * treat a stale number as live, and the specification calls the timestamp out explicitly
 * for that reason. When no balance has ever been retrieved, it says so rather than
 * rendering zero.
 */
function BalancePanelView() {
  const [balance, setBalance] = useState<BalancePanel | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setBalance(await api.analytics.balance());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The balance panel could not be loaded.');
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function refresh() {
    setRefreshing(true);
    setMessage(null);
    try {
      const result = await api.analytics.refreshBalance();
      setMessage(result.message);
      // Daraja answers asynchronously on the callback, so poll once shortly after.
      setTimeout(() => void load(), 6000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'The refresh could not be requested.');
    } finally {
      setRefreshing(false);
    }
  }

  const utility = balance?.accounts.find((a) => a.accountType.includes('Utility'));

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Organisation M-PESA balance</span>
        <div className="row">
          {balance?.asOf && (
            <span className="small muted">
              as of <RelativeTime value={balance.asOf} />
            </span>
          )}
          <button className="button button-sm" onClick={refresh} disabled={refreshing}>
            {refreshing ? 'Requesting…' : 'Refresh'}
          </button>
        </div>
      </div>
      <div className="card-body">
        {error && <Notice tone="danger">{error}</Notice>}
        {message && (
          <Notice tone="info" live="polite">
            {message}
          </Notice>
        )}

        {balance?.note ? (
          <EmptyState title="No balance retrieved yet">{balance.note}</EmptyState>
        ) : (
          <>
            <div className="grid">
              {balance?.accounts.map((account) => (
                <div key={account.accountType} className="stack" style={{ gap: 'var(--s1)' }}>
                  <span className="stat-label">{account.accountType}</span>
                  <Amount cents={account.availableCents} size="large" />
                  {account.unclearedCents !== account.availableCents && (
                    <span className="small muted">
                      Uncleared KES {formatCents(account.unclearedCents)}
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/*
             * The Utility account is the one B2C actually debits. Funds sitting in Working
             * (MMF) do not prevent a `1 — insufficient balance` failure, and that surprise
             * is common enough to be worth a standing note.
             */}
            {utility && (
              <Notice tone="info" >
                B2C disbursements debit the <strong>Utility</strong> account. Funds in Working (MMF)
                must be moved to Utility on the M-PESA organisation portal before they can be paid out.
              </Notice>
            )}

            {balance?.awaitingRefresh && (
              <p className="small muted mt-4" role="status">
                A balance query is in flight. This panel updates when M-PESA responds.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function RecentTransactionsPanel() {
  const [rows, setRows] = useState<
    {
      transactionId: string;
      status: string;
      amountCents: number;
      recipientName: string;
      msisdn: string;
      mpesaReceiptNumber: string | null;
      batchReference: string;
      failureReason: string | null;
      at: string;
    }[]
  >([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await api.analytics.recentTransactions();
        if (!cancelled) setRows(result.transactions);
      } catch {
        // The panel is supplementary; a failure here must not take the dashboard down.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">Recent disbursements</span>
        <span className="small muted">From the payment ledger</span>
      </div>
      {loading ? (
        <div className="card-body">
          <div className="skeleton" style={{ height: 120 }} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No disbursements yet" />
      ) : (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Recipient</th>
                <th scope="col" className="numeric">
                  Amount
                </th>
                <th scope="col">Status</th>
                <th scope="col">Receipt</th>
                <th scope="col">When</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.transactionId}>
                  <td>
                    <div>{row.recipientName}</div>
                    <div className="small muted mono">{maskMsisdn(row.msisdn)}</div>
                  </td>
                  <td className="numeric">
                    <Amount cents={row.amountCents} showCurrency={false} />
                  </td>
                  <td>
                    <StatusChip status={row.status as TxnState} />
                    {row.failureReason && (
                      <div className="small muted" style={{ maxWidth: '32ch' }}>
                        {row.failureReason}
                      </div>
                    )}
                  </td>
                  <td>
                    {row.mpesaReceiptNumber ? (
                      <code className="reference">{row.mpesaReceiptNumber}</code>
                    ) : (
                      <span className="muted small">—</span>
                    )}
                  </td>
                  <td>
                    <RelativeTime value={row.at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/**
 * A minimal inline chart.
 *
 * Deliberately hand-drawn SVG rather than a charting library: the dependency would be
 * larger than the rest of the bundle, and what is needed here is one comparison — how much
 * of each day's volume failed. Bars are labelled for screen readers, and the data is also
 * available as a table through the explorer, so the chart is not the only representation.
 */
function FailureTrend({
  data,
  onDrillDown,
}: {
  data: { day: string; total: number; failed: number }[];
  onDrillDown: () => void;
}) {
  const max = Math.max(...data.map((d) => d.total), 1);
  const width = 100;
  const barWidth = width / data.length;

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} 40`}
        preserveAspectRatio="none"
        style={{ width: '100%', height: 120 }}
        role="img"
        aria-label={`Daily transaction volume over ${data.length} days. ${data.reduce((sum, d) => sum + d.failed, 0)} failures in total.`}
      >
        {data.map((day, index) => {
          const height = (day.total / max) * 36;
          const failedHeight = (day.failed / max) * 36;
          return (
            <g key={day.day}>
              <rect
                x={index * barWidth + barWidth * 0.15}
                y={40 - height}
                width={barWidth * 0.7}
                height={height}
                fill="var(--accent-border)"
              />
              {day.failed > 0 && (
                <rect
                  x={index * barWidth + barWidth * 0.15}
                  y={40 - failedHeight}
                  width={barWidth * 0.7}
                  height={failedHeight}
                  fill="var(--danger)"
                />
              )}
            </g>
          );
        })}
      </svg>
      <div className="row small muted" style={{ justifyContent: 'space-between' }}>
        <span>{data[0]?.day}</span>
        <button className="button button-sm" data-variant="ghost" onClick={onDrillDown}>
          View failures
        </button>
        <span>{data[data.length - 1]?.day}</span>
      </div>
    </div>
  );
}

function greeting(): string {
  // Nairobi time, since that is where the finance team is.
  const hour = Number(
    new Intl.DateTimeFormat('en-KE', { hour: 'numeric', hour12: false, timeZone: 'Africa/Nairobi' }).format(
      new Date(),
    ),
  );
  if (hour < 12) return 'Good morning';
  if (hour < 17) return 'Good afternoon';
  return 'Good evening';
}
