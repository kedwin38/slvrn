/**
 * Transactions Explorer query contract (spec §6.3, TRK-003, NFR-OPS-002).
 *
 * Sorting and filtering happen in PostgreSQL, never in the browser, because a finance team
 * with 400,000 transactions cannot sort them client-side and a paginated client-side sort
 * is simply wrong. That means user input picks a column name — which is exactly how SQL
 * injection happens — so the sort column and direction are resolved through a closed
 * allowlist to a fixed SQL fragment. There is no path from user input to SQL text.
 */

import { z } from 'zod';
import { TXN_STATES } from './txn-state.js';

/** Allowlisted sort keys → the exact SQL expression used in ORDER BY. */
export const SORT_COLUMNS = {
  date: 't.created_at',
  submitted: 't.submitted_at',
  updated: 't.updated_at',
  amount: 'pi.amount_cents',
  recipient: 'r.full_name',
  status: 't.status',
  batch: 'b.batch_reference',
  failure: 't.failure_code',
} as const;

export type SortColumn = keyof typeof SORT_COLUMNS;

export const SORT_DIRECTIONS = ['asc', 'desc'] as const;
export type SortDirection = (typeof SORT_DIRECTIONS)[number];

export const MAX_PAGE_SIZE = 200;
export const DEFAULT_PAGE_SIZE = 50;
/** Hard ceiling on an export, to keep a single request bounded. Larger sets go via a job. */
export const MAX_EXPORT_ROWS = 100_000;

export const explorerQuerySchema = z.object({
  status: z.array(z.enum(TXN_STATES)).max(TXN_STATES.length).optional(),
  batchId: z.string().uuid().optional(),
  departmentId: z.string().uuid().optional(),
  recipientId: z.string().uuid().optional(),
  /** Free-text search across recipient name, receipt number and conversation ids. */
  search: z.string().trim().min(1).max(120).optional(),
  dateFrom: z.string().datetime({ offset: true }).optional(),
  dateTo: z.string().datetime({ offset: true }).optional(),
  amountMinCents: z.number().int().nonnegative().optional(),
  amountMaxCents: z.number().int().nonnegative().optional(),
  failureCode: z.string().trim().max(40).optional(),
  sort: z.enum(Object.keys(SORT_COLUMNS) as [SortColumn, ...SortColumn[]]).default('date'),
  direction: z.enum(SORT_DIRECTIONS).default('desc'),
  page: z.number().int().min(1).max(10_000).default(1),
  pageSize: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE),
});

export type ExplorerQuery = z.infer<typeof explorerQuerySchema>;

/**
 * Resolve a validated query into an ORDER BY clause.
 *
 * A secondary sort on the transaction id is always appended: without a tiebreaker,
 * PostgreSQL may return rows in a different order for equal sort keys across pages, which
 * shows the operator duplicate rows on page 2 and hides others entirely.
 */
export function buildOrderBy(query: Pick<ExplorerQuery, 'sort' | 'direction'>): string {
  const column = SORT_COLUMNS[query.sort];
  const direction = query.direction === 'asc' ? 'ASC' : 'DESC';
  // NULLS LAST keeps unsettled rows (null receipt, null failure code) out of the way when
  // sorting by an outcome column.
  return `${column} ${direction} NULLS LAST, t.id ${direction}`;
}

export interface FilterDescription {
  text: string;
  parts: string[];
}

/**
 * Human-readable rendering of the active filter. Written into the export's provenance
 * header and the audit event, so "who exported what" is answerable a year later (TRK-006).
 */
export function describeFilter(query: Partial<ExplorerQuery>): FilterDescription {
  const parts: string[] = [];
  if (query.status?.length) parts.push(`status in [${query.status.join(', ')}]`);
  if (query.batchId) parts.push(`batch ${query.batchId}`);
  if (query.departmentId) parts.push(`department ${query.departmentId}`);
  if (query.recipientId) parts.push(`recipient ${query.recipientId}`);
  if (query.failureCode) parts.push(`failure code ${query.failureCode}`);
  if (query.dateFrom) parts.push(`from ${query.dateFrom}`);
  if (query.dateTo) parts.push(`to ${query.dateTo}`);
  if (query.amountMinCents !== undefined) parts.push(`amount >= ${query.amountMinCents} cents`);
  if (query.amountMaxCents !== undefined) parts.push(`amount <= ${query.amountMaxCents} cents`);
  if (query.search) parts.push(`search "${query.search}"`);
  if (query.sort) parts.push(`sorted by ${query.sort} ${query.direction ?? 'desc'}`);
  return { text: parts.length ? parts.join('; ') : 'no filter (all transactions in scope)', parts };
}

/** Validate that a range makes sense before it reaches the database. */
export function assertCoherentRange(query: ExplorerQuery): string[] {
  const problems: string[] = [];
  if (query.dateFrom && query.dateTo && new Date(query.dateFrom) > new Date(query.dateTo)) {
    problems.push('The start of the date range is after its end');
  }
  if (
    query.amountMinCents !== undefined &&
    query.amountMaxCents !== undefined &&
    query.amountMinCents > query.amountMaxCents
  ) {
    problems.push('The minimum amount is greater than the maximum amount');
  }
  return problems;
}

export interface PageInfo {
  page: number;
  pageSize: number;
  totalRows: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export function pageInfo(
  query: Pick<ExplorerQuery, 'page' | 'pageSize'>,
  totalRows: number,
): PageInfo {
  const totalPages = Math.max(1, Math.ceil(totalRows / query.pageSize));
  return {
    page: query.page,
    pageSize: query.pageSize,
    totalRows,
    totalPages,
    hasNext: query.page < totalPages,
    hasPrevious: query.page > 1,
  };
}

export function offsetFor(query: Pick<ExplorerQuery, 'page' | 'pageSize'>): number {
  return (query.page - 1) * query.pageSize;
}
