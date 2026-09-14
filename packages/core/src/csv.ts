/**
 * CSV ingestion for payment batches (spec §5.2).
 *
 * The parser is deliberately hand-written and strict rather than permissive:
 *
 *  - Quoted fields, embedded commas, embedded newlines and escaped quotes are supported,
 *    because real payroll exports contain all four.
 *  - A UTF-8 BOM is stripped (Excel writes one on every save).
 *  - Any value beginning with `=`, `+`, `-` or `@` is neutralised on export, not here —
 *    but a *formula* in an uploaded amount column is rejected outright.
 *  - Every row that fails produces a row-level reason with a 1-based line number, so the
 *    operator fixes the file rather than guessing (§22 "expose row-level reasons").
 */

import {
  parseAmountToCents,
  DARAJA_B2C_MIN_CENTS,
  DARAJA_B2C_MAX_CENTS,
  formatCents,
} from './money.js';
import { tryNormalizeMsisdn } from './msisdn.js';
import { SolvarenError, validationError } from './errors.js';

/** Canonical upload schema. Header matching is case- and whitespace-insensitive. */
export const CSV_COLUMNS = {
  recipientName: ['recipient name', 'name', 'employee name', 'full name', 'recipientname'],
  msisdn: ['phone', 'phone number', 'msisdn', 'mobile', 'mobile number', 'telephone'],
  amount: ['amount', 'amount kes', 'amountkes', 'kes', 'gross', 'net pay', 'netpay'],
  department: ['department', 'dept', 'category', 'cost centre', 'cost center'],
  reference: ['reference', 'ref', 'employee id', 'employee number', 'staff id', 'payroll id'],
  remarks: ['remarks', 'remark', 'purpose', 'description', 'note', 'notes'],
} as const;

export type CsvColumnKey = keyof typeof CSV_COLUMNS;

const REQUIRED_COLUMNS: CsvColumnKey[] = ['recipientName', 'msisdn', 'amount'];

/** Hard ceiling on a single upload; larger payrolls are split into multiple batches. */
export const MAX_CSV_ROWS = 20_000;
export const MAX_CSV_BYTES = 8 * 1024 * 1024;

export interface ParsedRow {
  /** 1-based line number in the original file, including the header line. */
  lineNumber: number;
  recipientName: string;
  msisdn: string;
  amountCents: number;
  department: string | null;
  reference: string | null;
  remarks: string | null;
}

export interface RowError {
  lineNumber: number;
  column: CsvColumnKey | 'row';
  value: string;
  reason: string;
}

export interface CsvParseResult {
  rows: ParsedRow[];
  errors: RowError[];
  /** Duplicate (msisdn, amount) pairs within the same file — §11.1 duplicate detection. */
  duplicateWarnings: DuplicateWarning[];
  totalAmountCents: number;
  columnMapping: Partial<Record<CsvColumnKey, number>>;
  rowCount: number;
}

export interface DuplicateWarning {
  msisdn: string;
  amountCents: number;
  lineNumbers: number[];
  reason: string;
}

/** RFC 4180-ish tokenizer supporting quotes, embedded separators and CRLF. */
export function parseCsvGrid(text: string): string[][] {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let i = 0;

  const pushField = () => {
    row.push(field);
    field = '';
  };
  const pushRow = () => {
    pushField();
    // Skip lines that are entirely empty — trailing newlines are not data.
    if (!(row.length === 1 && row[0]!.trim() === '')) rows.push(row);
    row = [];
  };

  while (i < src.length) {
    const ch = src[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += ch;
      i++;
      continue;
    }
    if (ch === '"' && field.trim() === '') {
      inQuotes = true;
      field = '';
      i++;
      continue;
    }
    if (ch === ',' || ch === ';' || ch === '\t') {
      pushField();
      i++;
      continue;
    }
    if (ch === '\r') {
      i++;
      continue;
    }
    if (ch === '\n') {
      pushRow();
      i++;
      continue;
    }
    field += ch;
    i++;
  }
  if (field !== '' || row.length > 0) pushRow();
  return rows;
}

function normalizeHeader(h: string): string {
  return h.trim().toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ');
}

export function mapColumns(header: readonly string[]): Partial<Record<CsvColumnKey, number>> {
  const mapping: Partial<Record<CsvColumnKey, number>> = {};
  const normalized = header.map(normalizeHeader);
  for (const key of Object.keys(CSV_COLUMNS) as CsvColumnKey[]) {
    const aliases = CSV_COLUMNS[key] as readonly string[];
    const index = normalized.findIndex((h) => aliases.includes(h));
    if (index >= 0) mapping[key] = index;
  }
  return mapping;
}

const FORMULA_PREFIX = /^[=+\-@\t\r]/;

export interface CsvParseOptions {
  maxRows?: number;
}

/**
 * Parse and validate an uploaded batch file.
 *
 * Returns *both* valid rows and per-row errors rather than throwing on the first problem:
 * the operator screen shows "1,842 rows ready, 6 rows need attention" and lets them fix
 * the six, which is the difference between a five-minute correction and a re-upload cycle.
 */
export function parsePaymentCsv(text: string, options: CsvParseOptions = {}): CsvParseResult {
  const maxRows = options.maxRows ?? MAX_CSV_ROWS;

  if (text.length > MAX_CSV_BYTES) {
    throw validationError(
      'CSV_TOO_LARGE',
      `The file exceeds the ${MAX_CSV_BYTES / (1024 * 1024)} MB upload limit`,
    );
  }

  const grid = parseCsvGrid(text);
  if (grid.length === 0) {
    throw validationError('CSV_EMPTY', 'The uploaded file is empty');
  }

  const header = grid[0]!;
  const mapping = mapColumns(header);
  const missing = REQUIRED_COLUMNS.filter((c) => mapping[c] === undefined);
  if (missing.length > 0) {
    throw validationError(
      'CSV_MISSING_COLUMNS',
      `The file is missing required columns: ${missing.join(', ')}`,
      {
        missing,
        detected: header,
        expected: REQUIRED_COLUMNS.map((c) => CSV_COLUMNS[c][0]),
      },
    );
  }

  const dataRows = grid.slice(1);
  if (dataRows.length === 0) {
    throw validationError('CSV_NO_ROWS', 'The file contains a header but no payment rows');
  }
  if (dataRows.length > maxRows) {
    throw validationError(
      'CSV_TOO_MANY_ROWS',
      `The file contains ${dataRows.length} rows; the limit is ${maxRows}`,
      {
        rowCount: dataRows.length,
        maxRows,
      },
    );
  }

  const rows: ParsedRow[] = [];
  const errors: RowError[] = [];
  const at = (cells: readonly string[], key: CsvColumnKey): string => {
    const idx = mapping[key];
    if (idx === undefined) return '';
    return (cells[idx] ?? '').trim();
  };

  dataRows.forEach((cells, index) => {
    const lineNumber = index + 2; // +1 for zero-index, +1 for the header line

    if (cells.every((c) => c.trim() === '')) return; // blank separator line

    const name = at(cells, 'recipientName');
    const phoneRaw = at(cells, 'msisdn');
    const amountRaw = at(cells, 'amount');

    let rowFailed = false;

    if (name === '') {
      errors.push({
        lineNumber,
        column: 'recipientName',
        value: name,
        reason: 'Recipient name is required',
      });
      rowFailed = true;
    } else if (name.length > 140) {
      errors.push({
        lineNumber,
        column: 'recipientName',
        value: name,
        reason: 'Recipient name exceeds 140 characters',
      });
      rowFailed = true;
    }

    const phone = tryNormalizeMsisdn(phoneRaw);
    if (!phone.ok) {
      errors.push({
        lineNumber,
        column: 'msisdn',
        value: phoneRaw,
        reason: phone.reason ?? 'Invalid phone number',
      });
      rowFailed = true;
    }

    let amountCents = 0;
    if (FORMULA_PREFIX.test(amountRaw)) {
      errors.push({
        lineNumber,
        column: 'amount',
        value: amountRaw,
        reason:
          'Amount looks like a spreadsheet formula rather than a number. Paste values, not formulas.',
      });
      rowFailed = true;
    } else {
      try {
        amountCents = parseAmountToCents(amountRaw);
        if (amountCents <= 0) {
          errors.push({
            lineNumber,
            column: 'amount',
            value: amountRaw,
            reason: 'Amount must be greater than zero',
          });
          rowFailed = true;
        } else if (amountCents % 100 !== 0) {
          errors.push({
            lineNumber,
            column: 'amount',
            value: amountRaw,
            reason: 'M-PESA B2C pays whole shillings only; remove the cents component',
          });
          rowFailed = true;
        } else if (amountCents < DARAJA_B2C_MIN_CENTS) {
          errors.push({
            lineNumber,
            column: 'amount',
            value: amountRaw,
            reason: `Amount ${formatCents(amountCents)} is below the M-PESA minimum of ${formatCents(DARAJA_B2C_MIN_CENTS)}`,
          });
          rowFailed = true;
        } else if (amountCents > DARAJA_B2C_MAX_CENTS) {
          errors.push({
            lineNumber,
            column: 'amount',
            value: amountRaw,
            reason: `Amount ${formatCents(amountCents)} exceeds the M-PESA per-transaction maximum of ${formatCents(DARAJA_B2C_MAX_CENTS)}`,
          });
          rowFailed = true;
        }
      } catch (err) {
        const message = err instanceof SolvarenError ? err.message : 'Amount is not a valid number';
        errors.push({ lineNumber, column: 'amount', value: amountRaw, reason: message });
        rowFailed = true;
      }
    }

    if (rowFailed) return;

    rows.push({
      lineNumber,
      recipientName: name,
      msisdn: phone.msisdn!,
      amountCents,
      department: at(cells, 'department') || null,
      reference: at(cells, 'reference') || null,
      remarks: at(cells, 'remarks') || null,
    });
  });

  // Intra-file duplicate detection: same number, same amount, twice in one payroll run is
  // nearly always a copy-paste accident, and it is the single most expensive one.
  const byKey = new Map<string, number[]>();
  for (const r of rows) {
    const key = `${r.msisdn}:${r.amountCents}`;
    byKey.set(key, [...(byKey.get(key) ?? []), r.lineNumber]);
  }
  const duplicateWarnings: DuplicateWarning[] = [];
  for (const [key, lineNumbers] of byKey) {
    if (lineNumbers.length > 1) {
      const [msisdn, cents] = key.split(':') as [string, string];
      duplicateWarnings.push({
        msisdn,
        amountCents: Number(cents),
        lineNumbers,
        reason: `The same recipient appears ${lineNumbers.length} times with an identical amount (lines ${lineNumbers.join(', ')})`,
      });
    }
  }

  const totalAmountCents = rows.reduce((sum, r) => sum + r.amountCents, 0);

  return {
    rows,
    errors,
    duplicateWarnings,
    totalAmountCents,
    columnMapping: mapping,
    rowCount: dataRows.length,
  };
}
