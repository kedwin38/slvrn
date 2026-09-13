import { describe, it, expect } from 'vitest';
import { parsePaymentCsv, parseCsvGrid, mapColumns } from './csv.js';
import { tryNormalizeMsisdn, normalizeMsisdn, maskMsisdn } from './msisdn.js';
import { parseAmountToCents, formatCents, sumCents, centsToDarajaAmount } from './money.js';

describe('CSV grid tokenizer', () => {
  it('handles quotes, embedded commas, escaped quotes and CRLF', () => {
    const grid = parseCsvGrid('name,note\r\n"Doe, Jane","She said ""hello"""\r\n');
    expect(grid).toEqual([
      ['name', 'note'],
      ['Doe, Jane', 'She said "hello"'],
    ]);
  });

  it('handles an embedded newline inside a quoted field', () => {
    const grid = parseCsvGrid('a,b\n"line1\nline2",x\n');
    expect(grid[1]).toEqual(['line1\nline2', 'x']);
  });

  it('strips a UTF-8 BOM written by Excel', () => {
    const grid = parseCsvGrid('﻿name,amount\nJane,100\n');
    expect(grid[0]).toEqual(['name', 'amount']);
  });

  it('supports semicolon and tab separated files', () => {
    expect(parseCsvGrid('a;b\n1;2\n')[1]).toEqual(['1', '2']);
    expect(parseCsvGrid('a\tb\n1\t2\n')[1]).toEqual(['1', '2']);
  });

  it('ignores trailing blank lines', () => {
    expect(parseCsvGrid('a,b\n1,2\n\n\n')).toHaveLength(2);
  });
});

describe('column mapping', () => {
  it('matches header aliases case- and separator-insensitively', () => {
    const mapping = mapColumns(['Employee Name', 'Mobile Number', 'Amount KES', 'Cost Centre', 'Staff ID']);
    expect(mapping.recipientName).toBe(0);
    expect(mapping.msisdn).toBe(1);
    expect(mapping.amount).toBe(2);
    expect(mapping.department).toBe(3);
    expect(mapping.reference).toBe(4);
  });
});

describe('payment CSV validation (§5.2, §22)', () => {
  const header = 'Recipient Name,Phone,Amount,Department,Reference\n';

  it('parses a clean file', () => {
    const result = parsePaymentCsv(
      header + 'Jane Doe,0712345678,45000,Engineering,EMP-001\nJohn Smith,254733111222,32000,Finance,EMP-002\n',
    );
    expect(result.errors).toEqual([]);
    expect(result.rows).toHaveLength(2);
    expect(result.rows[0]).toMatchObject({
      recipientName: 'Jane Doe',
      msisdn: '254712345678',
      amountCents: 45_000_00,
      department: 'Engineering',
    });
    expect(result.totalAmountCents).toBe(77_000_00);
  });

  it('reports row-level errors with 1-based line numbers and keeps the good rows', () => {
    const result = parsePaymentCsv(
      header +
        'Jane Doe,0712345678,45000,Eng,E1\n' +
        ',0722000000,1000,Eng,E2\n' + // missing name
        'Bad Phone,12345,1000,Eng,E3\n' + // invalid number
        'Low Amount,0712345000,5,Eng,E4\n' + // below M-PESA minimum
        'Good Two,0745000111,7000,Eng,E5\n',
    );
    expect(result.rows).toHaveLength(2);
    expect(result.errors).toHaveLength(3);
    expect(result.errors.map((e) => e.lineNumber)).toEqual([3, 4, 5]);
    expect(result.errors[0]!.column).toBe('recipientName');
    expect(result.errors[1]!.reason).toMatch(/not a 12-digit Kenyan MSISDN|not a recognised/);
    expect(result.errors[2]!.reason).toMatch(/below the M-PESA minimum/);
  });

  it('rejects amounts above the M-PESA per-transaction maximum', () => {
    const result = parsePaymentCsv(header + 'Big Pay,0712345678,300000,Eng,E1\n');
    expect(result.rows).toHaveLength(0);
    expect(result.errors[0]!.reason).toMatch(/exceeds the M-PESA per-transaction maximum/);
  });

  it('rejects fractional shillings rather than rounding someone\'s salary', () => {
    const result = parsePaymentCsv(header + 'Jane,0712345678,45000.50,Eng,E1\n');
    expect(result.errors[0]!.reason).toMatch(/whole shillings only/);
  });

  it('rejects a spreadsheet formula in the amount column', () => {
    const result = parsePaymentCsv(header + 'Jane,0712345678,=A1*1000,Eng,E1\n');
    expect(result.errors[0]!.reason).toMatch(/formula/);
  });

  it('detects duplicate recipient+amount pairs within one file (§11.1)', () => {
    const result = parsePaymentCsv(
      header +
        'Jane Doe,0712345678,45000,Eng,E1\n' +
        'Jane Doe,0712345678,45000,Eng,E1\n' +
        'John,0733111222,30000,Fin,E2\n',
    );
    expect(result.rows).toHaveLength(3); // duplicates are a warning, not a hard error
    expect(result.duplicateWarnings).toHaveLength(1);
    expect(result.duplicateWarnings[0]!.lineNumbers).toEqual([2, 3]);
  });

  it('throws when required columns are missing, naming what is expected', () => {
    expect(() => parsePaymentCsv('name,dept\nJane,Eng\n')).toThrow(/missing required columns/);
  });

  it('throws on an empty file and on a header-only file', () => {
    expect(() => parsePaymentCsv('')).toThrow(/empty/);
    expect(() => parsePaymentCsv(header)).toThrow(/no payment rows/);
  });

  it('enforces the row limit', () => {
    const rows = Array.from({ length: 12 }, (_, i) => `P${i},0712345${String(i).padStart(3, '0')},1000,Eng,E${i}`).join('\n');
    expect(() => parsePaymentCsv(header + rows + '\n', { maxRows: 10 })).toThrow(/limit is 10/);
  });

  it('skips entirely blank interior rows without reporting an error', () => {
    const result = parsePaymentCsv(header + 'Jane,0712345678,45000,Eng,E1\n,,,,\nJohn,0733111222,30000,Fin,E2\n');
    expect(result.rows).toHaveLength(2);
    expect(result.errors).toEqual([]);
  });
});

describe('MSISDN normalization', () => {
  it.each([
    ['0712345678', '254712345678'],
    ['+254712345678', '254712345678'],
    ['254712345678', '254712345678'],
    ['712345678', '254712345678'],
    ['0712 345 678', '254712345678'],
    ['0712-345-678', '254712345678'],
    ['(0712) 345678', '254712345678'],
    ['00254712345678', '254712345678'],
    ['0110123456', '254110123456'],
  ])('normalizes %s to %s', (input, expected) => {
    expect(normalizeMsisdn(input)).toBe(expected);
  });

  it.each([
    ['', 'empty'],
    ['12345', 'not a 12-digit'],
    ['254812345678', 'not a recognised'], // 8xx is not a Kenyan mobile range
    ['abcdefghij', 'non-numeric'],
    ['+1 415 555 0100', 'not a 12-digit'],
  ])('rejects %s', (input, reasonFragment) => {
    const result = tryNormalizeMsisdn(input);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(new RegExp(reasonFragment));
  });

  it('masks for logs and lower-privilege display', () => {
    expect(maskMsisdn('254712345678')).toBe('2547****5678');
    expect(maskMsisdn('bad')).toBe('****');
  });
});

describe('money arithmetic', () => {
  it('parses amounts in the formats operators actually paste', () => {
    expect(parseAmountToCents('45000')).toBe(4_500_000);
    expect(parseAmountToCents('45,000.50')).toBe(4_500_050);
    expect(parseAmountToCents('KES 45000')).toBe(4_500_000);
    expect(parseAmountToCents(45000)).toBe(4_500_000);
    expect(parseAmountToCents('0.05')).toBe(5);
  });

  it('rejects junk rather than coercing it', () => {
    for (const bad of ['', 'abc', '1.2.3', '45 000 000 000 000 000 000', '--5']) {
      expect(() => parseAmountToCents(bad)).toThrow();
    }
  });

  it('never loses a cent across a large batch total', () => {
    // 0.1 + 0.2 in floating point is the canonical payroll bug; integer cents avoid it.
    const values = Array.from({ length: 10_000 }, () => 1_234_57);
    expect(sumCents(values)).toBe(1_234_57 * 10_000);
    expect(sumCents([10, 20])).toBe(30);
  });

  it('formats cents with thousands separators', () => {
    expect(formatCents(8_420_500_00)).toBe('8,420,500.00');
    expect(formatCents(-154_000)).toBe('-1,540.00');
    expect(formatCents(5)).toBe('0.05');
  });

  it('converts to the whole-shilling string Daraja expects and refuses fractions', () => {
    expect(centsToDarajaAmount(45_000_00)).toBe('45000');
    expect(() => centsToDarajaAmount(45_000_50)).toThrow(/whole shillings/);
    expect(() => centsToDarajaAmount(0)).toThrow();
  });
});
