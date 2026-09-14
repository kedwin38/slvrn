# Sample upload files

Two CSVs for exercising batch preparation end to end. Upload them from
**Payment batches → New batch**, or `POST /batches/:id/upload`.

## `payroll-clean.csv`

Eight rows, KES 596,000 in total, all valid. It deliberately covers the input
variety a real payroll export contains rather than eight identical rows:

| Row | What it exercises                                                      |
| --- | ---------------------------------------------------------------------- |
| 1   | `07…` local format, normalised to `2547…`                              |
| 2   | `254…` already canonical                                               |
| 4   | A quoted name containing a comma, and a `+254 722 334 455` with spaces |
| 5   | A `011…` Safaricom number, proving the 1xx range is accepted           |
| 7   | A department name containing `&`                                       |

Expect **8 accepted, 0 rejected**. Every recipient is new on a fresh
organisation, so validation raises `NEW_RECIPIENT` risk signals — that is
correct, not a fault: the reviewer is being told these people have never been
paid before.

## `payroll-rejections.csv`

Eleven rows, of which two are valid. Every other row fails for a different
reason, so the rejection table shows a distinct explanation on each line rather
than the same message repeated:

| Line | Why it is refused                                                              |
| ---- | ------------------------------------------------------------------------------ |
| 4    | Recipient name is required                                                     |
| 5    | `0812345678` is not a Kenyan mobile number                                     |
| 6    | Letters in the phone number                                                    |
| 7    | `1500.75` — M-PESA B2C pays whole shillings only                               |
| 8    | KES 5 is below the M-PESA minimum of KES 10                                    |
| 9    | KES 400,000 exceeds the per-transaction maximum of KES 250,000                 |
| 10   | A spreadsheet formula where an amount belongs                                  |
| 11   | Zero is not a payment                                                          |
| 12   | Same recipient and amount as line 2 — a **duplicate warning**, not a rejection |

Expect **3 accepted, 8 rejected, 1 duplicate warning**. The duplicate is the
interesting one: it is accepted into the batch and flagged, because paying
somebody twice in one run is sometimes legitimate (a correction, a second
instalment) and the decision belongs to the reviewer, not the parser.

## Accepted header names

Matching is case- and whitespace-insensitive, and each column accepts several
spellings so an existing payroll export usually needs no editing:

| Column     | Required | Accepted headers                                                   |
| ---------- | -------- | ------------------------------------------------------------------ |
| Recipient  | yes      | recipient name, name, employee name, full name                     |
| Phone      | yes      | phone, phone number, msisdn, mobile, mobile number, telephone      |
| Amount     | yes      | amount, amount kes, kes, gross, net pay                            |
| Department | no       | department, dept, category, cost centre, cost center               |
| Reference  | no       | reference, ref, employee id, employee number, staff id, payroll id |
| Remarks    | no       | remarks, remark, purpose, description, note, notes                 |

Limits: 20,000 rows and 8 MB per upload; larger payrolls are split across
batches.
