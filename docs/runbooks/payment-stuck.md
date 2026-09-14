# Runbook: a payment is stuck in PROCESSING or TIMEOUT

**Applies to:** spec §27, "Payment stuck in PROCESSING/TIMEOUT"
**Severity:** high — an employee may be unpaid, or may have been paid twice
**Do not:** resubmit the payment. Read the whole of section 1 before doing anything.

---

## 1. What "stuck" actually means

A transaction sitting in `TIMEOUT` or `RECONCILING` means **SOLVAREN does not know whether
the money moved.** That is different from "the payment failed", and the difference matters:

- If you resubmit and the first attempt succeeded, the recipient is paid twice, and B2C
  payments **cannot be reversed through the API** — recovery is a manual process on the
  M-PESA organisation portal, which means a phone call to the recipient.
- If you assume it failed and do nothing, an employee goes unpaid.

SOLVAREN will not guess. It queries the Transaction Status API until Safaricom gives a
definitive answer, and escalates to a human after eight attempts. Your job is to establish
the truth, not to retry.

---

## 2. Establish what M-PESA thinks happened

1. Open **Transactions**, filter to `TIMEOUT` and `RECONCILING`.
2. Expand the row. Note the **OriginatorConversationID** — this is SOLVAREN's own
   identifier for the attempt and is the key to everything that follows.
3. Press **Check status with M-PESA** (L2/L3). This issues a Transaction Status query;
   the answer arrives asynchronously and the row updates when it does. Give it two minutes.

If the status query resolves, you are done — the transaction settles to SUCCESS or FAILED
with a recorded reason and the batch roll-up updates.

### If the status query does not resolve

Query Safaricom directly, using the same identifier:

- M-PESA organisation portal → Transactions → search by the OriginatorConversationID or by
  the recipient MSISDN and the time window.
- If the portal shows a completed transaction with a receipt, the money moved.
- If it shows nothing at all for that identifier, the request never reached M-PESA.

Failing that, contact `apisupport@safaricom.co.ke` with the OriginatorConversationID, the
ConversationID if one was issued, the shortcode and the timestamp. Do not proceed until
you have an answer.

---

## 3. Resolve the case

Once you know the truth, record it. **SOLVAREN never rewrites a settled transaction**, so
the resolution is recorded on the reconciliation case, not by editing the ledger.

| What M-PESA says               | What to do                                                                                                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Completed, with a receipt      | Resolve the case as `RESOLVED_SUCCESS` and enter the receipt number. The transaction settles to SUCCESS.                                                    |
| Cancelled, declined or expired | Resolve as `RESOLVED_FAILED`. The transaction settles to FAILED with the provider's reason.                                                                 |
| No record of the request       | Resolve as `RESOLVED_FAILED` with a note. The instruction can then be reissued as a **new** instruction in a **new** batch — never by retrying the old one. |
| Still processing               | Leave the case open. The sweep will continue.                                                                                                               |

---

## 4. If many transactions are stuck at once

That is a different problem: it is an integration or provider incident, not a per-payment
one.

1. **Check whether callbacks are arriving at all.** Settings → Daraja shows the last
   callback received. If nothing has arrived for an hour while payments are in flight,
   the callback path is broken.
2. **Common cause: the callback URL is unreachable.** Safaricom does not retry a failed
   delivery. Verify the registered ResultURL matches what the configuration screen shows,
   and that it resolves from outside your network.
3. **Common cause: the WAF is blocking Safaricom.** If `safaricom_callback_ranges` in the
   Terraform configuration is out of date, legitimate callbacks are blocked at the edge
   and never reach the service. Check the API logs for rejected POSTs
   to `/integrations/daraja/`. If they are there, clear the variable and re-apply — the
   per-organisation shared secret remains the control.
4. The reconciliation sweep runs every five minutes and will resolve everything eventually,
   but it is slower than callbacks and consumes Transaction Status API quota.

---

## 5. What to tell the affected person

If someone asks whether they have been paid and the answer is genuinely unknown, say that.
"We are confirming with Safaricom and will have an answer within the hour" is accurate.
"It failed, we will resend it" is not, and if it turns out the first payment succeeded, the
second one is unrecoverable.
