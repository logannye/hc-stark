# Legacy TinyZKP retirement notice and disposition checklist

This is the reviewed, privacy-safe template for retiring the old hosted
TinyZKP service. Never commit tenant names, email addresses, API keys, usage
payloads, exports, or delivery receipts to this repository. Keep the delivery
ledger and any exports in the owner-controlled records system.

The owner audit verified directly against the legacy tenant and usage stores on
2026-07-24 identifies 10 free tenant accounts: all 10 are synthetic/test
accounts and 0 are external accounts. Two synthetic accounts used the API. No
external account has API or billed usage. Separately, the 2 owner-only legacy
TinyZKP subscriptions at $19 have been canceled and the legacy TinyZKP catalog
objects disabled. The unrelated Casino Coach product and subscription remain
outside this launch and were not changed. These counts are inventory facts,
not proof that deletion or retention duties are done.
The `legacy_obligations_resolved` gate must remain blocked until the signed
evidence records every checklist item below as complete.

## Customer notice template

Subject: TinyZKP hosted-service retirement and data options

TinyZKP's legacy hosted API, MCP, and webhook service is being retired. The
replacement TinyZKP Guard product is a customer-operated release and does not
receive your witness data. Legacy hosted endpoints will stop accepting work and
will return HTTP 410.

If you want an export of records or artifacts associated with your legacy
account, reply to the private support address in this message by the stated
response deadline. We will confirm the disposition of any retained records and
honor applicable privacy, accounting, refund, and legal-retention obligations.
Do not send API keys, secrets, witness data, or other sensitive payloads by
email.

## Owner completion checklist

- Reconcile the authoritative inventory before sending any notice. Send a
  notice only to an actual external account, and retain delivery evidence
  outside Git. The verified inventory currently requires 0 notices.
- For each actual external account with API usage, record whether an export was
  delivered or explicitly declined. The verified inventory currently requires
  0 external export dispositions.
- Do not send a customer notice or export to synthetic/test accounts. Record
  their internal test-data disposition separately.
- Preserve the outside-Git record showing both owner-only legacy TinyZKP $19
  subscriptions were canceled and only their legacy TinyZKP catalog objects
  were disabled. Do not modify Casino Coach or any other unrelated Stripe
  product, price, subscription, or customer.
- Confirm there are no open export requests, refunds, credits, paid-service
  promises, support commitments, or other unresolved obligations.
- Dispose of customer artifacts that are not subject to a documented retention
  duty. Record the purpose, custodian, access boundary, and deletion date for
  every retained record category.
- Record aggregate counts only in the signed launch envelope: external and
  synthetic accounts, API use, external billed use, required and sent notices,
  required external export dispositions, synthetic internal disposition, the
  2 owner-only $19 subscription dispositions, catalog isolation, and
  open-obligation counts.
- Hash these exact template bytes and bind that SHA-256 in the signed evidence.

Only after all checklist counts reconcile may the owner attest
`unresolved_obligations: 0`. The hosted-infrastructure gate separately proves
that writes, jobs, and credentials are disabled and the legacy hosts return
410/noindex.
