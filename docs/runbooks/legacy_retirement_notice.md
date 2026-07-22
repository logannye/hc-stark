# Legacy TinyZKP retirement notice and disposition checklist

This is the reviewed, privacy-safe template for retiring the old hosted
TinyZKP service. Never commit tenant names, email addresses, API keys, usage
payloads, exports, or delivery receipts to this repository. Keep the delivery
ledger and any exports in the owner-controlled records system.

The owner audit currently identifies 10 free tenant accounts: 9 external
accounts and 1 synthetic operator account. Two accounts ever used the API: 1
external account and the synthetic account. No external account has billed
usage. Separately, Stripe contains 2 active owner-only legacy TinyZKP
subscriptions at $19 and their legacy TinyZKP catalog objects. The unrelated
Casino Coach product and subscriptions are outside this launch and must not be
changed. These counts are inventory facts, not proof that notice, export,
subscription, deletion, or retention duties are done.
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

- Send the notice to all 9 external accounts through the private owner
  channel and retain delivery evidence outside Git.
- For the 1 external account with API usage, record whether an export was
  delivered or explicitly declined. Resolve failed delivery attempts directly.
- Do not send a customer notice or export to the synthetic operator account.
  Record its internal test-data disposition separately.
- Resolve both active owner-only legacy TinyZKP $19 subscriptions and disable
  only their legacy TinyZKP catalog objects. Record exact owner-only
  dispositions outside Git. Do not modify Casino Coach or any other unrelated
  Stripe product, price, subscription, or customer.
- Confirm there are no open export requests, refunds, credits, paid-service
  promises, support commitments, or other unresolved obligations.
- Dispose of customer artifacts that are not subject to a documented retention
  duty. Record the purpose, custodian, access boundary, and deletion date for
  every retained record category.
- Record aggregate counts only in the signed launch envelope: external and
  synthetic accounts, API use, external billed use, 9 notices, the 1 external
  export disposition, synthetic internal disposition, the 2 owner-only $19
  subscription dispositions, catalog isolation, and open-obligation counts.
- Hash these exact template bytes and bind that SHA-256 in the signed evidence.

Only after all checklist counts reconcile may the owner attest
`unresolved_obligations: 0`. The hosted-infrastructure gate separately proves
that writes, jobs, and credentials are disabled and the legacy hosts return
410/noindex.
