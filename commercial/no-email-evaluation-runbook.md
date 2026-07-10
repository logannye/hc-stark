# No-email evaluation operations

TinyZKP does not use an unrelated personal or business mailbox for outreach or
recovery-period application acknowledgements. The public form returns the
application ID and benchmark instructions synchronously and stores the record
in an owner-only SQLite ledger.

Applicants select a no-email reply channel (GitHub, LinkedIn, Signal, Discord,
Telegram, Matrix, or phone/SMS). Work email is optional and must not be used for
recovery-period follow-up. Use only the applicant-selected channel and handle.

## Review intake

Run on the production host:

```bash
cd /opt/hc-stark
.venv/bin/python billing/evaluation_intake.py list --status new
.venv/bin/python billing/evaluation_intake.py show eval_REPLACE --include-contact
.venv/bin/python billing/evaluation_intake.py set-status eval_REPLACE qualified
```

The default list is contact-redacted. Use `--include-contact` only when the
operator has a legitimate need to view the applicant's submitted contact data.
Do not copy handles, phone numbers, or optional email addresses into the
repository, issue tracker, benchmark reports, or review bundles.

## Retention

Preview and apply the twelve-month purge:

```bash
.venv/bin/python billing/evaluation_intake.py purge-expired
.venv/bin/python billing/evaluation_intake.py purge-expired --apply
```

The evaluation database is included in the encrypted/private off-host backup
set. Do not export it into the repository, issue tracker, or benchmark bundle.

## Contract and invoice handoff

1. Have counsel approve `commercial/evaluation-sow.counsel-draft.md`.
2. Freeze and hash a completed acceptance matrix.
3. Obtain signatures outside the public site.
4. Create a private contract-evidence record from the tracked template. Never
   put the completed record or contract documents in the repository:

```bash
install -d -m 700 /var/lib/tinyzkp-private/contracts
install -m 600 commercial/contract-evidence.template.json \
  /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json
sha256sum SIGNED_AGREEMENT ACCEPTANCE_MATRIX
```

   Fill the private record with those hashes, the canonical UTC signature
   time, the exact offer/agreement IDs, and the exact Stripe customer ID. For a
   delivery invoice, create a separate record that also includes the written
   acceptance hash and canonical acceptance time.
5. Create or select the positively identified Stripe customer. Before apply,
   its Stripe metadata must contain:

   - `tinyzkp_contract_customer=true`
   - `tinyzkp_agreement_id=AGREEMENT_ID`
   - `tinyzkp_offer_id=founding_evaluation` (or the exact contracted offer)

   The customer must have the customer's contractual billing address. Do not
   use the founder's unrelated-business email address as the customer or sender
   address.
6. Preview the $12,500 Founding Evaluation deposit:

```bash
python3 billing/contract_billing.py evaluation-deposit \
  --offer-id founding_evaluation \
  --customer-id cus_REPLACE \
  --agreement-id REPLACE \
  --contract-evidence /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json \
  --agreement-document SIGNED_AGREEMENT \
  --scope-document ACCEPTANCE_MATRIX
```

7. Record the returned `plan_sha256`. Apply only after exact Stripe account
   verification and explicit operator authorization, passing that hash as
   `--expected-plan-sha256`. Any change to the offer, amount, customer, due
   date, contract hashes, or acceptance evidence changes the plan hash and
   blocks the write. Public Checkout remains disabled. Do not finalize or send
   an invoice until Stripe's customer-facing sender identity has been verified
   as TinyZKP and does not use an unrelated business mailbox. The CLI verifies
   the retrieved Stripe account has public business name `TinyZKP`, a
   `@tinyzkp.com` support email, and a `tinyzkp.com` support URL; the environment
   acknowledgement alone is insufficient.

The delivery command additionally requires a paid deposit invoice in Stripe;
an open, draft, void, or uncollectible deposit is insufficient. It also
requires `--delivery-acceptance-document`; the CLI hashes all supplied private
documents and refuses any mismatch with the owner-only evidence record.

No evaluation work starts until the signed agreement, paid deposit, frozen
workload digest, acceptance matrix, and baseline host are all recorded.
