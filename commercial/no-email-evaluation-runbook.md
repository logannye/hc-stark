# No-email evaluation operations

TinyZKP does not use an unrelated personal or business mailbox for outreach or
recovery-period application acknowledgements. The public form returns the
application ID and benchmark instructions synchronously and stores the record
in an owner-only SQLite ledger.

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
4. Create or select the positively identified Stripe customer.
5. Preview the $12,500 Founding Evaluation deposit:

```bash
python3 billing/contract_billing.py evaluation-deposit \
  --offer-id founding_evaluation \
  --customer-id cus_REPLACE \
  --agreement-id REPLACE
```

6. Apply only after exact Stripe account verification and explicit operator
   authorization. Public Checkout remains disabled.

No evaluation work starts until the signed agreement, paid deposit, frozen
workload digest, acceptance matrix, and baseline host are all recorded.
