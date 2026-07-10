# TinyZKP Stripe operations during backend recovery

Public Checkout, legacy plans, usage meters, account creation, and hosted proving
are disabled. The historical Developer, Pro, Scale, Compute, Team, and
Production Pilot catalog is not a current storefront and must not be recreated.

Current commercial operations are contract-only:

1. Use the no-email evaluation application and qualify one reproducible
   Plonky3 memory bottleneck.
2. Obtain a counsel-approved signed agreement and a completed, hash-bound
   acceptance matrix.
3. Create or select an exact contract-tagged Stripe customer with the
   customer's legal name, billing address, and billing contact.
4. Preview and apply an evaluation milestone only through
   `billing/contract_billing.py`. It uses Stripe Invoicing with `send_invoice`;
   it never creates Checkout.
5. Run `billing/evaluation_start_ready.py` after the deposit is paid. No work
   starts until that read-only gate returns `ready: true`.

Legacy containment is a two-stage reviewed operation:

```bash
python3 billing/legacy_billing_containment.py \
  --expected-account-id acct_REPLACE \
  --expected-display-name TinyZKP \
  --inventory-output /var/lib/tinyzkp-private/stripe/inventory.json
```

An operator must create an exact-ID scope manifest bound to the reported
`inventory_sha256`, preview the resulting action plan, and separately authorize
the exact `plan_sha256`. No name or meter-event heuristic selects a write target.
Customer subscription pauses additionally require a strict no-email
notification/refund-or-credit ledger and exact open-invoice approvals.

The legacy catalog scripts are test/research-only and reject live Stripe keys.
Annual Certified/Fleet billing remains blocked until a hash-bound signed backend
release authorization passes the authoritative release validator.

The Stripe API is pinned to `2026-02-25.clover`. All customer-facing Stripe
identity must say TinyZKP and must never use an unrelated business address.
