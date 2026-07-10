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
   `billing/contract_billing.py`. It uses Stripe Invoicing with `send_invoice`,
   finalizes evaluation invoices with `auto_advance=false`, never calls the
   invoice-send API, and returns the hosted invoice URL only to the operator;
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
release authorization passes the authoritative release validator. Annual
preview and apply both require its separately configured Sigstore bundle and
verify the pinned `release-backend.yml` signer; a locally authored JSON file or
digest alone is not release authorization.
Annual order evidence must include the negotiated amount in cents and an
owner-only `tinyzkp-annual-order-v1` scope exported alongside the countersigned
agreement. The typed order binds that amount to the agreement/customer and the
exact Stripe Price/Product. Certified remains fixed-price; Fleet/OEM accepts an
exact Stripe Price at or above its advertised floor. Subscription creation alone is not entitlement:
the annual mode of `billing/evaluation_start_ready.py` must report `ready: true`
after the initial invoice is paid before any Certified/Fleet access is enabled.
Repeating an already-created contract plan returns the existing Stripe object
instead of issuing another invoice or subscription. This guarantee uses the
owner-only SQLite path in `TINYZKP_CONTRACT_BILLING_LEDGER_PATH`, not Stripe's
time-limited idempotency cache. Evaluation invoice phases resume from exact
Stripe objects and line items after interruption. An unbound annual
subscription reservation requires explicit `--reconcile-stripe-object-id`
recovery and can never issue another create.
On production this path is
`/var/lib/tinyzkp-private/billing/contract_billing.sqlite`, whose parent is
root-owned mode `0700`; it must not share the service-owned evaluation data
directory.
Contract and order JSON also rejects exponent spellings, negative zero,
trailing fractional zeroes, NaN/Infinity, duplicate keys, and booleans in
integer fields so the hashed numeric terms have one accepted representation.

The Stripe API is pinned to `2026-02-25.clover`. All customer-facing Stripe
identity must say TinyZKP and must never use an unrelated business address.
