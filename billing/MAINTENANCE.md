# Billing maintenance boundary

Self-serve Checkout, Developer/Pro/Scale prices, Compute meters, the legacy
Production Pilot, and live meter-event synchronization are retired during the
Plonky3 backend recovery.

The website checkout functions are hard-disabled. The legacy catalog scripts
also refuse writes by default, and `sync_usage.py` refuses live-key meter events
unless an explicit break-glass variable is set. That override exists only for
reconciliation of a pre-existing invoice; it is not authorization to sell the
legacy protocol.

Commercial work during maintenance is contracted and invoiced as one of:

- $15,000 Founding Memory-Bounded Evaluation for the first three customers
  (two weeks, at most eight engineering days, $7,500 per milestone)
- $40,000 standard Memory-Bounded Prover Evaluation
- $60,000/year TinyZKP Certified after backend v1 release (annual prepaid,
  capped support)
- $125,000/year minimum TinyZKP Fleet / OEM after backend v1 release (annual
  prepaid)
- custom engineering separately scoped at a $300/hour minimum effective rate

The replacement hosted catalog must not be activated until the audit and
review, demand, and 80% gross-margin gates pass. Evaluation milestones use
Stripe Invoicing; annual agreements use Billing subscriptions with
`send_invoice`. Public Checkout remains disabled.

Use `billing/contract_billing.py` to preview a deposit, delivery invoice, or
annual `send_invoice` subscription. Its default is read-only. Every request is
bound to an owner-only `ContractEvidenceV2` record containing the signed
agreement and scope hashes, signature time, exact offer, agreement, and Stripe
customer. Evaluation records additionally bind `EvaluationQualificationV1`,
`PartnerPreflightV1`, a counsel-approved agreement gate, and a fresh Stripe
test-mode drill. Delivery records bind the complete artifact/retention manifest.
Apply mode requires the exact read-only `plan_sha256`, exact Stripe
account identity, a contract-tagged customer, and the
`TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1` break-glass variable. Evaluation
invoices are finalized with `auto_advance=false`; the CLI never calls Stripe's
invoice-send API and returns the hosted invoice URL only to the operator for
delivery through the applicant-selected no-email channel. The delivery
invoice requires hashed delivery-acceptance evidence plus the exact paid
deposit invoice ID and deposit plan hash;
annual subscriptions require an active, exact-price yearly Stripe Price. Apply
mode reconciles existing Stripe invoices so the founding offer cannot exceed
the `customer_cap` in `site/pricing.json`. Preview and apply both hash the owner-only agreement and
scope documents directly and reject any mismatch with the evidence record.
Certified/Fleet previews additionally require the owner-only commercial release
authorization and its separately signed Sigstore bundle. The CLI verifies the
pinned backend release workflow, includes both artifact digests and the exact
release/source identity in `plan_sha256`, records that binding in Stripe
metadata, and revalidates it immediately before creating the subscription.
The signed evidence also carries `negotiated_annual_amount_cents`, but that
field is never trusted alone. The owner-only scope must be a typed
`tinyzkp-annual-order-v1` record exported with the countersigned agreement; it
binds the exact amount, agreement digest, customer, Price, Product, currency,
term, and both countersignature times. Certified must equal its fixed price,
while Fleet/OEM may exceed but never fall below the published minimum.

Every apply requires `TINYZKP_CONTRACT_BILLING_LEDGER_PATH`. An atomic SQLite
reservation is written before the first Stripe create. Evaluation invoices
persist `reserved`, `invoice_created`, `item_created`, and `finalized` phases.
A repeated apply locates the exact plan-bound draft or reads the recorded
object, validates the one exact line item, and resumes the remaining
idempotent phase without sending it. Annual single-object writes still require
`--reconcile-stripe-object-id` when Stripe accepted the write before its object
ID was recorded. Edited metadata or conflicting objects always fail closed.
The production ledger lives at
`/var/lib/tinyzkp-private/billing/contract_billing.sqlite` in a root-owned
`0700` directory so the documented root/operator invocation and its private
contract evidence share one ownership boundary.

All contract JSON uses the restricted canonical number grammar implemented by
`validate_canonical_json_numbers`: ordinary integers or decimal fractions only,
with no exponent notation, negative zero, or insignificant trailing zeroes.
Boolean values never satisfy integer fields, and NaN/Infinity are forbidden.

Creating a `send_invoice` subscription does not activate TinyZKP service.
`billing/evaluation_start_ready.py` is also the annual entitlement gate: its
machine-readable `annual_entitlement` report is emitted only when the exact
initial subscription invoice is fully paid and every contract, plan, price,
and backend-release binding matches.

Use `billing/configure_contract_portal.py` to preview the restricted Customer
Portal policy. Apply mode requires exact account identity and
`TINYZKP_ALLOW_PORTAL_CONFIGURATION_WRITE=1`; the portal exposes invoices and
payment-method updates but forbids subscription changes and cancellation.
