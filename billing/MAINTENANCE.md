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

- $25,000 Founding Memory-Bounded Evaluation for the first two customers
- $40,000 standard Memory-Bounded Prover Evaluation
- $60,000/year TinyZKP Certified (annual prepaid, capped support)
- $125,000/year minimum TinyZKP Fleet / OEM (annual prepaid)
- custom engineering separately scoped at a $300/hour minimum effective rate

The replacement hosted catalog must not be activated until the audit and
review, demand, and 80% gross-margin gates pass. Evaluation milestones use
Stripe Invoicing; annual agreements use Billing subscriptions with
`send_invoice`. Public Checkout remains disabled.

Use `billing/contract_billing.py` to preview a deposit, delivery invoice, or
annual `send_invoice` subscription. Its default is read-only. Apply mode also
requires exact Stripe account identity and the
`TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1` break-glass variable. The delivery
invoice requires explicit delivery-acceptance evidence; annual subscriptions
require an active, exact-price yearly Stripe Price.
