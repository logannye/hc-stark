# TinyZKP Stripe object policy

There are no public storefront Price IDs during backend recovery. Developer,
Pro, Scale, Compute, Team, Production Pilot, `proof_usage`, and
`trace_step_usage` are retired legacy objects; their IDs must be discovered
read-only and selected only through a reviewed exact-ID containment manifest.

Do not place live Stripe IDs in this repository or Cloudflare. Store private
inventory, scope, notification, refund/credit, and plan evidence in an
owner-only operator directory.

Evaluation milestones use invoice items created by
`billing/contract_billing.py`; they do not require a reusable Price or Checkout
Session. Certified and Fleet/OEM annual product/price IDs may be created only
after backend release authorization. The contract tool requires exact product
and price IDs plus these immutable provenance markers:

- Product metadata: `tinyzkp_contract_product=true` and the exact
  `tinyzkp_offer_id`.
- Price metadata: `tinyzkp_contract_price=true` and the exact
  `tinyzkp_offer_id`.
- Price lookup key: `<offer_id>_annual_contract_v1`.
- Active annual `send_invoice` product/price amounts matching
  `site/pricing.json`.

See `billing/STRIPE_SETUP.md` and
`commercial/no-email-evaluation-runbook.md` for the current operator flow.
