# Stripe Setup for TinyZKP

One-time setup steps for the self-serve billing model.

> **Current storefront model:** Free, Developer **$19/mo**, Pro **$79/mo**, Scale **$199/mo**, and Compute usage billing at **$0.50 per million trace steps**. Annual paid subscriptions are 20% off. The legacy `team` slug is preserved only as an admin/backward-compatibility alias for Pro.

## 1. Create Products

In Stripe Dashboard -> Products, create the following products. Save every Price ID (each starts with `price_`).

### Metered Proof Usage (Developer / Pro / Scale)
- **Name**: TinyZKP Proof Generation
- **Description**: STARK state-transition receipt generation API — metered usage
- **Price**: Usage-based, metered via `proof_usage`, $0.01/unit, monthly

### Trace-Step Usage (Compute)
- **Name**: TinyZKP Compute
- **Description**: Long state-transition traces — metered by trace step
- **Price**: Usage-based, metered via `trace_step_usage`, $0.50 per 1,000,000 trace steps, monthly

### Developer Monthly
- **Name**: TinyZKP Developer
- **Description**: Developer plan — base per-proof rates, 100 RPM, 4 concurrent jobs, $500/mo cap
- **Price**: **$19/month recurring**

### Developer Annual
- **Name**: TinyZKP Developer (annual)
- **Description**: Developer plan — same limits, 20% off via annual prepay
- **Price**: **$182.40/year recurring** (12 x $19 x 0.80)

### Pro Monthly
- **Name**: TinyZKP Pro
- **Description**: Pro plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs, $2,500/mo cap
- **Price**: **$79/month recurring**

### Pro Annual
- **Name**: TinyZKP Pro (annual)
- **Description**: Pro plan — same limits, 20% off via annual prepay
- **Price**: **$758.40/year recurring** (12 x $79 x 0.80)

### Scale Monthly
- **Name**: TinyZKP Scale
- **Description**: Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs, $10,000/mo cap
- **Price**: **$199/month recurring**

### Scale Annual
- **Name**: TinyZKP Scale (annual)
- **Description**: Scale plan — same limits, 20% off via annual prepay
- **Price**: **$1,910.40/year recurring** (12 x $199 x 0.80)

## 2. Create Meters

In Stripe Dashboard -> Billing -> Meters:

- **Event name**: `proof_usage`
- **Display name**: Proof Usage

And:

- **Event name**: `trace_step_usage`
- **Display name**: Trace Step Usage

The `proof_usage` meter bills discounted cents per generated receipt. The `trace_step_usage` meter bills raw trace steps for Compute, which is the RAM-replacement lane for long state-transition traces.

## 3. Create Webhook Endpoint

In Stripe Dashboard -> Developers -> Webhooks:

- **Endpoint URL**: `https://webhook.tinyzkp.com/webhook`
- **Events to listen for**:
  - `checkout.session.completed` — provisions new tenant
  - `customer.subscription.updated` — handles plan changes, including monthly <-> annual
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — suspends tenant on payment failure

Save the **Webhook Signing Secret** (starts with `whsec_`).

## 4. Store Secrets

Add to `/opt/hc-stark/.env` and Cloudflare Pages secrets as needed:

```bash
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_METERED=price_...              # proof_usage meter price
STRIPE_PRICE_ID_TRACE_STEP_METERED=price_...   # trace_step_usage meter price
STRIPE_PRICE_ID_DEVELOPER=price_...            # $19/mo Developer
STRIPE_PRICE_ID_DEVELOPER_ANNUAL=price_...     # $182.40/yr Developer
STRIPE_PRICE_ID_PRO=price_...                  # $79/mo Pro
STRIPE_PRICE_ID_PRO_ANNUAL=price_...           # $758.40/yr Pro
STRIPE_PRICE_ID_SCALE=price_...                # $199/mo Scale
STRIPE_PRICE_ID_SCALE_ANNUAL=price_...         # $1,910.40/yr Scale
```

Legacy fallback secrets `STRIPE_PRICE_ID_TEAM` and `STRIPE_PRICE_ID_TEAM_ANNUAL` may remain temporarily during rollout; checkout maps `team` to Pro. Do not advertise Team as a storefront plan.

## 5. Checkout Flow

Customers sign up at `https://tinyzkp.com/signup` and select a plan:

- **Free**: No Stripe — provisioned via internal `/provision-free` endpoint
- **Developer**: Stripe Checkout with Developer flat price + `proof_usage`
- **Pro**: Stripe Checkout with Pro flat price + `proof_usage`
- **Scale**: Stripe Checkout with Scale flat price + `proof_usage`
- **Compute**: Stripe Checkout with `trace_step_usage` only, no monthly base

Developer / Pro / Scale subscriptions may also include the trace-step meter if the secret is configured, so long traces can be priced by the RAM-saving Compute economics instead of the regular per-proof ladder.

The plan name and billing cadence are passed in `metadata.plan` and `metadata.cadence` on the checkout session and subscription, so the webhook handler can extract them during tenant provisioning.

## 6. Cloudflare Pages Secrets

Set via `wrangler pages secret put`:

- `STRIPE_SECRET_KEY` — Stripe secret key
- `STRIPE_PRICE_ID_METERED` — metered proof-usage price ID
- `STRIPE_PRICE_ID_TRACE_STEP_METERED` — metered trace-step price ID
- `STRIPE_PRICE_ID_DEVELOPER` and `STRIPE_PRICE_ID_DEVELOPER_ANNUAL`
- `STRIPE_PRICE_ID_PRO` and `STRIPE_PRICE_ID_PRO_ANNUAL`
- `STRIPE_PRICE_ID_SCALE` and `STRIPE_PRICE_ID_SCALE_ANNUAL`

## 7. Plan-Based Discount Logic

The `sync_usage.py` billing cron applies plan-based discounts before reporting `proof_usage` events to Stripe:

| Plan | Discount Factor | Example: 1M-step regular receipt |
|------|----------------|-----------------------------------|
| Free | 1.0 (no discount) | 800 cents ($8.00) |
| Developer | 1.0 (no discount) | 800 cents ($8.00) |
| Pro | 0.75 (25% off) | 600 cents ($6.00) |
| Scale | 0.60 (40% off) | 480 cents ($4.80) |

Compute does not use these discount factors. It bills raw trace steps at $0.50/M steps, with the existing $0.05 minimum enforced by the base-rate floor where applicable.

Annual variants use the same per-proof discount as their monthly equivalents. The 20% annual savings comes from the recurring base fee, not from lower usage prices.

## Price Tiers

Base rates for regular state-transition receipts before plan discounts:

| Trace Length | Base Cents | Pro (25% off) | Scale (40% off) |
|---|---:|---:|---:|
| < 10K steps | 5 ($0.05) | 4 ($0.04) | 3 ($0.03) |
| 10K-100K | 50 ($0.50) | 38 ($0.38) | 30 ($0.30) |
| 100K-1M | 200 ($2.00) | 150 ($1.50) | 120 ($1.20) |
| 1M-10M | 800 ($8.00) | 600 ($6.00) | 480 ($4.80) |
| > 10M steps | 3000 ($30.00) | 2250 ($22.50) | 1800 ($18.00) |

## Migration

Run `billing/migrate_plans.py` to normalize legacy plan names:

- `standard` -> `developer`
- `team` -> `pro`

Do not migrate existing `pro` tenants to Scale; Pro is now the public $79/month intermediate self-serve tier.
