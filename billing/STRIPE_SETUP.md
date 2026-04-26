# Stripe Setup for TinyZKP

One-time setup steps for Stripe billing.

> **Pricing change (2026):** The Developer plan moved from $0 to **$9/month** to filter for serious users. Annual variants of every paid plan ship at **20% off**. A new **Verifier-only** $0 plan grants 10,000 free `/verify` calls per month with no payment method on file.

## 1. Create Products

In Stripe Dashboard → Products, create the following products. Save every Price ID (each starts with `price_`).

### Metered Usage (every paid plan)
- **Name**: TinyZKP Proof Generation
- **Description**: ZK-STARK proof generation API — metered usage
- **Price**: Usage-based, metered via `proof_usage` meter, $0.01/unit, monthly

### Developer Monthly (NEW, paid)
- **Name**: TinyZKP Developer
- **Description**: Developer plan — base per-proof rates, 100 RPM, 4 concurrent jobs, $500/mo cap
- **Price**: **$9/month recurring**

### Developer Annual (NEW)
- **Name**: TinyZKP Developer (annual)
- **Description**: Developer plan — same limits, 20% off via annual prepay
- **Price**: **$86.40/year recurring** (12 × $9 × 0.80)

### Team Monthly
- **Name**: TinyZKP Team
- **Description**: Team plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs
- **Price**: $49/month recurring

### Team Annual (NEW)
- **Name**: TinyZKP Team (annual)
- **Description**: Team plan — 20% off via annual prepay
- **Price**: **$470.40/year recurring** (12 × $49 × 0.80)

### Scale Monthly
- **Name**: TinyZKP Scale
- **Description**: Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs
- **Price**: $199/month recurring

### Scale Annual (NEW)
- **Name**: TinyZKP Scale (annual)
- **Description**: Scale plan — 20% off via annual prepay
- **Price**: **$1,910.40/year recurring** (12 × $199 × 0.80)

> **Verifier-only:** No Stripe product. Provisioned via internal `/provision-verifier-only`
> endpoint with a `verifier_only=true` tenant flag. Limits: 0 prove calls, 10,000
> verify calls/month, no monthly cap.

## 2. Create Meter

In Stripe Dashboard → Billing → Meters:

- **Event name**: `proof_usage`
- **Display name**: Proof Usage

## 3. Create Webhook Endpoint

In Stripe Dashboard → Developers → Webhooks:

- **Endpoint URL**: `https://webhook.tinyzkp.com/webhook`
- **Events to listen for**:
  - `checkout.session.completed` — provisions new tenant
  - `customer.subscription.updated` — handles plan changes (incl. monthly ↔ annual)
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — suspends tenant on payment failure

Save the **Webhook Signing Secret** (starts with `whsec_`).

## 4. Store Secrets

Add to `/opt/hc-stark/.env`:

```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_METERED=price_...        # metered usage price
STRIPE_PRICE_ID_DEVELOPER=price_...      # NEW: $9/mo Developer price
STRIPE_PRICE_ID_DEVELOPER_ANNUAL=price_..  # NEW: $86.40/yr Developer annual
STRIPE_PRICE_ID_TEAM=price_...           # $49/mo Team price
STRIPE_PRICE_ID_TEAM_ANNUAL=price_...    # NEW: $470.40/yr Team annual
STRIPE_PRICE_ID_SCALE=price_...          # $199/mo Scale price
STRIPE_PRICE_ID_SCALE_ANNUAL=price_...   # NEW: $1,910.40/yr Scale annual
```

## 5. Checkout Flow

Customers sign up at `https://tinyzkp.com/signup` and select a plan:

- **Free**: No Stripe — provisioned via internal `/provision-free` endpoint (100 proofs/mo, 10 RPM)
- **Verifier-only**: No Stripe — provisioned via `/provision-verifier-only` (10K verifies/mo)
- **Developer**: Stripe Checkout with `STRIPE_PRICE_ID_DEVELOPER` (or `*_ANNUAL`) + metered usage
- **Team**: Stripe Checkout with `STRIPE_PRICE_ID_TEAM` (or `*_ANNUAL`) + metered usage
- **Scale**: Stripe Checkout with `STRIPE_PRICE_ID_SCALE` (or `*_ANNUAL`) + metered usage

The plan name and billing cadence are passed in `metadata.plan` and `metadata.cadence`
on the checkout session and subscription, so the webhook handler can extract them
during tenant provisioning.

## 6. Cloudflare Pages Secrets

Set via `wrangler pages secret put`:

- `STRIPE_SECRET_KEY` — Stripe secret key
- `STRIPE_PRICE_ID_METERED` — metered usage price ID (also accepted as `STRIPE_PRICE_ID` for backward compat)
- `STRIPE_PRICE_ID_DEVELOPER` and `STRIPE_PRICE_ID_DEVELOPER_ANNUAL`
- `STRIPE_PRICE_ID_TEAM` and `STRIPE_PRICE_ID_TEAM_ANNUAL`
- `STRIPE_PRICE_ID_SCALE` and `STRIPE_PRICE_ID_SCALE_ANNUAL`

## 7. Plan-Based Discount Logic

The `sync_usage.py` billing cron applies plan-based discounts before reporting to Stripe:

| Plan | Discount Factor | Example: 1M-step proof |
|------|----------------|----------------------|
| Free | 1.0 (no discount) | 800 cents ($8.00) |
| Verifier-only | n/a (no prove) | n/a |
| Developer | 1.0 (no discount) | 800 cents ($8.00) |
| Team | 0.75 (25% off) | 600 cents ($6.00) |
| Scale | 0.60 (40% off) | 480 cents ($4.80) |

The annual variants use the same per-proof discount as their monthly equivalents — the 20% annual savings
comes from the recurring base fee, not from per-proof rates.

## Price Tiers

Base rates (before plan discounts). `sync_usage.py` reports discounted cents per proof:

| Trace Length | Base Cents | Team (25% off) | Scale (40% off) |
|---|---|---|---|
| < 10K steps | 5 ($0.05) | 4 ($0.04) | 3 ($0.03) |
| 10K–100K | 50 ($0.50) | 38 ($0.38) | 30 ($0.30) |
| 100K–1M | 200 ($2.00) | 150 ($1.50) | 120 ($1.20) |
| 1M–10M | 800 ($8.00) | 600 ($6.00) | 480 ($4.80) |
| > 10M steps | 3000 ($30.00) | 2250 ($22.50) | 1800 ($18.00) |

## Migration

Run `billing/migrate_plans.py` to rename legacy plan names:
- `standard` → `developer`
- `pro` → `scale`

For the Developer-tier price change ($0 → $9/mo), see `billing/migrate_developer_paid.py`
(grandfathers existing Developer accounts at $0/mo for 60 days, then migrates them to the
$9 plan via a Stripe-Checkout-confirmed upgrade flow).
