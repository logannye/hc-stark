# Stripe Setup for TinyZKP

One-time setup steps for Stripe billing.

## 1. Create Products

In Stripe Dashboard > Products, create three products:

### Metered Usage (all paid plans)
- **Name**: TinyZKP Proof Generation
- **Description**: ZK-STARK proof generation API — metered usage
- **Price**: Usage-based, metered via `proof_usage` meter, $0.01/unit, monthly

### Team Monthly (Team plan)
- **Name**: TinyZKP Team
- **Description**: Team plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs
- **Price**: $49/month recurring

### Scale Monthly (Scale plan)
- **Name**: TinyZKP Scale
- **Description**: Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs
- **Price**: $199/month recurring

Save all three **Price IDs** (start with `price_`).

## 2. Create Meter

In Stripe Dashboard > Billing > Meters:

- **Event name**: `proof_usage`
- **Display name**: Proof Usage

## 3. Create Webhook Endpoint

In Stripe Dashboard > Developers > Webhooks:

- **Endpoint URL**: `https://webhook.tinyzkp.com/webhook`
- **Events to listen for**:
  - `checkout.session.completed` — provisions new tenant
  - `customer.subscription.updated` — handles plan changes
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — suspends tenant on payment failure

Save the **Webhook Signing Secret** (starts with `whsec_`).

## 4. Store Secrets

Add to `/opt/hc-stark/.env`:

```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_METERED=price_...    # metered usage price
STRIPE_PRICE_ID_TEAM=price_...       # $49/mo Team price
STRIPE_PRICE_ID_SCALE=price_...      # $199/mo Scale price
```

## 5. Checkout Flow

Customers sign up at `https://tinyzkp.com/signup` and select a plan:

- **Free**: No Stripe — provisioned via internal `/provision-free` endpoint
- **Developer**: Stripe Checkout with metered usage price only
- **Team**: Stripe Checkout with Team flat price + metered usage price
- **Scale**: Stripe Checkout with Scale flat price + metered usage price

The plan name is passed in `metadata.plan` on the checkout session and subscription,
so the webhook handler can extract it during tenant provisioning.

## 6. Cloudflare Pages Secrets

Set via `wrangler pages secret put`:

- `STRIPE_SECRET_KEY` — Stripe secret key
- `STRIPE_PRICE_ID_METERED` — metered usage price ID (also accepted as `STRIPE_PRICE_ID` for backward compat)
- `STRIPE_PRICE_ID_TEAM` — Team $49/mo price ID
- `STRIPE_PRICE_ID_SCALE` — Scale $199/mo price ID

## 7. Plan-Based Discount Logic

The `sync_usage.py` billing cron applies plan-based discounts before reporting to Stripe:

| Plan | Discount Factor | Example: 1M-step proof |
|------|----------------|----------------------|
| Free | 1.0 (no discount) | 800 cents ($8.00) |
| Developer | 1.0 (no discount) | 800 cents ($8.00) |
| Team | 0.75 (25% off) | 600 cents ($6.00) |
| Scale | 0.60 (40% off) | 480 cents ($4.80) |

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
