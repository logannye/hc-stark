# Stripe Setup for TinyZKP

One-time setup steps for Stripe billing.

## 1. Create Product

In Stripe Dashboard > Products:

- **Name**: TinyZKP Proof Generation
- **Description**: ZK-STARK proof generation API

## 2. Create Price

On the product, add a price:

- **Pricing model**: Usage-based
- **Usage type**: Metered
- **Billing scheme**: Per unit
- **Unit amount**: $0.01 (1 cent — we report actual cents per proof as quantity)
- **Billing period**: Monthly

Save the **Price ID** (starts with `price_`).

## 3. Create Webhook Endpoint

In Stripe Dashboard > Developers > Webhooks:

- **Endpoint URL**: `https://webhook.tinyzkp.com/webhook`
- **Events to listen for**:
  - `checkout.session.completed` — provisions new tenant
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — suspends tenant on payment failure

Save the **Webhook Signing Secret** (starts with `whsec_`).

## 4. Store Secrets

Add to `/opt/hc-stark/.env`:

```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID=price_...
```

## 5. Checkout

Customers sign up at `https://tinyzkp.com/signup`. The signup page calls a Cloudflare Pages Function that creates a Stripe Checkout session and redirects the customer.

To generate a checkout link manually (e.g., for direct sharing):

```bash
STRIPE_SECRET_KEY=sk_live_... STRIPE_PRICE_ID=price_... python3 billing/create_checkout.py
```

## 6. Cloudflare Pages Secrets

The checkout Pages Function needs these secrets (set via `wrangler pages secret put`):

- `STRIPE_SECRET_KEY` — same as above
- `STRIPE_PRICE_ID` — same as above

## 7. Going Live

Switch from Stripe test mode to live mode for real payments.

### Steps

1. **Switch to Live mode** in Stripe Dashboard (toggle at top-left)

2. **Create live Product**: Same name/description as test mode ("TinyZKP Proof Generation")

3. **Create live Meter**: Event name must be `proof_usage` (matches `sync_usage.py`)

4. **Create live Price** on the product:
   - Usage-based, metered via the `proof_usage` meter
   - Per unit: $0.01 (1 cent)
   - Monthly billing

5. **Create live Webhook** endpoint:
   - URL: `https://webhook.tinyzkp.com/webhook`
   - Events: `checkout.session.completed`, `customer.subscription.deleted`, `invoice.payment_failed`
   - Save the signing secret (`whsec_...`)

6. **Update Cloudflare Pages secrets** (website checkout):
   ```bash
   npx wrangler pages secret put STRIPE_SECRET_KEY --project-name tinyzkp  # sk_live_...
   npx wrangler pages secret put STRIPE_PRICE_ID --project-name tinyzkp    # price_...
   ```

7. **Update Hetzner `.env`** with live keys:
   ```
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   STRIPE_PRICE_ID=price_...
   ```

8. **Redeploy**:
   ```bash
   # Website
   npx wrangler pages deploy . --project-name tinyzkp

   # Server
   cd /opt/hc-stark && docker compose down && docker compose up -d
   ```

9. **Verify**: Make a test purchase at `https://tinyzkp.com/signup` with a real card

### Checklist

- [ ] Live Product created
- [ ] Live Meter created (event_name: `proof_usage`)
- [ ] Live Price created (usage-based, $0.01/unit, monthly)
- [ ] Live Webhook created (3 events)
- [ ] Cloudflare Pages secrets updated
- [ ] Hetzner `.env` updated
- [ ] Website redeployed
- [ ] Server redeployed
- [ ] Test purchase successful

## Price Tiers

The `sync_usage.py` script reports usage in cents per proof:

| Trace Length | Cents Reported |
|---|---|
| < 10K steps | 5 ($0.05) |
| 10K–100K | 50 ($0.50) |
| 100K–1M | 200 ($2.00) |
| 1M–10M | 500 ($5.00) |
| > 10M steps | 2000 ($20.00) |
