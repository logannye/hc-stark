# Stripe Setup for TinyZKP

One-time setup steps for the self-serve billing model.

> **Current storefront model:** Free, Developer **$19/mo**, Pro **$79/mo**, Scale **$199/mo**, Compute usage billing at **$0.50 per million trace steps**, and a one-time **$5,000 Production Pilot** checkout. Self-serve subscription checkout is monthly only until annual usage metering is wired deliberately. The legacy `team` slug is preserved only as an admin/backward-compatibility alias for Pro.

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

### Developer Annual (manual/future only)
- **Name**: TinyZKP Developer (annual)
- **Description**: Optional manual contract price; not wired to current self-serve checkout because usage meters are monthly
- **Price**: **$182.40/year recurring** (12 x $19 x 0.80)

### Pro Monthly
- **Name**: TinyZKP Pro
- **Description**: Pro plan — 25% off per-proof rates, 300 RPM, 8 concurrent jobs, $2,500/mo cap
- **Price**: **$79/month recurring**

### Pro Annual (manual/future only)
- **Name**: TinyZKP Pro (annual)
- **Description**: Optional manual contract price; not wired to current self-serve checkout because usage meters are monthly
- **Price**: **$758.40/year recurring** (12 x $79 x 0.80)

### Scale Monthly
- **Name**: TinyZKP Scale
- **Description**: Scale plan — 40% off per-proof rates, 500 RPM, 16 concurrent jobs, $10,000/mo cap
- **Price**: **$199/month recurring**

### Scale Annual (manual/future only)
- **Name**: TinyZKP Scale (annual)
- **Description**: Optional manual contract price; not wired to current self-serve checkout because usage meters are monthly
- **Price**: **$1,910.40/year recurring** (12 x $199 x 0.80)

### Production Pilot
- **Name**: TinyZKP Production Pilot
- **Description**: 14-day scoped proof-receipt workflow pilot; creditable toward annual, platform, or reserved-capacity agreement if converted within 60 days
- **Price**: **$5,000 one-time**
- **Storefront binding**: optional `STRIPE_PRICE_ID_PILOT`; if absent, `/api/create-pilot-checkout` uses server-defined inline `price_data`
- **Checkout mode**: `payment` via `/api/create-pilot-checkout`

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
  - `customer.subscription.updated` — handles plan changes
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — logs dunning events while Stripe Smart Retries continue

Save the **Webhook Signing Secret** (starts with `whsec_`).

## 4. Store Secrets

Add to `/opt/hc-stark/.env` and Cloudflare Pages secrets as needed:

```bash
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID_METERED=price_...              # proof_usage meter price
STRIPE_PRICE_ID_TRACE_STEP_METERED=price_...   # trace_step_usage meter price
STRIPE_PRICE_ID_DEVELOPER=price_...            # $19/mo Developer
STRIPE_PRICE_ID_PRO=price_...                  # $79/mo Pro
STRIPE_PRICE_ID_SCALE=price_...                # $199/mo Scale
STRIPE_PRICE_ID_PILOT=price_...                # Optional $5,000 one-time Production Pilot catalog price
```

Annual flat-price IDs may exist for manual contracts, but do not add them to self-serve checkout until matching annual usage-meter prices and reporting are explicitly wired. Legacy fallback secret `STRIPE_PRICE_ID_TEAM` may remain temporarily during rollout; checkout maps `team` to Pro. Do not advertise Team as a storefront plan.

The one-time pilot checkout route can create a Stripe Checkout Session with
server-defined inline `price_data` as long as `STRIPE_SECRET_KEY` is configured.
If you still want a reusable Stripe catalog Price for reporting or dashboard
organization, use the narrow setup script instead of rebuilding the whole
product catalog:

```bash
python3 billing/stripe_account_context_check.py \
  --stripe-bin /opt/homebrew/bin/stripe

python3 billing/stripe_catalog_write_preflight.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --live \
  --scope pilot

bash billing/setup_pilot_price.sh --stripe-cli --push-cloudflare
# with an explicit local CLI path:
bash billing/setup_pilot_price.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare
# or:
STRIPE_API_KEY=sk_live_... bash billing/setup_pilot_price.sh --push-cloudflare
```

The script finds or creates the live `TinyZKP Production Pilot` product, finds
or creates the one-time `$5,000` price, prints `STRIPE_PRICE_ID_PILOT=price_...`,
and can push that value to the `tinyzkp` Cloudflare Pages project. The
`--stripe-cli` path uses the authenticated local Stripe CLI live profile, which
must match the LN Holdings Stripe account used for TinyZKP and have
product/price write permission.
This is optional for taking pilot payments because the route has an inline
`price_data` fallback. The setup script runs the account-context check and the
`pilot` write preflight automatically, and fails before trying to create catalog
objects when the current profile is wrong or cannot write products or prices.

To rebuild or complete the full current Stripe catalog from the authenticated
local Stripe CLI profile, run:

```bash
python3 billing/stripe_account_context_check.py \
  --stripe-bin /opt/homebrew/bin/stripe

python3 billing/stripe_catalog_write_preflight.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --live \
  --scope full

bash billing/setup_stripe_products.sh --stripe-cli --push-cloudflare
# or:
STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_products.sh --push-cloudflare
```

That full setup path finds or creates the live products, prices, and billing
meters, rewrites `billing/STRIPE_PRODUCT_IDS.md`, writes the gitignored
`billing/.stripe_ids.json`, and can push all generated price IDs to the
`tinyzkp` Cloudflare Pages project. The Stripe profile or key must have live
product, price, and billing-meter write permission. The full setup script runs
the account-context check and the `full` write preflight automatically, and
fails before Step 1 when the current CLI profile is not TinyZKP or the current
key cannot reach product, price, or billing-meter create endpoints. Set
`STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK=1` only when the account was intentionally
renamed and independently verified. Set `STRIPE_SKIP_WRITE_PREFLIGHT=1` only
when deliberately testing the create path with a known-good write-capable key.

## 5. Checkout Flow

Customers sign up at `https://tinyzkp.com/signup` and select a plan:

- **Free**: No Stripe — provisioned via internal `/provision-free` endpoint
- **Developer**: Stripe Checkout with Developer flat price + `proof_usage`
- **Pro**: Stripe Checkout with Pro flat price + `proof_usage`
- **Scale**: Stripe Checkout with Scale flat price + `proof_usage`
- **Compute**: Stripe Checkout with `trace_step_usage` only, no monthly base
- **Production Pilot**: Stripe Checkout `mode=payment` with optional `STRIPE_PRICE_ID_PILOT` or server-defined inline `price_data`; webhook routes the paid pilot as a lead notification and does not provision a subscription tenant

Developer / Pro / Scale subscriptions may also include the trace-step meter if the secret is configured, so long traces can be priced by the RAM-saving Compute economics instead of the regular per-proof ladder.

The plan name and monthly billing cadence are passed in `metadata.plan` and `metadata.cadence` on the checkout session and subscription, so the webhook handler can extract them during tenant provisioning.

Pilot checkout passes `metadata.plan=production_pilot`, attribution fields, and
workflow context on both the Checkout Session and PaymentIntent. The webhook
handles the one-time payment as a paid-pilot contact event rather than creating
an API tenant.

`billing/checkout_recovery.py` runs from host cron and lists open Stripe
Checkout Sessions older than the recovery delay. It sends one plaintext recovery
email per eligible subscription Checkout Session, and also follows up open
`production_pilot` one-time payment Sessions. Subscription recovery skips
addresses that already have a tenant; pilot recovery can still email existing
account holders because the pilot is a separate paid consulting package.
Sent recoveries are recorded in `tenant_store.checkout_recovery_emails` so
retries are idempotent.

`billing/stripe_checkout_monitor.py` is the read-only GTM revenue canary for
Checkout Sessions. It keeps output aggregated and omits buyer emails, customer
IDs, session IDs, checkout URLs, and workflow free text. Production monitoring
should validate the Stripe API key against the TinyZKP Stripe account before
trusting Checkout data:

```bash
TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME="LN Holdings" \
TINYZKP_STRIPE_ACCOUNT_SOURCE=api \
TINYZKP_STRIPE_API_KEY_ENV=STRIPE_SECRET_KEY \
python3 billing/stripe_account_context_check.py --account-source api
```

Operator catalog/setup commands can still use the local CLI profile, and those
paths validate the local CLI `display_name` before trusting Stripe data:

```bash
python3 billing/stripe_account_context_check.py \
  --stripe-bin /opt/homebrew/bin/stripe
```

As of 2026-06-29, this machine's default Stripe CLI profile reports
`display_name = 'Galen Health'`, so CLI catalog writes are not authoritative
until the local CLI is switched to the `LN Holdings` Stripe account/profile used
for TinyZKP. `TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME` defaults to `LN Holdings`;
override it only after an intentional account rename.

Use the one-command readiness runner for the normal revenue loop:

```bash
python3 billing/stripe_revenue_readiness.py \
  --account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY \
  --sync-pipeline
```

It validates account context first, then runs the read-only checkout monitor and
optional no-PII pipeline sync. In CLI mode, it also runs the read-only catalog
audit. Add `--plan-only` to preview the commands without touching Stripe or
local ledgers. Add
`--setup-catalog pilot --push-cloudflare` or
`--setup-catalog full --push-cloudflare` only after the `LN Holdings` account
context passes and you intentionally want catalog writes. If that account is
stored under a non-default Stripe CLI profile, pass
`--stripe-project-name <profile>` to the readiness runner and the individual
Stripe CLI tools.

Run the read-only audit with:

```bash
python3 billing/stripe_revenue_ops_audit.py \
  --stripe-bin /opt/homebrew/bin/stripe
```

The revenue-ops audit checks live Stripe billing meters, products, prices,
Cloudflare Pages secret names, and the pilot checkout capability endpoint. It
exits zero when the route is sellable but catalog hygiene is incomplete; pass
`--strict-catalog` after running a write-capable Stripe setup to make remaining
catalog warnings fail the job.

The write preflight is deliberately separate from the read-only audit. It sends
invalid create requests through the Stripe CLI and expects Stripe validation
errors. If it receives a permissions error, the current local CLI profile can
read catalog state but cannot create the missing catalog objects:

```bash
python3 billing/stripe_catalog_write_preflight.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --live \
  --scope full
```

```bash
python3 billing/stripe_checkout_monitor.py \
  --account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY \
  --lookback-hours 168
```

For daily growth checks that should also include live Checkout state, run:

```bash
python3 scripts/monitoring/gtm_growth_monitor.py \
  --offline \
  --stripe-checkout \
  --stripe-account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY
```

To update `marketing/gtm_pipeline_state.json` and rerender the no-PII pipeline
ledger from aggregate Stripe evidence, run:

```bash
python3 scripts/marketing/sync_stripe_checkout_pipeline.py \
  --account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY \
  --lookback-hours 168
```

The sync command never lowers previously recorded revenue when a narrow
lookback window has no paid pilot sessions. It records row-level payment
evidence as the Stripe Dashboard payments page, not as customer emails, Stripe
object IDs, or checkout URLs.

Use `--min-paid-sessions` on the standalone monitor, or
`--stripe-checkout-min-paid-sessions` on the aggregate growth monitor, only for
alerting contexts where zero paid Checkout Sessions should fail the job.

## 6. Cloudflare Pages Secrets

Set via `wrangler pages secret put`:

- `STRIPE_SECRET_KEY` — Stripe secret key
- `STRIPE_PRICE_ID_METERED` — metered proof-usage price ID
- `STRIPE_PRICE_ID_TRACE_STEP_METERED` — metered trace-step price ID
- `STRIPE_PRICE_ID_DEVELOPER`
- `STRIPE_PRICE_ID_PRO`
- `STRIPE_PRICE_ID_SCALE`
- `STRIPE_PRICE_ID_PILOT`

## 7. Plan-Based Discount Logic

The `sync_usage.py` billing cron applies plan-based discounts before reporting `proof_usage` events to Stripe:

| Plan | Discount Factor | Example: 1M-step regular receipt |
|------|----------------|-----------------------------------|
| Free | 1.0 (no discount) | 800 cents ($8.00) |
| Developer | 1.0 (no discount) | 800 cents ($8.00) |
| Pro | 0.75 (25% off) | 600 cents ($6.00) |
| Scale | 0.60 (40% off) | 480 cents ($4.80) |

Compute does not use these discount factors. It bills raw trace steps at $0.50/M steps, with the existing $0.05 minimum enforced by the base-rate floor where applicable.

Annual self-serve checkout is intentionally disabled until annual usage-meter prices and usage reporting are wired end to end.

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
