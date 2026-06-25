# TinyZKP Stripe Product IDs

Generated Stripe IDs should be produced by `billing/setup_stripe_products.sh` and then stored as Cloudflare Pages secrets and production environment variables per `billing/STRIPE_SETUP.md`.

The active storefront requires the monthly flat prices and usage meters below.
The one-time pilot price ID is optional because `/api/create-pilot-checkout`
can use server-defined inline `price_data`. Annual flat-price IDs may exist in Stripe for manual prepaid
contracts, but `site/functions/api/create-checkout.js` intentionally does not
use them until annual usage-meter prices, reporting, and reconciliation are
wired end to end.

| Secret | Plan / meter |
|---|---|
| `STRIPE_PRICE_ID_DEVELOPER` | Developer monthly, $19 |
| `STRIPE_PRICE_ID_PRO` | Pro monthly, $79 |
| `STRIPE_PRICE_ID_SCALE` | Scale monthly, $199 |
| `STRIPE_PRICE_ID_METERED` | `proof_usage` metered price |
| `STRIPE_PRICE_ID_TRACE_STEP_METERED` | `trace_step_usage` metered price for Compute |
| `STRIPE_PRICE_ID_PILOT` | Optional Production Pilot one-time payment, $5,000 |

Optional manual-contract prices:

| Secret | Plan / price |
|---|---|
| `STRIPE_PRICE_ID_DEVELOPER_ANNUAL` | Developer annual, $182.40 |
| `STRIPE_PRICE_ID_PRO_ANNUAL` | Pro annual, $758.40 |
| `STRIPE_PRICE_ID_SCALE_ANNUAL` | Scale annual, $1,910.40 |

`team` is no longer a storefront plan. Old Team Stripe objects may remain in Stripe for legacy subscriptions or checkout-link fallback, but new public checkout should use Pro.

Check whether the authenticated Stripe profile can reach the catalog create
endpoints before setup:

```bash
python3 billing/stripe_account_context_check.py --stripe-bin /opt/homebrew/bin/stripe
python3 billing/stripe_catalog_write_preflight.py --stripe-bin /opt/homebrew/bin/stripe --live --scope full
python3 billing/stripe_catalog_write_preflight.py --stripe-bin /opt/homebrew/bin/stripe --live --scope pilot
```

If TinyZKP is not the default local Stripe CLI profile, add
`--stripe-project-name <profile>` to the account check and write preflight
commands.

The write preflight also validates the local CLI account context. Both setup
scripts run the account-context check and the relevant write preflight
automatically in `--stripe-cli` mode unless `STRIPE_SKIP_ACCOUNT_CONTEXT_CHECK=1`
or `STRIPE_SKIP_WRITE_PREFLIGHT=1` is set.

Run:

```bash
STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_products.sh
# or use the authenticated local Stripe CLI live profile:
bash billing/setup_stripe_products.sh --stripe-cli --push-cloudflare
# or target a non-default local Stripe CLI profile:
bash billing/setup_stripe_products.sh --stripe-cli --stripe-project-name tinyzkp-prod --push-cloudflare
```

The script rewrites this file with the concrete IDs from the active Stripe
account. The `--stripe-cli` path uses the local Stripe CLI profile and still
requires the active CLI `display_name` to match TinyZKP plus live product,
price, and meter write permissions.

If you want a reusable Stripe catalog Price for the pilot instead of relying on
the inline `price_data` fallback, run:

```bash
bash billing/setup_pilot_price.sh --stripe-cli --push-cloudflare
# with an explicit local CLI path:
bash billing/setup_pilot_price.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare
# with a non-default local CLI profile:
bash billing/setup_pilot_price.sh --stripe-cli --stripe-project-name tinyzkp-prod --push-cloudflare
# or:
STRIPE_API_KEY=sk_live_... bash billing/setup_pilot_price.sh --push-cloudflare
```
