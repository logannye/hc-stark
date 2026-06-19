# TinyZKP Stripe Product IDs

Generated Stripe IDs should be produced by `billing/setup_stripe_products.sh` and then stored as Cloudflare Pages secrets and production environment variables per `billing/STRIPE_SETUP.md`.

The active storefront requires these prices:

| Secret | Plan / meter |
|---|---|
| `STRIPE_PRICE_ID_DEVELOPER` | Developer monthly, $19 |
| `STRIPE_PRICE_ID_DEVELOPER_ANNUAL` | Developer annual, $182.40 |
| `STRIPE_PRICE_ID_PRO` | Pro monthly, $79 |
| `STRIPE_PRICE_ID_PRO_ANNUAL` | Pro annual, $758.40 |
| `STRIPE_PRICE_ID_SCALE` | Scale monthly, $199 |
| `STRIPE_PRICE_ID_SCALE_ANNUAL` | Scale annual, $1,910.40 |
| `STRIPE_PRICE_ID_METERED` | `proof_usage` metered price |
| `STRIPE_PRICE_ID_TRACE_STEP_METERED` | `trace_step_usage` metered price for Compute |

`team` is no longer a storefront plan. Old Team Stripe objects may remain in Stripe for legacy subscriptions or checkout-link fallback, but new public checkout should use Pro.

Run:

```bash
STRIPE_API_KEY=sk_live_... bash billing/setup_stripe_products.sh
```

The script rewrites this file with the concrete IDs from the active Stripe account.
