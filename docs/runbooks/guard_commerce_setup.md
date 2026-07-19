# TinyZKP Guard merchant setup and evidence runbook

Status: operator procedure. Never commit Lemon Squeezy credentials, license
keys, purchaser data, checkout-session data, or private evidence.

## Catalog contract

Create one Lemon Squeezy product for TinyZKP Guard with two subscription
variants:

| Variant | Price | Required behavior |
|---|---:|---|
| Annual | $4,990/year | Default and emphasized; founding customers use this exact undiscounted variant |
| Monthly | $499/month | Publicly available at GA but not the founding-customer gate |

Both variants cover one legal organization with unlimited internal users and
runners. Configure subscription license keys with no machine activation limit.
Enable the hosted customer portal, invoices, dunning, and cancel-at-period-end.
Disable trials, coupons, add-ons, usage metering, subscription pauses, and
enterprise variants.

Never delete or repurpose a reviewed store, product, monthly-variant, or
annual-variant ID. A catalog change requires the release class and evidence
defined in `docs/runbooks/release_provenance.md`.

## Test-mode lifecycle

Using test-mode credentials stored outside the repository:

1. Buy both variants through their hosted checkout.
2. Confirm receipt, subscription, and license-key creation.
3. Activate the exact Guard candidate and verify that only activation uses the
   network.
4. Confirm an invalid, expired, canceled-before-activation, and wrong-product
   license fails closed without exposing the key.
5. Exercise renewal, failed payment/dunning, payment-method change, invoice,
   cancel-at-period-end, refund, and portal access.
6. Exercise timeouts, invalid JSON, oversized responses, certificate failure,
   and provider error responses against the checked-in adapter fixtures.
7. Confirm logs, diagnostics, evidence, and support output redact credentials,
   license keys, purchaser identity, and provider responses.
8. Record only scrubbed result digests and reviewed catalog identifiers in the
   private evidence bundle.

Any semantic mismatch between this contract, checkout, portal, license
lifecycle, or Guard activation blocks launch.

## Live-hidden setup

After seller approval, counsel approval, sandbox lifecycle, canonical signing
trust, and release rehearsal pass:

1. Create or confirm the live product and exact variants.
2. Record the store, product, monthly-variant, and annual-variant IDs plus
   checkout and portal URLs in protected evidence.
3. Derive `commerce_state: live_hidden`. Do not edit `site/commerce.json`
   manually.
4. Confirm the public site still renders every checkout control as closed.
5. Complete one ordinary live owner purchase, receipt, license delivery,
   activation, portal, cancellation, and eligible refund smoke.
6. Supply the ordinary annual checkout URL privately to qualified founding
   organizations. Do not create a discount, coupon, invoice, or custom order.

## Founding and GA evidence

- Two distinct organizations must complete settled $4,990 annual purchases
  through the exact GA annual variant.
- Five clean external Linux machines must complete purchase, license delivery,
  download, signature verification, activation, proof, ordinary verification,
  interruption, and resume; at least four finish within 60 minutes.
- Public files contain only opaque identifiers, counts, digests, standardized
  outcomes, and reviewed release/catalog identity. Customer names, emails,
  payment data, license keys, and proof data remain private.
- Promotion publishes the existing candidate bytes. A later evidence-only
  change derives `commerce_state: public_live`; the checkout URLs must remain
  suppressed for every other state.

## Production canary and freeze

After `public_live`, verify both public checkout links, displayed prices,
annual-default emphasis, portal path, current release/index, and successful
ordinary purchase-to-activation behavior. Verify stale, missing, or mismatched
commerce/release evidence removes every purchase link.

Immediately freeze sales through signed reviewed evidence for a merchant
semantic failure, credential exposure, incorrect price, incorrect entitlement,
license activation defect, legal-document mismatch, or high/critical security
finding. Do not disable an already activated local release or claim remote
revocation.
