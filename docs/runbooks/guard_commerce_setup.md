# Retired: TinyZKP Guard merchant setup and evidence runbook

This runbook is historical and **must not be executed**.

The Guard SKU was withdrawn. `site/release-channels-v1.json` publishes
`current_channel: guard_withdrawn`, which means checkout is closed permanently,
no Lemon Squeezy store, product, or variant may be created or reopened, and no
bootstrap transition in the sequence below is available. Its former status line
read "operator procedure", which is exactly the failure this banner exists to
prevent: an operator reading it would have started standing up a merchant
catalog for a product that is not for sale. Revenue is zero by design.

Two things it references are still live and are **not** retired by this banner:
[`legacy_retirement_notice.md`](legacy_retirement_notice.md), whose exact bytes
are hashed by `scripts/ci/guard_launch_gate.py` and whose obligations checklist
still governs, and [`release_provenance.md`](release_provenance.md), the active
release-control runbook.

For the system that is actually running, see
[`production_operations.md`](production_operations.md).

The catalog contract, lifecycle, and evidence requirements are preserved below
so that a future commerce decision starts from the reviewed version rather than
from scratch. Never commit Lemon Squeezy credentials, license keys, purchaser
data, checkout-session data, or private evidence.

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

## Owner bootstrap and state changes

Do not hand-edit generated launch, commerce, pricing, release, or discovery
files. From protected `main`, dispatch
`.github/workflows/configure-guard-launch.yml` with the exact current main SHA.
For `configure`, supply strict `GuardOwnerLaunchConfigurationV1` JSON. The only
forward bootstrap transitions are `unconfigured → test_published →
test_verified → live_hidden`; each input names its expected current state and
the workflow opens a `codex/*` PR without merging it. The first transition
stages the exact version/Guard SHA/engine SHA identity, hashes the actual
repository legal bytes, and keeps checkout closed. Subsequent transitions are
accepted only when existing signed evidence remains valid.

For an emergency stop, dispatch the same workflow with `operation=freeze-sales`
and an empty configuration. It accepts only the canonical qualified
`public_live` state, creates a keyless owner-signed freeze envelope bound to the
exact dispatch commit and prior live-source digest, changes the requested
commerce state plus that freeze reference, regenerates checkout closed, and
preserves the customer portal and published artifacts. No other launch fact is
changed. The operation does not require a fresh 24-hour evaluation, so stale
mutable evidence cannot prevent an emergency stop.

All owner workflows push the exact prepared `codex/*` branch before requesting
a pull request. If repository Actions settings reject bot-created pull requests,
the job completes with a warning and places an owner-ready GitHub compare URL in
the workflow summary; open that URL, create the PR, wait for required CI, and
merge it as the repository owner. Nothing is rebuilt or re-signed. Automatic PR
creation is optional: the owner may enable **Settings → Actions → General →
Workflow permissions → Allow GitHub Actions to create and approve pull
requests**. The workflows never approve or merge their own PRs, and launch does
not depend on enabling that setting.

## Test-mode lifecycle

Using test-mode credentials stored outside the repository:

1. Buy both variants through their hosted checkout.
2. Confirm receipt, subscription, and license-key creation. Verify the receipt
   or confirmation download target is exactly `https://tinyzkp.com/releases`
   and that the page resolves the exact signed current artifact.
3. Confirm checkout presents and requires acceptance of the exact
   owner-approved EULA at
   `https://tinyzkp.com/legal/<eula_sha256>/EULA.txt`, and the receipt records
   the same effective date and digest without purchaser PII in public evidence.
4. Activate the exact Guard candidate and verify that only activation uses the
   network.
5. Confirm an invalid, expired, canceled-before-activation, and wrong-product
   license fails closed without exposing the key.
6. Exercise renewal, failed payment/dunning, payment-method change, invoice,
   cancel-at-period-end, refund, and portal access.
7. Exercise timeouts, invalid JSON, oversized responses, certificate failure,
   and provider error responses against the checked-in adapter fixtures.
8. Confirm logs, diagnostics, evidence, and support output redact credentials,
   license keys, purchaser identity, and provider responses.
9. Record only scrubbed result digests and reviewed catalog identifiers in the
   private evidence bundle.

Any semantic mismatch between this contract, checkout, portal, license
lifecycle, or Guard activation blocks launch.

## Live-hidden setup

After LN Holdings owner approval, sandbox lifecycle, canonical signing
trust, and release rehearsal pass:

1. Create or confirm the live product and exact variants.
2. Record the store, product, monthly-variant, and annual-variant IDs plus
   checkout and portal URLs in protected evidence.
3. Derive `commerce_state: live_hidden`. Do not edit `site/commerce.json`
   manually.
4. Confirm the public site still renders every checkout control as closed.
5. Without creating an expensive recurring self-purchase, inspect both active
   live variants, exact prices, checkout rendering, generic portal settings,
   and unlimited-activation subscription license-key configuration.
6. Configure a managed private ordinary-support mailbox. Send an end-to-end
   test message, verify owner access to the delivered message, and confirm the
   intended retention/deletion configuration. Record only the mailbox address
   and the five boolean readiness results in `MerchantLiveSmokeEvidenceV1`;
   never place test-message contents, purchaser data, credentials, proof data,
   or license keys in evidence. Until all support fields pass, checkout remains
   closed and the site does not publish the ordinary-support address.

## Advisory adoption evidence

- Two distinct annual customers and five unaided Linux journeys are optional,
  transparent post-launch/adoption metrics, not checkout gates. Until real
  evidence exists they remain `not_completed`.
- Public files contain only opaque identifiers, counts, digests, standardized
  outcomes, and reviewed release/catalog identity. Customer names, emails,
  payment data, license keys, and proof data remain private.
- Promotion publishes the existing candidate bytes. A later evidence-only
  change derives `commerce_state: public_live`; the checkout URLs must remain
  suppressed for every other state.

## Production canary and freeze

After `public_live`, verify both public checkout links, displayed prices,
annual-default emphasis, generic portal path, active license settings, and the
current release/index without creating a recurring test purchase. Verify
stale, missing, or mismatched commerce/release evidence removes every purchase
link.

Immediately freeze sales through signed reviewed evidence for a merchant
semantic failure, credential exposure, incorrect price, incorrect entitlement,
license activation defect, legal-document mismatch, or high/critical security
finding. Do not disable an already activated local release or claim remote
revocation.

## Legacy account retirement before transition

Before signing `legacy_obligations_resolved`, follow
[`legacy_retirement_notice.md`](legacy_retirement_notice.md). The current owner
inventory, verified directly from the legacy tenant and usage stores on
2026-07-24, is 10 synthetic/test free accounts and 0 external accounts.
Historical API use belongs to 2 of those synthetic accounts; no external
account has API or billed usage. The 2 owner-only legacy TinyZKP $19
subscriptions have been canceled and the legacy TinyZKP catalog objects have
been disabled without modifying unrelated Casino Coach records. These facts do
not satisfy the gate by themselves: the synthetic internal disposition,
owner-only subscription dispositions, retained-record documentation, and every
open obligation must be resolved first. No customer retirement notice or
external export disposition is required for a zero-external-account inventory.
Keep tenant identities and delivery evidence out of Git; sign only aggregate
claims and the exact notice-template digest.
