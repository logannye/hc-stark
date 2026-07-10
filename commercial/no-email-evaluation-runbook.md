# No-email evaluation operations

TinyZKP does not use an unrelated personal or business mailbox for outreach or
recovery-period application acknowledgements. The public form returns the
application ID and benchmark instructions synchronously and stores the record
in an owner-only SQLite ledger.

Applicants select a no-email reply channel (GitHub, LinkedIn, Signal, Discord,
Telegram, Matrix, or phone/SMS). Work email is optional and must not be used for
recovery-period follow-up. Use only the applicant-selected channel and handle.

## Review intake

Run on the production host:

```bash
cd /opt/hc-stark
.venv/bin/python billing/evaluation_intake.py list --status new
.venv/bin/python billing/evaluation_intake.py show eval_REPLACE --include-contact
.venv/bin/python billing/evaluation_intake.py set-status eval_REPLACE qualified
```

The default list is contact-redacted. Use `--include-contact` only when the
operator has a legitimate need to view the applicant's submitted contact data.
Do not copy handles, phone numbers, or optional email addresses into the
repository, issue tracker, benchmark reports, or review bundles.

## Retention

Preview and apply the twelve-month purge:

```bash
.venv/bin/python billing/evaluation_intake.py purge-expired
.venv/bin/python billing/evaluation_intake.py purge-expired --apply
```

The evaluation database is included in the encrypted/private off-host backup
set. Do not export it into the repository, issue tracker, or benchmark bundle.

The installed daily retention job runs as `tinyzkp-billing`, the same account
that owns the database and its `0700` parent directory. Its output is written
with `umask 077` to
`/opt/hc-stark/data/evaluation-retention.log`. A root-owned retention cron will
fail closed because the ledger rejects access by a process with a different
effective owner; do not change the cron user independently of the service
account and data ownership.

## Contract and invoice handoff

1. Have counsel approve `commercial/evaluation-sow.counsel-draft.md`.
2. Freeze and hash a completed acceptance matrix.
3. Obtain signatures outside the public site.
4. Create a private contract-evidence record from the tracked template. Never
   put the completed record or contract documents in the repository:

```bash
install -d -m 700 /var/lib/tinyzkp-private/contracts
install -m 600 commercial/contract-evidence.template.json \
  /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json
sha256sum SIGNED_AGREEMENT ACCEPTANCE_MATRIX
```

   Fill the private record with those hashes, the canonical UTC signature
   time, the exact offer/agreement IDs, and the exact Stripe customer ID. For a
   delivery invoice, create a separate record that also includes the written
   acceptance hash, canonical acceptance time, exact paid deposit invoice ID,
   and the deposit invoice's `tinyzkp_plan_sha256` metadata value.
5. Create or select the positively identified Stripe customer. Before apply,
   its Stripe metadata must contain:

   - `tinyzkp_contract_customer=true`
   - `tinyzkp_agreement_id=AGREEMENT_ID`
   - `tinyzkp_offer_id=founding_evaluation` (or the exact contracted offer)

   The customer must have the customer's contractual billing address. Do not
   use the founder's unrelated-business email address as the customer or sender
   address.
6. Preview the $12,500 Founding Evaluation deposit:

```bash
python3 billing/contract_billing.py evaluation-deposit \
  --offer-id founding_evaluation \
  --customer-id cus_REPLACE \
  --agreement-id REPLACE \
  --contract-evidence /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json \
  --agreement-document SIGNED_AGREEMENT \
  --scope-document ACCEPTANCE_MATRIX
```

7. Record the returned `plan_sha256`. Apply only after exact Stripe account
   verification and explicit operator authorization, passing that hash as
   `--expected-plan-sha256`. Any change to the offer, amount, customer, due
   date, contract hashes, or acceptance evidence changes the plan hash and
   blocks the write. Public Checkout remains disabled. Do not finalize or send
   an invoice until Stripe's customer-facing sender identity has been verified
   as TinyZKP and does not use an unrelated business mailbox. The CLI verifies
   the retrieved Stripe account has public business name `TinyZKP`, a
   `@tinyzkp.com` support email, and a `tinyzkp.com` support URL; the environment
   acknowledgement alone is insufficient. Evaluation invoices remain
   `auto_advance=false` after finalization and the CLI never invokes Stripe's
   send operation. Copy the returned `hosted_invoice_url` into the
   applicant-selected no-email channel; do not enable Stripe email reminders.

The delivery command additionally requires the exact paid deposit invoice in
Stripe. The object ID, customer, amount, currency, collection mode, document
hashes, and recorded deposit plan must all match the delivery evidence; an
open, draft, void, uncollectible, or edited deposit is insufficient. It also
requires `--delivery-acceptance-document`; the CLI hashes all supplied private
documents and refuses any mismatch with the owner-only evidence record.

No evaluation work starts until the signed agreement, paid deposit, frozen
workload digest, acceptance matrix, and baseline host are all recorded.

## Annual contract release authorization

Certified and Fleet/OEM invoicing remains blocked until the audited backend
release workflow emits `backend-v1-commercial-authorization.json` and its
separate `backend-v1-commercial-authorization.sigstore.json` bundle. Download
both only from the corresponding published, non-prerelease `backend-v*` GitHub
release. Verify each GitHub artifact attestation and independently verify that
the authorization was signed by the pinned backend release workflow:

```bash
gh attestation verify backend-v1-commercial-authorization.json \
  --repo logannye/hc-stark \
  --signer-workflow logannye/hc-stark/.github/workflows/release-backend.yml
gh attestation verify backend-v1-commercial-authorization.sigstore.json \
  --repo logannye/hc-stark \
  --signer-workflow logannye/hc-stark/.github/workflows/release-backend.yml
cosign verify-blob \
  --bundle backend-v1-commercial-authorization.sigstore.json \
  --certificate-identity-regexp \
  '^https://github\.com/logannye/hc-stark/\.github/workflows/release-backend\.yml@refs/tags/backend-v[^/]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  backend-v1-commercial-authorization.json
```

Only after all three checks succeed, install both files on the billing host
without trusting archive/download permissions:

```bash
install -m 0600 backend-v1-commercial-authorization.json \
  /var/lib/tinyzkp-private/backend-v1-commercial-authorization.json
install -m 0600 backend-v1-commercial-authorization.sigstore.json \
  /var/lib/tinyzkp-private/backend-v1-commercial-authorization.sigstore.json
sha256sum \
  /var/lib/tinyzkp-private/backend-v1-commercial-authorization.json \
  /var/lib/tinyzkp-private/backend-v1-commercial-authorization.sigstore.json
```

Set `TINYZKP_BACKEND_RELEASE_AUTHORIZATION` to that installed path and
`TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256` to the locally recomputed
digest. Set `TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE` to the installed
Sigstore bundle and `TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256` to
its locally recomputed digest. Never author or edit either file by hand. The
contract CLI reads each owner-only file through one `O_NOFOLLOW` descriptor,
checks both configured digests, and reruns the pinned Sigstore verification.
The authorization binds the final backend
evidence, validator report, signed checksum manifest, Sigstore bundle, release
SHA, and stable source-tree digest. Annual previews include the authorization
digest, its bundle digest, the release SHA, and the source-tree digest in
`plan_sha256`. Apply mode revalidates the exact same binding immediately before
the Stripe subscription write and stores it in Stripe metadata. Preview and
write therefore fail closed when either file, mode, schema, status, signer,
validator identity, configured hash, or release identity differs.

For an annual order, set `negotiated_annual_amount_cents` in the owner-only
contract evidence and complete an owner-only copy of
`commercial/annual-order.template.json`. Export that typed scope with the
countersigned agreement; it binds the exact amount to the agreement digest,
customer, Stripe Price/Product, term, and countersignature times. TinyZKP
Certified requires exactly `6000000`; Fleet/OEM accepts the signed negotiated
amount only when it is at least `12500000`, and the Stripe annual Price must
match it exactly.

Configure an owner-only `TINYZKP_CONTRACT_BILLING_LEDGER_PATH` before apply.
The production default is
`/var/lib/tinyzkp-private/billing/contract_billing.sqlite`; deploy/setup create
its parent as root-owned mode `0700`, matching the root/operator that owns the
contract evidence and runs this CLI. Do not put this ledger back under the
`tinyzkp-billing`-owned `/opt/hc-stark/data` directory.
The tool reserves the operation atomically before contacting Stripe.
Evaluation invoice creation records every durable phase and resumes the exact
draft, line item, or finalized object after a process or network failure.
Annual subscription creation is a single write; if it was accepted before the
object ID was recorded, locate that original result and pass
`--reconcile-stripe-object-id`.

Creating the annual `send_invoice` subscription is not permission to deliver
Certified or Fleet/OEM service. After Stripe records the initial invoice as
paid, generate the machine-checkable entitlement record:

```bash
python3 billing/evaluation_start_ready.py \
  --offer-id tinyzkp_fleet_oem \
  --customer-id cus_REPLACE \
  --agreement-id REPLACE \
  --annual-subscription-id sub_REPLACE \
  --annual-invoice-id in_REPLACE \
  --stripe-price-id price_REPLACE \
  --stripe-product-id prod_REPLACE \
  --contract-evidence /secure/contract-evidence.json \
  --agreement-document /secure/signed-agreement.pdf \
  --scope-document /secure/signed-order-form.json
```

Do not enable service unless this command emits `readiness_kind` equal to
`annual_entitlement` and `ready` equal to `true`. It verifies the paid amount,
initial invoice, exact subscription Price, signed plan, authorization and
source identities, and emits no customer contact data. Re-running any billing
apply command for an existing plan returns that exact Stripe object without a
second create; void or cancel the old object explicitly before replacing it.
