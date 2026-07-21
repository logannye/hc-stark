# No-email evaluation operations

> **Historical/retired recovery evidence — do not execute.** This runbook
> describes the former hosted evaluation, contract, invoicing, and product-tier
> workflow. It cannot qualify a customer, authorize a proposal, create a sale,
> or change current TinyZKP Guard launch state. Use
> `release/guard-launch-state-v2.json`, its digest-bound evidence source, and
> the current Community/Guard offer in `site/pricing.json` instead.

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
/var/lib/tinyzkp-runtime/billing-venv/bin/python billing/evaluation_intake.py list --status new
/var/lib/tinyzkp-runtime/billing-venv/bin/python billing/evaluation_intake.py show eval_REPLACE --include-contact
```

The default list is contact-redacted. Use `--include-contact` only when the
operator has a legitimate need to view the applicant's submitted contact data.
Do not copy handles, phone numbers, or optional email addresses into the
repository, issue tracker, benchmark reports, or review bundles.

The SQLite workflow status is not qualification authority. Do not mark an
application `qualified` or issue a proposal until both machine evidence files
below exist and independently verify. A manually edited status value or JSON
file is insufficient.

## Issue EvaluationQualificationV1

Install `commercial/evaluation-qualification-input.template.json` as mode
`0600` inside an owner-only working directory and replace every placeholder.
It contains no contact handle, email address, witness, credential, customer
data, or private source. Record byte counts, never rounded GiB strings.

For measured RSS, the recorded current peak must be at least 1.5 times the
target ceiling. For OOM evidence, select `oom`, leave
`current_peak_rss_bytes` null, and record the positive numeric cgroup or host
limit in `oom_limit_bytes`; that limit must be at least the target ceiling.

```bash
python3 scripts/commercial/evaluation_qualification.py issue \
  --input /secure/qualification-input.json \
  --output /secure/qualification-v1.json

python3 scripts/commercial/evaluation_qualification.py verify \
  --input /secure/qualification-input.json \
  --evidence /secure/qualification-v1.json
```

The tool requires Plonky3 0.6.1, `tinyzkp-p3-goldilocks-v1`, the
`unmodified-p3-uni-stark-0.6.1` verifier, a deterministic non-sensitive
generator at a full Git revision, a power-of-two row count, local NVMe scratch,
confirmed technical and budget owners, a decision date, and the strict
no-sensitive-data boundary. It reads no network resource and executes no
supplied command. Its owner-only output is canonical JSON; preserve the
reported SHA-256.

## Run PartnerPreflightV1 before a proposal

Qualification alone is not permission to propose work. Build the prospective
adapter in a controlled local environment, capture its source as a regular
archive or Git bundle, preserve the statically linked partner binary, prepare
the workload specification and scratch policy from the tracked templates, and
capture the complete `doctor` resource-estimate JSON. Calculate SHA-256 over
the exact bytes of all six bound files plus the qualification input/evidence,
then place those values in
`commercial/partner-preflight-input.template.json`.
Every private JSON, source archive, and binary supplied to either tool must be
a regular non-symlink file owned by the invoking operator with no group or
other permission bits; use mode `0600` for data and `0700` only when the bound
binary itself must remain executable.

```bash
python3 scripts/commercial/partner_preflight.py issue \
  --input /secure/partner-preflight-input.json \
  --qualification-input /secure/qualification-input.json \
  --qualification /secure/qualification-v1.json \
  --workload-spec /secure/partner-workload-spec.json \
  --adapter-source /secure/partner-adapter.bundle \
  --adapter-artifact /secure/partner-adapter \
  --resource-policy /secure/partner-resource-policy.json \
  --resource-estimate /secure/partner-resource-estimate.json \
  --output /secure/partner-preflight-v1.json

python3 scripts/commercial/partner_preflight.py verify \
  --evidence /secure/partner-preflight-v1.json \
  --input /secure/partner-preflight-input.json \
  --qualification-input /secure/qualification-input.json \
  --qualification /secure/qualification-v1.json \
  --workload-spec /secure/partner-workload-spec.json \
  --adapter-source /secure/partner-adapter.bundle \
  --adapter-artifact /secure/partner-adapter \
  --resource-policy /secure/partner-resource-policy.json \
  --resource-estimate /secure/partner-resource-estimate.json
```

PartnerPreflightV1 recomputes QualificationV1 from its original input; binds
every supplied file by digest; requires the fixed workload and adapter
revisions, argv-form build/baseline/bounded/official-verifier commands,
`ResourceBoundedWorkloadV1`, scratch mode with retain-on-failure checkpoints,
a fixed Linux x86-64 cgroup-v2 host, local NVMe, and estimates within both the
resource policy and host capacity. It validates commands as evidence but never
executes them. A proposal may reference only a verifying preflight evidence
digest.

## Retention

Preview and apply the twelve-month purge:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python billing/evaluation_intake.py purge-expired
/var/lib/tinyzkp-runtime/billing-venv/bin/python billing/evaluation_intake.py purge-expired --apply
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

1. Have counsel replace and approve `commercial/evaluation-sow.counsel-draft.md`.
   The tracked draft is deliberately unsendable. Record the approved template
   and counsel approval hashes in an owner-only copy of
   `commercial/agreement-form-profile.template.json`. After execution, build
   the exact agreement gate:

```bash
python3 billing/agreement_gate.py build \
  --profile /secure/agreement-form-profile.json \
  --approved-template /secure/approved-evaluation-form.md \
  --counsel-approval /secure/counsel-approval.pdf \
  --agreement-source /secure/completed-agreement.md \
  --signed-agreement /secure/signed-agreement.pdf \
  --scope /secure/acceptance-matrix.json \
  --qualification /secure/qualification-v1.json \
  --partner-preflight /secure/partner-preflight-v1.json \
  --agreement-id AGREEMENT_ID \
  --offer-id founding_evaluation \
  --execution-reviewed-by COUNSEL_REVIEWER_ID \
  --execution-reviewed-at RFC3339_UTC_Z_TIME \
  --material-deviations-reviewed \
  --output /secure/agreement-gate-v1.json
```

   This rejects the tracked warning, unresolved bracketed terms, missing fee,
   scope, data, IP, acceptance, retention, or signature clauses, unreviewed
   deviations, and any document/hash mismatch. Counsel approval remains an
   external prerequisite; the validator does not manufacture it.
2. Freeze and hash a completed acceptance matrix.
3. Obtain signatures outside the public site.
4. On a positively identified Stripe **test-mode** account and disposable test
   customer, run the isolated invoice drill. This is the only command in this
   section that mutates Stripe, and it rejects every live key. It creates,
   finalizes, retrieves, and voids one $12,500 test invoice without calling the
   send API or creating Checkout. Set the two non-secret identity variables
   below from the exact owner-reviewed `STRIPE_EXPECTED_ACCOUNT_ID` and
   `STRIPE_EXPECTED_DISPLAY_NAME` values; do not assume the legal/dashboard
   display name is `TinyZKP`:

```bash
EXPECTED_STRIPE_ACCOUNT_ID=acct_REPLACE_FROM_REVIEWED_ENV
EXPECTED_STRIPE_DASHBOARD_NAME='REPLACE_FROM_STRIPE_EXPECTED_DISPLAY_NAME'

TINYZKP_ALLOW_STRIPE_TEST_DRILL_WRITE=1 \
STRIPE_SECRET_KEY=sk_test_REPLACE \
python3 billing/stripe_test_drill.py run \
  --account-id "$EXPECTED_STRIPE_ACCOUNT_ID" \
  --display-name "$EXPECTED_STRIPE_DASHBOARD_NAME" \
  --customer-id cus_REPLACE \
  --drill-id AGREEMENT_ID-preinvoice \
  --release-sha FULL_40_HEX_RELEASE_SHA \
  --output /secure/stripe-test-drill-v1.json \
  --apply

python3 billing/stripe_test_drill.py verify \
  --evidence /secure/stripe-test-drill-v1.json
```

   Never use a live key for this drill. Contract preview rejects evidence older
   than 30 days or from a different account.
5. Create a private `ContractEvidenceV2` record from the tracked template. Never
   put the completed record or contract documents in the repository:

```bash
install -d -m 700 /var/lib/tinyzkp-private/contracts
install -m 600 commercial/contract-evidence.template.json \
  /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json
sha256sum SIGNED_AGREEMENT ACCEPTANCE_MATRIX
```

   Fill the private record with the agreement, scope, agreement-gate,
   qualification, partner-preflight, and Stripe-test-drill hashes; canonical
   signature time; exact offer/agreement IDs; and exact Stripe customer ID.
   For delivery, create a separate record that also includes the complete
   delivery-manifest hash, written-acceptance hash, canonical acceptance time,
   exact paid deposit invoice ID, and deposit invoice
   `tinyzkp_plan_sha256`.
6. Create or select the positively identified Stripe customer. Before apply,
   its Stripe metadata must contain:

   - `tinyzkp_contract_customer=true`
   - `tinyzkp_agreement_id=AGREEMENT_ID`
   - `tinyzkp_offer_id=founding_evaluation` (or the exact contracted offer)

   The customer must have the customer's contractual billing address. Do not
   use the founder's unrelated-business email address as the customer or sender
   address.
7. Preview the $12,500 Founding Evaluation deposit:

```bash
python3 billing/contract_billing.py evaluation-deposit \
  --offer-id founding_evaluation \
  --customer-id cus_REPLACE \
  --agreement-id REPLACE \
  --contract-evidence /var/lib/tinyzkp-private/contracts/AGREEMENT_ID.json \
  --agreement-document SIGNED_AGREEMENT \
  --scope-document ACCEPTANCE_MATRIX \
  --agreement-gate-document /secure/agreement-gate-v1.json \
  --qualification-document /secure/qualification-v1.json \
  --partner-preflight-document /secure/partner-preflight-v1.json \
  --stripe-test-drill-document /secure/stripe-test-drill-v1.json \
  --expected-account-id "$EXPECTED_STRIPE_ACCOUNT_ID" \
  --expected-display-name "$EXPECTED_STRIPE_DASHBOARD_NAME"
```

8. Record the returned `plan_sha256`. Apply only after exact Stripe account
   verification and explicit operator authorization, passing that hash as
   `--expected-plan-sha256`. Any change to the offer, amount, customer, due
   date, contract hashes, or acceptance evidence changes the plan hash and
   blocks the write. The exact dashboard/account identity above may be the
   legal entity name; it is distinct from the public sender profile. Public
   Checkout remains disabled. Do not finalize or send an invoice until
   Stripe's customer-facing sender identity has been verified as TinyZKP and
   does not use an unrelated business mailbox. The CLI separately verifies the
   retrieved Stripe account has public business name `TinyZKP`, a
   `@tinyzkp.com` support email, and a `tinyzkp.com` support URL; the environment
   acknowledgement alone is insufficient. Evaluation invoices remain
   `auto_advance=false` after finalization and the CLI never invokes Stripe's
   send operation. Copy the returned `hosted_invoice_url` into the
   applicant-selected no-email channel; do not enable Stripe email reminders.

The delivery command additionally requires the exact paid deposit invoice in
Stripe. The object ID, customer, amount, currency, collection mode, document
hashes, and recorded deposit plan must all match the delivery evidence; an
open, draft, void, uncollectible, or edited deposit is insufficient. It also
requires `--delivery-acceptance-document`, `--delivery-manifest-document`, and
`--delivery-artifact-root`. Start from
`commercial/evaluation-delivery-manifest.template.json`. The manifest binds the
adapter revision, baseline/candidate `BenchmarkReportV1`, `ProofBundleV1`,
official verifier result, raw measurements, reproduction instructions,
limitations, recommendation, written acceptance, and deletion schedule. The
CLI hashes and semantically checks every owner-only artifact and refuses any
mismatch.

No evaluation work starts until the signed agreement, paid deposit, frozen
workload digest, acceptance matrix, and baseline host are all recorded.

After payment, run `billing/evaluation_start_ready.py` with the same agreement,
scope, agreement-gate, qualification, partner-preflight, and Stripe-test-drill
arguments plus `--deposit-invoice-id`. It emits readiness only when the exact
plan-bound deposit is fully paid. It sends no email and contains no customer
contact data.

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

For an annual order, start from
`commercial/annual-contract-evidence.template.json`, set
`negotiated_annual_amount_cents` in the owner-only contract evidence, and
complete an owner-only copy of
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
