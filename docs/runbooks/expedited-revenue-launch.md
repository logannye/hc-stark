# TinyZKP expedited containment and evaluation launch

Status: **authoritative operator runbook** for the backend-recovery launch.

This runbook launches a fail-closed maintenance site, API, MCP service, and
no-email evaluation intake. It does **not** launch hosted proving, hosted
verification, public Checkout, account creation, metered billing, Certified,
or Fleet/OEM service.

The first revenue event is a countersigned Founding Evaluation followed by a
paid `$7,500` deposit. Production proving remains blocked.

## Non-negotiable communication boundary

- Never use the founder's unrelated personal or other-business email address
  for TinyZKP outreach, marketing, customer communication, Stripe sender
  identity, or website contact information.
- Do not send outbound email during recovery. Do not enable SMTP, lifecycle
  nudges, Checkout recovery, Stripe email reminders, or
  `TINYZKP_CUSTOMER_EMAILS_ENABLED`.
- The public site uses HTTPS forms and returns the application ID and benchmark
  instructions synchronously. Follow up only through the reply channel and
  handle selected by the applicant.
- Stripe's private customer-facing support identity may require a real
  `@tinyzkp.com` mailbox. That mailbox must be dedicated to TinyZKP, need not be
  listed on the website, and must not be the founder's unrelated-business
  address.
- The exact Stripe **dashboard/account display name** comes from the owner-only
  `STRIPE_EXPECTED_DISPLAY_NAME` setting. It may be a legal account name and is
  not assumed to equal `TinyZKP`. The separate sender-profile gate requires
  public business name `TinyZKP`, an `@tinyzkp.com` support address, and an
  HTTPS `tinyzkp.com` support URL.

## Authority classes

| Class | Examples | Rule |
|---|---|---|
| Local/read-only | Git inspection, local tests, templates, plans, digest calculation | May be run without changing an external system. |
| External/read-only | Stripe inventory, account identity retrieval, Cloudflare deployment preview, public GET canaries | Requires the correct credentials but performs no remote write. Preserve private outputs owner-only. |
| Host preparation | Runtime materialization, Docker image build/tag, evidence capture | Changes only the reviewed operator host. Run only after the final source SHA and host are selected. |
| Explicit external/write | Push/merge, Stripe archive/pause/refund/credit, test invoice drill, host deploy, Pages deploy/rollback, durable-intake canary, contract invoice, customer/prospect contact | Requires explicit operator authorization for that exact action and target. A plan hash is not authorization by itself. |

No command in this document authorizes a subsequent command.

## Release and branch order

The containment and backend branches are separate release trains.

1. Review and merge `codex/evaluation-revenue-launch` into `main` first. Do not
   include backend proving work in this emergency containment change.
2. Capture and independently review the fixed-host runtime and operator
   evidence described below. Any reviewed provenance or reviewer-key source
   change must be merged to `main` before choosing the final deployment SHA.
3. Use one clean checkout whose `HEAD` equals the freshly fetched remote
   `origin/main` SHA. That exact SHA is the API, MCP, site, image, preflight,
   and canary identity.
4. Only after containment is live, merge the final `origin/main` into
   `codex/plonky3-backend-recovery`, resolve its overlapping CI/site files, and
   rerun every backend gate. Backend evidence generated before that integration
   is not release evidence.

Local inspection is read-only:

```bash
git fetch origin
git status --short --branch
git rev-list --left-right --count origin/main...HEAD
git diff --check
```

Pushing the branch, opening the PR, and merging it are explicit remote writes.
After authorized merge, prepare the host checkout without a local merge:

```bash
cd /opt/hc-stark
/usr/bin/git fetch origin
/usr/bin/git switch main
/usr/bin/git pull --ff-only origin main
test "$(/usr/bin/git rev-parse HEAD)" = "$(/usr/bin/git rev-parse origin/main)"
test -z "$(/usr/bin/git status --porcelain=v1)"
RELEASE_SHA="$(/usr/bin/git rev-parse HEAD)"
test "${#RELEASE_SHA}" -eq 40
```

After containment deployment, integrate the backend locally before any backend
PR or evidence run:

```bash
cd /path/to/hc-stark-plonky3-recovery
git fetch origin
git switch codex/plonky3-backend-recovery
git merge --no-edit origin/main
test -z "$(git diff --name-only --diff-filter=U)"
git diff --check
```

The backend integration, push, and PR remain separately reviewed actions.

## Gate A: local containment source

From the clean containment source, run:

```bash
python3 scripts/ci/production_launch_preflight.py
python3 scripts/ci/recovery_reconciliation_invariants.py
python3 scripts/ci/backend_recovery_gate.py
python3 scripts/ci/site_route_check.py
python3 scripts/commercial/render_offers.py --check
git diff --check
```

This proves local source policy only. It does not prove production readiness.

## Gate B: immutable external evidence blockers

Every item below must exist and verify for the final deployment SHA. None can
be replaced by a hand-edited `passed` field.

| Evidence | Required location or source | Blocking condition |
|---|---|---|
| Reviewed Debian runtime provenance | `billing/host-runtime-provenance.json` | The committed file currently starts `unconfigured`; capture on the fixed Debian 12 host, obtain independent review, and merge the reviewed source file. |
| Billing wheelhouse and runtime | `/var/lib/tinyzkp-runtime/wheelhouse` and `/var/lib/tinyzkp-runtime/billing-venv` | Materialize the exact reviewed wheels and run `deploy/hetzner/install_billing_runtime.sh`. |
| Signed installer drill | `/var/lib/tinyzkp-private/deploy/installer-drill-evidence.json` | The reviewer key must be pinned in `release/operator-evidence-reviewers-v1.json`; the complete root/Linux crash, signal, concurrency, rollback, and retry drill must be signed and fresh. |
| Fixed-host backup/restore review | `/var/lib/tinyzkp-private/backup/fixed-host-evidence/` | The encrypted rclone upload, readback, semantic restore, failure/signal matrix, raw artifacts, and independent review must pass. |
| Legacy Stripe containment | `/var/lib/tinyzkp-private/deploy/legacy-billing-containment-status.json` | Exact TinyZKP objects must no longer be chargeable; unrelated products remain untouched; selected subscriptions require notification and refund/credit/`none_due` evidence. The status expires after 15 minutes. |
| Private deployment inputs | `/opt/hc-stark/.env`, Pages bindings, contact secret, backup loader token, rclone config | Required owner, mode, exact-account, no-legacy-secret, and backup capability checks must pass. |
| Pinned Pages runtime | reviewed Node and Wrangler paths under `/var/lib/tinyzkp-runtime` | Do not use `npx`, a global Wrangler, dashboard upload, or an unpinned runtime. |
| Immutable maintenance images | `tinyzkp/hc-server:$RELEASE_SHA` and `tinyzkp/hc-mcp:$RELEASE_SHA` | Both images must exist before preflight, contain no proving worker, and remain unchanged until evidence is consumed. |

### Capture and review the host runtime

Follow `billing/RUNTIME.md`. The candidate capture is a host-local evidence
write, not approval:

```bash
sudo /usr/bin/python3 billing/runtime_lock.py capture-host-provenance \
  --output /root/tinyzkp-host-runtime.candidate.json
```

After independent review and merge of the reviewed provenance file:

```bash
sudo /usr/bin/python3 billing/runtime_lock.py verify-host
sudo /usr/bin/python3 billing/runtime_lock.py verify-host-provenance
deploy/hetzner/install_billing_runtime.sh
sudo /usr/bin/python3 billing/runtime_lock.py verify-production-runtime \
  --venv-root /var/lib/tinyzkp-runtime/billing-venv \
  --node-binary /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node
```

The installer evidence verifier does not run the drill. Create the complete
owner-only pending workspace first; every measured field is `null`, no success
log exists, and the scaffold cannot satisfy capture or production verification:

```bash
RUN_ID="$(/usr/bin/openssl rand -hex 16)"
sudo /usr/bin/python3 scripts/ci/fixed_host_evidence_workspace.py \
  installer-scaffold \
  --release-sha "$RELEASE_SHA" \
  --host-identity-sha256 "$HOST_IDENTITY_SHA256" \
  --deployment-id tinyzkp-production-primary \
  --run-id "$RUN_ID" \
  --output-root "/var/lib/tinyzkp-private/deploy/installer-drill-runs/$RUN_ID"
```

An explicitly authorized privileged operator or independently reviewed harness
must execute all cases and replace the template with direct observations and
the exact nonempty logs. The scaffold never invokes the installer or injects a
failure. Retain those raw logs and observations, have the allowlisted reviewer
sign the exact subject, then capture and verify:

```bash
/usr/bin/python3 scripts/ci/installer_drill_evidence.py required-cases
/usr/bin/python3 scripts/ci/installer_drill_evidence.py capture \
  --observations /root/tinyzkp-installer-drill/observations.json \
  --raw-dir /root/tinyzkp-installer-drill/raw \
  --review /root/tinyzkp-installer-drill/review.json \
  --output /var/lib/tinyzkp-private/deploy/installer-drill-evidence.json
/usr/bin/python3 scripts/ci/installer_drill_evidence.py verify \
  --expected-release-sha "$RELEASE_SHA" \
  --expected-deployment-id tinyzkp-production-primary
```

The backup evidence verifier is verify-only. The observation workspace helper
can generate complete pending report/case templates and package a finished raw
set, but it never runs a backup or restore and cannot create `review.json` or a
signature. Follow `docs/operations.md` and `docs/runbooks/restore.md` to perform
the real fixed-host drill and independent review before running:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/fixed_host_backup_evidence.py \
  --expected-release-sha "$RELEASE_SHA" \
  --expected-host-identity-sha256 "$HOST_IDENTITY_SHA256" \
  --expected-deployment-id tinyzkp-production-primary
```

### Read-only Stripe inventory and exact-ID containment

Set the non-secret expected identity values from the reviewed owner-only env;
do not hard-code either value in source or assume the dashboard name is
`TinyZKP`:

```bash
EXPECTED_STRIPE_ACCOUNT_ID='acct_REPLACE_FROM_REVIEWED_ENV'
EXPECTED_STRIPE_DASHBOARD_NAME='REPLACE_FROM_STRIPE_EXPECTED_DISPLAY_NAME'
```

Verify the exact account and its separate customer-facing TinyZKP sender
profile, then capture the pre-containment baseline. These calls read Stripe but
do not mutate it:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  billing/stripe_production_identity_check.py \
  --env-file /opt/hc-stark/.env

/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  billing/legacy_billing_containment.py \
  --env-file /opt/hc-stark/.env \
  --expected-account-id "$EXPECTED_STRIPE_ACCOUNT_ID" \
  --expected-display-name "$EXPECTED_STRIPE_DASHBOARD_NAME" \
  --inventory-output /var/lib/tinyzkp-private/deploy/legacy-baseline.json \
  --scope-template-output /var/lib/tinyzkp-private/deploy/legacy-scope.json
```

Review and populate only exact TinyZKP IDs in the generated scope. Never select
the unrelated active product. Preview the action plan and generate a
fail-closed no-email resolution skeleton for selected subscriptions:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  billing/legacy_billing_containment.py \
  --env-file /opt/hc-stark/.env \
  --scope-manifest /var/lib/tinyzkp-private/deploy/legacy-scope.json \
  --notification-template-output /var/lib/tinyzkp-private/deploy/legacy-notifications.json
```

Populate notification and refund/credit/`none_due` evidence through an
approved non-email channel. Archiving catalog objects, pausing subscriptions,
voiding invoices, issuing a refund/credit, or contacting a customer are
separate explicitly authorized live actions. Apply only the exact reviewed
plan hash using the flags printed by the preview. The tool pauses collection;
it does not silently cancel customers or manufacture notification evidence.

After authorized containment, collect a fresh read-only inventory and build
the short-lived status:

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  billing/legacy_billing_containment.py \
  --env-file /opt/hc-stark/.env \
  --inventory-output /var/lib/tinyzkp-private/deploy/legacy-current.json

OBSERVED_AT="$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
/usr/bin/python3 scripts/ci/legacy_billing_containment_status.py capture \
  --baseline-inventory /var/lib/tinyzkp-private/deploy/legacy-baseline.json \
  --current-inventory /var/lib/tinyzkp-private/deploy/legacy-current.json \
  --scope-manifest /var/lib/tinyzkp-private/deploy/legacy-scope.json \
  --notification-ledger /var/lib/tinyzkp-private/deploy/legacy-notifications.json \
  --env-file /opt/hc-stark/.env \
  --expected-release-sha "$RELEASE_SHA" \
  --expected-deployment-id tinyzkp-production-primary \
  --observed-at "$OBSERVED_AT"
```

Omit `--notification-ledger` only when the reviewed scope selected no legacy
subscription or invoice.

### Materialize the pinned Pages runtime

```bash
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/materialize_cloudflare_toolchain.py --download
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/cloudflare_toolchain_check.py --runtime \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js
```

### Build and tag the exact maintenance image

Build once from the final clean `main` checkout and tag the identical image for
both entrypoints. Do this before issuing preflight evidence; do not rebuild,
retag, or prune it between evidence creation and deployment:

```bash
cd /opt/hc-stark
test "$RELEASE_SHA" = "$(/usr/bin/git rev-parse HEAD)"
export DOCKER_BUILDKIT=1
/usr/bin/docker build --pull=false \
  --build-arg HC_RELEASE_SHA="$RELEASE_SHA" \
  --build-arg HC_RELEASE_REF=main \
  --build-arg HC_RELEASE_BUILD_URL="https://github.com/logannye/hc-stark/commit/$RELEASE_SHA" \
  --tag "tinyzkp/hc-server:$RELEASE_SHA" .
/usr/bin/docker image tag \
  "tinyzkp/hc-server:$RELEASE_SHA" \
  "tinyzkp/hc-mcp:$RELEASE_SHA"
/usr/bin/docker image inspect \
  "tinyzkp/hc-server:$RELEASE_SHA" \
  "tinyzkp/hc-mcp:$RELEASE_SHA" >/dev/null
/usr/bin/docker run --rm --entrypoint /bin/sh \
  "tinyzkp/hc-server:$RELEASE_SHA" -c \
  'test ! -e /app/hc-worker && test ! -e /app/hc-job-worker'
```

The current emergency image build is not the signed backend-v1 release path.
Production preflight binds both full image IDs and inspect digests so any image
change invalidates the evidence.

## Gate C: issue one-time production preflight evidence

Create the empty, root-owned pycache directory and make tracked source
read-only as specified in `docs/operations.md`. Then run the clean wrapper
directly, not through `bash`:

```bash
scripts/ci/run_production_preflight.sh \
  --require-legacy \
  --production \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /var/lib/tinyzkp-private/deploy/pages-bindings.env \
  --check-host-python \
  --host-python /var/lib/tinyzkp-runtime/billing-venv/bin/python \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js \
  --git-executable /usr/bin/git \
  --deployment-id tinyzkp-production-primary \
  --expected-release-sha "$RELEASE_SHA" \
  --evidence-output /var/lib/tinyzkp-private/deploy/production-preflight.json
```

The artifact is short-lived, nonce-bound, and single-use. Changing source,
configuration, runtime, backup credentials, Stripe status, or images requires
a new preflight.

## Gate D: explicitly authorized host and Pages deployment

The following commands mutate production and require explicit authorization.

Deploy the maintenance API, MCP service, billing/contact webhook, Caddy config,
and recovery cron from the consumed evidence:

```bash
cd /opt/hc-stark
deploy/hetzner/deploy.sh
```

The host transaction commits before Pages deployment. A subsequent Pages
failure therefore blocks announcement but does not automatically roll the
already committed host back. Do not edit deployment state files or invoke
`rollback.sh` after a committed transaction; prepare a separately reviewed,
fully evidenced host deployment if host rollback is required.

Use only the Pages transaction wrapper described in
`docs/runbooks/cloudflare_pages_release.md`. Preview is remote-read-only:

```bash
python3 scripts/deploy/cloudflare_pages_release.py deploy \
  --release-sha "$RELEASE_SHA" \
  --expected-account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --plan-output /var/lib/tinyzkp-private/pages-releases/deploy-plan.json
```

After reviewing the exact plan, authorized apply requires the recorded plan
hash and write switch:

```bash
export TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1
python3 scripts/deploy/cloudflare_pages_release.py deploy \
  --release-sha "$RELEASE_SHA" \
  --expected-account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --apply \
  --expected-plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --record-output /var/lib/tinyzkp-private/pages-releases/deployment.json
unset TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE
```

The status page is part of this same Pages release and must say
`backend_recovery` or `protocol/backend upgrade`, never `all systems
operational`.

## Gate E: post-deploy canaries and announcement

The Pages canary can roll Pages back, so it is an explicitly authorized write
transaction even though a passing run performs only reads:

```bash
export TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1
python3 scripts/deploy/cloudflare_pages_release.py canary \
  --deployment-record /var/lib/tinyzkp-private/pages-releases/deployment.json \
  --expected-record-sha256 REPLACE_WITH_REVIEWED_RECORD_SHA256 \
  --expected-account-id "$CLOUDFLARE_ACCOUNT_ID" \
  --output /var/lib/tinyzkp-private/pages-releases/canary.json
unset TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE
```

Then run the complete live launch preflight. Its durable intake canary creates
and deletes/retains synthetic operator evidence according to the tested intake
contract, so authorize it as a live operational write:

```bash
CLOUDFLARE_API_TOKEN=REDACTED CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID" \
scripts/ci/run_production_preflight.sh \
  --require-legacy --production --live \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /var/lib/tinyzkp-private/deploy/pages-bindings.env \
  --host-python /var/lib/tinyzkp-runtime/billing-venv/bin/python \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js \
  --git-executable /usr/bin/git \
  --deployment-id tinyzkp-production-primary \
  --contact-readiness-secret-file /var/lib/tinyzkp-private/deploy/internal-secret \
  --expected-release-sha "$RELEASE_SHA"
```

Do not announce or begin outreach unless all of the following are true:

- site, API, MCP, and expected release identities are the same SHA;
- capabilities report proving, verification, Checkout, and account creation
  unavailable;
- proving returns `503 protocol_upgrade` and legacy verification returns
  `422 legacy_statement_unbound`;
- no public route exposes a founder/unrelated email, `mailto:` contact, v5,
  privacy, full-prover `O(sqrt(N))`, 100M-row, free-key, or self-serve claim;
- the HTTPS evaluation and operational-request forms pass durable intake;
- public Checkout and every selected legacy Stripe charge path remain closed.

## Gate F: evaluation sales and deposit

Containment can be live before backend certification. A paid evaluation is a
bounded professional-service engagement, not production proving or audited
software access.

Use `commercial/no-email-evaluation-runbook.md` as the exact evidence flow:

1. Qualify a reproducible, non-sensitive Plonky3 bottleneck.
2. Run and verify `PartnerPreflightV1` before proposing work.
3. Obtain a counsel-approved form, countersigned agreement, and frozen
   acceptance matrix. The tracked counsel draft is deliberately unsendable.
4. Run the isolated Stripe **test-mode** invoice drill for
   `founding_evaluation`. It derives the `$7,500` deposit and exact offer
   digest from `site/pricing.json`; it is a test Stripe write and rejects live
   keys.
5. Verify the live Stripe account identity and separate TinyZKP sender profile.
6. Preview the exact deposit invoice. Creating/finalizing it is a separately
   authorized live Stripe write; the CLI never calls Stripe's send-invoice API.
7. Share only the hosted invoice URL through the applicant-selected non-email
   channel.
8. Start work only after `billing/evaluation_start_ready.py` proves the exact
   deposit is paid and the workload, acceptance matrix, and baseline host are
   frozen.

Customer acquisition is inbound-only. Reply only to applicants through their
selected GitHub, LinkedIn, Signal, Discord, Telegram, Matrix, or phone/SMS
channel after operator authorization. Never open an unsolicited sales issue or
initiate prospect outreach.

## Certified, Fleet/OEM, and hosted proving remain blocked

After containment is merged into the backend branch, backend v1 still requires
all hashed machine gates in `release/evidence/README.md`, including both 1M and
16M fixed-host workloads, independent reproduction, crash/fuzz evidence,
Plonky3 specialist review, implementation review, design-partner acceptance,
reviewed external signer/tool trust anchors, signed artifacts, SBOM, and
site/API/MCP/CLI identity parity.

Do not invoice Certified or Fleet/OEM until the attested commercial
authorization and its Sigstore bundle verify. Do not enable hosted proving
without separately signed demand, security review, measured COGS, and at least
80% projected gross margin.
