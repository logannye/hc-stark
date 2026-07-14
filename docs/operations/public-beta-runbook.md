# TinyZKP Paid Public-Beta Runbook

Production remains in containment until the signed `public_beta` authorization matches every deployed component. The beta API may be deployed dark for operator canaries without changing public routing.

## External prerequisites

1. Create a GitHub OAuth app with callback `https://api.tinyzkp.com/v1/auth/github/callback` and record the client ID and secret in the owner-only API environment file. The callback must use the API hostname; `https://tinyzkp.com/v1/auth/github/callback` is not valid for the beta API.
2. Preview `billing/configure_public_beta_portal.py`, then apply it in Stripe test mode with `TINYZKP_ALLOW_BETA_PORTAL_WRITE=1`. Record the returned configuration ID as `TINYZKP_STRIPE_PORTAL_CONFIGURATION`. The beta Portal permits invoice history, payment-method updates, and cancellation at period end, while plan switching remains disabled. Live application is release-authorization gated.
3. Use the private `tinyzkp-beta-artifacts` and `tinyzkp-beta-pgbackrest` R2 buckets. Disable public access. Issue separate artifact and backup credentials with no cross-bucket permissions. Do not substitute the legacy `tinyzkp-proofs` or `tinyzkp-backups` buckets.
4. Apply and verify the tracked lifecycle policies with `configure-r2-lifecycle.sh apply artifacts` and `apply backups`, setting the corresponding bucket variables and the explicit write gate. Apply the artifact bucket's exact-origin browser policy with `configure-r2-cors.sh apply`; it permits only `tinyzkp.com` origins and the methods and signed metadata headers required by presigned uploads/downloads. Upload keys use the `uploads/` prefix and expire after 24 hours. Bundle keys use `bundles/` with a 90-day hard maximum; the database sweeper enforces the earlier 7/30/90-day plan retention. pgBackRest, not an R2 expiration rule, owns valid backup/WAL retention.
5. Use Hetzner worker `3034990`, with two mirrored 1-TB NVMe devices and at least 500 GB free on `/srv/tinyzkp-scratch`. Mount scratch with `noexec,nodev,nosuid` and mode `0700` owned by UID 10001. Record advertised physical capacity and effective free scratch separately.
6. Install WireGuard using the tracked API and worker templates. Only UDP 51820 is public; TCP 8091 is permitted only over the tunnel.
7. Obtain one-time accountant or counsel approval for the Stripe product tax classification and live tax registrations. Create the isolated `tinyzkp_public_beta_v1` Stripe catalog with that approved `txcd_...` tax code, automatic tax, required billing addresses, a separate Portal configuration, and a dedicated live webhook destination. Do not modify legacy TinyZKP or Casino Coach objects. API startup fails closed until all of these objects pass preflight.

## Secrets and credentials

- Copy the tracked environment examples to `/etc/tinyzkp/beta` and `/etc/tinyzkp/worker`; copy `compose.api.env.example` or `compose.worker.env.example` to the corresponding `compose.env`; set files to `0600` and directories to `0700`.
- Generate independent OAuth encryption, API-key pepper, reconciliation-HMAC, worker, PostgreSQL, R2, and pgBackRest encryption secrets.
- Register the worker with `register-worker.sh` using the same base64 pepper as the API. The raw worker credential is placed only in the worker environment.
- Keep the pgBackRest recovery key copy outside the VM and outside the R2 account.
- Rotate GitHub, Stripe, R2, worker, and database credentials after any suspected exposure. Worker rotation is an idempotent re-registration followed by worker restart.
- Generate a separate random metrics token of at least 32 characters. Put the same raw token in `TINYZKP_BETA_METRICS_TOKEN` and the Prometheus-only owner-readable `/etc/prometheus/beta_metrics_token`. Metrics listen only on the internal `tinyzkp-observability` Docker network and are never published on a host port.
- Deploy the authenticated Cloudflare email relay under `deploy/cloudflare/alert-relay`. Verify `logan@galenhealth.org` as its fixed Email Routing destination, restrict its send binding to `alerts@tinyzkp.com`, and install one independent high-entropy token as `ALERT_RELAY_TOKEN`, `TINYZKP_ALERT_WEBHOOK_TOKEN`, and the uptime probe's `ALERT_WEBHOOK_TOKEN`. Confirm a synthetic email before beginning the 24-hour canary. Do not use an unauthenticated generic webhook.
- Create `/var/lib/tinyzkp-owner/owner-cost.json` from `owner-cost.json.example`, set owner UID 10001 and mode `0600`, and replace the example amount with the actual monthly worker, API host, R2, backup, and monitoring cost. Do not put customer or Stripe data in this file.

## Dark deployment

1. Dispatch `public-beta-candidate.yml` from `main` with the exact current merged commit. It publishes digest-pinned API, worker, and PostgreSQL images, a signed CLI, and a signed narrow `dark_canary` authorization. The narrow authorization permits only the isolated live Stripe canary catalog and cannot activate public API mode.
2. Install the API host with `install-beta-host.sh api`; the installer places the containment Caddy policy and refuses permissive secret modes.
3. Start PostgreSQL and PgBouncer, create the pgBackRest stanza, take an initial full backup, and confirm WAL archive checks pass.
4. Start the API with `TINYZKP_BETA_EXPOSURE=dark_canary`, `TINYZKP_BETA_WRITES_ENABLED=1`, and an operator GitHub numeric-ID allowlist.
5. Install the worker host with `install-beta-host.sh worker`, confirm WireGuard reachability, then start the worker with the same release SHA.
6. Access the dark API through an SSH tunnel. Public DNS and Caddy remain in containment.

The signed CLI always targets `https://api.tinyzkp.com`; release binaries do not accept an endpoint override. The dark Caddy policy therefore forwards API reads and writes to the beta service, while the service itself restricts GitHub identities to the operator allowlist and requires tenant API keys. The public website and discovery surface remain in containment.

## Required drills

- Install the pinned Python dependency from `scripts/benchmark/requirements.txt`, then run the first complete hosted lifecycle with the signed candidate CLI:

  ```sh
  hc-cli beta quickstart --fixture customer_cubic8 --output-dir ./customer-cubic8
  hc-cli beta doctor
  hc-cli beta submit \
    --air ./customer-cubic8/air.json \
    --qualification-trace ./customer-cubic8/qualification.trace \
    --qualification-public-inputs ./customer-cubic8/qualification-public-inputs.json \
    --job-trace ./customer-cubic8/job.trace \
    --row-count 16384 \
    --job-public-inputs ./customer-cubic8/job-public-inputs.json \
    --policy ./customer-cubic8/policy.json \
    --output-bundle ./customer-cubic8/proof-bundle.json \
    --state ./customer-cubic8/resume-state.json
  ```

  Credentials come only from `TINYZKP_API_KEY` or an owner-only credentials file. Resume state is mode `0600`, is input- and release-bound, and never contains credentials or presigned URLs. Interrupted upload attempts obtain fresh URLs without changing the logical AIR/job idempotency operations.

  Then run the evidence-specific negative matrix:

  ```sh
  export TINYZKP_CLI=/opt/tinyzkp/bin/hc-cli
  export TINYZKP_RELEASE_SHA=<exact-40-character-candidate-sha>
  export TINYZKP_API_URL=https://<dark-api-endpoint>
  export TINYZKP_API_KEY=<primary-paid-canary-key>
  export TINYZKP_SECONDARY_API_KEY=<different-tenant-key>
  export TINYZKP_E2E_STATE_DIR=/var/lib/tinyzkp-e2e/state
  export TINYZKP_E2E_EVIDENCE_DIR=/var/lib/tinyzkp-e2e/evidence
  python3 scripts/canary/hc_beta_e2e.py proof customer_cubic8 --rows 262144 --negative-tests
  ```

  The strict run proves a 1,024-row local registration statement, uploads a multi-chunk `2^18` trace, completes and officially verifies the hosted bundle, checks exact and conflicting idempotency retries, rejects a modified signed checksum, exercises wrong-length and corrupt chunks, proves wrong public inputs cannot charge, and denies a second tenant's bundle request. Evidence files are owner-only and reject secret-like fields and URLs.
- Complete Stripe test-mode subscription, top-up, failed payment, duplicate webhook, delayed webhook, Portal, cancellation, full refund, partial refund, and failed-refund flows. Webhook delivery is successful once the raw signed body is durably queued; inspect the database-backed processor attempts separately. Require semantic grants and refund reversals to appear exactly once, then run `hc-beta-reconcile` and retain its clean HMAC-signed report.
  Create refunds only through the write-gated operator command: set `TINYZKP_REFUND_PAYMENT_INTENT`, a unique `TINYZKP_REFUND_OPERATION_ID`, optional `TINYZKP_REFUND_AMOUNT_MINOR` for a partial refund, and `TINYZKP_ALLOW_REFUND_WRITE=1`, then run `hc-beta-refund` in the API container. Repeating the same operation ID is a Stripe-idempotent retry.
- Materialize the release-trust-pinned Stripe CLI 1.43.7, then use `billing/public_beta_stripe_drill.py prepare|run|reconcile|destroy|verify`. `prepare` creates a SHA-named disposable database and owner-only one-time API keys; `run` verifies every referenced event against the processed PostgreSQL ledger and rejects any event not formatted with Stripe API `2026-02-25.clover`; `destroy` refuses to drop the database before validated evidence exists.
- Create a separate `tinyzkp_beta_race_<sha12>` database, apply the production migrations, and run `scripts/load/run_public_beta_races.py`. The runner covers idempotency, overspend, competing terminal states, stale leases, settlement, refund/use, webhook delivery, and ledger reconstruction.
- Run the fixed-host 1M/16M matrix, customer_cubic8 matrix, fault/fuzz suite, security review, four-job load test, and identity check on the final candidate. The load runner creates four digest-distinct `customer_cubic8` AIRs, verifies a 1,024-row local proof for each, selects the largest candidate row count whose signed-CLI estimate is within 85–100% of 2 GiB and below the 60-minute admission limit, registers four AIRs, and uploads four independent traces:

  Run the declarative customer workload through its resumable fixed-host controller rather than invoking the three proof modes by hand:

  ```sh
  python3 scripts/benchmark/run_customer_cubic8_matrix.py \
    --release-sha "$TINYZKP_RELEASE_SHA" \
    --cli "$TINYZKP_CLI" \
    --output-dir /var/lib/tinyzkp-evidence/customer-cubic8 \
    --work-root /srv/tinyzkp-scratch/customer-cubic8
  ```

  The controller requires clean exact source, the signed CLI identity, eight effective CPUs, a 15–17 GiB cgroup limit, zero swap, and at least 500 GB of NVMe scratch. It hash-binds and revalidates the reference 1M, bounded 1M, and bounded 16M reports before recording a pass.

  ```sh
  export TINYZKP_LOAD_API_KEY=<scale-canary-api-key>
  python3 scripts/load/run_public_beta_load.py \
    --prepare-scenario \
    --prepare-state-dir /var/lib/tinyzkp-load/prepare-<release-sha> \
    --release-sha "$TINYZKP_RELEASE_SHA" \
    --output /var/lib/tinyzkp-load/scenario-<release-sha>.json

  python3 scripts/load/run_public_beta_load.py \
    --scenario /var/lib/tinyzkp-load/scenario-<release-sha>.json \
    --telemetry /var/lib/tinyzkp-load/telemetry-<release-sha>.json \
    --release-sha "$TINYZKP_RELEASE_SHA" \
    --output /var/lib/tinyzkp-load/public-beta-load-evidence-v2.json
  ```

  Scenario and evidence outputs are owner-only and cannot be replaced. Supply the required host telemetry JSON. Release mode requires five-second readiness samples, the exact 8-CPU/16-GiB worker envelope, zero swap/OOM/restarts, heartbeat age below 60 seconds, scratch use below 70%, and clean PostgreSQL limits. All four jobs must complete, download, officially verify, and leave `/readyz` continuously healthy.
- Run `restore-drill.sh --confirm-isolated-restore`. Recompute credit balances from immutable events, authenticate a retained test API key, recover a queued job, and verify a retained proof bundle before recording success.
- Every one of the twelve `public_beta` gates has a dedicated semantic record and validator. A generic JSON file containing only `status: passed` and the release SHA is deliberately rejected. Use the exact `public-beta-*-v1` schemas enforced by `scripts/ci/public_beta_gate.py`; fixed-host gates additionally re-run the resource and customer-cubic validators against the hash-bound raw reports. Fault evidence distinguishes successfully resumed and officially verified work from failures that must release the complete reservation, and separately proves that stale completions cannot settle.
- Run the resumable 24-hour allowlisted canary with `scripts/canary/run_public_beta_canary.py` and `scripts/canary/hc_beta_e2e.py`. The tracked driver implements `proof`, `cancel`, `billing`, and `audit`; the latter two accept only release-bound, owner-only, HMAC-signed attestations from `TINYZKP_CANARY_ATTESTATION_DIR`. Billing attestations must reference validated live Stripe objects, immutable credit-ledger results, refund reversals, clean reconciliation, and subscription cancellation where applicable. The audit attestation must reference the invariant watchdog, cross-tenant denial exercise, worker scratch scan, and clean reconciliation. Create signed copies with `scripts/canary/sign_canary_attestation.py`; never place Stripe IDs, URLs, credentials, or customer data in these files. The harness pins the driver digest, records one proof per hour, runs cancellation/refund every six hours, performs both tagged live billing canaries, and writes owner-only state after every event. Validate its evidence with `validate_public_beta_canary.py`.

## Autopilot operations

The API runs its invariant watchdog every five minutes. Any failing invariant disables signup, Checkout, and new job submission in one database transaction. Verification, balances, Portal, cancellation, status, account deletion, and completed downloads remain available. An incident is alerted once; a failed alert is retried, but an open incident never floods the owner. A clean later check closes the incident window but does not re-enable writes.

Required checks include exact release identity, immutable-ledger reconstruction, billing discrepancies and reconciliation freshness, Stripe event age, official verifier outcomes, worker heartbeat and leases, backup/WAL freshness, private R2 health, API/scratch free space, and the four-slot worker envelope. The API-host storage timer reports every five minutes. Successful pgBackRest full and differential jobs report backup health; a failed or missing report becomes stale after 26 hours.

After investigating and fixing an incident, run the complete check and explicitly recover with a unique operation ID:

```sh
docker compose -f docker-compose.api.yml run --rm --no-deps \
  --entrypoint /usr/local/bin/hc-beta-watchdog beta-ops check
docker compose -f docker-compose.api.yml run --rm --no-deps \
  --entrypoint /usr/local/bin/hc-beta-watchdog beta-ops recover recovery-YYYYMMDD-reason
```

Recovery fails while any invariant remains open. A historical official-verifier rejection is acknowledged only by this explicit recovery operation; it is never deleted or silently ignored.

Prometheus must join the external, internal-only `tinyzkp-observability` network and scrape `beta-api:9091` with `/etc/prometheus/beta_metrics_token`. Use the beta alert rules in `deploy/prometheus/alerts.yml`; the legacy `hc-server` billing/proving alerts are intentionally retired for this service.

The Monday 16:00 UTC owner digest writes a mode-`0600` aggregate JSON report under `/var/lib/tinyzkp-owner/reports` and sends only a redacted aggregate summary to the existing alert webhook. It contains no tenant IDs, emails, API keys, Stripe IDs, cookies, object keys, or URLs. Record support work without copying customer messages:

```sh
docker compose -f docker-compose.api.yml run --rm --no-deps \
  --entrypoint /usr/local/bin/hc-beta-support-log beta-ops \
  onboarding 15 support-20260713-onboarding
```

Valid categories are `onboarding`, `billing`, `proof`, `security`, `operations`, and `other`; each entry is 1–240 minutes and idempotent by operation ID.

The activation transaction records the viability window only after the public smoke and external probe pass. A daily timer emits signed day-30, day-60, and day-90 reports. At day 90 the gate requires five real paying tenants, trailing revenue at least three times direct cost, at least 70% realized gross margin, no more than 60 support minutes per ten jobs, at least 25% paid-tenant retention, and no unresolved invariant. Failure disables only new signup and Checkout and emits a wind-down report. Cancelling subscriptions, refunding credits, stopping existing jobs, or cancelling Hetzner always requires a separate explicit operator decision.

The exact-release recovery gate must include `public-beta-autopilot-evidence-v1` proving every watchdog trigger, one alert per incident, no automatic re-enable, preserved read/recovery capabilities, owner-digest reconciliation/redaction, and the non-destructive viability behavior.

## Activation

The signed candidate `04e8af8ed0be29433adc60730ab5e3eef13b13aa` is explicitly abandoned for activation. Its artifacts and evidence are comparison data only; `activate_public_beta.py` rejects it even if an authorization is supplied.

1. Package the private evidence workspace as `public-beta-evidence.tar.gz` with every path rooted under `release-evidence/`, and attach it to a private draft evidence release. The manifest must be `release-evidence/public-beta-evidence.json` and every referenced artifact must remain under that root.
2. Tag the unchanged candidate `public-beta-v*`, then dispatch `public-beta-release.yml` on that tag with the private evidence release tag. The workflow safely extracts and verifies the evidence, then signs the public-beta authorization without rebuilding the candidate images.
3. Install the authorization JSON and Sigstore bundle under `/etc/tinyzkp/beta/release`, set the expected SHA-256 and signing-identity regexp, and restart the same API image in `public_beta` mode.
4. Stage the exact site with `scripts/release/stage_public_beta_site.sh RELEASE_SHA OUTPUT`, then verify the dashboard, discovery, pricing, OpenAPI, and asset checksums through a Pages preview.
5. Confirm discovery reports `public_beta`, the exact release SHA, and disabled writes. After explicit operator confirmation, run `scripts/release/activate_public_beta.py` with the staged site, API SSH target, Cloudflare account, and owner-controlled smoke command. It snapshots Pages, promotes the site, commits Caddy, enables writes only after read checks, and switches the external probe.
6. If any Pages, Caddy, discovery, write-state, smoke, or probe step fails, the activation operator disables writes, restores the rollback route, rolls Pages back to the prior successful production deployment, and restores containment monitoring.

The current signed comparison candidate `04e8af8ed0be29433adc60730ab5e3eef13b13aa` remains abandoned. Build a new exact candidate only after the self-service contract and autopilot operations PRs merge. Rerun all twelve semantic gates, including the custom-AIR CLI lifecycle, PAYG/Sandbox and tax-address drills, watchdog matrix, owner-digest redaction, four-job load, restore/replay, and unchanged 24-hour canary. Do not activate or perform live customer purchases from this runbook without Logan's explicit final go-live approval.

## Rollback

Run `switch-beta-route.sh rollback RELEASE_SHA public_beta`. This immediately blocks signup, Checkout, uploads, and new jobs while retaining Stripe webhook delivery, job status, bundle downloads, verification, and Portal access. Do not roll back PostgreSQL migrations, delete R2 objects, or revoke customer balances. Existing worker leases may complete or cancel normally. Return to full containment with `switch-beta-route.sh containment RELEASE_SHA backend_recovery` only if read access must also be removed.
