# TinyZKP Paid Public-Beta Runbook

Production remains in containment until the signed `public_beta` authorization matches every deployed component. The beta API may be deployed dark for operator canaries without changing public routing.

## External prerequisites

1. Create a GitHub OAuth app with callback `https://api.tinyzkp.com/v1/auth/github/callback` and record the client ID and secret in the owner-only API environment file. The callback must use the API hostname; `https://tinyzkp.com/v1/auth/github/callback` is not valid for the beta API.
2. Preview `billing/configure_public_beta_portal.py`, then apply it in Stripe test mode with `TINYZKP_ALLOW_BETA_PORTAL_WRITE=1`. Record the returned configuration ID as `TINYZKP_STRIPE_PORTAL_CONFIGURATION`. The beta Portal permits invoice history, payment-method updates, and cancellation at period end, while plan switching remains disabled. Live application is release-authorization gated.
3. Use the private `tinyzkp-beta-artifacts` and `tinyzkp-beta-pgbackrest` R2 buckets. Disable public access. Issue separate artifact and backup credentials with no cross-bucket permissions. Do not substitute the legacy `tinyzkp-proofs` or `tinyzkp-backups` buckets.
4. Apply and verify the tracked lifecycle policies with `configure-r2-lifecycle.sh apply artifacts` and `apply backups`, setting the corresponding bucket variables and the explicit write gate. Upload keys use the `uploads/` prefix and expire after 24 hours. Bundle keys use `bundles/` with a 90-day hard maximum; the database sweeper enforces the earlier 7/30/90-day plan retention. pgBackRest, not an R2 expiration rule, owns valid backup/WAL retention.
5. Use Hetzner worker `3034990`, with two mirrored 1-TB NVMe devices and at least 500 GB free on `/srv/tinyzkp-scratch`. Mount scratch with `noexec,nodev,nosuid` and mode `0700` owned by UID 10001. Record advertised physical capacity and effective free scratch separately.
6. Install WireGuard using the tracked API and worker templates. Only UDP 51820 is public; TCP 8091 is permitted only over the tunnel.
7. Create the isolated `tinyzkp_public_beta_v1` Stripe catalog and separate Portal configuration. Do not modify legacy TinyZKP or Casino Coach objects.

## Secrets and credentials

- Copy the tracked environment examples to `/etc/tinyzkp/beta` and `/etc/tinyzkp/worker`; copy `compose.api.env.example` or `compose.worker.env.example` to the corresponding `compose.env`; set files to `0600` and directories to `0700`.
- Generate independent OAuth encryption, API-key pepper, reconciliation-HMAC, worker, PostgreSQL, R2, and pgBackRest encryption secrets.
- Register the worker with `register-worker.sh` using the same base64 pepper as the API. The raw worker credential is placed only in the worker environment.
- Keep the pgBackRest recovery key copy outside the VM and outside the R2 account.
- Rotate GitHub, Stripe, R2, worker, and database credentials after any suspected exposure. Worker rotation is an idempotent re-registration followed by worker restart.

## Dark deployment

1. Dispatch `public-beta-candidate.yml` from `main` with the exact current merged commit. It publishes digest-pinned API, worker, and PostgreSQL images, a signed CLI, and a signed narrow `dark_canary` authorization. The narrow authorization permits only the isolated live Stripe canary catalog and cannot activate public API mode.
2. Install the API host with `install-beta-host.sh api`; the installer places the containment Caddy policy and refuses permissive secret modes.
3. Start PostgreSQL and PgBouncer, create the pgBackRest stanza, take an initial full backup, and confirm WAL archive checks pass.
4. Start the API with `TINYZKP_BETA_EXPOSURE=dark_canary`, `TINYZKP_BETA_WRITES_ENABLED=1`, and an operator GitHub numeric-ID allowlist.
5. Install the worker host with `install-beta-host.sh worker`, confirm WireGuard reachability, then start the worker with the same release SHA.
6. Access the dark API through an SSH tunnel. Public DNS and Caddy remain in containment.

## Required drills

- Install the pinned Python dependency from `scripts/benchmark/requirements.txt`, then run the first complete hosted lifecycle with the signed candidate CLI:

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
- Run the resumable 24-hour allowlisted canary with `scripts/canary/run_public_beta_canary.py` and an owner-controlled driver implementing `proof`, `cancel`, `billing`, and `audit` subcommands. The harness pins the driver digest, records one proof per hour, runs cancellation/refund every six hours, performs both tagged live billing canaries, and writes owner-only state after every event. Validate its evidence with `validate_public_beta_canary.py`.

## Activation

1. Package the private evidence workspace as `public-beta-evidence.tar.gz` with every path rooted under `release-evidence/`, and attach it to a private draft evidence release. The manifest must be `release-evidence/public-beta-evidence.json` and every referenced artifact must remain under that root.
2. Tag the unchanged candidate `public-beta-v*`, then dispatch `public-beta-release.yml` on that tag with the private evidence release tag. The workflow safely extracts and verifies the evidence, then signs the public-beta authorization without rebuilding the candidate images.
3. Install the authorization JSON and Sigstore bundle under `/etc/tinyzkp/beta/release`, set the expected SHA-256 and signing-identity regexp, and restart the same API image in `public_beta` mode.
4. Stage the exact site with `scripts/release/stage_public_beta_site.sh RELEASE_SHA OUTPUT`, then verify the dashboard, discovery, pricing, OpenAPI, and asset checksums through a Pages preview.
5. Confirm discovery reports `public_beta`, the exact release SHA, and disabled writes. After explicit operator confirmation, run `scripts/release/activate_public_beta.py` with the staged site, API SSH target, Cloudflare account, and owner-controlled smoke command. It snapshots Pages, promotes the site, commits Caddy, enables writes only after read checks, and switches the external probe.
6. If any Pages, Caddy, discovery, write-state, smoke, or probe step fails, the activation operator disables writes, restores the rollback route, rolls Pages back to the prior successful production deployment, and restores containment monitoring.

## Rollback

Run `switch-beta-route.sh rollback RELEASE_SHA public_beta`. This immediately blocks signup, Checkout, uploads, and new jobs while retaining Stripe webhook delivery, job status, bundle downloads, verification, and Portal access. Do not roll back PostgreSQL migrations, delete R2 objects, or revoke customer balances. Existing worker leases may complete or cancel normally. Return to full containment with `switch-beta-route.sh containment RELEASE_SHA backend_recovery` only if read access must also be removed.
