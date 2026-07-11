# TinyZKP Paid Public-Beta Runbook

Production remains in containment until the signed `public_beta` authorization matches every deployed component. The beta API may be deployed dark for operator canaries without changing public routing.

## External prerequisites

1. Create a GitHub OAuth app with callback `https://api.tinyzkp.com/v1/auth/github/callback` and record the client ID and secret in the owner-only API environment file. The callback must use the API hostname; `https://tinyzkp.com/v1/auth/github/callback` is not valid for the beta API.
2. Create private R2 artifact and backup buckets. Disable public access. Issue separate artifact and backup credentials with no cross-bucket permissions.
3. Apply 24-hour lifecycle rules to incomplete uploads and traces. Proof deletion remains driven by the database’s 7/30/90-day retention queue.
4. Provision a Debian 12 worker with mirrored NVMe providing at least 1 TB usable. Mount `/srv/tinyzkp-scratch` with `noexec,nodev,nosuid` and mode `0700` owned by UID 10001.
5. Install WireGuard using the tracked API and worker templates. Only UDP 51820 is public; TCP 8091 is permitted only over the tunnel.
6. Create the isolated `tinyzkp_public_beta_v1` Stripe catalog and separate Portal configuration. Do not modify legacy TinyZKP or Casino Coach objects.

## Secrets and credentials

- Copy the tracked environment examples to `/etc/tinyzkp/beta` and `/etc/tinyzkp/worker`; copy `compose.api.env.example` or `compose.worker.env.example` to the corresponding `compose.env`; set files to `0600` and directories to `0700`.
- Generate independent OAuth encryption, API-key pepper, worker, PostgreSQL, R2, and pgBackRest encryption secrets.
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

- Complete Stripe test-mode subscription, top-up, failed payment, duplicate webhook, delayed webhook, Portal, and cancellation flows.
- Run the fixed-host 1M/16M matrix, customer_cubic8 matrix, fault/fuzz suite, security review, four-job load test, and identity check on the final candidate. Prepare four paid job request bodies and execute `scripts/load/run_public_beta_load.py`; release evidence requires all four jobs to complete, download, officially verify, and leave `/readyz` continuously healthy.
- Run `restore-drill.sh --confirm-isolated-restore`. Recompute credit balances from immutable events, authenticate a retained test API key, recover a queued job, and verify a retained proof bundle before recording success.
- Run the resumable 24-hour allowlisted canary with `scripts/canary/run_public_beta_canary.py` and an owner-controlled driver implementing `proof`, `cancel`, `billing`, and `audit` subcommands. The harness pins the driver digest, records one proof per hour, runs cancellation/refund every six hours, performs both tagged live billing canaries, and writes owner-only state after every event. Validate its evidence with `validate_public_beta_canary.py`.

## Activation

1. Package the private evidence workspace as `public-beta-evidence.tar.gz` with every path rooted under `release-evidence/`, and attach it to a private draft evidence release. The manifest must be `release-evidence/public-beta-evidence.json` and every referenced artifact must remain under that root.
2. Tag the unchanged candidate `public-beta-v*`, then dispatch `public-beta-release.yml` on that tag with the private evidence release tag. The workflow safely extracts and verifies the evidence, then signs the public-beta authorization without rebuilding the candidate images.
3. Install the authorization JSON and Sigstore bundle under `/etc/tinyzkp/beta/release`, set the expected SHA-256 and signing-identity regexp, and restart the same API image in `public_beta` mode.
4. Confirm discovery reports `public_beta`, the exact release SHA, and enabled capabilities.
5. Run `switch-beta-route.sh public`, then execute signup, Checkout, upload, prove, download, verify, Portal, and cancellation smoke tests.

## Rollback

Run `switch-beta-route.sh rollback`. This immediately blocks signup, Checkout, uploads, and new jobs while retaining job status, bundle downloads, verification, and Portal access. Do not roll back PostgreSQL migrations, delete R2 objects, or revoke customer balances. Existing worker leases may complete or cancel normally. Return to full containment with `switch-beta-route.sh containment` only if read access must also be removed.
