# Operations Guide

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_SERVER_LISTEN` | `0.0.0.0:8080` | Listen address |
| `HC_SERVER_DATA_DIR` | `.hc-server` | Data directory for local job status artifacts |
| `HC_SERVER_MAX_INFLIGHT` | `4` | Max concurrent prove jobs per tenant |
| `HC_SERVER_MAX_PROVE_SECS` | `300` | Prove job timeout (seconds) |
| `HC_SERVER_ALLOW_CUSTOM_PROGRAMS` | `false` | Allow arbitrary VM programs |
| `HC_SERVER_MAX_BODY_BYTES` | `25MB` | Max request body size |
| `HC_SERVER_MAX_VERIFY_INFLIGHT` | `8` | Max concurrent verify requests |
| `HC_SERVER_VERIFY_TIMEOUT_MS` | `30000` | Verify request timeout |
| `HC_SERVER_RETENTION_SECS` | `86400` | Job artifact retention (24h) |
| `HC_SERVER_JOB_INDEX_SQLITE` | `true` | Legacy switch for SQLite job index; superseded by `HC_SERVER_JOB_INDEX_SOURCE` |
| `HC_SERVER_JOB_INDEX_SOURCE` | `sqlite` | Job index backend: `sqlite`, `postgres`, or `disabled`. `postgres` stores request/status JSON and completed proof bytes in Postgres |
| `HC_JOB_INDEX_PG_URL` | falls back to `HC_SERVER_PG_URL` | Postgres connection string for `HC_SERVER_JOB_INDEX_SOURCE=postgres` |
| `HC_JOB_INDEX_PG_TLS` | inferred from URL | Optional TLS override for the Postgres job-index connection |
| `HC_SERVER_JOB_INDEX_DISABLED` | `false` | Force-disable job index |
| `HC_SERVER_MAX_PROVE_RPM` | `100` | Prove rate limit (requests/minute, 0=unlimited) |
| `HC_SERVER_MAX_VERIFY_RPM` | `300` | Verify rate limit (requests/minute, 0=unlimited) |
| `HC_SERVER_RATE_LIMIT_DISABLED` | `false` | Disable all rate limits |
| `HC_SERVER_MAX_BLOCK_SIZE` | `1048576` | Max allowed block_size (2^20) |
| `HC_SERVER_MIN_QUERY_COUNT` | `80` | Min allowed query_count for security |
| `HC_SERVER_GC_INTERVAL_SECS` | `300` | Background GC interval |
| `HC_SERVER_API_KEYS` | (none) | Comma-separated `tenant:key` pairs |
| `HC_SERVER_API_KEYS_FILE` | (none) | Path to API keys file |
| `HC_SERVER_AUTH_PG_URL` | (none) | Optional shared Postgres tenant/auth source. Takes precedence over `HC_SERVER_AUTH_DB_PATH` when set |
| `HC_SERVER_AUTH_PG_TLS` | inferred from URL | Optional TLS override for the Postgres tenant/auth connection |
| `HC_SERVER_AUTH_GRACE_MS` | `300000` | Rotation grace window: rotated-out keys still authenticate for this long after a hot-reload swap (5min default) |
| `HC_SERVER_WORKER_PATH` | (auto-detect) | Path to hc-worker binary; **validated at boot** — refusal to start if missing or non-executable |
| `HC_SERVER_MAX_WORKER_SPAWN` | `32` | Global cap on concurrent worker subprocess spawns (EMFILE / process-table-exhaustion guard); 0 disables |
| `HC_SERVER_PROVE_DISPATCH` | `local` | `local` spawns `hc-worker` inside the API process; `shared` enqueues jobs for `hc-job-worker` |
| `HC_SERVER_PG_URL` | (none) | Postgres connection string for Phase 1 usage dual-write. When set, usage writes mirror to Postgres while SQLite remains the read/cap source |
| `HC_SERVER_PG_TLS` | inferred from URL | Optional Postgres TLS override: `true`/`require` or `false`/`disable`. URL `sslmode=require`, `verify-ca`, or `verify-full` also enables TLS |
| `HC_SERVER_USAGE_READ_FROM` | `sqlite` | Usage read source for `/usage` and monthly cap checks: `sqlite` or `postgres`. Requires `HC_SERVER_PG_URL` when set to `postgres` |
| `HC_RATE_LIMIT_PG_URL` | (none) | Optional Postgres shared rate-limit store. Set in both `hc-server` and `hc-mcp-http` to share authenticated tenant RPM windows |
| `HC_RATE_LIMIT_PG_TLS` | inferred from URL | Optional TLS override for the shared rate-limit Postgres connection |
| `RUST_LOG` | (none) | Logging level (e.g., `info`, `debug`) |

### MCP server (hc-mcp-http)

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_MCP_HTTP_HOST` | `0.0.0.0` | Bind host |
| `HC_MCP_HTTP_PORT` | `3001` | Bind port |
| `HC_MCP_REQUIRE_AUTH` | `false` | If true, every MCP request must carry `Authorization: Bearer ...`; missing header → 401 |
| `HC_MCP_TENANT_RPM` | `0` | Optional global RPM override for authenticated tenants. 0 (default) = use per-plan ladder (Free 10, Dev 100, Team 300, Scale 500) — same values as hc-server's `prove_rpm` |
| `HC_MCP_MAX_INFLIGHT` | `2` | Concurrency cap on the anonymous (no-Bearer) lane |
| `HC_MCP_ALLOWED_HOSTS` | `mcp.tinyzkp.com`, loopback hosts | Comma-separated extra hostnames or `host:port` authorities accepted by rmcp's Host-header DNS-rebinding guard |
| `HC_MCP_ALLOWED_ORIGINS` | (none) | Comma-separated extra CORS origins on top of the default allowlist (`*.claude.ai`, `*.anthropic.com`, `tinyzkp.com`) |
| `HC_SERVER_AUTH_PG_URL` | (none) | Optional shared Postgres tenant/auth source; should match the API server when enabled |
| `HC_SERVER_AUTH_PG_TLS` | inferred from URL | Optional TLS override for the Postgres tenant/auth connection |
| `HC_RATE_LIMIT_PG_URL` | (none) | Optional shared authenticated tenant RPM store; must match the API server value when enabled |

### Billing webhook tenant store

The billing webhook still writes SQLite as its primary local store. For the
Postgres auth cutover, enable continuous mirroring before changing API/MCP auth
reads:

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_TENANT_STORE_PATH` | `/opt/hc-stark/data/tenant_store.sqlite` | SQLite tenant store used by the billing webhook and admin scripts |
| `HC_TENANT_PG_URL` | falls back to `HC_SERVER_AUTH_PG_URL` | Optional Postgres mirror target for tenants, Stripe event idempotency, magic links, and sessions |
| `HC_TENANT_PG_REQUIRED` | `false` | If true, tenant-store mutations fail when the Postgres mirror write fails. Use during/after auth read cutover |

On Hetzner, the host-level billing webhook and hourly billing cron run from
`/var/lib/tinyzkp-runtime/billing-venv`, installed by
`deploy/hetzner/install_billing_runtime.sh` from the reviewed,
hash-locked `billing/requirements.lock`.
Run that installer as a separate operator preparation step before creating
production preflight evidence. The deploy script never installs or changes
runtime packages; it verifies the byte-bound, read-only virtualenv, rewrites
the billing cron and `hc-billing-webhook.service` definitions to use it, and
then restarts the webhook.

The repository now pins one dependency profile only: Debian 12 x86-64,
`/usr/bin` CPython 3.11, and `manylinux2014_x86_64` wheels. Exact direct roots,
the exact active transitive closure, the bootstrap pip wheel, target profile,
and all 23 wheel identities are separately hash-bound. The installer verifies
wheel structure and dependency closure, builds offline in a fixed staging
directory, and restores the prior runtime on failure.

This does not by itself authorize production. The committed
`billing/host-runtime-provenance.json` deliberately remains `unconfigured` and
the installer fails until an independently reproduced inventory of the fixed
host interpreter, standard library, loader tool, and recursively resolved
shared libraries is reviewed and committed. See
`billing/RUNTIME.md` for wheel materialization, host capture, review,
installation, and rollback commands. Production preflight must also bind that
reviewed source file and the resulting immutable venv before deploy evidence
can be issued.

### Shared prove worker (hc-job-worker)

Enable only after `HC_SERVER_JOB_INDEX_SOURCE=postgres` and Postgres usage
recording are proven in production. In Docker Compose, set
`HC_SERVER_PROVE_DISPATCH=shared` and run with `COMPOSE_PROFILES=shared-workers`
or use the Hetzner deploy script, which enables the profile automatically when
the `.env` file sets shared dispatch.

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_JOB_WORKER_INDEX_SOURCE` | `postgres` | Job queue backend for `hc-job-worker`; production should use Postgres |
| `HC_JOB_INDEX_PG_URL` | falls back to `HC_SERVER_PG_URL` | Postgres job index used for lease claims |
| `HC_JOB_WORKER_USAGE_PG_URL` | falls back to `HC_SERVER_PG_URL` | Postgres usage recorder for jobs executed by the shared worker |
| `HC_JOB_WORKER_ID` | process id derived | Lease owner id recorded in `prove_jobs.lease_owner` |
| `HC_JOB_WORKER_LEASE_MS` | `30000` | Lease duration; should be comfortably above heartbeat interval |
| `HC_JOB_WORKER_HEARTBEAT_MS` | `5000` | Lease renewal and cancellation polling interval |
| `HC_JOB_WORKER_POLL_MS` | `1000` | Idle polling interval when no jobs are claimable |
| `HC_JOB_WORKER_MAX_PROVE_SECS` | `3600` | Max wall-clock prove time per claimed job |
| `HC_JOB_WORKER_USAGE_DISABLED` | `false` | Development-only escape hatch; do not enable in production |

Run `hc-job-worker --check-config` on a candidate host before enabling the
service. It validates the configured job-index and usage-recording connections
without claiming work. In staging, `hc-job-worker --once` is the controlled
rehearsal mode: it claims at most one pending job, executes it, records usage,
and exits.

On `SIGTERM` or Ctrl-C, `hc-job-worker` stops claiming new work. If a proof is
running, the worker drops the child `hc-worker` process and exits; the job
remains `running` until its lease expires, then another worker can reclaim it.
Keep `HC_JOB_WORKER_LEASE_MS` low enough for deploy recovery, but high enough
that normal heartbeat jitter does not cause duplicate proving.

If a claimed proof exceeds `HC_JOB_WORKER_MAX_PROVE_SECS`, the worker records a
terminal failed status and a failed-usage row. Timeouts should not loop through
lease expiry and repeated reclaim attempts.

For successful proofs, `hc-job-worker` records metered usage before publishing a
`Succeeded` job status. If usage recording is unavailable, the job fails closed
instead of exposing an unmetered proof.

### Deploy readiness gate

Run the state-cutover policy check before changing production env vars:

```sh
python3 scripts/ci/deploy_readiness_check.py --env-file /opt/hc-stark/.env --production --check-host-python
```

The Hetzner deploy script runs this automatically before rebuilding services.
It fails on dangerous combinations such as Postgres usage reads without
`HC_SERVER_PG_URL`, shared dispatch without a Postgres job index, or API/MCP
auth reads without fail-closed tenant Postgres mirroring.

### Launch gate audit

Before a coordinated reconciliation release, run the local launch-gate audit.
It maps the roadmap phases to concrete repo evidence and keeps deploy/observe
requirements explicit instead of treating local readiness as production
completion:

```sh
python3 scripts/ci/launch_gate_audit.py
python3 scripts/ci/production_launch_preflight.py
python3 scripts/ci/server_card_check.py
```

For a production deploy rehearsal, run the aggregate preflight with the
production env file and Cloudflare Pages binding file. This keeps local repo
evidence, deploy-readiness policy, Pages configuration, Compose rendering,
backup/restore drift, package distribution surfaces, and the launch-gate audit
under one operator command:

```sh
scripts/ci/run_production_preflight.sh \
  --production \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /var/lib/tinyzkp-private/deploy/pages-bindings.env \
  --check-host-python \
  --host-python /var/lib/tinyzkp-runtime/billing-venv/bin/python \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js \
  --git-executable /usr/bin/git \
  --deployment-id tinyzkp-production-primary \
  --expected-release-sha "$(git rev-parse HEAD)" \
  --evidence-output /var/lib/tinyzkp-private/deploy/production-preflight.json
```

Run this from a clean `main` checkout whose `HEAD` equals the locally fetched
remote `main` SHA at the reviewed GitHub URL. Before issuing evidence, run
`deploy/hetzner/install_billing_runtime.sh`, then materialize the reviewed
JavaScript toolchain outside the checkout:

```sh
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/materialize_cloudflare_toolchain.py --download

/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/cloudflare_toolchain_check.py --runtime \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js
```

To pre-fetch the Node artifact, download the exact archive named in
`release/cloudflare-production-toolchain-v1.json`, transfer it without
extracting it, and use `--archive /owner-only/path/node-v24.18.0-linux-x64.tar.xz`
instead of `--download`. This is not a fully offline install: `npm ci` still
fetches the exact Wrangler dependency tarballs from `registry.npmjs.org` and
verifies every lockfile SHA-512 integrity value. The static gate rejects linked,
file, Git, non-HTTPS, non-registry, noncanonical, or integrity-free lock entries.
Wrangler's required dependency graph declares install scripts in `esbuild`,
`workerd`, and `sharp` (plus optional `fsevents`); their exact versions and
integrities are explicit in the profile's metadata allowlist. That allowlist
does not authorize execution; scripts are never run.
The materializer verifies the official archive and
Node binary hashes, uses the archive's pinned npm 11.16.0 only as a build-time
input, and runs `npm ci --ignore-scripts`. It retains only the reviewed Node
binary plus the complete locked Wrangler dependency tree, removes npm PATH
shims, rejects remaining links, and freezes the retained bytes read-only. It
refuses existing destinations; there is no in-place update mode. Neither
`node_modules` nor any other generated runtime byte is written into the Git
checkout.

Then make every tracked file read-only
(`git ls-files -z | xargs -0 chmod a-w`). The billing runtime installer creates
a non-symlink copied interpreter, validates its packages, and freezes the entire
venv; deploy never reinstalls or changes it. The source checkout and private
configuration must be root-owned and unavailable for group/world writes.
Create `/var/lib/tinyzkp-preflight-pycache` as an empty root-owned mode-`0700`
directory. Always invoke the wrapper directly; invoking it through `bash` is
rejected because only its clean shebang can discard exported functions,
dynamic-loader settings, Docker/Compose routing, proxies, and Python import
state before any repository code runs.

The host env, fixed Pages binding file, evidence file, and their parent
directories must be owner-only; Pages bindings and evidence are mode `0600`.
The aggregate gate compares the host and Pages
`INTERNAL_SECRET` values without printing either value. Its short-lived
evidence binds a random nonce, machine identity, deployment ID, fresh remote
main SHA, immutable source, private configuration files, the full venv and
installed package bytes, exact Git/Node executables, the reviewed Node release
artifact, the full Wrangler install tree and package lock, both locally built
maintenance container IDs/full inspect digests, the deterministic
profile/lock-to-installed-tree materialization attestation, the backup loader capability and
selected off-host transport credential by SHA-256 (never raw secret bytes), and
the canonical identity of the Debian base runtime, complete billing virtualenv,
pinned Node executable, and their recursive ELF dependency closure. Every
passing gate is included. Rotating a backup credential or changing any bound
runtime byte after preflight intentionally invalidates the short-lived deploy
claim.

`deploy/hetzner/deploy.sh` performs no fetch or pull after evidence creation.
It verifies the artifact before changing the billing runtime, cron, systemd,
containers, or Caddy:

```sh
deploy/hetzner/deploy.sh
```

Deploy atomically consumes the artifact before its first mutation and starts
the already-attested images with `--no-build`. Success,
failure, interruption, or retry therefore requires a newly run preflight and a
new nonce; the artifact is root self-attestation, not a separate human approval.

Hosted proving and authenticated proving smoke remain disabled. After API/MCP
and Pages deploys finish, the public live canary is still blocked until a pinned,
reviewed Wrangler/Node toolchain is provisioned outside the checkout and bound
into production evidence; do not fall back to `npx` or an unpinned global tool.

For coordinated API, MCP, and website releases, pin the expected deployed
commit and require all three surfaces to report it before announcing:

```sh
CLOUDFLARE_API_TOKEN=REDACTED CLOUDFLARE_ACCOUNT_ID=REDACTED \
scripts/ci/run_production_preflight.sh \
  --production --live \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /var/lib/tinyzkp-private/deploy/pages-bindings.env \
  --host-python /var/lib/tinyzkp-runtime/billing-venv/bin/python \
  --node-executable /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node \
  --wrangler-entrypoint /var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js \
  --git-executable /usr/bin/git \
  --deployment-id tinyzkp-production-primary \
  --contact-readiness-secret-file /var/lib/tinyzkp-private/deploy/internal-secret \
  --expected-release-sha "$(/usr/bin/git rev-parse HEAD)"
```

The API and MCP HTTP server report `HC_RELEASE_SHA` from `/version`. The Pages
worker reports `TINYZKP_RELEASE_SHA` when set, otherwise Cloudflare's
`CF_PAGES_COMMIT_SHA`, from `/api/release`.

### Backup and restore gate

Before changing backup scripts or restore instructions, run the static
backup/restore consistency check:

```sh
python3 scripts/ci/backup_restore_check.py
python3 -m pytest scripts/ci/test_backup_restore_check.py billing/tests/test_backup_script.py
```

This verifies that `backup.sh` still snapshots `tenant_store.sqlite`,
`usage.sqlite`, `evaluation_applications.sqlite`, `api_keys.txt`, and private
contract evidence/documents with restrictive permissions and off-box `rclone`
support, and that the restore runbook still references current API, contract,
and SQLite verification paths. The executable smoke test runs `backup.sh` as an
unprivileged test user against temporary SQLite databases through the test-only
loader contract, then validates the snapshots, current-run digest manifest,
permissions, and restore data. Root production runs always use
`/opt/hc-stark/.env`, `/opt/hc-stark/backups`, and the root-private loader token;
environment overrides cannot redirect those paths.

Production-grade recovery requires an off-box encrypted rclone remote. Configure
the private Cloudflare R2 bucket `tinyzkp-prod-backups` through rclone crypt and
set:

```sh
HC_BACKUP_REMOTE=tinyzkp-backups-crypt:prod-sqlite
```

Store the reviewed rclone configuration at
`/var/lib/tinyzkp-private/backup/rclone.conf`, owned by root with mode `0600`.
Use `rclone --config /var/lib/tinyzkp-private/backup/rclone.conf ...` for every
manual probe so operator checks and the backup runtime use the same config.

HTTP backup ingest remains implemented for non-production testing but is not
release-authorized: the fixed-host drill and production preflight currently
prove only the encrypted rclone path.

After configuring credentials, run a production backup push and restore smoke.
Do not describe the business as production-grade recoverable until the restore
smoke succeeds.

The Linux root backup integration is a fixed-host release gate, not covered by
the unprivileged local smoke test. On the production-equivalent Linux host it
must exercise writer quiescence, service-UID SQLite staging, root descriptor
copies, every failure/signal cleanup path, service restart, manifest upload,
and a scratch restore. Production launch must remain blocked until that run and
its raw log are independently reviewed.

#### Fixed-host backup evidence

`scripts/ci/fixed_host_backup_evidence.py` is a verify-only gate; it never runs
a backup, performs a restore, or manufactures passing evidence. It reads the
canonical bundle at
`/var/lib/tinyzkp-private/backup/fixed-host-evidence/bundle.json`, the files
listed beneath `/var/lib/tinyzkp-private/backup/fixed-host-evidence/raw/`, and
the independent review at
`/var/lib/tinyzkp-private/backup/fixed-host-evidence/review.json`. Invoke it on
the fixed Linux host with all three expected identities:

```sh
/var/lib/tinyzkp-runtime/billing-venv/bin/python \
  scripts/ci/fixed_host_backup_evidence.py \
  --expected-release-sha "$RELEASE_SHA" \
  --expected-host-identity-sha256 "$HOST_IDENTITY_SHA256" \
  --expected-deployment-id tinyzkp-production-primary
```

The host digest is derived from the root-controlled `/etc/machine-id`; the
explicit host digest above is an optional additional comparison. Use
`--machine-id-file` only for an independently controlled fixed-host identity
file. Successful verification returns a deterministic
`evidence_identity_sha256` over the bundle, independent review, and complete
raw-artifact descriptor set so a later release gate can bind the same bytes.

The bundle must bind the exact release, host, deployment, backup manifest,
off-host readback, restored semantic results, service transitions, and every
raw artifact by size and SHA-256. The separate review must bind the complete
bundle and raw-artifact set, identify an independent reviewer, and record a
passing disposition. Evidence older than 30 days fails closed. Ordinary local
CI can unit-test this policy, but it cannot create or pass fixed-host evidence:
the reviewed bundle, raw artifacts, host identity, private ownership boundary,
and independent review must come from the production-equivalent Linux drill.

### Cloudflare Pages deploy gate

Run the site deploy preflight before every Pages deploy:

```sh
python3 scripts/ci/site_deploy_check.py
python3 scripts/ci/site_deploy_check.py --production --bindings-file /secure/tinyzkp-pages.env
python3 scripts/ci/cloudflare_toolchain_check.py
node scripts/ci/site_worker_dispatch_test.mjs
node scripts/ci/test_analytics_attribution.mjs
```

The static mode verifies `site/wrangler.toml`, the Advanced Mode `_worker.js`
route table, every Pages API function handler, and classified Cloudflare
bindings. Production mode also checks that the expected Pages bindings/secrets
are exact: `INTERNAL_SECRET` is present, while legacy Stripe, demo, and any
other unused secrets are absent. The worker dispatch test imports the real `_worker.js`
module with mocked Pages assets/cache APIs and verifies API dispatch, method
405s, static asset passthrough, extensionless `.html` fallback, and baseline browser security headers on static and API responses.
The analytics attribution test simulates browser CTA clicks and verifies that
conversion links preserve first-touch source context while adding internal
campaign/intent markers for signup, MCP, verifier, playground, pilot, rollout,
and contact flows.

### GTM distribution monitor

Run the offline GTM distribution monitor before changing MCP listings,
machine-readable offer metadata, or agent-directory copy:

```sh
python3 scripts/marketing/render_mcp_submissions.py
python3 scripts/marketing/render_mcp_submissions.py --check
python3 -m pytest scripts/ci/test_mcp_submission_renderer.py
python3 scripts/monitoring/gtm_distribution_monitor.py --offline
python3 -m pytest scripts/ci/test_gtm_distribution_monitor.py
```

The renderer writes source-tagged submission drafts to
`marketing/generated/mcp_submissions/` from
`marketing/mcp_distribution_targets.json`; `--check` fails when generated drafts
are stale. Offline monitor mode validates the target catalog, including
source-tagged signup URLs for MCP directories and agent-IDE communities. After
publishing or updating a live listing, run the online monitor without
`--offline`; it checks canonical TinyZKP MCP/offer assets plus every `active`
directory target with a `listing_url`.

### GTM growth monitor

Run the aggregate growth monitor for one revenue-facing view of distribution
contracts, source-tagged CTAs, package surfaces, MCP submission drafts, launch
assets, and local revenue attribution:

```sh
python3 scripts/monitoring/gtm_growth_monitor.py --offline
```

On the Hetzner host this runs daily from `/etc/cron.d/hc-billing` through
`scripts/monitoring/host_cron_env.sh`, so `/opt/hc-stark/.env` is loaded before
the monitor reads production stores. It writes to `/var/log/hc-gtm-growth.log`.
Use `--live` after a deploy to add
non-mutating public checks for the site, playground, verifier, signup page,
well-known agent assets, API health, MCP version, and invalid-email signup /
checkout endpoint behavior, plus PyPI, npm, and crates.io package registry
availability. Use strict mode for production alerting once the self-serve
funnel should be generating revenue:

```sh
python3 scripts/monitoring/gtm_growth_monitor.py \
  --offline \
  --tenant-db /opt/hc-stark/data/tenant_store.sqlite \
  --usage-db /opt/hc-stark/data/usage.sqlite \
  --strict-revenue \
  --min-activated-accounts 1 \
  --min-paid-accounts 1 \
  --min-paid-proofs 1 \
  --min-total-proofs 1
```

The JSON form is safe for dashboards and omits tenant email addresses:

```sh
python3 scripts/monitoring/gtm_growth_monitor.py --offline --json
```

### Daily growth decision memo

Run the daily decision layer after the GTM growth monitor to persist a
non-repo snapshot, evaluate yesterday's experiment, and print today's selected
growth experiment with an implementation policy:

```sh
python3 scripts/monitoring/daily_growth_decision.py \
  --tenant-db /opt/hc-stark/data/tenant_store.sqlite \
  --usage-db /opt/hc-stark/data/usage.sqlite
```

Production cron runs `scripts/monitoring/daily_growth_decision_cron.sh`. The
wrapper sources `/opt/hc-stark/.env`, requires non-empty tenant and usage
stores, writes the normal snapshot, and scans the memo plus latest snapshot and
experiment ledger for emails, Stripe object IDs, Checkout URLs, and
API-key-like values. It includes live Stripe Checkout metrics only when
`TINYZKP_GROWTH_STRIPE_CHECKOUT=1` is set with a trusted account source. For
production, prefer API-key validation:

```bash
TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME="LN Holdings" \
TINYZKP_STRIPE_ACCOUNT_SOURCE=api \
TINYZKP_STRIPE_API_KEY_ENV=STRIPE_SECRET_KEY \
python3 billing/stripe_account_context_check.py --account-source api
```

Then configure the host with
`TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE=api`,
`TINYZKP_GROWTH_STRIPE_API_KEY_ENV=STRIPE_SECRET_KEY`, and
`TINYZKP_GROWTH_STRIPE_CHECKOUT=1`. CLI profiles are still supported for
operator/catalog setup via `TINYZKP_GROWTH_STRIPE_PROJECT_NAME` or
`TINYZKP_STRIPE_PROJECT_NAME`, but verify that profile first with
`billing/stripe_account_context_check.py`. The trusted Stripe account display
name is `LN Holdings`, the legal Stripe account used for TinyZKP revenue
automation.

Snapshots are written to `/opt/hc-stark/data/growth_snapshots/YYYY-MM-DD.json`
by default. They contain aggregate adoption, activation, paid-customer,
revenue, source, and pipeline counts only; emails, Stripe object IDs, checkout
URLs, and API-key-like values are redacted from JSON and Markdown output. Use
`--stripe-checkout --stripe-account-source api --stripe-api-key-env STRIPE_SECRET_KEY`
only after `billing/stripe_account_context_check.py --account-source api`
verifies the API key belongs to `LN Holdings`.

The daily decision also writes a no-PII experiment ledger at
`/opt/hc-stark/data/growth_experiment_ledger.json` by default. The ledger
deduplicates by date and stores the selected experiment, prior experiment
evaluation, implementation policy, scorecard, and funnel stage that is blocking
revenue. It is the durable handoff that lets the next day's memo decide whether
to keep, revert, iterate, or escalate the prior day's action.

After each production deploy, verify the data wiring on the host:

```bash
cd /opt/hc-stark
bash scripts/monitoring/verify_growth_data_wiring.sh
tail -50 /var/log/hc-daily-growth-decision.log
```

The verifier fails if `/opt/hc-stark/data/tenant_store.sqlite` or
`/opt/hc-stark/data/usage.sqlite` is missing or empty, runs
`gtm_growth_monitor.py` against those exact paths, syntax-checks the cron
wrapper, runs the daily growth cron, confirms a snapshot exists under
`/opt/hc-stark/data/growth_snapshots`, confirms
`growth_experiment_ledger.json` exists, and expects
`daily_growth_decision_redaction_scan=ok`.

The memo includes a business-copilot autonomy policy and safe action queue.
Allowed daily actions are read-only production checks, non-repo aggregate
snapshot/ledger writes, repo-local no-PII product/docs/instrumentation changes,
focused tests, PR preparation, and public/no-PII GTM follow-up. Explicit
operator approval is still required before customer/prospect messaging, private
contact use, spend, Stripe/catalog/customer mutations, production env changes,
merge/deploy, live checkout/session creation, live payment activity, or
Postgres/shared-worker/billing read cutovers.

The Codex daily automation should run this command around 10:15
America/Los_Angeles, after the 09:45 production GTM cron, and report the
scorecard, what is working, whether yesterday's experiment worked, the main
bottleneck, the selected experiment, implementation status, and any data gaps.
It may implement small safe repo-local or public/no-PII experiments and run
focused tests. It must report blockers instead of sending customer messages,
using private contact data, spending money, changing Stripe/catalog state, or
modifying production behavior without explicit approval.

### Receipt share contract gate

Run the receipt-share contract check before changing `/try`, `/verify`,
agent-readable metadata, or receipt-share CTAs:

```sh
python3 scripts/ci/receipt_share_contract_check.py
python3 -m pytest scripts/ci/test_receipt_share_contract_check.py
```

This validates the public `#proof=` fragment contract, `source=receipt_share`
attribution, share-link size ceiling, data-boundary language, analytics event
allowlist, and discovery links from `llms.txt`, `robots.txt`, and
`discovery.json`.

### Badge embed contract gate

Run the badge embed check before changing `/badges`, badge snippets in recipes,
the badge SVG, `llms.txt`, `robots.txt`, `discovery.json`, or integration
metadata:

```sh
python3 scripts/ci/badge_embed_check.py
python3 -m pytest scripts/ci/test_badge_embed_check.py
```

This validates the public `/.well-known/tinyzkp-badge.json` contract,
source-tagged verifier embed template, SVG dimensions, transparent-receipt
data boundaries, and discovery links for agents and crawlers.

### Manual distribution asset gate

Run the manual distribution asset check before posting HN/X launch copy,
sending founder outbound, or publishing integration tutorials:

```sh
python3 scripts/ci/manual_distribution_assets_check.py
python3 -m pytest scripts/ci/test_manual_distribution_assets_check.py
```

This blocks stale MCP tool names, outdated pricing/verification claims, and
bare TinyZKP conversion URLs that would lose source attribution.

### OpenAI ChatGPT app prototype

The ChatGPT app prototype uses the existing hosted MCP server plus a noindex
widget resource:

- App submission metadata: `marketing/openai_chatgpt_app_submission.json`
- Prototype plan: `marketing/OPENAI_CHATGPT_APP_PROTOTYPE.md`
- Widget: `site/apps/tinyzkp-receipt-widget.html`

Before editing those assets or submitting for review, run:

```sh
python3 scripts/ci/openai_chatgpt_app_check.py
python3 -m pytest scripts/ci/test_openai_chatgpt_app_check.py
```

The checker validates the streamable MCP endpoint, source-tagged ChatGPT signup
URL, privacy/terms links, human-confirmation requirement, review test prompts,
and MCP Apps bridge markers in the widget.

### Package distribution gate

Run the package distribution check before publishing SDK, CLI, WASM verifier,
or MCP package/readme changes:

```sh
python3 scripts/ci/package_distribution_check.py
python3 -m pytest scripts/ci/test_package_distribution_check.py
```

This validates that PyPI, npm, crates.io, CLI, WASM verifier, and MCP README
surfaces preserve source-tagged signup, verifier, limits, and agent-offer
links, and that package metadata keeps registry attribution markers.

### SEO conversion gate

Run the SEO conversion check before changing priority acquisition pages,
comparison pages, integration pages, `llms.txt`, or the sitemap:

```sh
python3 scripts/ci/seo_conversion_check.py
python3 -m pytest scripts/ci/test_seo_conversion_check.py
```

This validates that the priority SEO pages are present in both `sitemap.xml`
and `llms.txt`, have basic crawlable metadata, and preserve at least one
source-tagged, tracked CTA into the TinyZKP funnel.

### GTM revenue report

Use the GTM revenue report to inspect which channels are producing accounts,
activated accounts, paid-plan accounts, active base MRR, estimated usage
revenue, paid proofs, Compute trace-step volume, and time-to-first-proof:

```sh
python3 billing/gtm_revenue_report.py \
  --tenant-db /opt/hc-stark/data/tenant_store.sqlite \
  --usage-db /opt/hc-stark/data/usage.sqlite
```

The report groups by stored attribution source, medium, and platform. It does
not print email addresses. Use `--json` when feeding the summary into a BI
dashboard or scheduled internal digest.

### Billing cron and lifecycle nudges

The host cron `/etc/cron.d/hc-billing` runs three billing-adjacent jobs, one
daily GTM monitor, and one daily growth decision memo. Billing and GTM Python
jobs run through `scripts/monitoring/host_cron_env.sh`, which sources
`/opt/hc-stark/.env`, changes to `/opt/hc-stark`, and then execs
`/var/lib/tinyzkp-runtime/billing-venv/bin/python`:

- `billing/sync_usage.py` hourly to report billable usage to Stripe.
- `billing/lifecycle_nudges.py` hourly to send idempotent activation and
  upgrade nudges after signup, first proof, free-quota threshold events, and
  14-day idle win-back windows.
- `billing/checkout_recovery.py` hourly to inspect open Stripe Checkout
  Sessions and send idempotent recovery links for paid checkouts that were
  started but not completed, including both self-serve subscription Sessions and
  one-time Production Pilot payment Sessions.
- `scripts/monitoring/gtm_growth_monitor.py --offline` daily to log GTM
  distribution health, source-tagged surfaces, revenue attribution, lifecycle
  ledgers, and checkout recovery counts.
- `scripts/monitoring/daily_growth_decision_cron.sh` daily, after the GTM
  monitor, to persist aggregate growth snapshots, evaluate the prior
  experiment, produce the next experiment plus implementation policy, and fail
  closed if output redaction fails.

Lifecycle nudges and checkout recovery use the same SMTP environment as the
webhook, but they default to dry-run/no-send. Set
`TINYZKP_CUSTOMER_EMAILS_ENABLED=1` only after lifecycle/recovery copy review
and SPF/DKIM/DMARC checks pass. Each sent lifecycle nudge is recorded in
`tenant_store.lifecycle_emails` by `(tenant_id, kind)`, and each checkout
recovery is recorded in `tenant_store.checkout_recovery_emails` by Stripe
Checkout Session ID, so cron retries do not resend the same email.
Lifecycle dry-run and failure logs use stable `recipient_ref` hashes instead of
raw email addresses; checkout recovery logs also use stable recipient and
session refs instead of Stripe object IDs or checkout URLs.

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIPE_SECRET_KEY` | required | Stripe API key |
| `TINYZKP_CUSTOMER_EMAILS_ENABLED` | `0` | Customer lifecycle/recovery email kill switch. Anything other than an affirmative value keeps cron in dry-run/no-send mode |
| `TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE` | `cli` | Stripe checkout source for daily growth cron: `api` validates `STRIPE_SECRET_KEY`; `cli` validates a named Stripe CLI profile |
| `TINYZKP_GROWTH_STRIPE_API_KEY_ENV` | `STRIPE_SECRET_KEY` | Env var read when `TINYZKP_GROWTH_STRIPE_ACCOUNT_SOURCE=api` |
| `TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME` | `LN Holdings` | Required Stripe account display-name substring for revenue automation |
| `TINYZKP_GROWTH_SNAPSHOT_DIR` | `/opt/hc-stark/data/growth_snapshots` | Non-repo daily aggregate snapshot directory used by the growth decision cron |
| `TINYZKP_GROWTH_EXPERIMENT_LEDGER` | `/opt/hc-stark/data/growth_experiment_ledger.json` | No-PII daily experiment ledger used to score prior actions and compound the business loop |
| `HC_USAGE_SOURCE` | `sqlite` | Billing usage source: `sqlite` or `postgres`. `postgres` uses `HC_SERVER_PG_URL` and `psql` |
| `HC_USAGE_DB_PATH` | `/opt/hc-stark/data/usage.sqlite` | SQLite usage log path |
| `HC_SERVER_PG_URL` | required when `HC_USAGE_SOURCE=postgres` | Postgres connection string for billing reads and `billed=1` updates |
| `STRIPE_METER_EVENT_NAME` | `proof_usage` | Stripe Meter event name |
| `HC_UNBILLED_ALERT_HOURS` | `12` | Alert if unbilled rows are older than this — must stay below Stripe's ~24h Meter-event dedup window |
| `ALERT_WEBHOOK_URL` | (none) | Slack/Discord webhook for billing alerts |

### Postgres migration helper (usage_pg_tools.py)

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_SERVER_PG_URL` | required for Postgres commands | Postgres connection string used by `hc-server` Phase 1 dual-write and `billing/usage_pg_tools.py` |
| `HC_USAGE_DB_PATH` | `/opt/hc-stark/data/usage.sqlite` | Source SQLite usage log for summaries and backfill |
| `PSQL_BIN` | `psql` | Path to the `psql` binary |

During the usage-state migration, `hc-server` initializes
`crates/hc-server/sql/usage_pg.sql` at boot when `HC_SERVER_PG_URL` is set.
Use `billing/usage_pg_tools.py compare --since-ms <dual_write_start_ms>` to
prove SQLite/Postgres parity for the dual-write window. After parity is clean,
operators can switch `/usage` and monthly caps with
`HC_SERVER_USAGE_READ_FROM=postgres`, then switch Stripe sync with
`HC_USAGE_SOURCE=postgres`. Set `HC_RATE_LIMIT_PG_URL` in both API and MCP
processes to share authenticated tenant RPM windows across surfaces. Set
`HC_SERVER_JOB_INDEX_SOURCE=postgres` to store submitted requests, status, and
completed proof bytes in Postgres so polling/download can work across API
processes. Worker request/proof handoff streams over stdin/stdout; local
`request.json` / `proof.json` files are no longer part of the hot path. The
shared job index also carries tenant plan, computed trace length, and
lease-based claim fields used by `hc-job-worker`; do not advertise multi-host
proving until shared dispatch is deployed, monitored, and observed under load.
Historical backfill is available for `usage_log` and
`failed_proofs`; `verify_log` is compare-only because it has no semantic
idempotency key.

Shared proving/worker cutover is historical research during backend recovery.
Do not set `HC_SERVER_PROVE_DISPATCH=shared` or run authenticated proving smoke
against production. The current wrapper-only maintenance canary verifies that
proving, hosted verification, signup, and checkout remain unavailable.

## Deployment

### Docker Compose (Development)

```bash
GRAFANA_ADMIN_PASSWORD=changeme docker compose up
```

Before relying on Compose changes, run the same render gate CI uses. It validates
the local, production, and shared-worker production invocations with dummy
non-secret values:

```bash
python3 scripts/ci/compose_config_check.py
```

### Docker Compose (Production / Hetzner)

```bash
export HC_SERVER_API_KEYS="tenant1:key1,tenant2:key2"
export GRAFANA_ADMIN_PASSWORD="<strong-password>"
docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml up -d
```

### Bare Metal

```bash
cargo build -p hc-server --release --bins
HC_SERVER_API_KEYS="demo:demo_key" ./target/release/hc-server
```

## Monitoring

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `hc_prove_submitted_total` | Counter | Total prove submissions |
| `hc_verify_requests_total` | Counter | Total verify requests |
| `hc_prove_completed_total` | CounterVec | Completed proofs (by tenant) |
| `hc_prove_failed_total` | CounterVec | Failed proofs (by tenant) |
| `hc_prove_duration_seconds` | Histogram | Prove job duration |
| `hc_jobs_inflight` | Gauge | Currently in-flight jobs |
| `hc_gc_runs_total` | Counter | Background GC cycles |
| `hc_gc_removed_total` | Counter | Jobs removed by GC |
| `hc_rate_limit_rejections_total` | CounterVec | Rate limit rejections (by endpoint) |

### Alerting Rules

Defined in `deploy/prometheus/alerts.yml`:

- **HcHighFailureRate**: >10% failure rate over 5 minutes
- **HcSlowProves**: P99 prove duration >5 minutes over 10 minutes
- **HcNoCompletions**: No completions despite submissions for 30 minutes

For customer-visible outages, use
[`docs/runbooks/incident_response.md`](runbooks/incident_response.md). The
runbook defines SEV1/SEV2/SEV3 levels, incident categories, public update
templates, billing safeguards, and rollback rules.

### GTM Revenue Monitoring

Start with the safe readiness runner. It validates that the local Stripe CLI
profile is the `LN Holdings` Stripe account used for TinyZKP before it runs the
read-only audit, summarizes Checkout Sessions, and optionally syncs aggregate
evidence into the no-PII GTM pipeline ledger:

```bash
python3 billing/stripe_revenue_readiness.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --sync-pipeline
```

Use `--plan-only` to preview the full sequence without touching Stripe or local
ledgers. Use `--setup-catalog pilot --push-cloudflare` or
`--setup-catalog full --push-cloudflare` only when intentionally writing Stripe
catalog objects from the verified `LN Holdings` account. If that account is a
non-default Stripe CLI profile, pass `--stripe-project-name <profile>` so the
account check, reads, sync, canary visibility checks, and setup scripts all use
that profile.

For diagnosis, the read-only revenue-ops audit can be run directly. It compares
live Stripe billing meters, products/prices, Cloudflare Pages secret names, and
the pilot checkout capability endpoint without printing secret values or Stripe
IDs:

```bash
python3 billing/stripe_revenue_ops_audit.py \
  --stripe-bin /opt/homebrew/bin/stripe
```

Use `--strict-catalog` only after the current Stripe catalog has been rebuilt
with a write-capable profile; before then, warnings are expected when the live
pilot route remains sellable through inline `price_data`.

Use the local Stripe CLI profile to summarize Checkout Session starts and paid
revenue without printing buyer PII:

```bash
python3 billing/stripe_checkout_monitor.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --lookback-hours 168
```

For production hosts without Stripe CLI, use the read-only API path after
account validation passes:

```bash
python3 billing/stripe_checkout_monitor.py \
  --account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY \
  --lookback-hours 168
```

To include live Checkout state in the aggregate GTM monitor:

```bash
python3 scripts/monitoring/gtm_growth_monitor.py \
  --offline \
  --stripe-checkout \
  --stripe-account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY
```

To sync aggregate Stripe checkout evidence into the no-PII pipeline ledger and
rerender `marketing/generated/gtm_pipeline_ledger.*`:

```bash
python3 scripts/marketing/sync_stripe_checkout_pipeline.py \
  --account-source api \
  --stripe-api-key-env STRIPE_SECRET_KEY \
  --lookback-hours 168
```

The sync command never lowers previously recorded revenue when the current
lookback has no paid pilot sessions. It stores aggregate counts and dashboard
evidence only; do not commit customer emails, Stripe object IDs, or checkout
URLs into the pipeline state.

The standalone monitor supports `--min-paid-sessions` and
`--min-pilot-paid-sessions` for alerting jobs. The aggregate monitor supports
the matching `--stripe-checkout-min-paid-sessions` and
`--stripe-checkout-min-pilot-paid-sessions` flags.

### Grafana

Dashboard provisioned at `deploy/grafana/dashboards/`. Credentials configured via `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` environment variables.

## Troubleshooting

### Stale jobs after crash

On startup, the server reconciles any `Pending` or `Running` jobs to `Failed` with error "server restarted — job was in progress". Check logs for `reconciled stale jobs` message.

### Rate limit errors (429)

- Check `hc_rate_limit_rejections_total` metric
- Override with `HC_SERVER_RATE_LIMIT_DISABLED=1` in emergencies
- Adjust `HC_SERVER_MAX_PROVE_RPM` / `HC_SERVER_MAX_VERIFY_RPM`

### Job index disabled (501 on GET /prove)

- Set `HC_SERVER_JOB_INDEX_SQLITE=true` or remove `HC_SERVER_JOB_INDEX_DISABLED`

## Capacity Planning

- **Memory per job**: ~100MB per block_size=2^16, scales linearly
- **CPU per job**: Single-threaded prover, one worker process per job
- **Disk**: Proof artifacts ~50-500KB each, cleaned by GC after retention period
- **Max concurrent**: Controlled by `HC_SERVER_MAX_INFLIGHT` (default: 4)
