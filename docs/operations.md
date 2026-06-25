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
`/opt/hc-stark/.venv`, installed by
`deploy/hetzner/install_billing_runtime.sh` from `billing/requirements.txt`.
The deploy script refreshes this virtualenv, rewrites the billing cron and
`hc-billing-webhook.service` definitions to use it, and only then restarts the
webhook.

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

When the legacy research repo is checked out next to `hc-stark`, include it in
the audit:

```sh
python3 scripts/ci/launch_gate_audit.py --require-legacy
python3 scripts/ci/production_launch_preflight.py --require-legacy
```

For a production deploy rehearsal, run the aggregate preflight with the
production env file and Cloudflare Pages binding file. This keeps local repo
evidence, deploy-readiness policy, Pages configuration, Compose rendering,
backup/restore drift, package distribution surfaces, and the launch-gate audit
under one operator command:

```sh
python3 scripts/ci/production_launch_preflight.py \
  --require-legacy \
  --production \
  --env-file /opt/hc-stark/.env \
  --pages-bindings-file /secure/tinyzkp-pages.env \
  --check-host-python \
  --host-python /opt/hc-stark/.venv/bin/python
```

After API/MCP and Pages deploys finish, add `--live` before announcing the
release. Add `--authenticated-smoke` when `TINYZKP_SMOKE_API_KEY` or
`TINYZKP_AUDIT_API_KEY` is available and the prove/verify path should be
exercised end to end.

Live mode starts by reading Cloudflare Pages production secret names through
`wrangler pages secret list --project-name tinyzkp`; it fails before public
smoke tests if any required binding is missing, including
`STRIPE_PRICE_ID_PILOT` for the paid Production Pilot checkout path.

For coordinated API, MCP, and website releases, pin the expected deployed
commit and require all three surfaces to report it before announcing:

```sh
TINYZKP_EXPECT_RELEASE_SHA="$(git rev-parse HEAD)" \
  python3 scripts/ci/production_launch_preflight.py --live
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
`usage.sqlite`, and `api_keys.txt` with restrictive permissions and off-box
`rclone` support, and that the restore runbook still references current API
and SQLite verification paths. The executable smoke test runs `backup.sh`
against temporary SQLite databases using `HC_BACKUP_DATA_DIR`, `HC_BACKUP_DIR`,
`HC_BACKUP_DATE`, and `HC_BACKUP_REMOTE_DATE` overrides, then validates that the
snapshots are readable and permissioned for restore.

### Cloudflare Pages deploy gate

Run the site deploy preflight before every Pages deploy:

```sh
python3 scripts/ci/site_deploy_check.py
python3 scripts/ci/site_deploy_check.py --production --bindings-file /secure/tinyzkp-pages.env
node scripts/ci/site_worker_dispatch_test.mjs
node scripts/ci/test_analytics_attribution.mjs
```

The static mode verifies `site/wrangler.toml`, the Advanced Mode `_worker.js`
route table, every Pages API function handler, and classified Cloudflare
bindings. Production mode also checks that the expected Pages bindings/secrets
are present: `INTERNAL_SECRET`, Stripe secret/price IDs, and
`TINYZKP_DEMO_API_KEY`. The worker dispatch test imports the real `_worker.js`
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

On the Hetzner host this runs daily from `/etc/cron.d/hc-billing` and writes
to `/var/log/hc-gtm-growth.log`. Use `--live` after a deploy to add
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

The host cron `/etc/cron.d/hc-billing` runs three billing-adjacent jobs and
one daily GTM monitor:

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

Lifecycle nudges and checkout recovery use the same SMTP environment as the
webhook. Each sent lifecycle nudge is recorded in
`tenant_store.lifecycle_emails` by `(tenant_id, kind)`, and each checkout
recovery is recorded in `tenant_store.checkout_recovery_emails` by Stripe
Checkout Session ID, so cron retries do not resend the same email.

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIPE_SECRET_KEY` | required | Stripe API key |
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

Before and after flipping `HC_SERVER_PROVE_DISPATCH=shared`, run the focused
cutover smoke test against the target environment:

```bash
TINYZKP_SMOKE_API=https://api.tinyzkp.com \
TINYZKP_SMOKE_SITE=https://tinyzkp.com \
TINYZKP_SMOKE_API_KEY=tzk_... \
  scripts/monitoring/shared_dispatch_smoke.sh
```

This gate checks public lifecycle metadata, reconciliation site markers, a
template prove, poll/download, inspect, verify, the cancel route, and `/usage`.
Use `TINYZKP_SMOKE_PUBLIC_ONLY=1` only for unauthenticated website/API marker
checks; it is not sufficient for a shared-worker cutover.

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
profile is the TinyZKP account before it runs the read-only audit, summarizes
Checkout Sessions, and optionally syncs aggregate evidence into the no-PII GTM
pipeline ledger:

```bash
python3 billing/stripe_revenue_readiness.py \
  --stripe-bin /opt/homebrew/bin/stripe \
  --sync-pipeline
```

Use `--plan-only` to preview the full sequence without touching Stripe or local
ledgers. Use `--setup-catalog pilot --push-cloudflare` or
`--setup-catalog full --push-cloudflare` only when intentionally writing Stripe
catalog objects from the verified TinyZKP account. If the TinyZKP account is a
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

To include live Checkout state in the aggregate GTM monitor:

```bash
python3 scripts/monitoring/gtm_growth_monitor.py \
  --offline \
  --stripe-checkout \
  --stripe-bin /opt/homebrew/bin/stripe
```

To sync aggregate Stripe checkout evidence into the no-PII pipeline ledger and
rerender `marketing/generated/gtm_pipeline_ledger.*`:

```bash
python3 scripts/marketing/sync_stripe_checkout_pipeline.py \
  --stripe-bin /opt/homebrew/bin/stripe \
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
