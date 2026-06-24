# Postgres migration plan

> **Status**: Usage dual-write, shared quotas, shared job index, shared worker
> dispatch, and Postgres tenant/auth read paths are implemented locally.
> Production still needs an operator to provision managed Postgres (Hetzner
> managed PG, RDS, Neon, etc.), set `HC_SERVER_PG_URL`, and run the parity
> checks below before enabling Postgres reads or any shared-state cutover.

## Why migrate

`hc-server` keeps job and usage state in two SQLite files:

- `data/jobs.sqlite` — `prove_jobs` table; one row per submitted prove job.
- `data/usage.sqlite` — `usage_log`, `verify_log`, `failed_proofs` tables.

SQLite has been the right call so far: zero ops cost, no second moving piece,
and WAL+busy_timeout (Day 1c) handles in-process contention adequately.

The structural ceiling is **horizontal scale**. SQLite cannot be safely
shared across hosts, so:

- We can't run two `hc-server` instances behind a load balancer for failover.
- We can't burst-scale CPU by running more `hc-worker` processes on different
  boxes (workers also need to read/write job state).
- Cross-process billing reconciliation between `hc-server` and the Python
  cron is already messy — the cron has to open the same SQLite file with
  matching pragmas.

The realistic ceiling on a single Hetzner box is **tens of proves per minute
sustained** before SQLite write contention dominates and dispatch latency
grows past acceptable bounds. Postgres unblocks the next ~2 orders of
magnitude.

## Scope

This migration moves *operational state* (jobs, usage, billing, tenant auth) to Postgres.
It does **NOT** move:

- Local job status files (`data/jobs/<tenant>/<id>/status.json`). Worker
  request/proof handoff uses stdin/stdout, so the hot path no longer depends on
  transient `request.json` / `proof.json` files. The status files are still
  per-host compatibility artifacts until the Postgres job index is the
  production read/write source.
- Cryptographic primitives or proof bytes themselves.
- The billing webhook write master in one jump. `tenant_store.sqlite` remains
  the initial source for Stripe customer/subscription state while
  `billing/tenant_pg_tools.py` backfills and compares Postgres. API/MCP can
  then read tenant/API-key auth from Postgres with `HC_SERVER_AUTH_PG_URL`
  after parity is proven.

## Schema

The Postgres schema mirrors the SQLite shape with three caveats:

1. `id INTEGER PRIMARY KEY AUTOINCREMENT` → `id BIGSERIAL PRIMARY KEY`.
2. `INTEGER` storage of millisecond timestamps → `TIMESTAMPTZ` with
   millisecond precision. Migration helper converts on read.
3. `INSERT OR IGNORE` (SQLite) → `ON CONFLICT DO NOTHING` (Postgres).

See [`crates/hc-server/sql/usage_pg.sql`](../crates/hc-server/sql/usage_pg.sql)
and [`crates/hc-server/sql/tenant_auth_pg.sql`](../crates/hc-server/sql/tenant_auth_pg.sql)
for the exact DDL — runnable today against any Postgres 14+.

## Dual-write strategy (recommended path)

The migration runs in 4 phases. Each phase is reversible — backing out
just means dropping the env var.

### Phase 0 — Provision (operator)

```sh
# Provision PG (managed or self-hosted), TLS to non-public networks.
psql "$HC_SERVER_PG_URL" -f crates/hc-server/sql/usage_pg.sql
psql "$HC_SERVER_PG_URL" -f crates/hc-server/sql/tenant_auth_pg.sql
```

Verify schema is current:

```sh
psql "$HC_SERVER_PG_URL" -c "\dt"
```

### Phase 1 — Dual-write usage tables (low risk)

Set `HC_SERVER_PG_URL`. `hc-server` writes every `usage_log.record()`,
`record_verify()`, and `record_failure()` to BOTH SQLite (source of
truth) AND Postgres (mirror). Postgres write failures are logged at WARN
but do not fail the request — we are still single-master on SQLite.
`HC_SERVER_PG_TLS=true` can force TLS; otherwise TLS is inferred from
`sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full` in the URL.
At boot, the server initializes
[`crates/hc-server/sql/usage_pg.sql`](../crates/hc-server/sql/usage_pg.sql)
against the configured database.

Capture the dual-write start timestamp in milliseconds, then run for a week
and compare Postgres against SQLite daily:

```sh
DUAL_WRITE_START_MS="$(date +%s000)"
python3 billing/usage_pg_tools.py compare --since-ms "$DUAL_WRITE_START_MS"
```

If Postgres ever drifts, alert and investigate before cutting reads over. The
compare command checks row counts plus stable aggregate sums across
`usage_log`, `verify_log`, and `failed_proofs`.

### Phase 2 — Cutover usage read-side and billing sync (medium risk)

After parity is clean, set `HC_SERVER_USAGE_READ_FROM=postgres`. The `/usage`
HTTP handler and monthly cap checks read from Postgres instead of SQLite.
SQLite keeps getting written for one more week as a safety net. Reverting is a
single env-var flip (`HC_SERVER_USAGE_READ_FROM=sqlite`).

Then set `HC_USAGE_SOURCE=postgres` for `billing/sync_usage.py`. The cron reads
unbilled rows from Postgres and marks `billed=1` in Postgres using `psql`.
Keep the cron on SQLite until the server read-side has passed a smoke test.

### Phase 2B — Share authenticated rate-limit state (low risk)

Set `HC_RATE_LIMIT_PG_URL` in both `hc-server` and `hc-mcp-http`. Both
processes initialize the `rate_limit_windows` table and consume the same
per-tenant fixed window for authenticated requests. Reverting is a single
env-var removal; both binaries fall back to their local in-process counters.

### Phase 2C — Mirror tenant/auth state and enable shared auth reads (medium risk)

Initialize the tenant/auth schema and backfill the current SQLite tenant store:

```sh
python3 billing/tenant_pg_tools.py --pg-url "$HC_SERVER_PG_URL" init
python3 billing/tenant_pg_tools.py --pg-url "$HC_SERVER_PG_URL" backfill --dry-run
python3 billing/tenant_pg_tools.py --pg-url "$HC_SERVER_PG_URL" backfill --apply
python3 billing/tenant_pg_tools.py --pg-url "$HC_SERVER_PG_URL" compare
```

Then set `HC_TENANT_PG_URL` on the host-level billing webhook so new tenant,
Stripe event, magic-link, and session mutations continuously mirror into
Postgres. Leave `HC_TENANT_PG_REQUIRED=0` during the observation window; after
`billing/tenant_pg_tools.py compare` remains clean, flip it to `1` so tenant
mutations fail visibly if the mirror is unavailable.

After mirrored parity is clean, set `HC_SERVER_AUTH_PG_URL` in both `hc-server`
and `hc-mcp-http` (it may use the same URL as `HC_SERVER_PG_URL`). This makes
Bearer auth miss the env/file key map, then resolve against Postgres
`tenants.api_key_hash` where `status='active'`. The file/env keys remain the
primary rollback path; removing `HC_SERVER_AUTH_PG_URL` returns both surfaces to
the host-local `api_keys.txt`/SQLite behavior.

### Phase 3 — Move job index to Postgres (medium risk)

Set `HC_SERVER_JOB_INDEX_SOURCE=postgres` and either `HC_JOB_INDEX_PG_URL` or
`HC_SERVER_PG_URL`. The server initializes `prove_jobs` in Postgres and stores
request JSON, status JSON, status tags, timestamps, and completed proof bytes in
the `Succeeded` status payload. This lets any API process poll or download a
completed proof after the worker has updated the shared index.

The worker hot path streams the request to `hc-worker` over stdin and reads the
proof from stdout, then stores the terminal status in the shared index. This
phase removes the `jobs.sqlite` sharing problem for submitted/completed status,
but it is not yet a distributed worker queue: the API process that accepts a job
still executes that job locally.

### Phase 4 — Cutover usage write-side + decommission (high risk)

Drop the SQLite usage_log writes. SQLite file is preserved on disk for
rollback but no longer touched. Two weeks of observation, then archive
or delete.

### Phase 5 — Move worker dispatch off the accepting API process

Introduce a shared worker queue so any worker host can claim a submitted job
from Postgres, execute it, and publish status/proof bytes back to the shared
job index. The store-level pieces are now in place: `prove_jobs` carries
tenant plan, computed trace length, lease owner, and lease expiry; `JobStore`
can atomically claim the next pending/expired job; and cancellation can update a
non-local pending/running job through the shared index.

The worker loop is implemented as `hc-job-worker`. It claims jobs from the
shared index, launches `hc-worker --stdio`, renews the lease while the child
runs, watches the shared status for cancellation, and writes terminal status
plus usage records. During a rolling deploy, `SIGTERM` stops new claims; an
active child is dropped and the running job becomes reclaimable after
`HC_JOB_WORKER_LEASE_MS`. Before starting the daemon, run
`hc-job-worker --check-config` on each candidate worker host. In staging, submit
one proof with shared dispatch and run `hc-job-worker --once` to claim exactly
one job, publish the result, and exit. To cut over:

```sh
HC_SERVER_JOB_INDEX_SOURCE=postgres
HC_SERVER_PROVE_DISPATCH=shared
COMPOSE_PROFILES=shared-workers docker compose \
  -f docker-compose.yml \
  -f deploy/hetzner/docker-compose.prod.yml \
  up -d --build hc-server hc-job-worker
```

On Hetzner, `deploy/hetzner/deploy.sh` automatically enables the
`shared-workers` profile when `.env` sets
`HC_SERVER_PROVE_DISPATCH=shared`.

Run the focused cutover smoke test immediately before and after the flip:

```sh
TINYZKP_SMOKE_API=https://api.tinyzkp.com \
TINYZKP_SMOKE_SITE=https://tinyzkp.com \
TINYZKP_SMOKE_API_KEY=tzk_... \
  scripts/monitoring/shared_dispatch_smoke.sh
```

The smoke test must pass in authenticated mode. Public-only mode proves only
that the deployed surfaces are coherent; it does not prove worker dispatch,
usage recording, or proof retrieval.

Add object/blob storage only if proof payload size outgrows the Postgres status
payload. This is the final step before multiple hosts can accept, execute,
poll, download, cancel, and garbage-collect jobs without host affinity.

## Connection abstraction

`crates/hc-server/src/usage_log.rs` defines the `UsageRecorder` trait:

```rust
pub trait UsageRecorder: Send + Sync {
    fn record(&self, tenant_id: &str, job_id: &str, trace_length: usize,
              workload_id: Option<&str>, duration_ms: u64) -> anyhow::Result<()>;
    fn record_verify(&self, tenant_id: &str, duration_ms: u64) -> anyhow::Result<()>;
    fn record_failure(&self, tenant_id: &str, job_id: &str, error: &str,
                      duration_ms: u64) -> anyhow::Result<()>;
}
```

`UsageLog` (existing SQLite) and `PgUsageRecorder` both implement this.
When `HC_SERVER_PG_URL` is set, `hc-server` uses
`DualWriter<Arc<UsageLog>, PgUsageRecorder>` so every prove success, verify,
and prove failure is recorded in SQLite first and mirrored to Postgres.

## Backfill and parity tooling

`billing/usage_pg_tools.py` is the operator tool for this migration:

```sh
# Local SQLite summary.
python3 billing/usage_pg_tools.py summary --source sqlite

# Postgres summary using HC_SERVER_PG_URL.
python3 billing/usage_pg_tools.py summary --source postgres

# Exact parity check, optionally bounded to the dual-write window.
python3 billing/usage_pg_tools.py compare --since-ms "$DUAL_WRITE_START_MS"

# Idempotent historical backfill for successful and failed prove rows.
python3 billing/usage_pg_tools.py backfill --dry-run
python3 billing/usage_pg_tools.py backfill --apply
```

The backfill command intentionally copies only `usage_log` and `failed_proofs`.
Those tables have a semantic `job_id` uniqueness contract, so repeated
backfills are safe via `ON CONFLICT (job_id) DO NOTHING`. `verify_log` has no
semantic event key; compare it after the dual-write boundary instead of
backfilling old rows and risking duplicate verify events.

`billing/tenant_pg_tools.py` is the operator tool for tenant/auth migration:

```sh
# Initialize tenant/auth schema.
python3 billing/tenant_pg_tools.py init

# Summaries and parity checks.
python3 billing/tenant_pg_tools.py summary --source sqlite
python3 billing/tenant_pg_tools.py summary --source postgres
python3 billing/tenant_pg_tools.py compare

# Idempotent historical backfill for tenants, Stripe event ids,
# magic-link rows, and dashboard sessions.
python3 billing/tenant_pg_tools.py backfill --dry-run
python3 billing/tenant_pg_tools.py backfill --apply
```

Tenant rows upsert mutable fields such as plan, status, key hash, and Stripe
IDs. Processed Stripe event IDs are insert-only. Magic links and sessions update
their TTL/used state by token hash.

For ongoing writes, `billing/tenant_store.py` mirrors SQLite mutations to
Postgres when `HC_TENANT_PG_URL` is set (or falls back to
`HC_SERVER_AUTH_PG_URL`). The mirror is fail-open by default for rollout safety;
set `HC_TENANT_PG_REQUIRED=1` during/after the auth read cutover.

## What's deferred

- Production enablement of Postgres reads and Stripe sync. The code paths are
  implemented, but SQLite remains the source of truth until parity has been
  observed through the dual-write window and operators flip
  `HC_SERVER_USAGE_READ_FROM=postgres` plus `HC_USAGE_SOURCE=postgres`.
- Production enablement of Postgres tenant/auth reads. The API/MCP read path,
  billing-webhook write mirror, and backfill/compare tooling are implemented,
  but operators still need to initialize `tenant_auth_pg.sql`, run
  `tenant_pg_tools.py compare`, set `HC_TENANT_PG_URL` on the billing webhook,
  then set `HC_SERVER_AUTH_PG_URL` in both services and rehearse rollback.
- Production enablement of the Postgres job index. The code path is
  implemented, but operators still need to flip
  `HC_SERVER_JOB_INDEX_SOURCE=postgres` after a deployment smoke test.
- Production enablement of the shared worker-dispatch loop. The code path is
  implemented, but multi-host proving is not production-grade until operators
  run `HC_SERVER_PROVE_DISPATCH=shared` with `hc-job-worker`, observe successful
  claims/completions/cancellations, and rehearse rollback to local dispatch.

## Operational notes

- Phase 1 connection model: one synchronous Postgres client per `hc-server`
  process behind a mutex. This is acceptable for low-volume mirror writes;
  move to a real async pool before Postgres becomes the read/write primary.
- Statement timeout: default `5s` matches our SQLite `busy_timeout` —
  keeps consistent timing characteristics across Phase 1.
- Backups: managed Postgres providers handle this. Self-hosted needs
  pg_dump nightly + WAL archiving for PITR.
- Connection limits: Phase 1 is one Postgres connection per `hc-server`
  process. For Phase 2/3, size the future async pool deliberately; for example,
  four server processes with a 10-connection max plus cron/admin access still
  fits comfortably under a typical managed Postgres 100-connection default.
