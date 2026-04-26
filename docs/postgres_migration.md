# Postgres migration plan

> **Status**: planning + scaffolding committed; live dual-write deferred until
> an operator provisions a managed Postgres (Hetzner managed PG, RDS, Neon,
> etc.). This document is the contract for that work — when Postgres is
> ready, the steps below should be the only checklist needed.

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

This migration moves *operational state* (jobs, usage, billing) to Postgres.
It does **NOT** move:

- Job artifacts on disk (`data/jobs/<tenant>/<id>/proof.json`, request.json).
  Stays on the local filesystem; per-host. A future commit can move these
  to S3-class blob storage when multi-host becomes real.
- Cryptographic primitives or proof bytes themselves.
- The `tenant_store.sqlite` (Stripe customer/subscription state) — that
  stays in the billing/ Python world for now since the Python tooling reads
  it directly.

## Schema

The Postgres schema mirrors the SQLite shape with three caveats:

1. `id INTEGER PRIMARY KEY AUTOINCREMENT` → `id BIGSERIAL PRIMARY KEY`.
2. `INTEGER` storage of millisecond timestamps → `TIMESTAMPTZ` with
   millisecond precision. Migration helper converts on read.
3. `INSERT OR IGNORE` (SQLite) → `ON CONFLICT DO NOTHING` (Postgres).

See [`crates/hc-server/sql/usage_pg.sql`](../crates/hc-server/sql/usage_pg.sql)
for the exact DDL — runnable today against any Postgres 14+.

## Dual-write strategy (recommended path)

The migration runs in 4 phases. Each phase is reversible — backing out
just means dropping the env var.

### Phase 0 — Provision (operator)

```sh
# Provision PG (managed or self-hosted), TLS to non-public networks.
psql "$HC_SERVER_PG_URL" -f crates/hc-server/sql/usage_pg.sql
```

Verify schema is current:

```sh
psql "$HC_SERVER_PG_URL" -c "\dt"
```

### Phase 1 — Dual-write usage_log (low risk)

Set `HC_SERVER_PG_URL`. `hc-server` writes every `usage_log.record()`,
`record_verify()`, and `record_failure()` to BOTH SQLite (source of
truth) AND Postgres (mirror). Postgres write failures are logged at WARN
but do not fail the request — we are still single-master on SQLite.

Run for a week. Compare row counts daily. If Postgres ever drifts more
than 0.1% behind, alert and investigate.

### Phase 2 — Cutover read-side (medium risk)

The `/usage` HTTP handler reads from Postgres instead of SQLite. SQLite
keeps getting written for one more week as a safety net. Reverting is a
single env-var flip (`HC_SERVER_USAGE_READ_FROM=sqlite`).

### Phase 3 — Cutover write-side + decommission (high risk)

Drop the SQLite usage_log writes. SQLite file is preserved on disk for
rollback but no longer touched. Two weeks of observation, then archive
or delete.

### Phase 4 — Repeat for jobs.sqlite

Same dance for `prove_jobs`. This is more disruptive because the prove
hot-path reads + writes the table on every transition; do it after Phase
3 has been stable.

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

`UsageLog` (existing SQLite) implements this. A future `PgUsageRecorder`
also implements it. A `DualWriter<A, B>` composition wraps two recorders
and forwards each call — used during Phase 1 with `(SqliteWriter, PgWriter)`.

## What's deferred

- The actual `tokio-postgres` (or `sqlx`) dependency. Adding it pulls in
  ~30 transitive crates and an asynchronous database client we don't run
  yet. Add it together with the `PgUsageRecorder` impl when Phase 0 lands.
- A migration tool that backfills SQLite history into Postgres. The
  current proposal is "start fresh on Postgres, don't backfill" —
  acceptable because billing is already squared with Stripe (see
  `billing/sync_usage.py`), so historical usage rows in SQLite are
  already paid up. Operators who want history can run a one-off
  `pg_loader` script reading SQLite via the Python adapter.
- Postgres support in `billing/sync_usage.py`. The cron currently reads
  `usage.sqlite` directly; once Phase 2 cuts the read-side over, the
  cron must read Postgres or the dual-write will be one-sided. Track as
  follow-up: `billing/sync_usage_pg.py`.

## Operational notes

- Pool size: start with `min=2, max=10` for `hc-server`. Workers connect
  through the same pool.
- Statement timeout: default `5s` matches our SQLite `busy_timeout` —
  keeps consistent timing characteristics across Phase 1.
- Backups: managed Postgres providers handle this. Self-hosted needs
  pg_dump nightly + WAL archiving for PITR.
- Connection limits: Postgres default is 100. With 4 hc-server processes
  × 10 conns + 4 workers × 2 conns + cron + admin = ~50, comfortable
  headroom.
