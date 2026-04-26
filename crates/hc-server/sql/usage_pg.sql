-- Postgres schema for hc-server usage and verify logs.
-- Mirrors crates/hc-server/src/usage_log.rs:UsageLog::open() with the
-- mechanical sqlite-to-postgres translations:
--   INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL PRIMARY KEY
--   INTEGER millis-since-epoch         ->  TIMESTAMPTZ (kept as ms for
--                                          parity during dual-write phase;
--                                          a follow-up commit can switch
--                                          to TIMESTAMPTZ once Phase 2
--                                          read-side cuts over)
--   INSERT OR IGNORE                   ->  ON CONFLICT DO NOTHING
--
-- See docs/postgres_migration.md for the full migration plan.

BEGIN;

CREATE TABLE IF NOT EXISTS usage_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT      NOT NULL,
    job_id          TEXT      NOT NULL UNIQUE,
    trace_length    BIGINT    NOT NULL,
    workload_id     TEXT,
    duration_ms     BIGINT    NOT NULL,
    completed_at_ms BIGINT    NOT NULL,
    billed          INTEGER   NOT NULL DEFAULT 0
);

-- Mirrors `idx_usage_unbilled` (partial index on unbilled rows). The
-- billing cron scans this index on every run; sized to be cheap at
-- millions-of-rows scale.
CREATE INDEX IF NOT EXISTS idx_usage_unbilled
    ON usage_log (billed, tenant_id)
    WHERE billed = 0;

-- Mirrors `idx_usage_tenant_time`. Used by /usage handler to slice
-- per-tenant history.
CREATE INDEX IF NOT EXISTS idx_usage_tenant_time
    ON usage_log (tenant_id, completed_at_ms);

CREATE TABLE IF NOT EXISTS verify_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT      NOT NULL,
    duration_ms     BIGINT    NOT NULL,
    completed_at_ms BIGINT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verify_tenant_time
    ON verify_log (tenant_id, completed_at_ms);

CREATE TABLE IF NOT EXISTS failed_proofs (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT      NOT NULL,
    job_id       TEXT      NOT NULL UNIQUE,
    error        TEXT      NOT NULL,
    duration_ms  BIGINT    NOT NULL,
    failed_at_ms BIGINT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_failed_tenant_time
    ON failed_proofs (tenant_id, failed_at_ms);

COMMIT;

-- Verify with: \dt
-- Reset (test environments only): DROP TABLE usage_log, verify_log, failed_proofs CASCADE;
