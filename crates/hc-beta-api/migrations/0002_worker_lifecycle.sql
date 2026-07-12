ALTER TABLE beta_workers
    ADD COLUMN IF NOT EXISTS draining BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS draining_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS beta_workers_claimable_idx
    ON beta_workers (release_sha, last_heartbeat_at)
    WHERE enabled AND NOT draining;
