-- Free API keys for the hosted estimator (Task 5) and their own keyed
-- rate-limit counter.
--
-- `estimator_keys` stores only a SHA-256 hash of the opaque bearer key
-- `POST /v1/keys` mints (`site/_worker.js`'s `keysResponse`) -- never the
-- key itself, and never an email address. There is deliberately no email
-- column, and no separate email table either: `POST /v1/keys` only
-- validates that the submitted address is shaped like an email before
-- minting, then discards it. Nothing in this repo persists it. This is a
-- considered choice, not an oversight -- there is no account, password,
-- confirmation flow, lost-key recovery flow, or abuse-notification flow
-- that would need a way to reach the caller, and the kill-criterion this
-- table exists to feed (`scripts/ci/demand_report.py`) only needs to count
-- distinct organizations, not contact them. Storing an email with no
-- present use would be pure liability. See the Task 5 report for the full
-- reasoning.
--
-- `key_id` is a second, independently-random opaque identifier minted
-- alongside the key (not derived from it, and not derived from
-- `key_hash`): it is what `demand_log.key_id` (migrations/0001_demand_log.sql)
-- and `keyed_rate_limit_windows.key_id` below both use, so neither of
-- those tables' rows are traceable back to the raw key or `key_hash` by
-- anyone who only has read access to them.
--
-- `minted_at_hour` is unix seconds truncated to the top of the hour --
-- coarse, like every other timestamp this worker stores -- kept only for
-- ordinary operational visibility (e.g. mint-rate over time), not identity.
-- `revoked` exists so a key can be disabled later without a schema change;
-- nothing in Task 5 sets it, and no revocation endpoint exists yet.
CREATE TABLE IF NOT EXISTS estimator_keys (
  key_id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL UNIQUE,
  minted_at_hour INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS estimator_keys_key_hash_idx
  ON estimator_keys (key_hash);

-- Per-key fixed-window rate limiting, structurally identical to
-- migrations/0000_rate_limit_windows.sql's per-IP table but keyed on the
-- caller's `key_id` instead of a salted IP hash -- a keyed caller's raised
-- ceiling must never share a bucket, or be confused, with anonymous
-- IP-based limiting.
CREATE TABLE IF NOT EXISTS keyed_rate_limit_windows (
  key_id TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_id, window_start)
);

CREATE INDEX IF NOT EXISTS keyed_rate_limit_windows_window_start_idx
  ON keyed_rate_limit_windows (window_start);
