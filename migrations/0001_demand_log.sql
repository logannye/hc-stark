-- Shape-only demand log for `POST /v1/estimate` (Task 4). This is the
-- deliverable that starts the 90-day kill-criterion clock: see
-- `scripts/ci/demand_report.py` for the report this table feeds.
--
-- Every column below describes the SHAPE of a request the engine already
-- accepted and estimated (an `EstimateResponseV1`, never the error
-- envelope). This table must NEVER contain: a raw request body, a raw IP
-- address, an email, a path, an AIR, or a witness.
--
-- Bucket boundaries (chosen so no column can reconstruct an exact value):
--
--   trace_width_bucket: `EstimateRequestV1.trace_width` is valid on
--   [1, 256] (`MAX_TRACE_WIDTH` in crates/tinyzkp-contracts). Bucketed into
--   8 fixed 32-wide bands: "1-32", "33-64", "65-96", "97-128", "129-160",
--   "161-192", "193-224", "225-256". Each band collapses 32 distinct exact
--   widths into one label.
--
--   logical_rows_bucket: `EstimateRequestV1.logical_rows` is only ever a
--   power of two on [2^10, 2^24] (`MIN_ROWS`/`MAX_ROWS`). Rather than store
--   the exact exponent (which, since the domain is already restricted to
--   powers of two, would be equivalent to storing the exact row count),
--   this buckets the exponent into 4 wide bands: "2^10-2^13", "2^14-2^17",
--   "2^18-2^21", "2^22-2^24". Each band still collapses at least 3 distinct
--   exact row counts into one label.
--
--   observed_at_hour: unix seconds truncated to the top of the hour -- a
--   coarse timestamp, never a precise one.
--
-- Exactly one of `key_id` / `anon_ip_hash` is populated per row (never
-- both, never neither): `key_id` identifies a keyed organization (Task 5's
-- free keys; this column exists now so the schema does not need a second
-- migration when that ships, but every row written before Task 5 leaves it
-- NULL). `anon_ip_hash` is the same salted `CF-Connecting-IP` hash the rate
-- limiter computes (see migrations/0000_rate_limit_windows.sql) and is only
-- an APPROXIMATE proxy for a distinct anonymous source: NAT and rotating
-- IPs mean it both over- and under-counts distinct callers. This is exactly
-- why `scripts/ci/demand_report.py` reports keyed-organization and
-- anonymous-source counts separately and never sums them.
CREATE TABLE IF NOT EXISTS demand_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at_hour INTEGER NOT NULL,
  request_digest TEXT,
  field TEXT,
  extension_degree INTEGER,
  trace_width_bucket TEXT,
  logical_rows_bucket TEXT,
  uses_lookups INTEGER,
  uses_buses INTEGER,
  uses_permutations INTEGER,
  uses_multi_table INTEGER,
  uses_preprocessed_columns INTEGER,
  uses_periodic_columns INTEGER,
  uses_recursion INTEGER,
  uses_gpu INTEGER,
  provable_today INTEGER,
  blocking_reason_codes TEXT,
  key_id TEXT,
  anon_ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS demand_log_observed_at_hour_idx
  ON demand_log (observed_at_hour);
