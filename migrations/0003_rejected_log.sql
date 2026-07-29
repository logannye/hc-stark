-- Rejected-request counter for `POST /v1/estimate`.
--
-- `demand_log` (migrations/0001_demand_log.sql) only records requests the
-- engine ACCEPTED and estimated: `logDemand` returns early unless the
-- response carries `provable_today` and `estimates`. Everything else --
-- malformed JSON, a body over the size cap, a manifest that fails the
-- contract -- was dropped and counted nowhere.
--
-- That is a measurement bias in the one metric a business decision depends
-- on. Someone wiring up an integration and getting the request shape wrong
-- is among the strongest available signals that a caller wanted this tool,
-- and under the previous behaviour they were indistinguishable from silence.
-- `scripts/ci/demand_report.py` now reports these counts, SEPARATELY and
-- never summed into any demand figure -- a rejected request is evidence of
-- interest, not evidence of a served need.
--
-- This table is deliberately narrower than `demand_log`. A malformed body is
-- precisely where a witness, a path, or a secret is most likely to appear, so
-- nothing derived from the body is stored: not the body, not a digest of it,
-- not its length, not the field it declared. Only the hour, the engine's own
-- reason code (a closed vocabulary from `ReasonV1`), and the same
-- mutually-exclusive caller columns the other tables use.
CREATE TABLE IF NOT EXISTS rejected_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at_hour INTEGER NOT NULL,
  reason_code TEXT,
  key_id TEXT,
  anon_ip_hash TEXT
);

CREATE INDEX IF NOT EXISTS rejected_log_observed_at_hour_idx
  ON rejected_log (observed_at_hour);
