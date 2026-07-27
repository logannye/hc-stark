-- Per-IP fixed-window rate limiting for `POST /v1/estimate` (Task 3).
--
-- `ip_hash` is HMAC-SHA256(IP_HASH_SALT, CF-Connecting-IP) computed in
-- `site/_worker.js` -- the raw client IP is never written to D1, only this
-- salted hash. `window_start` is the start of a fixed one-hour window (unix
-- seconds, truncated to the hour). `(ip_hash, window_start)` is the primary
-- key so a single `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING
-- request_count` both creates and increments a window's counter atomically.
--
-- This table intentionally has no foreign key to `demand_log`: rate
-- limiting and demand logging are independent concerns that merely happen
-- to share one D1 database and binding.
CREATE TABLE IF NOT EXISTS rate_limit_windows (
  ip_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip_hash, window_start)
);

-- Supports opportunistic cleanup of expired windows by `window_start` alone
-- (the primary key is only useful when `ip_hash` is also known).
CREATE INDEX IF NOT EXISTS rate_limit_windows_window_start_idx
  ON rate_limit_windows (window_start);
