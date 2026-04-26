use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, StatusCode};

#[derive(Clone, Debug)]
pub struct TenantContext {
    pub tenant_id: String,
    pub plan: String,
}

#[derive(Clone, Debug)]
struct TenantEntry {
    tenant_id: String,
    plan: String,
}

#[derive(Clone, Debug, Default)]
pub struct AuthConfig {
    /// Maps active API key -> (tenant_id, plan).
    keys: HashMap<String, TenantEntry>,
    /// Recently-rotated keys that should still authenticate during the
    /// grace window. Maps key -> (entry, expiry_ms_unix). Authentication
    /// falls through to this map only if `keys` does not contain the
    /// presented token. Entries past their expiry are ignored and pruned
    /// opportunistically on each `authenticate` call.
    retired: HashMap<String, RetiredEntry>,
}

/// Default grace window for retired keys: 5 minutes. Long enough to drain
/// in-flight requests after a rotation, short enough that a leaked key
/// stops working quickly. Override via `HC_SERVER_AUTH_GRACE_MS`.
pub const DEFAULT_AUTH_GRACE_MS: u64 = 5 * 60 * 1000;

#[derive(Clone, Debug)]
struct RetiredEntry {
    entry: TenantEntry,
    expiry_ms: u64,
}

/// Per-IP auth failure tracking for brute-force protection.
#[derive(Clone)]
pub struct AuthGuard {
    /// IP -> (failure_count, first_failure_ms, lockout_until_ms)
    failures: Arc<Mutex<HashMap<String, AuthFailureState>>>,
    /// Max failures before lockout.
    max_failures: u32,
    /// Lockout duration in milliseconds.
    lockout_ms: u64,
    /// Window for counting failures (ms). Failures older than this are forgotten.
    window_ms: u64,
    /// Max entries before eviction of stale records.
    max_entries: usize,
}

#[derive(Clone, Debug)]
struct AuthFailureState {
    count: u32,
    window_start_ms: u64,
    lockout_until_ms: u64,
}

impl Default for AuthGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthGuard {
    pub fn new() -> Self {
        Self {
            failures: Arc::new(Mutex::new(HashMap::new())),
            max_failures: 10,   // 10 failures per window
            lockout_ms: 60_000, // 1 minute lockout
            window_ms: 300_000, // 5 minute window
            max_entries: 50_000,
        }
    }

    /// Check if an IP is currently locked out. Returns true if the request should be rejected.
    pub fn is_locked_out(&self, ip: &str) -> bool {
        let now_ms = now_ms();
        let map = self.failures.lock().expect("auth guard lock");
        if let Some(state) = map.get(ip) {
            if now_ms < state.lockout_until_ms {
                return true;
            }
        }
        false
    }

    /// Record an auth failure for an IP. Returns true if the IP is now locked out.
    pub fn record_failure(&self, ip: &str) -> bool {
        let now_ms = now_ms();
        let mut map = self.failures.lock().expect("auth guard lock");

        // Evict stale entries when map grows too large.
        if map.len() > self.max_entries {
            let cutoff = now_ms.saturating_sub(self.window_ms + self.lockout_ms);
            map.retain(|_, v| v.window_start_ms > cutoff || v.lockout_until_ms > now_ms);
        }

        let state = map.entry(ip.to_string()).or_insert(AuthFailureState {
            count: 0,
            window_start_ms: now_ms,
            lockout_until_ms: 0,
        });

        // Reset window if expired.
        if now_ms.saturating_sub(state.window_start_ms) > self.window_ms {
            state.count = 0;
            state.window_start_ms = now_ms;
            state.lockout_until_ms = 0;
        }

        state.count += 1;

        if state.count >= self.max_failures {
            state.lockout_until_ms = now_ms + self.lockout_ms;
            return true;
        }
        false
    }

    /// Clear failure state for an IP (on successful auth).
    pub fn clear(&self, ip: &str) {
        let mut map = self.failures.lock().expect("auth guard lock");
        map.remove(ip);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Constant-time comparison to prevent timing attacks on API keys.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl AuthConfig {
    /// Construct an auth config from explicit `(tenant_id, api_key)` pairs.
    ///
    /// This is intended for tests and embedding; production should use `from_env`.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut keys = HashMap::new();
        for (tenant, key) in pairs {
            keys.insert(
                (*key).to_string(),
                TenantEntry {
                    tenant_id: (*tenant).to_string(),
                    plan: "developer".to_string(),
                },
            );
        }
        Self {
            keys,
            ..Default::default()
        }
    }

    /// Construct from pairs with explicit plans.
    pub fn from_pairs_with_plan(pairs: &[(&str, &str, &str)]) -> Self {
        let mut keys = HashMap::new();
        for (tenant, key, plan) in pairs {
            keys.insert(
                (*key).to_string(),
                TenantEntry {
                    tenant_id: (*tenant).to_string(),
                    plan: (*plan).to_string(),
                },
            );
        }
        Self {
            keys,
            ..Default::default()
        }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let raw = std::env::var("HC_SERVER_API_KEYS").unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(Self::default());
        }

        // Format: "tenant1:key1,tenant2:key2" (commas separate entries)
        let mut keys = HashMap::new();
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (tenant, key) = entry.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("invalid HC_SERVER_API_KEYS entry (expected tenant:key): {entry}")
            })?;
            let tenant = tenant.trim();
            let key = key.trim();
            if tenant.is_empty() || key.is_empty() {
                anyhow::bail!("invalid HC_SERVER_API_KEYS entry (empty tenant/key): {entry}");
            }
            keys.insert(
                key.to_string(),
                TenantEntry {
                    tenant_id: tenant.to_string(),
                    plan: "developer".to_string(),
                },
            );
        }
        Ok(Self {
            keys,
            ..Default::default()
        })
    }

    /// Load keys from a file.
    ///
    /// Supports two formats:
    /// - `tenant:key` (plan defaults to "developer")
    /// - `tenant:key:plan`
    ///
    /// Lines starting with `#` are comments.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read api keys file {}: {e}", path.display()))?;
        let mut keys = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            let (tenant, key, plan) = match parts.len() {
                2 => (parts[0].trim(), parts[1].trim(), "developer"),
                3 => (parts[0].trim(), parts[1].trim(), parts[2].trim()),
                _ => {
                    anyhow::bail!(
                        "invalid api keys file entry (expected tenant:key[:plan]): {line}"
                    );
                }
            };
            if tenant.is_empty() || key.is_empty() {
                continue;
            }
            keys.insert(
                key.to_string(),
                TenantEntry {
                    tenant_id: tenant.to_string(),
                    plan: plan.to_string(),
                },
            );
        }
        Ok(Self {
            keys,
            ..Default::default()
        })
    }

    /// Merge another config's keys into this one (additive). Retired
    /// entries from `other` are carried over too — a key that was
    /// retired in either source remains retired in the merge.
    pub fn merge(&mut self, other: &AuthConfig) {
        for (key, entry) in &other.keys {
            self.keys.insert(key.clone(), entry.clone());
        }
        for (key, retired) in &other.retired {
            self.retired.insert(key.clone(), retired.clone());
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Compare this config to a `previous` one (typically the live config
    /// just before a hot-reload swap) and seed retired entries for keys
    /// that were active there but are missing here. The grace window is
    /// `grace_ms` from `now_ms`.
    ///
    /// This is the operator-facing protection against rotation kicking
    /// in-flight requests — a request holding the old key keeps working
    /// for `grace_ms` after the rotation reload.
    ///
    /// If a key is in BOTH the previous active set AND the new active
    /// set (re-issued unchanged), it stays purely active — no grace
    /// entry is created.
    pub fn retire_missing(&mut self, previous: &AuthConfig, grace_ms: u64, now_ms: u64) {
        let expiry = now_ms.saturating_add(grace_ms);
        for (key, prev_entry) in &previous.keys {
            if !self.keys.contains_key(key) {
                self.retired.insert(
                    key.clone(),
                    RetiredEntry {
                        entry: prev_entry.clone(),
                        expiry_ms: expiry,
                    },
                );
            }
        }
        // Carry over still-valid retired entries from the previous config
        // (a key that was retired 30s ago should keep its original expiry,
        // not get its grace window extended).
        for (key, retired) in &previous.retired {
            if !self.keys.contains_key(key) && !self.retired.contains_key(key) {
                self.retired.insert(key.clone(), retired.clone());
            }
        }
        // Drop any retired entries whose grace window has already expired.
        // Without this, the retired map would grow unbounded over many
        // reload cycles.
        self.retired.retain(|_, r| r.expiry_ms > now_ms);
    }

    /// Cardinality of currently-active keys + retired-but-still-valid
    /// keys. Used by tests + observability.
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// Authenticate a request. Uses constant-time comparison to prevent timing attacks.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<TenantContext, (StatusCode, &'static str)> {
        if !self.is_enabled() {
            return Ok(TenantContext {
                tenant_id: "dev".to_string(),
                plan: "developer".to_string(),
            });
        }

        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "missing Authorization header"))?;
        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer token"))?;

        // Constant-time scan over ACTIVE keys: iterate every entry, never
        // early-exit. The match record is set unconditionally; comparing
        // each entry takes the same time whether it's the match or not.
        let mut matched: Option<&TenantEntry> = None;
        for (stored_key, entry) in &self.keys {
            if constant_time_eq(token.as_bytes(), stored_key.as_bytes()) {
                matched = Some(entry);
            }
        }

        if let Some(entry) = matched {
            return Ok(TenantContext {
                tenant_id: entry.tenant_id.clone(),
                plan: entry.plan.clone(),
            });
        }

        // Fallback: scan retired (recently-rotated) keys whose grace
        // window hasn't elapsed. Same constant-time iteration shape so
        // the timing-side-channel posture matches the active-keys path.
        // Skipping this scan when keys.match exists costs us a tiny
        // timing leak between "active-match" and "retired-match" branches;
        // we accept that as a reasonable trade since retired matches are
        // already log-warned (operator visibility on grace usage).
        let now = now_ms();
        let mut retired_matched: Option<&TenantEntry> = None;
        for (stored_key, retired) in &self.retired {
            // Only honor the match if the grace window hasn't expired.
            // Comparing the key still happens to keep iteration shape
            // uniform — the expiry filter is applied AFTER the compare.
            let key_eq = constant_time_eq(token.as_bytes(), stored_key.as_bytes());
            if key_eq && retired.expiry_ms > now {
                retired_matched = Some(&retired.entry);
            }
        }

        if let Some(entry) = retired_matched {
            tracing::warn!(
                tenant_id = %entry.tenant_id,
                "authenticated via grace-window retired key — operator should rotate the holder soon"
            );
            return Ok(TenantContext {
                tenant_id: entry.tenant_id.clone(),
                plan: entry.plan.clone(),
            });
        }

        Err((StatusCode::UNAUTHORIZED, "invalid API key"))
    }
}

#[cfg(test)]
mod grace_window_tests {
    use super::*;
    use axum::http::HeaderValue;

    fn auth_with(pairs: &[(&str, &str)]) -> AuthConfig {
        AuthConfig::from_pairs(pairs)
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[test]
    fn retire_missing_seeds_grace_for_removed_keys() {
        let prev = auth_with(&[("acme", "key_a"), ("beta", "key_b")]);
        let mut next = auth_with(&[("acme", "key_a")]); // key_b rotated out
        next.retire_missing(&prev, 60_000, 1_000_000);

        assert_eq!(next.retired_len(), 1);
        // key_a stays purely active — it's in both prev and next.
        assert!(next.keys.contains_key("key_a"));
        // key_b is now retired with grace.
        let r = next.retired.get("key_b").expect("key_b retired");
        assert_eq!(r.entry.tenant_id, "beta");
        assert_eq!(r.expiry_ms, 1_060_000);
    }

    #[test]
    fn retired_key_authenticates_within_grace_window() {
        let prev = auth_with(&[("acme", "old_key")]);
        let mut next = auth_with(&[("acme", "new_key")]);
        let now = now_ms();
        next.retire_missing(&prev, 5 * 60 * 1000, now);

        // Old key still works — it's in the grace window.
        let result = next.authenticate(&bearer_headers("old_key"));
        let tenant = result.expect("retired key should still authenticate");
        assert_eq!(tenant.tenant_id, "acme");

        // New key works too.
        let result2 = next.authenticate(&bearer_headers("new_key"));
        assert_eq!(result2.unwrap().tenant_id, "acme");
    }

    #[test]
    fn retired_key_rejected_after_grace_expires() {
        let prev = auth_with(&[("acme", "old_key")]);
        let mut next = auth_with(&[("acme", "new_key")]);
        // Insert a grace entry whose expiry is already in the past.
        next.retire_missing(&prev, 0, now_ms().saturating_sub(60_000));

        let result = next.authenticate(&bearer_headers("old_key"));
        assert!(result.is_err(), "expired retired key must not authenticate");
    }

    #[test]
    fn retire_missing_preserves_carryover_grace_expiry() {
        // A key was retired 30s ago with a 5min window. It should keep
        // its original expiry, not get a fresh window.
        let now = 1_000_000_u64;
        let original_expiry = now + 4 * 60 * 1000 + 30_000;

        let mut prev = auth_with(&[("acme", "current")]);
        prev.retired.insert(
            "old_key".to_string(),
            RetiredEntry {
                entry: TenantEntry {
                    tenant_id: "acme".to_string(),
                    plan: "developer".to_string(),
                },
                expiry_ms: original_expiry,
            },
        );

        let mut next = auth_with(&[("acme", "current")]);
        next.retire_missing(&prev, 60_000, now);

        let carried = next.retired.get("old_key").expect("retired key carried");
        // Expiry should match the prev's value, not now+grace_ms.
        assert_eq!(carried.expiry_ms, original_expiry);
    }

    #[test]
    fn unknown_key_still_rejected_with_grace_active() {
        let prev = auth_with(&[("acme", "old_key")]);
        let mut next = auth_with(&[("acme", "new_key")]);
        next.retire_missing(&prev, 5 * 60 * 1000, now_ms());

        let result = next.authenticate(&bearer_headers("totally_random_token"));
        assert!(result.is_err());
    }

    #[test]
    fn retire_missing_prunes_already_expired_entries() {
        // Verifies the prune-on-reload path: an expired retired entry
        // from previous shouldn't leak into next.retired.
        let now = 1_000_000_u64;
        let expired = now.saturating_sub(1);

        let mut prev = auth_with(&[("acme", "current")]);
        prev.retired.insert(
            "stale_key".to_string(),
            RetiredEntry {
                entry: TenantEntry {
                    tenant_id: "acme".to_string(),
                    plan: "developer".to_string(),
                },
                expiry_ms: expired,
            },
        );

        let mut next = auth_with(&[("acme", "current")]);
        next.retire_missing(&prev, 60_000, now);

        assert!(
            !next.retired.contains_key("stale_key"),
            "expired retired entries should be pruned during reload"
        );
    }
}
