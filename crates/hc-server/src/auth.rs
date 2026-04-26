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
    /// Maps API key -> (tenant_id, plan).
    keys: HashMap<String, TenantEntry>,
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
        Self { keys }
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
        Self { keys }
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
        Ok(Self { keys })
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
        Ok(Self { keys })
    }

    /// Merge another config's keys into this one (additive).
    pub fn merge(&mut self, other: &AuthConfig) {
        for (key, entry) in &other.keys {
            self.keys.insert(key.clone(), entry.clone());
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.keys.is_empty()
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

        // Constant-time scan: check ALL keys to prevent timing leaks.
        // We iterate every key and compare in constant time, collecting the match.
        let mut matched: Option<&TenantEntry> = None;
        for (stored_key, entry) in &self.keys {
            if constant_time_eq(token.as_bytes(), stored_key.as_bytes()) {
                matched = Some(entry);
            }
        }

        let entry = matched.ok_or((StatusCode::UNAUTHORIZED, "invalid API key"))?;
        Ok(TenantContext {
            tenant_id: entry.tenant_id.clone(),
            plan: entry.plan.clone(),
        })
    }
}
