//! DB-backed auth fallback.
//!
//! Provides `DbAuthSource`, which looks up the SHA-256 of a presented
//! Bearer token against a `tenants` table. The original backend is
//! `tenant_store.sqlite` (managed by the billing webhook); production
//! scale cutovers can use the same table shape in Postgres. Used as a
//! fallback when an API key is not present in `AuthConfig.keys` —
//! typically because it was provisioned in the last 60s and the
//! file-based hot-reload hasn't caught up yet, or because operators are
//! cutting auth over to shared Postgres state.
//!
//! Off by default. Enabled via `AuthConfig::with_db_source` from
//! `lib.rs` when `HC_SERVER_AUTH_DB_PATH` or `HC_SERVER_AUTH_PG_URL` is
//! set. The original file + env source remains primary; the DB source is
//! consulted only on miss.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use native_tls::TlsConnector;
use postgres::{Client, NoTls};
use postgres_native_tls::MakeTlsConnector;
use rusqlite::{Connection, OpenFlags};

use crate::usage_log::PgTlsMode;

use super::TenantEntry;

/// Postgres schema for shared tenant/auth state. This mirrors
/// `billing/tenant_store.py` closely enough for auth, account sessions,
/// magic links, Stripe event idempotency, and later billing cutover tooling.
pub const PG_TENANT_AUTH_SCHEMA_SQL: &str = include_str!("../../sql/tenant_auth_pg.sql");

/// Cache TTL: matches the file-based hot-reload interval. After 60s a
/// cached entry is re-validated against the DB; status changes (suspend,
/// rotate) take effect at most 60s after the writer commits, with the
/// auth path holding only momentary stale data.
const CACHE_TTL_MS: u64 = 60_000;

/// Cap on positive-cache size. With one entry per tenant, even an
/// installation with thousands of active keys per minute fits well
/// within this — and the eviction path below is O(N) over expired
/// entries when full, which is fine at this scale.
const CACHE_MAX_ENTRIES: usize = 4096;

struct CacheEntry {
    entry: TenantEntry,
    expiry_ms: u64,
}

pub struct DbAuthSource {
    /// One connection guarded by a Mutex. Auth-path lookups normally hit
    /// the cache; the DB is only touched on miss (new keys, evictions).
    /// At expected miss rates (<100/s) the mutex is uncontended.
    backend: DbAuthBackend,
    /// Positive-only TTL cache, keyed by the SHA-256 of the bearer
    /// token. Negatives are NOT cached so that a freshly-provisioned
    /// key starts working on first request, not after the next eviction.
    cache: Mutex<HashMap<[u8; 32], CacheEntry>>,
    /// Retained for diagnostics/logging. Not required for runtime.
    #[allow(dead_code)]
    source_label: String,
}

enum DbAuthBackend {
    Sqlite(Mutex<Connection>),
    Postgres(Box<Mutex<Client>>),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl DbAuthSource {
    /// Open a SQLite tenant store read-only. Verifies the `tenants`
    /// table exposes the columns we need; refuses to start otherwise so
    /// schema drift is caught at boot, not at the first auth attempt.
    pub fn open(path: &Path) -> anyhow::Result<Arc<Self>> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| anyhow::anyhow!("open tenant_store at {}: {e}", path.display()))?;

        // Schema sanity: column presence + types we read. A cheap pragma
        // avoids surprises if the webhook ever renames a column.
        let mut required = ["tenant_id", "api_key_hash", "status", "plan"]
            .iter()
            .map(|c| (*c, false))
            .collect::<HashMap<_, _>>();
        let mut stmt = conn.prepare("PRAGMA table_info(tenants)")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let name: String = r.get(1)?;
            if let Some(seen) = required.get_mut(name.as_str()) {
                *seen = true;
            }
        }
        for (col, seen) in &required {
            if !*seen {
                anyhow::bail!(
                    "tenant_store schema missing column `{col}` — refusing to enable DB auth fallback"
                );
            }
        }
        drop(rows);
        drop(stmt);

        Ok(Arc::new(Self {
            backend: DbAuthBackend::Sqlite(Mutex::new(conn)),
            cache: Mutex::new(HashMap::new()),
            source_label: path.display().to_string(),
        }))
    }

    /// Open a Postgres tenant auth source. Initializes the schema if needed
    /// and verifies the `tenants` table exposes the columns the auth path
    /// requires.
    pub fn connect_postgres(url: &str, tls_mode: PgTlsMode) -> anyhow::Result<Arc<Self>> {
        let mut client = match tls_mode {
            PgTlsMode::Disable => Client::connect(url, NoTls)
                .map_err(|e| anyhow::anyhow!("connect postgres tenant auth source: {e}"))?,
            PgTlsMode::Require => {
                let connector = TlsConnector::builder().build().map_err(|e| {
                    anyhow::anyhow!("build native TLS connector for tenant auth: {e}")
                })?;
                Client::connect(url, MakeTlsConnector::new(connector))
                    .map_err(|e| anyhow::anyhow!("connect postgres tenant auth source: {e}"))?
            }
        };
        client
            .batch_execute(PG_TENANT_AUTH_SCHEMA_SQL)
            .map_err(|e| anyhow::anyhow!("initialize postgres tenant auth schema: {e}"))?;
        client
            .batch_execute("SET statement_timeout = '2s';")
            .map_err(|e| anyhow::anyhow!("set postgres tenant auth statement_timeout: {e}"))?;

        let missing: Vec<String> = client
            .query(
                "SELECT c FROM (
                   VALUES ('tenant_id'), ('api_key_hash'), ('status'), ('plan')
                 ) AS required(c)
                 WHERE NOT EXISTS (
                   SELECT 1
                   FROM information_schema.columns
                   WHERE table_schema = current_schema()
                     AND table_name = 'tenants'
                     AND column_name = required.c
                 )",
                &[],
            )
            .map_err(|e| anyhow::anyhow!("inspect postgres tenant auth schema: {e}"))?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "postgres tenant auth schema missing required columns: {}",
                missing.join(", ")
            );
        }

        Ok(Arc::new(Self {
            backend: DbAuthBackend::Postgres(Box::new(Mutex::new(client))),
            cache: Mutex::new(HashMap::new()),
            source_label: "postgres".to_string(),
        }))
    }

    /// Look up a tenant by SHA-256 of the presented Bearer token (raw 32
    /// bytes). Returns `None` if the hash is unknown, the tenant is not
    /// `active`, or the lookup fails (logged, not raised — auth must
    /// still reject cleanly).
    pub(crate) fn lookup(&self, hash: &[u8; 32]) -> Option<TenantEntry> {
        let now = now_ms();

        // Cache hit?
        if let Ok(cache) = self.cache.lock() {
            if let Some(c) = cache.get(hash) {
                if c.expiry_ms > now {
                    return Some(c.entry.clone());
                }
            }
        }

        // Cache miss → DB. Hex-encode for the comparison since
        // tenant_store stores `sha256(api_key).hexdigest()`.
        let hex_hash = hex::encode(hash);
        let entry = match self.query_active_tenant(&hex_hash) {
            Ok(opt) => opt,
            Err(e) => {
                tracing::warn!(error = %e, "DB auth fallback query failed");
                return None;
            }
        };

        if let Some(ref entry) = entry {
            self.insert_cache(*hash, entry.clone(), now + CACHE_TTL_MS);
        }
        entry
    }

    fn query_active_tenant(&self, hex_hash: &str) -> anyhow::Result<Option<TenantEntry>> {
        match &self.backend {
            DbAuthBackend::Sqlite(conn) => {
                let conn = conn.lock().expect("auth db mutex");
                let mut stmt = conn.prepare_cached(
                    "SELECT tenant_id, plan FROM tenants WHERE api_key_hash = ?1 AND status = 'active'",
                )?;
                let mut rows = stmt.query([hex_hash])?;
                if let Some(row) = rows.next()? {
                    let tenant_id: String = row.get(0)?;
                    let plan: String = row.get(1)?;
                    Ok(Some(TenantEntry { tenant_id, plan }))
                } else {
                    Ok(None)
                }
            }
            DbAuthBackend::Postgres(client) => {
                let mut client = client
                    .lock()
                    .map_err(|_| anyhow::anyhow!("tenant auth postgres mutex poisoned"))?;
                let row = client.query_opt(
                    "SELECT tenant_id, plan FROM tenants WHERE api_key_hash = $1 AND status = 'active'",
                    &[&hex_hash],
                )?;
                Ok(row.map(|row| TenantEntry {
                    tenant_id: row.get(0),
                    plan: row.get(1),
                }))
            }
        }
    }

    fn insert_cache(&self, hash: [u8; 32], entry: TenantEntry, expiry_ms: u64) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        // Bounded: when full, drop expired entries first; if still full,
        // skip the insert. Auth correctness doesn't depend on caching —
        // this just protects memory under unexpected key churn.
        if cache.len() >= CACHE_MAX_ENTRIES {
            let now = now_ms();
            cache.retain(|_, c| c.expiry_ms > now);
            if cache.len() >= CACHE_MAX_ENTRIES {
                return;
            }
        }
        cache.insert(hash, CacheEntry { entry, expiry_ms });
    }
}
