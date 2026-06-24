use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use native_tls::TlsConnector;
use postgres::{Client, NoTls};
use postgres_native_tls::MakeTlsConnector;

use crate::usage_log::PgTlsMode;

const WINDOW_MS: u64 = 60_000;

const PG_RATE_LIMIT_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS rate_limit_windows (
  tenant_id       TEXT   NOT NULL,
  endpoint        TEXT   NOT NULL,
  window_start_ms BIGINT NOT NULL,
  count           BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, endpoint)
);
"#;

const PG_CHECK_AND_INCREMENT_SQL: &str = r#"
INSERT INTO rate_limit_windows (tenant_id, endpoint, window_start_ms, count)
VALUES ($1, $2, $3, 1)
ON CONFLICT (tenant_id, endpoint) DO UPDATE SET
  window_start_ms = CASE
    WHEN rate_limit_windows.window_start_ms = EXCLUDED.window_start_ms
    THEN rate_limit_windows.window_start_ms
    ELSE EXCLUDED.window_start_ms
  END,
  count = CASE
    WHEN rate_limit_windows.window_start_ms = EXCLUDED.window_start_ms
    THEN rate_limit_windows.count + 1
    ELSE 1
  END
WHERE
  rate_limit_windows.window_start_ms <> EXCLUDED.window_start_ms
  OR rate_limit_windows.count < $4
RETURNING count;
"#;

const PG_REMAINING_SQL: &str = r#"
SELECT window_start_ms, count
FROM rate_limit_windows
WHERE tenant_id = $1 AND endpoint = $2
"#;

/// Postgres-backed fixed-window rate limiter shared by hc-server and hc-mcp.
///
/// The default deployment still uses in-process counters. When operators set
/// `HC_RATE_LIMIT_PG_URL` in both processes, authenticated HTTP and MCP
/// requests burn the same per-tenant window and a multi-process deployment no
/// longer multiplies customer quota by the number of workers.
pub struct SharedRateLimiter {
    client: Mutex<Client>,
}

impl SharedRateLimiter {
    pub fn connect(url: &str, tls_mode: PgTlsMode) -> anyhow::Result<Self> {
        let mut client = match tls_mode {
            PgTlsMode::Disable => {
                Client::connect(url, NoTls).context("connect postgres shared rate limiter")?
            }
            PgTlsMode::Require => {
                let connector = TlsConnector::builder()
                    .build()
                    .context("build native TLS connector for postgres shared rate limiter")?;
                Client::connect(url, MakeTlsConnector::new(connector))
                    .context("connect postgres shared rate limiter")?
            }
        };
        client
            .batch_execute(PG_RATE_LIMIT_SCHEMA_SQL)
            .context("initialize postgres shared rate limit schema")?;
        client
            .batch_execute("SET statement_timeout = '2s'")
            .context("set postgres shared rate limit statement_timeout")?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    pub fn check_and_increment(
        &self,
        tenant_id: &str,
        endpoint: &str,
        limit_per_minute: u32,
    ) -> anyhow::Result<bool> {
        if limit_per_minute == 0 {
            return Ok(true);
        }
        let now_window = current_window_start_ms() as i64;
        let limit = i64::from(limit_per_minute);
        let mut client = self.lock_client()?;
        let rows = client.query(
            PG_CHECK_AND_INCREMENT_SQL,
            &[&tenant_id, &endpoint, &now_window, &limit],
        )?;
        Ok(!rows.is_empty())
    }

    pub fn remaining(
        &self,
        tenant_id: &str,
        endpoint: &str,
        limit_per_minute: u32,
    ) -> anyhow::Result<u32> {
        if limit_per_minute == 0 {
            return Ok(u32::MAX);
        }
        let now_window = current_window_start_ms() as i64;
        let mut client = self.lock_client()?;
        let Some(row) = client
            .query_opt(PG_REMAINING_SQL, &[&tenant_id, &endpoint])
            .context("query postgres shared rate limit window")?
        else {
            return Ok(limit_per_minute);
        };
        let window_start: i64 = row.get(0);
        if window_start != now_window {
            return Ok(limit_per_minute);
        }
        let count: i64 = row.get(1);
        Ok(limit_per_minute.saturating_sub(count.max(0) as u32))
    }

    fn lock_client(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Client>> {
        self.client
            .lock()
            .map_err(|_| anyhow::anyhow!("postgres shared rate limiter lock poisoned"))
    }
}

pub fn endpoint_name(endpoint: &str) -> &str {
    match endpoint {
        "verify" => "verify",
        _ => "prove",
    }
}

fn current_window_start_ms() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    (now_ms / WINDOW_MS) * WINDOW_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_sql_enforces_limit_in_postgres() {
        assert!(PG_RATE_LIMIT_SCHEMA_SQL.contains("PRIMARY KEY (tenant_id, endpoint)"));
        assert!(PG_CHECK_AND_INCREMENT_SQL.contains("rate_limit_windows.count < $4"));
        assert!(PG_CHECK_AND_INCREMENT_SQL.contains("RETURNING count"));
    }

    #[test]
    fn endpoint_name_shares_mcp_with_prove_quota() {
        assert_eq!(endpoint_name("mcp"), "prove");
        assert_eq!(endpoint_name("prove"), "prove");
        assert_eq!(endpoint_name("verify"), "verify");
    }
}
