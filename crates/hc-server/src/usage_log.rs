use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use rusqlite::{params, Connection};

/// SQLite usage log for billing.
///
/// Records every completed proof with tenant, trace length, and duration.
/// The `billed` column is updated externally by the billing cron script.
pub struct UsageLog {
    conn: Arc<Mutex<Connection>>,
}

/// Aggregated usage summary for a tenant.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UsageSummary {
    pub total_proofs: u64,
    pub total_verifies: u64,
    pub failed_proofs: u64,
    pub estimated_cost_cents: u64,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
}

impl UsageLog {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(path).context("open usage sqlite")?;
        // 5s busy_timeout: see job_index::open for rationale. usage_log
        // sees roughly one INSERT per completed prove and is read by both
        // the in-process /usage handler and the out-of-process billing
        // cron, so contention is more likely here than on jobs.sqlite.
        conn.busy_timeout(std::time::Duration::from_millis(5_000))
            .context("set usage sqlite busy_timeout")?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS usage_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT NOT NULL,
              job_id TEXT NOT NULL UNIQUE,
              trace_length INTEGER NOT NULL,
              workload_id TEXT,
              duration_ms INTEGER NOT NULL,
              completed_at_ms INTEGER NOT NULL,
              billed INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_usage_unbilled
              ON usage_log(billed, tenant_id) WHERE billed = 0;
            CREATE INDEX IF NOT EXISTS idx_usage_tenant_time
              ON usage_log(tenant_id, completed_at_ms);
            CREATE TABLE IF NOT EXISTS verify_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT NOT NULL,
              duration_ms INTEGER NOT NULL,
              completed_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_verify_tenant_time
              ON verify_log(tenant_id, completed_at_ms);
            CREATE TABLE IF NOT EXISTS failed_proofs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id TEXT NOT NULL,
              job_id TEXT NOT NULL UNIQUE,
              error TEXT NOT NULL,
              duration_ms INTEGER NOT NULL,
              failed_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_failed_tenant_time
              ON failed_proofs(tenant_id, failed_at_ms);
            "#,
        )
        .context("init usage sqlite schema")?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn record(
        &self,
        tenant_id: &str,
        job_id: &str,
        trace_length: usize,
        workload_id: Option<&str>,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let now_ms = now_ms();
        let conn = self.conn.lock().expect("usage sqlite lock");
        conn.execute(
            r#"
            INSERT OR IGNORE INTO usage_log
              (tenant_id, job_id, trace_length, workload_id, duration_ms, completed_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                tenant_id,
                job_id,
                trace_length as i64,
                workload_id,
                duration_ms as i64,
                now_ms,
            ],
        )?;
        Ok(())
    }

    pub fn record_verify(&self, tenant_id: &str, duration_ms: u64) -> anyhow::Result<()> {
        let now_ms = now_ms();
        let conn = self.conn.lock().expect("usage sqlite lock");
        conn.execute(
            "INSERT INTO verify_log (tenant_id, duration_ms, completed_at_ms) VALUES (?1, ?2, ?3)",
            params![tenant_id, duration_ms as i64, now_ms],
        )?;
        Ok(())
    }

    pub fn record_failure(
        &self,
        tenant_id: &str,
        job_id: &str,
        error: &str,
        duration_ms: u64,
    ) -> anyhow::Result<()> {
        let now_ms = now_ms();
        let conn = self.conn.lock().expect("usage sqlite lock");
        conn.execute(
            r#"INSERT OR IGNORE INTO failed_proofs
               (tenant_id, job_id, error, duration_ms, failed_at_ms)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![tenant_id, job_id, error, duration_ms as i64, now_ms],
        )?;
        Ok(())
    }

    pub fn query_usage(
        &self,
        tenant_id: &str,
        plan: &str,
        since_ms: u64,
        until_ms: u64,
    ) -> anyhow::Result<UsageSummary> {
        let conn = self.conn.lock().expect("usage sqlite lock");
        let factor = discount_factor(plan);

        // Cap to i64::MAX to avoid overflow when casting to SQLite integer.
        let since_i = since_ms.min(i64::MAX as u64) as i64;
        let until_i = until_ms.min(i64::MAX as u64) as i64;

        // Successful proofs.
        let (total_proofs, estimated_cost_cents): (u64, u64) = {
            let mut stmt = conn.prepare(
                "SELECT trace_length FROM usage_log WHERE tenant_id = ?1 AND completed_at_ms >= ?2 AND completed_at_ms <= ?3"
            )?;
            let rows = stmt.query_map(params![tenant_id, since_i, until_i], |row| {
                row.get::<_, i64>(0)
            })?;
            let mut count = 0u64;
            let mut cost = 0u64;
            for row in rows {
                let trace_length = row? as u64;
                count += 1;
                cost += (price_cents(trace_length as usize) as f64 * factor).round() as u64;
            }
            (count, cost)
        };

        // Verify count.
        let total_verifies: u64 = conn.query_row(
            "SELECT COUNT(*) FROM verify_log WHERE tenant_id = ?1 AND completed_at_ms >= ?2 AND completed_at_ms <= ?3",
            params![tenant_id, since_i, until_i],
            |row| row.get(0),
        )?;

        // Failed proofs.
        let failed_proofs: u64 = conn.query_row(
            "SELECT COUNT(*) FROM failed_proofs WHERE tenant_id = ?1 AND failed_at_ms >= ?2 AND failed_at_ms <= ?3",
            params![tenant_id, since_i, until_i],
            |row| row.get(0),
        )?;

        Ok(UsageSummary {
            total_proofs,
            total_verifies,
            failed_proofs,
            estimated_cost_cents,
            period_start_ms: since_ms,
            period_end_ms: until_ms,
        })
    }

    pub fn monthly_cost_cents(&self, tenant_id: &str, plan: &str) -> anyhow::Result<u64> {
        let conn = self.conn.lock().expect("usage sqlite lock");
        let (month_start_ms, month_end_ms) = current_month_bounds_ms();

        // Use SQL CASE to compute base cost in a single aggregation query.
        let base_cost: i64 = conn.query_row(
            r#"SELECT COALESCE(SUM(
                CASE
                    WHEN trace_length < 10000 THEN 5
                    WHEN trace_length < 100000 THEN 50
                    WHEN trace_length < 1000000 THEN 200
                    WHEN trace_length < 10000000 THEN 800
                    ELSE 3000
                END
            ), 0) FROM usage_log
            WHERE tenant_id = ?1 AND completed_at_ms >= ?2 AND completed_at_ms <= ?3"#,
            params![tenant_id, month_start_ms as i64, month_end_ms as i64],
            |row| row.get(0),
        )?;
        // Apply plan-based discount.
        let factor = discount_factor(plan);
        Ok((base_cost as f64 * factor).round() as u64)
    }
}

/// Public price lookup for metrics tracking.
pub fn price_cents_pub(trace_length: usize) -> u64 {
    price_cents(trace_length)
}

fn price_cents(trace_length: usize) -> u64 {
    match trace_length {
        0..10_000 => 5,               // $0.05
        10_000..100_000 => 50,        // $0.50
        100_000..1_000_000 => 200,    // $2.00
        1_000_000..10_000_000 => 800, // $8.00
        _ => 3000,                    // $30.00 (>10M steps)
    }
}

/// Plan-based discount factor for per-proof pricing.
fn discount_factor(plan: &str) -> f64 {
    match plan {
        "team" => 0.75,  // 25% off
        "scale" => 0.60, // 40% off
        _ => 1.0,
    }
}

fn now_ms() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_millis() as i64
}

fn current_month_bounds_ms() -> (u64, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now_secs = now.as_secs();

    // Calculate start of current month (approximate: use chrono-free approach).
    // We just need the start of the current calendar month in UTC.
    let days_since_epoch = now_secs / 86400;
    // Approximate: find start of month by backing up to day 1.
    // This is a simple approach — good enough for billing windows.
    let secs_today = now_secs % 86400;
    let day_of_month_approx = {
        // Simple calculation: days since epoch -> date components
        // Using a rough month calculation
        let mut remaining = days_since_epoch;
        let mut year = 1970u64;
        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            year += 1;
        }
        let month_days = if is_leap_year(year) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut day = remaining;
        for &md in &month_days {
            if day < md {
                break;
            }
            day -= md;
        }
        day // 0-indexed day of month
    };

    let month_start_secs = now_secs - (day_of_month_approx * 86400) - secs_today;
    let month_start_ms = month_start_secs * 1000;
    let month_end_ms = now.as_millis() as u64;

    (month_start_ms, month_end_ms)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_price_cents() {
        assert_eq!(price_cents(100), 5);
        assert_eq!(price_cents(9_999), 5);
        assert_eq!(price_cents(10_000), 50);
        assert_eq!(price_cents(99_999), 50);
        assert_eq!(price_cents(100_000), 200);
        assert_eq!(price_cents(999_999), 200);
        assert_eq!(price_cents(1_000_000), 800);
        assert_eq!(price_cents(9_999_999), 800);
        assert_eq!(price_cents(10_000_000), 3000);
        assert_eq!(price_cents(100_000_000), 3000);
    }

    #[test]
    fn test_discount_factor() {
        assert_eq!(discount_factor("free"), 1.0);
        assert_eq!(discount_factor("developer"), 1.0);
        assert_eq!(discount_factor("standard"), 1.0); // legacy
        assert_eq!(discount_factor("team"), 0.75);
        assert_eq!(discount_factor("scale"), 0.60);
    }

    #[test]
    fn test_record_and_query() {
        let tmp = NamedTempFile::new().unwrap();
        let log = UsageLog::open(tmp.path().to_path_buf()).unwrap();

        log.record("t_test", "job1", 5000, None, 100).unwrap();
        log.record("t_test", "job2", 50000, None, 200).unwrap();
        log.record_verify("t_test", 50).unwrap();
        log.record_failure("t_test", "job3", "timeout", 300)
            .unwrap();

        // Developer plan: no discount, base rates (5 + 50 = 55)
        let summary = log
            .query_usage("t_test", "developer", 0, i64::MAX as u64)
            .unwrap();
        assert_eq!(summary.total_proofs, 2);
        assert_eq!(summary.total_verifies, 1);
        assert_eq!(summary.failed_proofs, 1);
        assert_eq!(summary.estimated_cost_cents, 55); // 5 + 50

        // Team plan: 25% off → round(5 * 0.75) + round(50 * 0.75) = 4 + 38 = 42
        let summary = log
            .query_usage("t_test", "team", 0, i64::MAX as u64)
            .unwrap();
        assert_eq!(summary.estimated_cost_cents, 42);

        // Scale plan: 40% off → round(5 * 0.60) + round(50 * 0.60) = 3 + 30 = 33
        let summary = log
            .query_usage("t_test", "scale", 0, i64::MAX as u64)
            .unwrap();
        assert_eq!(summary.estimated_cost_cents, 33);
    }

    #[test]
    fn test_monthly_cost() {
        let tmp = NamedTempFile::new().unwrap();
        let log = UsageLog::open(tmp.path().to_path_buf()).unwrap();

        log.record("t_test", "job1", 5000, None, 100).unwrap();

        // Developer plan: no discount
        let cost = log.monthly_cost_cents("t_test", "developer").unwrap();
        assert_eq!(cost, 5);

        // Team plan: round(5 * 0.75) = 4
        let cost = log.monthly_cost_cents("t_test", "team").unwrap();
        assert_eq!(cost, 4);

        // Scale plan: round(5 * 0.60) = 3
        let cost = log.monthly_cost_cents("t_test", "scale").unwrap();
        assert_eq!(cost, 3);
    }

    #[test]
    fn test_record_verify_idempotent() {
        let tmp = NamedTempFile::new().unwrap();
        let log = UsageLog::open(tmp.path().to_path_buf()).unwrap();

        log.record_verify("t_test", 50).unwrap();
        log.record_verify("t_test", 60).unwrap();

        let summary = log
            .query_usage("t_test", "developer", 0, i64::MAX as u64)
            .unwrap();
        assert_eq!(summary.total_verifies, 2);
    }

    #[test]
    fn test_record_failure_idempotent() {
        let tmp = NamedTempFile::new().unwrap();
        let log = UsageLog::open(tmp.path().to_path_buf()).unwrap();

        log.record_failure("t_test", "job1", "err", 100).unwrap();
        // Duplicate job_id should be ignored.
        log.record_failure("t_test", "job1", "err2", 200).unwrap();

        let summary = log
            .query_usage("t_test", "developer", 0, i64::MAX as u64)
            .unwrap();
        assert_eq!(summary.failed_proofs, 1);
    }
}
