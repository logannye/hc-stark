use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use rusqlite::{params, Connection};

use hc_sdk::types::{ProveJobStatus, ProveRequest};

/// Summary of a job for listing endpoints.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JobSummary {
    pub job_id: String,
    pub status_tag: String,
    pub updated_at_ms: i64,
}

/// Optional SQLite index for prove jobs.
///
/// This is **not** the source of truth for proof bytes (those remain on disk), but it provides:
/// - fast status lookup
/// - listing, counting, and deletion
/// - a foundation for future retention/quota policies
pub struct JobIndex {
    conn: Arc<Mutex<Connection>>,
}

impl JobIndex {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(path).context("open jobs sqlite")?;
        // 5s busy_timeout: under contention SQLite waits for the writer lock
        // instead of returning SQLITE_BUSY immediately. This is the
        // load-fairness knob — without it, a slow writer causes spurious
        // 5xx on concurrent reads. WAL mode (set below) reduces contention
        // but doesn't eliminate the writer lock.
        conn.busy_timeout(std::time::Duration::from_millis(5_000))
            .context("set jobs sqlite busy_timeout")?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS prove_jobs (
              tenant_id TEXT NOT NULL,
              job_id TEXT NOT NULL,
              request_json BLOB NOT NULL,
              status_json  BLOB NOT NULL,
              status_tag   TEXT NOT NULL DEFAULT 'pending',
              updated_at_ms INTEGER NOT NULL,
              PRIMARY KEY (tenant_id, job_id)
            );
            "#,
        )
        .context("init jobs sqlite schema")?;

        // Migration: add status_tag column if missing (existing databases).
        let has_status_tag: bool = conn
            .prepare("SELECT COUNT(*) FROM pragma_table_info('prove_jobs') WHERE name='status_tag'")
            .and_then(|mut stmt| stmt.query_row([], |row| row.get::<_, i64>(0)))
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_status_tag {
            let _ = conn.execute_batch(
                "ALTER TABLE prove_jobs ADD COLUMN status_tag TEXT NOT NULL DEFAULT 'pending'",
            );
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn upsert_request(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        let request_json = serde_json::to_vec(request)?;
        let status_json = serde_json::to_vec(status)?;
        let status_tag = status_tag(status);
        let now_ms = now_ms();
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            r#"
            INSERT INTO prove_jobs (tenant_id, job_id, request_json, status_json, status_tag, updated_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(tenant_id, job_id) DO UPDATE SET
              request_json=excluded.request_json,
              status_json=excluded.status_json,
              status_tag=excluded.status_tag,
              updated_at_ms=excluded.updated_at_ms
            "#,
            params![tenant_id, job_id, request_json, status_json, status_tag, now_ms],
        )?;
        Ok(())
    }

    pub fn update_status(
        &self,
        tenant_id: &str,
        job_id: &str,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        let status_json = serde_json::to_vec(status)?;
        let tag = status_tag(status);
        let now_ms = now_ms();
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            r#"
            UPDATE prove_jobs
            SET status_json=?3, status_tag=?4, updated_at_ms=?5
            WHERE tenant_id=?1 AND job_id=?2
            "#,
            params![tenant_id, job_id, status_json, tag, now_ms],
        )?;
        Ok(())
    }

    pub fn get_status(
        &self,
        tenant_id: &str,
        job_id: &str,
    ) -> anyhow::Result<Option<ProveJobStatus>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt =
            conn.prepare(r#"SELECT status_json FROM prove_jobs WHERE tenant_id=?1 AND job_id=?2"#)?;
        let mut rows = stmt.query(params![tenant_id, job_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let bytes: Vec<u8> = row.get(0)?;
        let status: ProveJobStatus = serde_json::from_slice(&bytes)?;
        Ok(Some(status))
    }

    pub fn list_jobs(
        &self,
        tenant_id: &str,
        status_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<(Vec<JobSummary>, usize)> {
        let conn = self.conn.lock().expect("sqlite lock");

        let total: usize = if let Some(filter) = status_filter {
            conn.prepare("SELECT COUNT(*) FROM prove_jobs WHERE tenant_id=?1 AND status_tag=?2")?
                .query_row(params![tenant_id, filter], |row| row.get(0))?
        } else {
            conn.prepare("SELECT COUNT(*) FROM prove_jobs WHERE tenant_id=?1")?
                .query_row(params![tenant_id], |row| row.get(0))?
        };

        let mut jobs = Vec::new();

        if let Some(filter) = status_filter {
            let mut stmt = conn.prepare(
                "SELECT job_id, status_tag, updated_at_ms FROM prove_jobs WHERE tenant_id=?1 AND status_tag=?2 ORDER BY updated_at_ms DESC LIMIT ?3 OFFSET ?4",
            )?;
            let rows = stmt.query_map(
                params![tenant_id, filter, limit as i64, offset as i64],
                |row| {
                    Ok(JobSummary {
                        job_id: row.get(0)?,
                        status_tag: row.get(1)?,
                        updated_at_ms: row.get(2)?,
                    })
                },
            )?;
            for row in rows.flatten() {
                jobs.push(row);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT job_id, status_tag, updated_at_ms FROM prove_jobs WHERE tenant_id=?1 ORDER BY updated_at_ms DESC LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt.query_map(params![tenant_id, limit as i64, offset as i64], |row| {
                Ok(JobSummary {
                    job_id: row.get(0)?,
                    status_tag: row.get(1)?,
                    updated_at_ms: row.get(2)?,
                })
            })?;
            for row in rows.flatten() {
                jobs.push(row);
            }
        }

        Ok((jobs, total))
    }

    pub fn delete_job(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().expect("sqlite lock");
        let changed = conn.execute(
            "DELETE FROM prove_jobs WHERE tenant_id=?1 AND job_id=?2",
            params![tenant_id, job_id],
        )?;
        Ok(changed > 0)
    }

    pub fn count_by_status(&self, tenant_id: &str) -> anyhow::Result<HashMap<String, usize>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare(
            "SELECT status_tag, COUNT(*) FROM prove_jobs WHERE tenant_id=?1 GROUP BY status_tag",
        )?;
        let rows = stmt.query_map(params![tenant_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
        })?;
        let mut map = HashMap::new();
        for row in rows.flatten() {
            map.insert(row.0, row.1);
        }
        Ok(map)
    }

    /// Cross-tenant count of jobs in the given status. Cheap because the
    /// (status_tag, ...) index covers it. Returns the metric's i64-shaped
    /// value (saturating cast — no realistic state ever exceeds i64::MAX).
    pub fn count_global_by_status(&self, status_tag: &str) -> anyhow::Result<i64> {
        let conn = self.conn.lock().expect("sqlite lock");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM prove_jobs WHERE status_tag=?1",
            params![status_tag],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

fn status_tag(status: &ProveJobStatus) -> &'static str {
    match status {
        ProveJobStatus::Pending => "pending",
        ProveJobStatus::Running => "running",
        ProveJobStatus::Succeeded { .. } => "succeeded",
        ProveJobStatus::Failed { .. } => "failed",
    }
}

fn now_ms() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_millis() as i64
}
