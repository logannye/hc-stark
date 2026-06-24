use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use native_tls::TlsConnector;
use postgres::{Client, NoTls};
use postgres_native_tls::MakeTlsConnector;
use rusqlite::{params, Connection, OptionalExtension};

use crate::usage_log::PgTlsMode;
use hc_sdk::types::{ProveJobStatus, ProveRequest};

const PG_JOB_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS prove_jobs (
  tenant_id      TEXT  NOT NULL,
  job_id         TEXT  NOT NULL,
  request_json   BYTEA NOT NULL,
  status_json    BYTEA NOT NULL,
  status_tag     TEXT  NOT NULL DEFAULT 'pending',
  tenant_plan    TEXT,
  computed_trace_length BIGINT,
  lease_owner    TEXT,
  lease_until_ms BIGINT,
  updated_at_ms  BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, job_id)
);
ALTER TABLE prove_jobs ADD COLUMN IF NOT EXISTS tenant_plan TEXT;
ALTER TABLE prove_jobs ADD COLUMN IF NOT EXISTS computed_trace_length BIGINT;
ALTER TABLE prove_jobs ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE prove_jobs ADD COLUMN IF NOT EXISTS lease_until_ms BIGINT;
CREATE INDEX IF NOT EXISTS idx_prove_jobs_tenant_status_updated
  ON prove_jobs (tenant_id, status_tag, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_prove_jobs_tenant_updated
  ON prove_jobs (tenant_id, updated_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_prove_jobs_status
  ON prove_jobs (status_tag);
CREATE INDEX IF NOT EXISTS idx_prove_jobs_claim
  ON prove_jobs (status_tag, lease_until_ms, updated_at_ms);
"#;

/// Summary of a job for listing endpoints.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JobSummary {
    pub job_id: String,
    pub status_tag: String,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct JobMetadata {
    pub tenant_plan: Option<String>,
    pub computed_trace_length: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct ClaimedJob {
    pub tenant_id: String,
    pub job_id: String,
    pub request: ProveRequest,
    pub metadata: JobMetadata,
}

type SelectedClaimRow = (String, String, Vec<u8>, Option<String>, Option<i64>);

pub trait JobStore: Send + Sync {
    fn upsert_job(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
        metadata: &JobMetadata,
    ) -> anyhow::Result<()>;

    fn upsert_request(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        self.upsert_job(tenant_id, job_id, request, status, &JobMetadata::default())
    }

    fn update_status(
        &self,
        tenant_id: &str,
        job_id: &str,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()>;

    fn get_status(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<Option<ProveJobStatus>>;

    fn list_jobs(
        &self,
        tenant_id: &str,
        status_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<(Vec<JobSummary>, usize)>;

    fn delete_job(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<bool>;

    fn count_by_status(&self, tenant_id: &str) -> anyhow::Result<HashMap<String, usize>>;

    fn count_global_by_status(&self, status_tag: &str) -> anyhow::Result<i64>;

    fn claim_next(&self, worker_id: &str, lease_ms: i64) -> anyhow::Result<Option<ClaimedJob>>;

    fn renew_claim(
        &self,
        tenant_id: &str,
        job_id: &str,
        worker_id: &str,
        lease_ms: i64,
    ) -> anyhow::Result<bool>;
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

pub struct PgJobIndex {
    client: Mutex<Client>,
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
              tenant_plan TEXT,
              computed_trace_length INTEGER,
              lease_owner TEXT,
              lease_until_ms INTEGER,
              updated_at_ms INTEGER NOT NULL,
              PRIMARY KEY (tenant_id, job_id)
            );
            "#,
        )
        .context("init jobs sqlite schema")?;

        // Migration: add columns if missing (existing databases).
        for (column, ddl) in [
            (
                "status_tag",
                "ALTER TABLE prove_jobs ADD COLUMN status_tag TEXT NOT NULL DEFAULT 'pending'",
            ),
            (
                "tenant_plan",
                "ALTER TABLE prove_jobs ADD COLUMN tenant_plan TEXT",
            ),
            (
                "computed_trace_length",
                "ALTER TABLE prove_jobs ADD COLUMN computed_trace_length INTEGER",
            ),
            (
                "lease_owner",
                "ALTER TABLE prove_jobs ADD COLUMN lease_owner TEXT",
            ),
            (
                "lease_until_ms",
                "ALTER TABLE prove_jobs ADD COLUMN lease_until_ms INTEGER",
            ),
        ] {
            let exists: bool = conn
                .prepare("SELECT COUNT(*) FROM pragma_table_info('prove_jobs') WHERE name=?1")
                .and_then(|mut stmt| stmt.query_row(params![column], |row| row.get::<_, i64>(0)))
                .map(|c| c > 0)
                .unwrap_or(false);
            if !exists {
                let _ = conn.execute_batch(ddl);
            }
        }

        conn.execute_batch(
            r#"
            CREATE INDEX IF NOT EXISTS idx_prove_jobs_claim
              ON prove_jobs (status_tag, lease_until_ms, updated_at_ms);
            "#,
        )
        .context("init jobs sqlite indexes")?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn upsert_job(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
        metadata: &JobMetadata,
    ) -> anyhow::Result<()> {
        let request_json = serde_json::to_vec(request)?;
        let status_json = serde_json::to_vec(status)?;
        let status_tag = status_tag(status);
        let now_ms = now_ms();
        let trace_length = opt_usize_to_i64(metadata.computed_trace_length);
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            r#"
            INSERT INTO prove_jobs
              (tenant_id, job_id, request_json, status_json, status_tag, tenant_plan,
               computed_trace_length, lease_owner, lease_until_ms, updated_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, ?8)
            ON CONFLICT(tenant_id, job_id) DO UPDATE SET
              request_json=excluded.request_json,
              status_json=excluded.status_json,
              status_tag=excluded.status_tag,
              tenant_plan=excluded.tenant_plan,
              computed_trace_length=excluded.computed_trace_length,
              lease_owner=NULL,
              lease_until_ms=NULL,
              updated_at_ms=excluded.updated_at_ms
            "#,
            params![
                tenant_id,
                job_id,
                request_json,
                status_json,
                status_tag,
                metadata.tenant_plan.as_deref(),
                trace_length,
                now_ms
            ],
        )?;
        Ok(())
    }

    pub fn upsert_request(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        self.upsert_job(tenant_id, job_id, request, status, &JobMetadata::default())
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

    pub fn claim_next(&self, worker_id: &str, lease_ms: i64) -> anyhow::Result<Option<ClaimedJob>> {
        let now = now_ms();
        let lease_until = now.saturating_add(lease_ms.max(1));
        let running = ProveJobStatus::Running;
        let status_json = serde_json::to_vec(&running)?;
        let conn = self.conn.lock().expect("sqlite lock");
        let selected: Option<SelectedClaimRow> = {
            let mut stmt = conn.prepare(
                r#"
                SELECT tenant_id, job_id, request_json, tenant_plan, computed_trace_length
                FROM prove_jobs
                WHERE status_tag='pending'
                   OR (status_tag='running' AND (lease_until_ms IS NULL OR lease_until_ms <= ?1))
                ORDER BY updated_at_ms ASC
                LIMIT 1
                "#,
            )?;
            stmt.query_row(params![now], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .optional()?
        };
        let Some((tenant_id, job_id, request_json, tenant_plan, trace_length)) = selected else {
            return Ok(None);
        };
        let changed = conn.execute(
            r#"
            UPDATE prove_jobs
            SET status_json=?3,
                status_tag='running',
                lease_owner=?4,
                lease_until_ms=?5,
                updated_at_ms=?6
            WHERE tenant_id=?1
              AND job_id=?2
              AND (
                status_tag='pending'
                OR (status_tag='running' AND (lease_until_ms IS NULL OR lease_until_ms <= ?7))
              )
            "#,
            params![
                tenant_id,
                job_id,
                status_json,
                worker_id,
                lease_until,
                now,
                now
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(ClaimedJob {
            tenant_id,
            job_id,
            request: serde_json::from_slice(&request_json)?,
            metadata: JobMetadata {
                tenant_plan,
                computed_trace_length: trace_length.and_then(i64_to_usize),
            },
        }))
    }

    pub fn renew_claim(
        &self,
        tenant_id: &str,
        job_id: &str,
        worker_id: &str,
        lease_ms: i64,
    ) -> anyhow::Result<bool> {
        let now = now_ms();
        let lease_until = now.saturating_add(lease_ms.max(1));
        let conn = self.conn.lock().expect("sqlite lock");
        let changed = conn.execute(
            r#"
            UPDATE prove_jobs
            SET lease_until_ms=?4, updated_at_ms=?5
            WHERE tenant_id=?1
              AND job_id=?2
              AND lease_owner=?3
              AND status_tag='running'
            "#,
            params![tenant_id, job_id, worker_id, lease_until, now],
        )?;
        Ok(changed > 0)
    }
}

impl JobStore for JobIndex {
    fn upsert_job(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
        metadata: &JobMetadata,
    ) -> anyhow::Result<()> {
        JobIndex::upsert_job(self, tenant_id, job_id, request, status, metadata)
    }

    fn update_status(
        &self,
        tenant_id: &str,
        job_id: &str,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        JobIndex::update_status(self, tenant_id, job_id, status)
    }

    fn get_status(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<Option<ProveJobStatus>> {
        JobIndex::get_status(self, tenant_id, job_id)
    }

    fn list_jobs(
        &self,
        tenant_id: &str,
        status_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<(Vec<JobSummary>, usize)> {
        JobIndex::list_jobs(self, tenant_id, status_filter, limit, offset)
    }

    fn delete_job(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<bool> {
        JobIndex::delete_job(self, tenant_id, job_id)
    }

    fn count_by_status(&self, tenant_id: &str) -> anyhow::Result<HashMap<String, usize>> {
        JobIndex::count_by_status(self, tenant_id)
    }

    fn count_global_by_status(&self, status_tag: &str) -> anyhow::Result<i64> {
        JobIndex::count_global_by_status(self, status_tag)
    }

    fn claim_next(&self, worker_id: &str, lease_ms: i64) -> anyhow::Result<Option<ClaimedJob>> {
        JobIndex::claim_next(self, worker_id, lease_ms)
    }

    fn renew_claim(
        &self,
        tenant_id: &str,
        job_id: &str,
        worker_id: &str,
        lease_ms: i64,
    ) -> anyhow::Result<bool> {
        JobIndex::renew_claim(self, tenant_id, job_id, worker_id, lease_ms)
    }
}

impl PgJobIndex {
    pub fn connect(url: &str, tls_mode: PgTlsMode) -> anyhow::Result<Self> {
        let mut client = match tls_mode {
            PgTlsMode::Disable => {
                Client::connect(url, NoTls).context("connect postgres job index")?
            }
            PgTlsMode::Require => {
                let connector = TlsConnector::builder()
                    .build()
                    .context("build native TLS connector for postgres job index")?;
                Client::connect(url, MakeTlsConnector::new(connector))
                    .context("connect postgres job index")?
            }
        };
        client
            .batch_execute(PG_JOB_SCHEMA_SQL)
            .context("initialize postgres job index schema")?;
        client
            .batch_execute("SET statement_timeout = '5s'")
            .context("set postgres job index statement_timeout")?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }

    fn lock_client(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Client>> {
        self.client
            .lock()
            .map_err(|_| anyhow::anyhow!("postgres job index client lock poisoned"))
    }
}

impl JobStore for PgJobIndex {
    fn upsert_job(
        &self,
        tenant_id: &str,
        job_id: &str,
        request: &ProveRequest,
        status: &ProveJobStatus,
        metadata: &JobMetadata,
    ) -> anyhow::Result<()> {
        let request_json = serde_json::to_vec(request)?;
        let status_json = serde_json::to_vec(status)?;
        let tag = status_tag(status);
        let now_ms = now_ms();
        let trace_length = opt_usize_to_i64(metadata.computed_trace_length);
        let mut client = self.lock_client()?;
        client.execute(
            r#"
            INSERT INTO prove_jobs
              (tenant_id, job_id, request_json, status_json, status_tag, tenant_plan,
               computed_trace_length, lease_owner, lease_until_ms, updated_at_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, $8)
            ON CONFLICT (tenant_id, job_id) DO UPDATE SET
              request_json=EXCLUDED.request_json,
              status_json=EXCLUDED.status_json,
              status_tag=EXCLUDED.status_tag,
              tenant_plan=EXCLUDED.tenant_plan,
              computed_trace_length=EXCLUDED.computed_trace_length,
              lease_owner=NULL,
              lease_until_ms=NULL,
              updated_at_ms=EXCLUDED.updated_at_ms
            "#,
            &[
                &tenant_id,
                &job_id,
                &request_json,
                &status_json,
                &tag,
                &metadata.tenant_plan,
                &trace_length,
                &now_ms,
            ],
        )?;
        Ok(())
    }

    fn update_status(
        &self,
        tenant_id: &str,
        job_id: &str,
        status: &ProveJobStatus,
    ) -> anyhow::Result<()> {
        let status_json = serde_json::to_vec(status)?;
        let tag = status_tag(status);
        let now_ms = now_ms();
        let mut client = self.lock_client()?;
        client.execute(
            r#"
            UPDATE prove_jobs
            SET status_json=$3, status_tag=$4, updated_at_ms=$5
            WHERE tenant_id=$1 AND job_id=$2
            "#,
            &[&tenant_id, &job_id, &status_json, &tag, &now_ms],
        )?;
        Ok(())
    }

    fn get_status(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<Option<ProveJobStatus>> {
        let mut client = self.lock_client()?;
        let Some(row) = client.query_opt(
            "SELECT status_json FROM prove_jobs WHERE tenant_id=$1 AND job_id=$2",
            &[&tenant_id, &job_id],
        )?
        else {
            return Ok(None);
        };
        let bytes: Vec<u8> = row.get(0);
        let status = serde_json::from_slice(&bytes)?;
        Ok(Some(status))
    }

    fn list_jobs(
        &self,
        tenant_id: &str,
        status_filter: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<(Vec<JobSummary>, usize)> {
        let mut client = self.lock_client()?;
        let limit_i = limit.min(i64::MAX as usize) as i64;
        let offset_i = offset.min(i64::MAX as usize) as i64;
        let total: i64;
        let rows;
        if let Some(filter) = status_filter {
            total = client
                .query_one(
                    "SELECT COUNT(*)::bigint FROM prove_jobs WHERE tenant_id=$1 AND status_tag=$2",
                    &[&tenant_id, &filter],
                )?
                .get(0);
            rows = client.query(
                r#"
                SELECT job_id, status_tag, updated_at_ms
                FROM prove_jobs
                WHERE tenant_id=$1 AND status_tag=$2
                ORDER BY updated_at_ms DESC
                LIMIT $3 OFFSET $4
                "#,
                &[&tenant_id, &filter, &limit_i, &offset_i],
            )?;
        } else {
            total = client
                .query_one(
                    "SELECT COUNT(*)::bigint FROM prove_jobs WHERE tenant_id=$1",
                    &[&tenant_id],
                )?
                .get(0);
            rows = client.query(
                r#"
                SELECT job_id, status_tag, updated_at_ms
                FROM prove_jobs
                WHERE tenant_id=$1
                ORDER BY updated_at_ms DESC
                LIMIT $2 OFFSET $3
                "#,
                &[&tenant_id, &limit_i, &offset_i],
            )?;
        }
        let jobs = rows
            .into_iter()
            .map(|row| JobSummary {
                job_id: row.get(0),
                status_tag: row.get(1),
                updated_at_ms: row.get(2),
            })
            .collect();
        Ok((jobs, total.max(0) as usize))
    }

    fn delete_job(&self, tenant_id: &str, job_id: &str) -> anyhow::Result<bool> {
        let mut client = self.lock_client()?;
        let changed = client.execute(
            "DELETE FROM prove_jobs WHERE tenant_id=$1 AND job_id=$2",
            &[&tenant_id, &job_id],
        )?;
        Ok(changed > 0)
    }

    fn count_by_status(&self, tenant_id: &str) -> anyhow::Result<HashMap<String, usize>> {
        let mut client = self.lock_client()?;
        let rows = client.query(
            "SELECT status_tag, COUNT(*)::bigint FROM prove_jobs WHERE tenant_id=$1 GROUP BY status_tag",
            &[&tenant_id],
        )?;
        let mut map = HashMap::new();
        for row in rows {
            let status: String = row.get(0);
            let count: i64 = row.get(1);
            map.insert(status, count.max(0) as usize);
        }
        Ok(map)
    }

    fn count_global_by_status(&self, status_tag: &str) -> anyhow::Result<i64> {
        let mut client = self.lock_client()?;
        let count: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM prove_jobs WHERE status_tag=$1",
                &[&status_tag],
            )?
            .get(0);
        Ok(count)
    }

    fn claim_next(&self, worker_id: &str, lease_ms: i64) -> anyhow::Result<Option<ClaimedJob>> {
        let now = now_ms();
        let lease_until = now.saturating_add(lease_ms.max(1));
        let running = ProveJobStatus::Running;
        let status_json = serde_json::to_vec(&running)?;
        let mut client = self.lock_client()?;
        let Some(row) = client.query_opt(
            r#"
            WITH candidate AS (
              SELECT tenant_id, job_id
              FROM prove_jobs
              WHERE status_tag='pending'
                 OR (status_tag='running' AND (lease_until_ms IS NULL OR lease_until_ms <= $1))
              ORDER BY updated_at_ms ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE prove_jobs AS j
            SET status_json=$2,
                status_tag='running',
                lease_owner=$3,
                lease_until_ms=$4,
                updated_at_ms=$1
            FROM candidate AS c
            WHERE j.tenant_id=c.tenant_id AND j.job_id=c.job_id
            RETURNING j.tenant_id, j.job_id, j.request_json, j.tenant_plan,
                      j.computed_trace_length
            "#,
            &[&now, &status_json, &worker_id, &lease_until],
        )?
        else {
            return Ok(None);
        };
        let request_json: Vec<u8> = row.get(2);
        let tenant_plan: Option<String> = row.get(3);
        let trace_length: Option<i64> = row.get(4);
        Ok(Some(ClaimedJob {
            tenant_id: row.get(0),
            job_id: row.get(1),
            request: serde_json::from_slice(&request_json)?,
            metadata: JobMetadata {
                tenant_plan,
                computed_trace_length: trace_length.and_then(i64_to_usize),
            },
        }))
    }

    fn renew_claim(
        &self,
        tenant_id: &str,
        job_id: &str,
        worker_id: &str,
        lease_ms: i64,
    ) -> anyhow::Result<bool> {
        let now = now_ms();
        let lease_until = now.saturating_add(lease_ms.max(1));
        let mut client = self.lock_client()?;
        let changed = client.execute(
            r#"
            UPDATE prove_jobs
            SET lease_until_ms=$4, updated_at_ms=$5
            WHERE tenant_id=$1
              AND job_id=$2
              AND lease_owner=$3
              AND status_tag='running'
            "#,
            &[&tenant_id, &job_id, &worker_id, &lease_until, &now],
        )?;
        Ok(changed > 0)
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

fn opt_usize_to_i64(value: Option<usize>) -> Option<i64> {
    value.map(|v| v.min(i64::MAX as usize) as i64)
}

fn i64_to_usize(value: i64) -> Option<usize> {
    usize::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ProveRequest {
        ProveRequest {
            workload_id: Some("accumulator".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 1,
            final_acc: 2,
            block_size: 16,
            fri_final_poly_size: 4,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        }
    }

    #[test]
    fn postgres_job_schema_stores_completed_proof_status() {
        assert!(PG_JOB_SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS prove_jobs"));
        assert!(PG_JOB_SCHEMA_SQL.contains("status_json    BYTEA NOT NULL"));
        assert!(PG_JOB_SCHEMA_SQL.contains("tenant_plan    TEXT"));
        assert!(PG_JOB_SCHEMA_SQL.contains("lease_until_ms BIGINT"));
        assert!(PG_JOB_SCHEMA_SQL.contains("PRIMARY KEY (tenant_id, job_id)"));
        assert!(PG_JOB_SCHEMA_SQL.contains("idx_prove_jobs_tenant_status_updated"));
        assert!(PG_JOB_SCHEMA_SQL.contains("idx_prove_jobs_claim"));
    }

    #[test]
    fn sqlite_job_index_works_through_job_store_trait() {
        let tmp = tempfile::tempdir().unwrap();
        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let store: &dyn JobStore = &index;
        let request = sample_request();
        let pending = ProveJobStatus::Pending;

        store
            .upsert_request("tenant", "job_1", &request, &pending)
            .unwrap();
        assert!(matches!(
            store.get_status("tenant", "job_1").unwrap(),
            Some(ProveJobStatus::Pending)
        ));

        let status = ProveJobStatus::Succeeded {
            proof: hc_sdk::types::ProofBytes {
                version: 7,
                bytes: vec![1, 2, 3],
            },
        };
        store.update_status("tenant", "job_1", &status).unwrap();
        assert!(matches!(
            store.get_status("tenant", "job_1").unwrap(),
            Some(ProveJobStatus::Succeeded { .. })
        ));

        let (jobs, total) = store.list_jobs("tenant", Some("succeeded"), 10, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(jobs[0].job_id, "job_1");
        assert_eq!(store.count_global_by_status("succeeded").unwrap(), 1);
    }

    #[test]
    fn sqlite_job_index_migrates_existing_table_before_creating_claim_index() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("jobs.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE prove_jobs (
                  tenant_id TEXT NOT NULL,
                  job_id TEXT NOT NULL,
                  request_json BLOB NOT NULL,
                  status_json BLOB NOT NULL,
                  status_tag TEXT NOT NULL DEFAULT 'pending',
                  updated_at_ms INTEGER NOT NULL,
                  PRIMARY KEY (tenant_id, job_id)
                );
                "#,
            )
            .unwrap();
        }

        let index = JobIndex::open(path).unwrap();
        let request = sample_request();
        index
            .upsert_request("tenant", "job_1", &request, &ProveJobStatus::Pending)
            .unwrap();
        assert!(index.claim_next("worker", 30_000).unwrap().is_some());
    }

    #[test]
    fn sqlite_job_index_claims_oldest_pending_job_with_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let request = sample_request();
        let metadata = JobMetadata {
            tenant_plan: Some("pro".to_string()),
            computed_trace_length: Some(1024),
        };

        index
            .upsert_job(
                "tenant",
                "job_1",
                &request,
                &ProveJobStatus::Pending,
                &metadata,
            )
            .unwrap();

        let claimed = index
            .claim_next("worker-a", 30_000)
            .unwrap()
            .expect("pending job should be claimed");
        assert_eq!(claimed.tenant_id, "tenant");
        assert_eq!(claimed.job_id, "job_1");
        assert_eq!(claimed.request.block_size, request.block_size);
        assert_eq!(claimed.metadata.tenant_plan.as_deref(), Some("pro"));
        assert_eq!(claimed.metadata.computed_trace_length, Some(1024));
        assert!(matches!(
            index.get_status("tenant", "job_1").unwrap(),
            Some(ProveJobStatus::Running)
        ));
        assert!(
            index.claim_next("worker-b", 30_000).unwrap().is_none(),
            "an unexpired running lease must not be double-claimed"
        );
        assert!(
            index
                .renew_claim("tenant", "job_1", "worker-a", 30_000)
                .unwrap(),
            "lease owner should be able to renew"
        );
        assert!(
            !index
                .renew_claim("tenant", "job_1", "worker-b", 30_000)
                .unwrap(),
            "non-owner must not renew another worker's lease"
        );
    }
}
