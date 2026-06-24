use std::{path::PathBuf, process::Stdio, time::Instant};

use anyhow::Context;
use hc_sdk::types::{ProofBytes, ProveJobStatus, ProveRequest};
use hc_server::{
    job_index::{ClaimedJob, JobIndex, JobStore, PgJobIndex},
    usage_log::{PgTlsMode, PgUsageRecorder, UsageLog, UsageRecorder},
};
use tokio::{io::AsyncWriteExt, time::Duration};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let run_mode = WorkerRunMode::from_args(std::env::args().skip(1))?;
    let cfg = WorkerConfig::from_env()?;
    let worker_id = cfg.worker_id.clone();
    let store = open_job_store(&cfg)?;
    let usage = open_usage_recorder(&cfg)?;
    if run_mode == WorkerRunMode::CheckConfig {
        info!(%worker_id, "hc-job-worker configuration ok");
        println!("hc-job-worker configuration ok");
        return Ok(());
    }
    if run_mode == WorkerRunMode::Once {
        let claimed = run_once(store.as_ref(), usage.as_deref(), &cfg).await?;
        if !claimed {
            info!(%worker_id, "hc-job-worker found no claimable jobs");
        }
        return Ok(());
    }

    info!(%worker_id, "hc-job-worker starting");
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        match store.claim_next(&worker_id, cfg.lease_ms as i64) {
            Ok(Some(job)) => {
                let tenant_id = job.tenant_id.clone();
                let job_id = job.job_id.clone();
                tokio::select! {
                    result = execute_claimed_job(job, store.as_ref(), usage.as_deref(), &cfg) => {
                        if let Err(err) = result {
                            error!(error = %err, "claimed job execution failed");
                        }
                    }
                    _ = &mut shutdown => {
                        warn!(
                            %tenant_id,
                            %job_id,
                            "shutdown requested while job was running; dropping worker child and leaving lease to expire"
                        );
                        break;
                    }
                }
            }
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(cfg.poll_interval) => {}
                    _ = &mut shutdown => {
                        info!("shutdown requested while idle");
                        break;
                    }
                }
            }
            Err(err) => {
                error!(error = %err, "claim_next failed");
                tokio::select! {
                    _ = tokio::time::sleep(cfg.error_backoff) => {}
                    _ = &mut shutdown => {
                        info!("shutdown requested during claim backoff");
                        break;
                    }
                }
            }
        }
    }
    info!(%worker_id, "hc-job-worker stopped");
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerRunMode {
    Loop,
    Once,
    CheckConfig,
}

impl WorkerRunMode {
    fn from_args(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut mode = WorkerRunMode::Loop;
        for arg in args {
            match arg.as_str() {
                "--once" => {
                    if mode != WorkerRunMode::Loop {
                        anyhow::bail!("use only one of --once or --check-config");
                    }
                    mode = WorkerRunMode::Once;
                }
                "--check-config" => {
                    if mode != WorkerRunMode::Loop {
                        anyhow::bail!("use only one of --once or --check-config");
                    }
                    mode = WorkerRunMode::CheckConfig;
                }
                "-h" | "--help" => {
                    anyhow::bail!("usage: hc-job-worker [--once | --check-config]");
                }
                other => {
                    anyhow::bail!("unknown argument '{other}'; usage: hc-job-worker [--once | --check-config]");
                }
            }
        }
        Ok(mode)
    }
}

struct WorkerConfig {
    worker_id: String,
    job_index_source: JobIndexSource,
    job_index_pg_url: Option<String>,
    job_index_pg_tls_mode: PgTlsMode,
    job_index_sqlite_path: Option<PathBuf>,
    usage_pg_url: Option<String>,
    usage_pg_tls_mode: PgTlsMode,
    usage_sqlite_path: Option<PathBuf>,
    usage_disabled: bool,
    worker_path: PathBuf,
    allow_custom_programs: bool,
    poll_interval: Duration,
    heartbeat_interval: Duration,
    error_backoff: Duration,
    lease_ms: u64,
    max_prove: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobIndexSource {
    Postgres,
    Sqlite,
}

impl WorkerConfig {
    fn from_env() -> anyhow::Result<Self> {
        let source = std::env::var("HC_JOB_WORKER_INDEX_SOURCE")
            .or_else(|_| std::env::var("HC_SERVER_JOB_INDEX_SOURCE"))
            .unwrap_or_else(|_| "postgres".to_string());
        let job_index_source = match source.trim().to_ascii_lowercase().as_str() {
            "postgres" | "pg" => JobIndexSource::Postgres,
            "sqlite" => JobIndexSource::Sqlite,
            other => anyhow::bail!(
                "HC_JOB_WORKER_INDEX_SOURCE must be 'postgres' or 'sqlite', got '{other}'"
            ),
        };
        let job_index_pg_url = std::env::var("HC_JOB_INDEX_PG_URL")
            .or_else(|_| std::env::var("HC_SERVER_PG_URL"))
            .ok()
            .filter(|v| !v.trim().is_empty());
        let job_index_pg_tls_mode = job_index_pg_url
            .as_deref()
            .map(|url| {
                std::env::var("HC_JOB_INDEX_PG_TLS")
                    .ok()
                    .map(|raw| PgTlsMode::from_raw_env_and_url(Some(&raw), url))
                    .unwrap_or_else(|| PgTlsMode::from_raw_env_and_url(None, url))
            })
            .unwrap_or(PgTlsMode::Disable);
        let data_dir = std::env::var("HC_SERVER_DATA_DIR")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".hc-server"));
        let job_index_sqlite_path = std::env::var("HC_JOB_WORKER_SQLITE_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(data_dir.join("jobs.sqlite")));
        let usage_pg_url = std::env::var("HC_JOB_WORKER_USAGE_PG_URL")
            .or_else(|_| std::env::var("HC_SERVER_PG_URL"))
            .ok()
            .filter(|v| !v.trim().is_empty());
        let usage_pg_tls_mode = usage_pg_url
            .as_deref()
            .map(PgTlsMode::from_env_and_url)
            .unwrap_or(PgTlsMode::Disable);
        let usage_sqlite_path = std::env::var("HC_JOB_WORKER_USAGE_SQLITE_PATH")
            .or_else(|_| std::env::var("HC_USAGE_DB_PATH"))
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let worker_id = std::env::var("HC_JOB_WORKER_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| format!("hc-job-worker-{}", std::process::id()));
        Ok(Self {
            worker_id,
            job_index_source,
            job_index_pg_url,
            job_index_pg_tls_mode,
            job_index_sqlite_path,
            usage_pg_url,
            usage_pg_tls_mode,
            usage_sqlite_path,
            usage_disabled: env_bool("HC_JOB_WORKER_USAGE_DISABLED", false),
            worker_path: worker_executable_path(),
            allow_custom_programs: env_bool("HC_SERVER_ALLOW_CUSTOM_PROGRAMS", false),
            poll_interval: env_duration_ms("HC_JOB_WORKER_POLL_MS", 1_000),
            heartbeat_interval: env_duration_ms("HC_JOB_WORKER_HEARTBEAT_MS", 5_000),
            error_backoff: env_duration_ms("HC_JOB_WORKER_ERROR_BACKOFF_MS", 5_000),
            lease_ms: env_u64("HC_JOB_WORKER_LEASE_MS", 30_000),
            max_prove: Duration::from_secs(env_u64("HC_JOB_WORKER_MAX_PROVE_SECS", 3_600)),
        })
    }
}

fn open_job_store(cfg: &WorkerConfig) -> anyhow::Result<Box<dyn JobStore>> {
    match cfg.job_index_source {
        JobIndexSource::Postgres => {
            let url = cfg.job_index_pg_url.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "HC_JOB_WORKER_INDEX_SOURCE=postgres requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL"
                )
            })?;
            Ok(Box::new(PgJobIndex::connect(
                url,
                cfg.job_index_pg_tls_mode,
            )?))
        }
        JobIndexSource::Sqlite => {
            let path = cfg
                .job_index_sqlite_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing SQLite job index path"))?;
            Ok(Box::new(JobIndex::open(path)?))
        }
    }
}

fn open_usage_recorder(cfg: &WorkerConfig) -> anyhow::Result<Option<Box<dyn UsageRecorder>>> {
    if cfg.usage_disabled {
        warn!(
            "HC_JOB_WORKER_USAGE_DISABLED=true; completed jobs will not be billed by this worker"
        );
        return Ok(None);
    }
    if let Some(url) = cfg.usage_pg_url.as_deref() {
        return Ok(Some(Box::new(PgUsageRecorder::connect(
            url,
            cfg.usage_pg_tls_mode,
        )?)));
    }
    if let Some(path) = cfg.usage_sqlite_path.as_ref() {
        return Ok(Some(Box::new(UsageLog::open(path.clone())?)));
    }
    anyhow::bail!(
        "hc-job-worker requires HC_SERVER_PG_URL/HC_JOB_WORKER_USAGE_PG_URL for usage recording \
         (or HC_JOB_WORKER_USAGE_SQLITE_PATH for local dev, or HC_JOB_WORKER_USAGE_DISABLED=true)"
    );
}

async fn run_once(
    store: &dyn JobStore,
    usage: Option<&dyn UsageRecorder>,
    cfg: &WorkerConfig,
) -> anyhow::Result<bool> {
    match store.claim_next(&cfg.worker_id, cfg.lease_ms as i64)? {
        Some(job) => {
            execute_claimed_job(job, store, usage, cfg).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

async fn execute_claimed_job(
    job: ClaimedJob,
    store: &dyn JobStore,
    usage: Option<&dyn UsageRecorder>,
    cfg: &WorkerConfig,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let tenant_plan = job
        .metadata
        .tenant_plan
        .as_deref()
        .unwrap_or("developer")
        .to_string();
    let trace_length = job
        .metadata
        .computed_trace_length
        .unwrap_or_else(|| computed_trace_length(&job.request));
    info!(tenant_id=%job.tenant_id, job_id=%job.job_id, "claimed job");

    let result = match tokio::time::timeout(
        cfg.max_prove,
        prove_with_cancellation(&job, store, cfg),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "prove timeout after {}s",
            cfg.max_prove.as_secs()
        )),
    };

    match result {
        Ok(proof) => {
            if matches!(
                store.get_status(&job.tenant_id, &job.job_id)?,
                Some(ProveJobStatus::Failed { .. })
            ) {
                info!(tenant_id=%job.tenant_id, job_id=%job.job_id, "job finished after cancellation; preserving failed status");
                return Ok(());
            }
            if let Some(usage) = usage {
                if let Err(err) = usage.record(
                    &job.tenant_id,
                    &job.job_id,
                    trace_length,
                    job.request.workload_id.as_deref(),
                    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                ) {
                    let error = format!("usage recording failed after proof generation: {err}");
                    store.update_status(
                        &job.tenant_id,
                        &job.job_id,
                        &ProveJobStatus::Failed {
                            error: error.clone(),
                        },
                    )?;
                    anyhow::bail!(error);
                }
            }
            let status = ProveJobStatus::Succeeded { proof };
            store.update_status(&job.tenant_id, &job.job_id, &status)?;
            info!(tenant_id=%job.tenant_id, job_id=%job.job_id, plan=%tenant_plan, "job succeeded");
        }
        Err(err) => {
            if matches!(
                store.get_status(&job.tenant_id, &job.job_id)?,
                Some(ProveJobStatus::Failed { .. })
            ) {
                info!(tenant_id=%job.tenant_id, job_id=%job.job_id, "job already failed externally");
                return Ok(());
            }
            let error = err.to_string();
            let status = ProveJobStatus::Failed {
                error: error.clone(),
            };
            store.update_status(&job.tenant_id, &job.job_id, &status)?;
            if let Some(usage) = usage {
                usage.record_failure(
                    &job.tenant_id,
                    &job.job_id,
                    &error,
                    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                )?;
            }
            warn!(tenant_id=%job.tenant_id, job_id=%job.job_id, error=%error, "job failed");
        }
    }
    Ok(())
}

async fn prove_with_cancellation(
    job: &ClaimedJob,
    store: &dyn JobStore,
    cfg: &WorkerConfig,
) -> anyhow::Result<ProofBytes> {
    if job.request.workload_id.is_none()
        && job.request.template_id.is_none()
        && !cfg.allow_custom_programs
    {
        anyhow::bail!(
            "custom programs are disabled; supply workload_id, template_id, or enable HC_SERVER_ALLOW_CUSTOM_PROGRAMS"
        );
    }

    let request_json = serde_json::to_vec(&job.request)?;
    let spawn_result = tokio::process::Command::new(&cfg.worker_path)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env(
            "HC_SERVER_ALLOW_CUSTOM_PROGRAMS",
            if cfg.allow_custom_programs {
                "true"
            } else {
                "false"
            },
        )
        .spawn();
    let mut child = spawn_result
        .with_context(|| format!("failed to spawn hc-worker at {}", cfg.worker_path.display()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("hc-worker stdin unavailable"))?;
    stdin.write_all(&request_json).await?;
    stdin.shutdown().await?;
    drop(stdin);

    let wait_with_output = child.wait_with_output();
    tokio::pin!(wait_with_output);
    let mut tick = tokio::time::interval(cfg.heartbeat_interval);
    loop {
        tokio::select! {
            output = &mut wait_with_output => {
                let output = output?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("hc-worker exited with status {}: {}", output.status, stderr.trim());
                }
                let proof: ProofBytes = serde_json::from_slice(&output.stdout)
                    .context("parse hc-worker stdout")?;
                return Ok(proof);
            }
            _ = tick.tick() => {
                match store.get_status(&job.tenant_id, &job.job_id)? {
                    Some(ProveJobStatus::Failed { error }) => {
                        anyhow::bail!("job cancelled or failed externally: {error}");
                    }
                    Some(ProveJobStatus::Running) => {
                        if !store.renew_claim(&job.tenant_id, &job.job_id, &cfg.worker_id, cfg.lease_ms as i64)? {
                            anyhow::bail!("job lease was lost");
                        }
                    }
                    Some(ProveJobStatus::Pending) => {
                        anyhow::bail!("claimed job reverted to pending");
                    }
                    Some(ProveJobStatus::Succeeded { .. }) => {
                        anyhow::bail!("claimed job already completed externally");
                    }
                    None => {
                        anyhow::bail!("claimed job disappeared from job index");
                    }
                }
            }
        }
    }
}

fn computed_trace_length(req: &ProveRequest) -> usize {
    let program_len = req.program.as_ref().map(|p| p.len()).unwrap_or(1);
    program_len.max(1).next_power_of_two() * req.block_size.max(1)
}

fn worker_executable_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("HC_SERVER_WORKER_PATH") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("hc-worker");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("hc-worker")
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    Duration::from_millis(env_u64(name, default_ms))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                }
                Err(err) => {
                    warn!(error = %err, "failed to install SIGTERM handler");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_run_mode_parses_flags() {
        assert_eq!(
            WorkerRunMode::from_args(std::iter::empty::<String>()).unwrap(),
            WorkerRunMode::Loop
        );
        assert_eq!(
            WorkerRunMode::from_args(["--once".to_string()]).unwrap(),
            WorkerRunMode::Once
        );
        assert_eq!(
            WorkerRunMode::from_args(["--check-config".to_string()]).unwrap(),
            WorkerRunMode::CheckConfig
        );
        assert!(
            WorkerRunMode::from_args(["--once".to_string(), "--check-config".to_string()]).is_err()
        );
        assert!(WorkerRunMode::from_args(["--unknown".to_string()]).is_err());
    }

    #[test]
    fn computed_trace_length_uses_server_formula() {
        let req = ProveRequest {
            workload_id: None,
            template_id: None,
            template_params: None,
            program: Some(vec!["add_immediate 1".into(); 9]),
            initial_acc: 0,
            final_acc: 9,
            block_size: 8,
            fri_final_poly_size: 2,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        assert_eq!(computed_trace_length(&req), 16 * 8);
    }

    #[cfg(unix)]
    fn write_fake_worker(tmp: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let fake_worker = tmp.join("fake-hc-worker");
        std::fs::write(
            &fake_worker,
            b"#!/bin/sh\ncat >/dev/null\nprintf '{\"version\":7,\"bytes\":[1,2,3]}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_worker, std::fs::Permissions::from_mode(0o755)).unwrap();
        fake_worker
    }

    fn test_cfg(tmp: &std::path::Path, worker_path: PathBuf) -> WorkerConfig {
        WorkerConfig {
            worker_id: "test-worker".to_string(),
            job_index_source: JobIndexSource::Sqlite,
            job_index_pg_url: None,
            job_index_pg_tls_mode: PgTlsMode::Disable,
            job_index_sqlite_path: Some(tmp.join("jobs.sqlite")),
            usage_pg_url: None,
            usage_pg_tls_mode: PgTlsMode::Disable,
            usage_sqlite_path: Some(tmp.join("usage.sqlite")),
            usage_disabled: false,
            worker_path,
            allow_custom_programs: false,
            poll_interval: Duration::from_millis(10),
            heartbeat_interval: Duration::from_millis(10),
            error_backoff: Duration::from_millis(10),
            lease_ms: 30_000,
            max_prove: Duration::from_secs(5),
        }
    }

    struct FailingUsageRecorder;

    impl UsageRecorder for FailingUsageRecorder {
        fn record(
            &self,
            _tenant_id: &str,
            _job_id: &str,
            _trace_length: usize,
            _workload_id: Option<&str>,
            _duration_ms: u64,
        ) -> anyhow::Result<()> {
            anyhow::bail!("synthetic usage outage")
        }

        fn record_verify(&self, _tenant_id: &str, _duration_ms: u64) -> anyhow::Result<()> {
            Ok(())
        }

        fn record_failure(
            &self,
            _tenant_id: &str,
            _job_id: &str,
            _error: &str,
            _duration_ms: u64,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn write_sleeping_worker(tmp: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let fake_worker = tmp.join("sleeping-hc-worker");
        std::fs::write(&fake_worker, b"#!/bin/sh\ncat >/dev/null\nsleep 1\n").unwrap();
        std::fs::set_permissions(&fake_worker, std::fs::Permissions::from_mode(0o755)).unwrap();
        fake_worker
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_once_returns_false_when_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let usage = UsageLog::open(tmp.path().join("usage.sqlite")).unwrap();
        let cfg = test_cfg(tmp.path(), write_fake_worker(tmp.path()));

        let claimed = run_once(&index, Some(&usage), &cfg).await.unwrap();

        assert!(!claimed);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_once_claims_and_completes_one_job() {
        let tmp = tempfile::tempdir().unwrap();
        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let usage = UsageLog::open(tmp.path().join("usage.sqlite")).unwrap();
        let cfg = test_cfg(tmp.path(), write_fake_worker(tmp.path()));
        let request = ProveRequest {
            workload_id: Some("toy_add_1_2".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 1,
            final_acc: 4,
            block_size: 8,
            fri_final_poly_size: 2,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        index
            .upsert_job(
                "tenant",
                "job_1",
                &request,
                &ProveJobStatus::Pending,
                &hc_server::job_index::JobMetadata {
                    tenant_plan: Some("developer".to_string()),
                    computed_trace_length: Some(8),
                },
            )
            .unwrap();

        let claimed = run_once(&index, Some(&usage), &cfg).await.unwrap();

        assert!(claimed);
        assert!(matches!(
            index.get_status("tenant", "job_1").unwrap(),
            Some(ProveJobStatus::Succeeded { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_claimed_job_publishes_success_and_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_worker = write_fake_worker(tmp.path());

        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let request = ProveRequest {
            workload_id: Some("toy_add_1_2".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 1,
            final_acc: 4,
            block_size: 8,
            fri_final_poly_size: 2,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        index
            .upsert_job(
                "tenant",
                "job_1",
                &request,
                &ProveJobStatus::Pending,
                &hc_server::job_index::JobMetadata {
                    tenant_plan: Some("developer".to_string()),
                    computed_trace_length: Some(8),
                },
            )
            .unwrap();
        let job = index
            .claim_next("test-worker", 30_000)
            .unwrap()
            .expect("claim queued job");
        let usage = UsageLog::open(tmp.path().join("usage.sqlite")).unwrap();
        let cfg = test_cfg(tmp.path(), fake_worker);

        execute_claimed_job(job, &index, Some(&usage), &cfg)
            .await
            .unwrap();

        assert!(matches!(
            index.get_status("tenant", "job_1").unwrap(),
            Some(ProveJobStatus::Succeeded { .. })
        ));
        let summary = usage
            .query_usage("tenant", "developer", 0, u64::MAX)
            .unwrap();
        assert_eq!(summary.total_proofs, 1);
        assert_eq!(summary.failed_proofs, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_claimed_job_does_not_publish_success_when_usage_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_worker = write_fake_worker(tmp.path());

        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let request = ProveRequest {
            workload_id: Some("toy_add_1_2".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 1,
            final_acc: 4,
            block_size: 8,
            fri_final_poly_size: 2,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        index
            .upsert_job(
                "tenant",
                "job_usage_failure",
                &request,
                &ProveJobStatus::Pending,
                &hc_server::job_index::JobMetadata {
                    tenant_plan: Some("developer".to_string()),
                    computed_trace_length: Some(8),
                },
            )
            .unwrap();
        let job = index
            .claim_next("test-worker", 30_000)
            .unwrap()
            .expect("claim queued job");
        let cfg = test_cfg(tmp.path(), fake_worker);
        let usage = FailingUsageRecorder;

        let err = execute_claimed_job(job, &index, Some(&usage), &cfg)
            .await
            .expect_err("usage failure should fail closed");

        assert!(
            err.to_string().contains("usage recording failed"),
            "unexpected usage error: {err}"
        );
        match index.get_status("tenant", "job_usage_failure").unwrap() {
            Some(ProveJobStatus::Failed { error }) => {
                assert!(
                    error.contains("usage recording failed"),
                    "unexpected terminal error: {error}"
                );
            }
            other => panic!("expected failed status, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_claimed_job_marks_timeout_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_worker = write_sleeping_worker(tmp.path());

        let index = JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
        let request = ProveRequest {
            workload_id: Some("toy_add_1_2".to_string()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: 1,
            final_acc: 4,
            block_size: 8,
            fri_final_poly_size: 2,
            query_count: 80,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };
        index
            .upsert_job(
                "tenant",
                "job_timeout",
                &request,
                &ProveJobStatus::Pending,
                &hc_server::job_index::JobMetadata {
                    tenant_plan: Some("developer".to_string()),
                    computed_trace_length: Some(8),
                },
            )
            .unwrap();
        let job = index
            .claim_next("test-worker", 30_000)
            .unwrap()
            .expect("claim queued job");
        let usage = UsageLog::open(tmp.path().join("usage.sqlite")).unwrap();
        let mut cfg = test_cfg(tmp.path(), fake_worker);
        cfg.max_prove = Duration::from_millis(10);

        execute_claimed_job(job, &index, Some(&usage), &cfg)
            .await
            .unwrap();

        match index.get_status("tenant", "job_timeout").unwrap() {
            Some(ProveJobStatus::Failed { error }) => {
                assert!(
                    error.contains("prove timeout"),
                    "unexpected timeout error: {error}"
                );
            }
            other => panic!("expected timeout failure, got {other:?}"),
        }
        let summary = usage
            .query_usage("tenant", "developer", 0, u64::MAX)
            .unwrap();
        assert_eq!(summary.total_proofs, 0);
        assert_eq!(summary.failed_proofs, 1);
    }
}
