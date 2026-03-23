use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hc_sdk::{
    evm_proof,
    proof::{decode_proof_bytes, verify_proof_bytes},
    types::{
        EstimateRange, EstimateRequest, EstimateResponse, ProveJobStatus, ProveRequest,
        ProveSubmitResponse, TemplateListResponse, TemplateProveRequest, TemplateSummary,
        UsageSummary, VerifyRequest,
    },
};
use hc_vm::Instruction;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use tokio::{
    task::JoinHandle,
    time::{timeout, Duration},
};
use tokio_util::sync::CancellationToken;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

pub mod auth;
pub mod job_index;
pub mod usage_log;
pub mod workloads;

use auth::{AuthConfig, AuthGuard};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct JobKey {
    tenant_id: String,
    job_id: Uuid,
}

#[derive(Clone)]
pub struct AppState {
    jobs: Arc<Mutex<HashMap<JobKey, JobState>>>,
    metrics: Metrics,
    cfg: ServerConfig,
    auth: Arc<std::sync::RwLock<AuthConfig>>,
    auth_guard: AuthGuard,
    verify_inflight: Arc<tokio::sync::Semaphore>,
    job_index: Option<Arc<job_index::JobIndex>>,
    usage_log: Option<Arc<usage_log::UsageLog>>,
    rate_limits: Arc<Mutex<HashMap<String, TenantRateLimits>>>,
}

struct JobState {
    status: ProveJobStatus,
    handle: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

#[derive(Clone, Debug)]
struct PlanLimits {
    prove_rpm: u32,
    verify_rpm: u32,
    max_inflight: usize,
    monthly_cap_cents: u64,
    max_prove_seconds: u64,
}

impl PlanLimits {
    fn for_plan(plan: &str) -> Self {
        match plan {
            "free" => Self {
                prove_rpm: 10,
                verify_rpm: 30,
                max_inflight: 1,
                monthly_cap_cents: 500,
                max_prove_seconds: 300, // 5 min
            },
            "team" => Self {
                prove_rpm: 300,
                verify_rpm: 900,
                max_inflight: 8,
                monthly_cap_cents: 250_000,
                max_prove_seconds: 1800, // 30 min
            },
            "scale" => Self {
                prove_rpm: 500,
                verify_rpm: 1500,
                max_inflight: 16,
                monthly_cap_cents: 1_000_000,
                max_prove_seconds: 3600, // 60 min
            },
            _ => Self {
                // "developer" is the default; also covers legacy "standard" and "pro"
                prove_rpm: 100,
                verify_rpm: 300,
                max_inflight: 4,
                monthly_cap_cents: 50_000,
                max_prove_seconds: 600, // 10 min
            },
        }
    }
}


#[derive(Clone)]
struct Metrics {
    registry: Registry,
    prove_submitted: IntCounter,
    verify_requests: IntCounter,
    prove_completed: IntCounterVec,
    prove_failed: IntCounterVec,
    prove_duration: Histogram,
    jobs_inflight: IntGauge,
    gc_runs_total: IntCounter,
    gc_removed_total: IntCounter,
    rate_limit_rejections: IntCounterVec,
    usage_cents_total: IntCounterVec,
    usage_cap_rejections: IntCounter,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let prove_submitted = IntCounter::new("hc_prove_submitted_total", "prove submissions")
            .expect("counter must be valid");
        let verify_requests = IntCounter::new("hc_verify_requests_total", "verify requests")
            .expect("counter must be valid");
        let prove_completed = IntCounterVec::new(
            Opts::new("hc_prove_completed_total", "completed proofs by tenant"),
            &["tenant_id"],
        )
        .expect("counter vec must be valid");
        let prove_failed = IntCounterVec::new(
            Opts::new("hc_prove_failed_total", "failed proofs by tenant"),
            &["tenant_id"],
        )
        .expect("counter vec must be valid");
        let prove_duration = Histogram::with_opts(
            HistogramOpts::new("hc_prove_duration_seconds", "prove job duration")
                .buckets(prometheus::exponential_buckets(0.5, 2.0, 12).unwrap()),
        )
        .expect("histogram must be valid");
        let jobs_inflight =
            IntGauge::new("hc_jobs_inflight", "in-flight prove jobs").expect("gauge must be valid");
        let gc_runs_total = IntCounter::new("hc_gc_runs_total", "background GC cycles")
            .expect("counter must be valid");
        let gc_removed_total = IntCounter::new("hc_gc_removed_total", "jobs removed by GC")
            .expect("counter must be valid");
        let rate_limit_rejections = IntCounterVec::new(
            Opts::new("hc_rate_limit_rejections_total", "rate limit rejections"),
            &["endpoint"],
        )
        .expect("counter vec must be valid");
        let usage_cents_total = IntCounterVec::new(
            Opts::new("hc_usage_cents_total", "billed usage in cents"),
            &["tenant_id"],
        )
        .expect("counter vec must be valid");
        let usage_cap_rejections =
            IntCounter::new("hc_usage_cap_rejections_total", "usage cap rejections (402)")
                .expect("counter must be valid");

        for m in [
            Box::new(prove_submitted.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(verify_requests.clone()),
            Box::new(prove_completed.clone()),
            Box::new(prove_failed.clone()),
            Box::new(prove_duration.clone()),
            Box::new(jobs_inflight.clone()),
            Box::new(gc_runs_total.clone()),
            Box::new(gc_removed_total.clone()),
            Box::new(rate_limit_rejections.clone()),
            Box::new(usage_cents_total.clone()),
            Box::new(usage_cap_rejections.clone()),
        ] {
            registry.register(m).expect("register must succeed");
        }

        Self {
            registry,
            prove_submitted,
            verify_requests,
            prove_completed,
            prove_failed,
            prove_duration,
            jobs_inflight,
            gc_runs_total,
            gc_removed_total,
            rate_limit_rejections,
            usage_cents_total,
            usage_cap_rejections,
        }
    }
}

#[derive(Clone)]
struct ServerConfig {
    data_dir: PathBuf,
    max_inflight_jobs: usize,
    max_prove_seconds: u64,
    allow_custom_programs: bool,
    max_body_bytes: usize,
    max_verify_inflight: usize,
    verify_timeout_ms: u64,
    retention_secs: u64,
    job_index_sqlite: bool,
    max_prove_rpm: u32,
    max_verify_rpm: u32,
    max_block_size: usize,
    min_query_count: usize,
    max_rate_limit_entries: usize,
}

impl ServerConfig {
    fn from_env() -> anyhow::Result<Self> {
        let data_dir =
            std::env::var("HC_SERVER_DATA_DIR").unwrap_or_else(|_| ".hc-server".to_string());
        let max_inflight_jobs = std::env::var("HC_SERVER_MAX_INFLIGHT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let max_prove_seconds = std::env::var("HC_SERVER_MAX_PROVE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let allow_custom_programs = std::env::var("HC_SERVER_ALLOW_CUSTOM_PROGRAMS")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_body_bytes = std::env::var("HC_SERVER_MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(25 * 1024 * 1024);
        let max_verify_inflight = std::env::var("HC_SERVER_MAX_VERIFY_INFLIGHT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8);
        let verify_timeout_ms = std::env::var("HC_SERVER_VERIFY_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000);
        let retention_secs = std::env::var("HC_SERVER_RETENTION_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(24 * 3600);
        let job_index_disabled = std::env::var("HC_SERVER_JOB_INDEX_DISABLED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let job_index_sqlite = if job_index_disabled {
            false
        } else {
            std::env::var("HC_SERVER_JOB_INDEX_SQLITE")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true)
        };
        let rate_limit_disabled = std::env::var("HC_SERVER_RATE_LIMIT_DISABLED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_prove_rpm = if rate_limit_disabled {
            0
        } else {
            std::env::var("HC_SERVER_MAX_PROVE_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100)
        };
        let max_verify_rpm = if rate_limit_disabled {
            0
        } else {
            std::env::var("HC_SERVER_MAX_VERIFY_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300)
        };
        let max_block_size = std::env::var("HC_SERVER_MAX_BLOCK_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1 << 20);
        let min_query_count = std::env::var("HC_SERVER_MIN_QUERY_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(80);
        Ok(Self {
            data_dir: PathBuf::from(data_dir),
            max_inflight_jobs,
            max_prove_seconds,
            allow_custom_programs,
            max_body_bytes,
            max_verify_inflight,
            verify_timeout_ms,
            retention_secs,
            job_index_sqlite,
            max_prove_rpm,
            max_verify_rpm,
            max_block_size,
            min_query_count,
            max_rate_limit_entries: 10_000,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct TenantRateLimits {
    prove: FixedWindow,
    verify: FixedWindow,
}

#[derive(Clone, Debug, Default)]
struct FixedWindow {
    window_start_ms: u64,
    count: u32,
}

enum RateEndpoint {
    Prove,
    Verify,
}

fn check_rate_limit(state: &AppState, tenant_id: &str, plan: &str, endpoint: RateEndpoint) -> bool {
    let plan_limits = PlanLimits::for_plan(plan);
    let limit = match endpoint {
        RateEndpoint::Prove => {
            if state.cfg.max_prove_rpm > 0 {
                state.cfg.max_prove_rpm.min(plan_limits.prove_rpm)
            } else {
                plan_limits.prove_rpm
            }
        }
        RateEndpoint::Verify => {
            if state.cfg.max_verify_rpm > 0 {
                state.cfg.max_verify_rpm.min(plan_limits.verify_rpm)
            } else {
                plan_limits.verify_rpm
            }
        }
    };
    if limit == 0 {
        return true;
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let window_ms = 60_000u64;

    let mut map = state.rate_limits.lock().expect("rate lock");

    // Evict stale entries when map grows too large.
    if map.len() > state.cfg.max_rate_limit_entries {
        let cutoff = now_ms.saturating_sub(2 * window_ms);
        let stale_keys: Vec<String> = map
            .iter()
            .filter(|(_, v)| v.prove.window_start_ms < cutoff && v.verify.window_start_ms < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        for key in stale_keys {
            map.remove(&key);
        }
    }

    let entry = map.entry(tenant_id.to_string()).or_default();
    let window = match endpoint {
        RateEndpoint::Prove => &mut entry.prove,
        RateEndpoint::Verify => &mut entry.verify,
    };
    if now_ms.saturating_sub(window.window_start_ms) >= window_ms {
        window.window_start_ms = now_ms;
        window.count = 0;
    }
    if window.count >= limit {
        return false;
    }
    window.count += 1;
    true
}

fn remaining_rate_quota(state: &AppState, tenant_id: &str, plan: &str, endpoint: RateEndpoint) -> u32 {
    let plan_limits = PlanLimits::for_plan(plan);
    let limit = match endpoint {
        RateEndpoint::Prove => {
            if state.cfg.max_prove_rpm > 0 {
                state.cfg.max_prove_rpm.min(plan_limits.prove_rpm)
            } else {
                plan_limits.prove_rpm
            }
        }
        RateEndpoint::Verify => {
            if state.cfg.max_verify_rpm > 0 {
                state.cfg.max_verify_rpm.min(plan_limits.verify_rpm)
            } else {
                plan_limits.verify_rpm
            }
        }
    };
    if limit == 0 {
        return u32::MAX;
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let window_ms = 60_000u64;

    let map = state.rate_limits.lock().expect("rate lock");
    let Some(entry) = map.get(tenant_id) else {
        return limit;
    };
    let window = match endpoint {
        RateEndpoint::Prove => &entry.prove,
        RateEndpoint::Verify => &entry.verify,
    };
    if now_ms.saturating_sub(window.window_start_ms) >= window_ms {
        return limit;
    }
    limit.saturating_sub(window.count)
}

#[derive(OpenApi)]
#[openapi(
    paths(healthz, metrics, verify, prove_submit, prove_get, prove_batch, proof_calldata, aggregate, usage, templates_list, template_detail, prove_template, prove_inspect, estimate),
    components(schemas(
        VerifyRequest,
        hc_sdk::types::VerifyResult,
        ProveRequest,
        ProveSubmitResponse,
        ProveJobStatus,
        hc_sdk::types::ProofBytes,
        UsageSummary,
        TemplateSummary,
        TemplateListResponse,
        TemplateProveRequest,
        EstimateRequest,
        EstimateResponse,
        EstimateRange,
        hc_sdk::types::ProofInspection,
        hc_sdk::types::QueryCommitmentsJson,
        AggregateProofSummary
    )),
    tags(
        (name = "hc-stark", description = "hc-stark proving/verifying service")
    )
)]
struct ApiDoc;

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = ServerConfig::from_env()?;
    let mut auth = AuthConfig::from_env()?;

    // Merge file-based keys if configured.
    let api_keys_file = std::env::var("HC_SERVER_API_KEYS_FILE")
        .ok()
        .map(PathBuf::from);
    if let Some(ref path) = api_keys_file {
        if path.exists() {
            let file_auth = AuthConfig::from_file(path)?;
            auth.merge(&file_auth);
        }
    }
    let auth = Arc::new(std::sync::RwLock::new(auth));

    fs::create_dir_all(cfg.data_dir.join("jobs"))?;

    let job_index = if cfg.job_index_sqlite {
        Some(Arc::new(job_index::JobIndex::open(
            cfg.data_dir.join("jobs.sqlite"),
        )?))
    } else {
        None
    };

    let usage_log = if cfg.job_index_sqlite {
        Some(Arc::new(usage_log::UsageLog::open(
            cfg.data_dir.join("usage.sqlite"),
        )?))
    } else {
        None
    };

    let state = AppState {
        jobs: Arc::new(Mutex::new(HashMap::new())),
        metrics: Metrics::new(),
        verify_inflight: Arc::new(tokio::sync::Semaphore::new(cfg.max_verify_inflight)),
        cfg,
        auth,
        auth_guard: AuthGuard::new(),
        job_index,
        usage_log,
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    };

    // Reconcile stale jobs from previous runs.
    reconcile_stale_jobs(&state.cfg.data_dir, state.job_index.as_deref());

    // Spawn background GC task.
    {
        let gc_state = state.clone();
        let gc_interval = std::env::var("HC_SERVER_GC_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300u64);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(gc_interval));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                gc_state.metrics.gc_runs_total.inc();
                let jobs_dir = gc_state.cfg.data_dir.join("jobs");
                if let Ok(tenants) = fs::read_dir(&jobs_dir) {
                    let mut removed = 0u64;
                    for tenant_entry in tenants.flatten() {
                        if tenant_entry.path().is_dir() {
                            let tenant_id = tenant_entry.file_name().to_string_lossy().to_string();
                            let before = count_job_dirs(&tenant_entry.path());
                            gc_tenant_jobs(
                                gc_state.cfg.data_dir.as_path(),
                                &tenant_id,
                                gc_state.cfg.retention_secs,
                            );
                            let after = count_job_dirs(&tenant_entry.path());
                            removed += before.saturating_sub(after) as u64;
                        }
                    }
                    if removed > 0 {
                        gc_state.metrics.gc_removed_total.inc_by(removed);
                    }
                }
            }
        });
    }

    // Spawn background auth reload from file (every 60s).
    if let Some(ref path) = api_keys_file {
        info!(path=%path.display(), "auth hot-reload enabled (60s interval)");
        let auth_ref = state.auth.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                if let Ok(mut fresh) = AuthConfig::from_env() {
                    if path.exists() {
                        if let Ok(file_auth) = AuthConfig::from_file(&path) {
                            fresh.merge(&file_auth);
                        }
                    }
                    if let Ok(mut guard) = auth_ref.write() {
                        *guard = fresh;
                    }
                }
            }
        });
    }

    let app = build_app(state);
    let listen = std::env::var("HC_SERVER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = listen.parse().context("invalid HC_SERVER_LISTEN address")?;
    info!(%addr, "hc-server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Extract client IP from headers (Cloudflare CF-Connecting-IP, X-Forwarded-For, or fallback).
fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("unknown").trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Authenticate with brute-force protection. Returns tenant or error response.
fn guarded_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<auth::TenantContext, ApiError> {
    let ip = client_ip(headers);

    // Check lockout before attempting auth.
    if state.auth_guard.is_locked_out(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_auth_failures",
            "too many failed authentication attempts, try again later",
        ));
    }

    match state.auth.read().unwrap().authenticate(headers) {
        Ok(tenant) => {
            state.auth_guard.clear(&ip);
            Ok(tenant)
        }
        Err((code, msg)) => {
            state.auth_guard.record_failure(&ip);
            Err(ApiError::new(code, "unauthorized", msg))
        }
    }
}

async fn request_id_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    req.headers_mut().insert(
        "x-request-id",
        axum::http::HeaderValue::from_str(&request_id).unwrap(),
    );
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        "x-request-id",
        axum::http::HeaderValue::from_str(&request_id).unwrap(),
    );
    resp
}

pub fn build_app(state: AppState) -> Router {
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/verify", post(verify))
        .route("/prove", post(prove_submit).get(prove_list))
        .route("/prove/batch", post(prove_batch))
        .route("/prove/:job_id", get(prove_get))
        .route("/prove/:job_id/cancel", post(prove_cancel))
        .route("/prove/:job_id", axum::routing::delete(prove_delete))
        .route("/proof/:job_id/calldata", get(proof_calldata))
        .route("/templates", get(templates_list))
        .route("/templates/:template_id", get(template_detail))
        .route("/prove/template/:template_id", post(prove_template))
        .route("/prove/:job_id/inspect", get(prove_inspect))
        .route("/estimate", post(estimate))
        .route("/aggregate", post(aggregate))
        .route("/usage", get(usage))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .layer(axum_middleware::from_fn(request_id_middleware))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(600),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

pub fn test_state(temp_dir: PathBuf) -> AppState {
    let cfg = ServerConfig {
        data_dir: temp_dir,
        max_inflight_jobs: 4,
        max_prove_seconds: 30,
        allow_custom_programs: true,
        max_body_bytes: 2 * 1024 * 1024,
        max_verify_inflight: 8,
        verify_timeout_ms: 30_000,
        retention_secs: 24 * 3600,
        job_index_sqlite: false,
        max_prove_rpm: 0,
        max_verify_rpm: 0,
        max_block_size: usize::MAX,
        min_query_count: 1,
        max_rate_limit_entries: 10_000,
    };
    let auth = Arc::new(std::sync::RwLock::new(AuthConfig::default()));
    fs::create_dir_all(cfg.data_dir.join("jobs")).expect("create jobs dir");
    AppState {
        jobs: Arc::new(Mutex::new(HashMap::new())),
        metrics: Metrics::new(),
        verify_inflight: Arc::new(tokio::sync::Semaphore::new(cfg.max_verify_inflight)),
        cfg,
        auth,
        auth_guard: AuthGuard::new(),
        job_index: None,
        usage_log: None,
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub fn test_state_with_server_caps(
    temp_dir: PathBuf,
    max_block_size: usize,
    min_query_count: usize,
) -> AppState {
    let mut state = test_state(temp_dir);
    state.cfg.max_block_size = max_block_size;
    state.cfg.min_query_count = min_query_count;
    state
}

pub fn test_state_with_auth(temp_dir: PathBuf, auth: AuthConfig) -> AppState {
    let mut state = test_state(temp_dir);
    state.auth = Arc::new(std::sync::RwLock::new(auth));
    state
}

pub fn test_state_with_overrides(
    temp_dir: PathBuf,
    auth: AuthConfig,
    max_body_bytes: usize,
    max_verify_inflight: usize,
    verify_timeout_ms: u64,
) -> AppState {
    let mut state = test_state_with_auth(temp_dir, auth);
    state.cfg.max_body_bytes = max_body_bytes;
    state.cfg.max_verify_inflight = max_verify_inflight;
    state.cfg.verify_timeout_ms = verify_timeout_ms;
    state.verify_inflight = Arc::new(tokio::sync::Semaphore::new(max_verify_inflight));
    state
}

pub fn test_state_with_rate_limits(
    temp_dir: PathBuf,
    auth: AuthConfig,
    max_prove_rpm: u32,
    max_verify_rpm: u32,
) -> AppState {
    let mut state = test_state_with_auth(temp_dir, auth);
    state.cfg.max_prove_rpm = max_prove_rpm;
    state.cfg.max_verify_rpm = max_verify_rpm;
    state
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[utoipa::path(get, path = "/healthz", responses((status = 200, description = "ok")))]
async fn healthz() -> impl IntoResponse {
    StatusCode::OK
}

#[utoipa::path(get, path = "/readyz", responses((status = 200, description = "ready")))]
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    // Minimal readiness: ensure job directory is writable.
    let probe_dir = state.cfg.data_dir.join("jobs");
    if fs::create_dir_all(&probe_dir).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let probe_file = probe_dir.join(".ready_probe");
    match fs::write(&probe_file, b"ok") {
        Ok(_) => {
            let _ = fs::remove_file(probe_file);
            StatusCode::OK
        }
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[utoipa::path(get, path = "/metrics", responses((status = 200, description = "prometheus metrics", body = String)))]
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.metrics.registry.gather();
    let mut buf = Vec::new();
    if let Err(err) = encoder.encode(&metric_families, &mut buf) {
        return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
    }
    (StatusCode::OK, String::from_utf8_lossy(&buf).to_string()).into_response()
}

#[utoipa::path(
    post,
    path = "/verify",
    request_body = VerifyRequest,
    responses((status = 200, body = hc_sdk::types::VerifyResult))
)]
async fn verify(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    // Require auth if configured (prevents unauthenticated CPU burn).
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if !check_rate_limit(&state, &tenant.tenant_id, &tenant.plan, RateEndpoint::Verify) {
        state
            .metrics
            .rate_limit_rejections
            .with_label_values(&["verify"])
            .inc();
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "verify rate limit exceeded",
        )
        .into_response();
    }
    state.metrics.verify_requests.inc();
    let tenant_id_for_verify = tenant.tenant_id.clone();
    let usage_log_for_verify = state.usage_log.clone();
    let permit = match state.verify_inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_inflight",
                "too many in-flight verify requests",
            )
            .into_response()
        }
    };
    let verify_start = std::time::Instant::now();
    let timeout_ms = state.cfg.verify_timeout_ms;
    let result = timeout(
        Duration::from_millis(timeout_ms),
        tokio::task::spawn_blocking(move || {
            // Test hook: allow integration tests to deterministically hold the verify semaphore
            // or trigger timeouts. Disabled unless explicitly enabled via env var.
            if std::env::var("HC_SERVER_TEST_HOOKS").ok().as_deref() == Some("1") {
                if let Some(value) = headers
                    .get("x-hc-test-sleep-ms")
                    .and_then(|v| v.to_str().ok())
                {
                    if let Ok(ms) = value.parse::<u64>() {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                    }
                }
            }
            verify_proof_bytes(&req.proof, req.allow_legacy_v2)
        }),
    )
    .await;
    drop(permit);
    let verify_elapsed_ms = verify_start.elapsed().as_millis() as u64;
    match result {
        Ok(joined) => match joined {
            Ok(v) => {
                if let Some(ref usage) = usage_log_for_verify {
                    let _ = usage.record_verify(&tenant_id_for_verify, verify_elapsed_ms);
                }
                Json(v).into_response()
            }
            Err(err) => {
                ApiError::internal(format!("verify task join error: {err}")).into_response()
            }
        },
        Err(_) => {
            ApiError::new(StatusCode::REQUEST_TIMEOUT, "timeout", "verify timeout").into_response()
        }
    }
}

fn spawn_prove_worker(
    state: &AppState,
    key: JobKey,
    job_id: Uuid,
    tenant_id: &str,
    plan: &str,
    job_dir: &std::path::Path,
    req: ProveRequest,
) {
    let state2 = state.clone();
    let key2 = key.clone();
    let tenant_id2 = tenant_id.to_string();
    let plan2 = plan.to_string();
    let job_dir2 = job_dir.to_path_buf();
    let handle = tokio::spawn(async move {
        let prove_start = std::time::Instant::now();
        let cancel = {
            let mut jobs = state2.jobs.lock().expect("job lock");
            if let Some(job) = jobs.get_mut(&key2) {
                job.status = ProveJobStatus::Running;
                job.cancel.clone()
            } else {
                CancellationToken::new()
            }
        };
        let _ = write_json_atomic(job_dir2.join("status.json"), &ProveJobStatus::Running);
        if let Some(index) = state2.job_index.as_ref() {
            let _ = index.update_status(&tenant_id2, &job_id.to_string(), &ProveJobStatus::Running);
        }

        let plan_limits = PlanLimits::for_plan(&plan2);
        let max = Duration::from_secs(state2.cfg.max_prove_seconds.max(plan_limits.max_prove_seconds));
        let result = prove_with_worker_process(
            &job_dir2,
            &req,
            state2.cfg.allow_custom_programs,
            max,
            cancel,
        )
        .await;

        let status = match result {
            Ok(proof) => ProveJobStatus::Succeeded { proof },
            Err(err) => {
                error!(job_id=%job_id, "prove failed: {err}");
                ProveJobStatus::Failed {
                    error: err.to_string(),
                }
            }
        };

        let _ = write_json_atomic(job_dir2.join("status.json"), &status);
        if let Some(index) = state2.job_index.as_ref() {
            let _ = index.update_status(&tenant_id2, &job_id.to_string(), &status);
        }

        let elapsed_secs = prove_start.elapsed().as_secs_f64();
        state2.metrics.prove_duration.observe(elapsed_secs);
        match &status {
            ProveJobStatus::Succeeded { ref proof } => {
                state2
                    .metrics
                    .prove_completed
                    .with_label_values(&[&tenant_id2])
                    .inc();
                if let Some(ref usage) = state2.usage_log {
                    #[derive(serde::Deserialize)]
                    struct TraceOnly {
                        trace_length: usize,
                    }
                    let trace_len = serde_json::from_slice::<TraceOnly>(&proof.bytes)
                        .map(|t| t.trace_length)
                        .unwrap_or(0);
                    let _ = usage.record(
                        &tenant_id2,
                        &job_id.to_string(),
                        trace_len,
                        req.workload_id.as_deref(),
                        prove_start.elapsed().as_millis() as u64,
                    );
                    // Update billing metric.
                    let cost = usage_log::price_cents_pub(trace_len);
                    state2
                        .metrics
                        .usage_cents_total
                        .with_label_values(&[&tenant_id2])
                        .inc_by(cost);
                }
            }
            ProveJobStatus::Failed { ref error } => {
                state2
                    .metrics
                    .prove_failed
                    .with_label_values(&[&tenant_id2])
                    .inc();
                if let Some(ref usage) = state2.usage_log {
                    let _ = usage.record_failure(
                        &tenant_id2,
                        &job_id.to_string(),
                        error,
                        prove_start.elapsed().as_millis() as u64,
                    );
                }
            }
            _ => {}
        }

        state2.metrics.jobs_inflight.dec();
        let mut jobs = state2.jobs.lock().expect("job lock");
        if let Some(job) = jobs.get_mut(&key2) {
            job.status = status;
        }
    });

    let mut jobs = state.jobs.lock().expect("job lock");
    if let Some(job) = jobs.get_mut(&key) {
        job.handle = Some(handle);
    }
}

#[utoipa::path(
    post,
    path = "/prove",
    request_body = ProveRequest,
    responses((status = 200, body = ProveSubmitResponse))
)]
async fn prove_submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveSubmitResponse>, ApiError> {
    state.metrics.prove_submitted.inc();
    let job_id = Uuid::new_v4();

    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };
    let tenant_id = tenant.tenant_id.clone();

    let tenant_plan = tenant.plan.clone();
    if !check_rate_limit(&state, &tenant_id, &tenant_plan, RateEndpoint::Prove) {
        state
            .metrics
            .rate_limit_rejections
            .with_label_values(&["prove"])
            .inc();
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "prove rate limit exceeded".to_string(),
        });
    }

    let plan_limits = PlanLimits::for_plan(&tenant_plan);
    let max_inflight = plan_limits.max_inflight.min(state.cfg.max_inflight_jobs);

    // Usage cap enforcement.
    if let Some(ref usage) = state.usage_log {
        if let Ok(cost) = usage.monthly_cost_cents(&tenant_id, &tenant_plan) {
            if cost >= plan_limits.monthly_cap_cents {
                state.metrics.usage_cap_rejections.inc();
                return Err(ApiError {
                    status: StatusCode::PAYMENT_REQUIRED,
                    code: "usage_cap_reached",
                    message: "monthly usage cap reached".to_string(),
                });
            }
        }
    }

    let inflight = {
        let jobs = state
            .jobs
            .lock()
            .map_err(|_| ApiError::internal("job lock poisoned"))?;
        jobs.iter()
            .filter(|(k, j)| {
                k.tenant_id == tenant_id
                    && matches!(j.status, ProveJobStatus::Pending | ProveJobStatus::Running)
            })
            .count()
    };
    if inflight >= max_inflight {
        return Err(ApiError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_inflight",
            message: "too many in-flight prove jobs".to_string(),
        });
    }

    // Validate workload/template/program selection up-front.
    if let Some(tid) = req.template_id.as_deref() {
        if hc_workloads::templates::template_by_id(tid).is_none() {
            return Err(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "bad_request",
                message: format!("unknown template_id: {tid}"),
            });
        }
        if req.template_params.is_none() {
            return Err(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "bad_request",
                message: "template_params required when template_id is set".to_string(),
            });
        }
    } else if let Some(id) = req.workload_id.as_deref() {
        if !crate::workloads::known_workload(id) {
            return Err(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "bad_request",
                message: format!("unknown workload_id: {id}"),
            });
        }
    } else if !state.cfg.allow_custom_programs {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: "custom programs are disabled; supply workload_id or template_id".to_string(),
        });
    } else if req.program.as_ref().map_or(true, |p| p.is_empty()) {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: "missing program (custom programs enabled)".to_string(),
        });
    }

    // Server-side parameter caps.
    validate_prove_params(&req, &state.cfg)?;

    let job_dir = state
        .cfg
        .data_dir
        .join("jobs")
        .join(&tenant_id)
        .join(job_id.to_string());
    fs::create_dir_all(&job_dir).map_err(|err| ApiError::internal(err.to_string()))?;
    write_json_atomic(job_dir.join("request.json"), &req)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    write_json_atomic(job_dir.join("status.json"), &ProveJobStatus::Pending)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    if let Some(index) = state.job_index.as_ref() {
        let _ = index.upsert_request(
            &tenant_id,
            &job_id.to_string(),
            &req,
            &ProveJobStatus::Pending,
        );
    }

    let key = JobKey {
        tenant_id: tenant_id.clone(),
        job_id,
    };

    {
        let mut jobs = state
            .jobs
            .lock()
            .map_err(|_| ApiError::internal("job lock poisoned"))?;
        jobs.insert(
            key.clone(),
            JobState {
                status: ProveJobStatus::Pending,
                handle: None,
                cancel: CancellationToken::new(),
            },
        );
    }

    spawn_prove_worker(&state, key, job_id, &tenant_id, &tenant_plan, &job_dir, req);

    state.metrics.jobs_inflight.inc();

    Ok(Json(ProveSubmitResponse {
        job_id: job_id.to_string(),
    }))
}

fn count_job_dirs(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0)
}

fn reconcile_stale_jobs(data_dir: &std::path::Path, job_index: Option<&job_index::JobIndex>) {
    let jobs_dir = data_dir.join("jobs");
    let Ok(tenants) = fs::read_dir(&jobs_dir) else {
        return;
    };
    let mut count = 0usize;
    for tenant_entry in tenants.flatten() {
        let tenant_path = tenant_entry.path();
        if !tenant_path.is_dir() {
            continue;
        }
        let tenant_id = tenant_entry.file_name().to_string_lossy().to_string();
        let Ok(jobs) = fs::read_dir(&tenant_path) else {
            continue;
        };
        for job_entry in jobs.flatten() {
            let job_path = job_entry.path();
            if !job_path.is_dir() {
                continue;
            }
            let status_path = job_path.join("status.json");
            let Ok(bytes) = fs::read(&status_path) else {
                continue;
            };
            let Ok(status) = serde_json::from_slice::<ProveJobStatus>(&bytes) else {
                continue;
            };
            if matches!(status, ProveJobStatus::Pending | ProveJobStatus::Running) {
                let failed = ProveJobStatus::Failed {
                    error: "server restarted — job was in progress".to_string(),
                };
                let _ = write_json_atomic(&status_path, &failed);
                if let Some(index) = job_index {
                    let job_id = job_entry.file_name().to_string_lossy().to_string();
                    let _ = index.update_status(&tenant_id, &job_id, &failed);
                }
                count += 1;
            }
        }
    }
    if count > 0 {
        tracing::warn!(count, "reconciled stale jobs to Failed on startup");
    }
}

fn validate_prove_params(req: &ProveRequest, cfg: &ServerConfig) -> Result<(), ApiError> {
    if req.block_size > 1 && !req.block_size.is_power_of_two() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "block_size must be a power of two",
        ));
    }
    if req.block_size > cfg.max_block_size {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            format!(
                "block_size {} exceeds server maximum {}",
                req.block_size, cfg.max_block_size
            ),
        ));
    }
    if req.query_count < cfg.min_query_count {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            format!(
                "query_count {} is below server minimum {} for security",
                req.query_count, cfg.min_query_count
            ),
        ));
    }
    Ok(())
}

fn gc_tenant_jobs(data_dir: &std::path::Path, tenant_id: &str, retention_secs: u64) {
    if retention_secs == 0 {
        return;
    }
    let tenant_dir = data_dir.join("jobs").join(tenant_id);
    let Ok(entries) = fs::read_dir(&tenant_dir) else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let status_path = path.join("status.json");
        let Ok(bytes) = fs::read(&status_path) else {
            continue;
        };
        let Ok(status) = serde_json::from_slice::<ProveJobStatus>(&bytes) else {
            continue;
        };
        let is_terminal = matches!(
            status,
            ProveJobStatus::Succeeded { .. } | ProveJobStatus::Failed { .. }
        );
        if !is_terminal {
            continue;
        }
        let Ok(meta) = fs::metadata(&status_path) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let age_secs = now.saturating_sub(
            modified
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        if age_secs >= retention_secs {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

#[utoipa::path(
    get,
    path = "/prove/{job_id}",
    params(("job_id" = String, Path, description = "prove job id")),
    responses((status = 200, body = ProveJobStatus))
)]
async fn prove_get(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let parsed = match Uuid::parse_str(&job_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid job_id").into_response(),
    };
    // NOTE: this endpoint intentionally requires auth and is tenant-scoped.
    // Otherwise, job IDs become cross-tenant capability tokens.
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let key = JobKey {
        tenant_id: tenant.tenant_id.clone(),
        job_id: parsed,
    };
    if let Ok(jobs) = state.jobs.lock() {
        if let Some(job) = jobs.get(&key) {
            return Json(job.status.clone()).into_response();
        }
    }
    let job_dir = state
        .cfg
        .data_dir
        .join("jobs")
        .join(&tenant.tenant_id)
        .join(parsed.to_string());
    let status_path = job_dir.join("status.json");
    if !status_path.exists() {
        if let Some(index) = state.job_index.as_ref() {
            if let Ok(Some(status)) = index.get_status(&tenant.tenant_id, &parsed.to_string()) {
                return Json(status).into_response();
            }
        }
        return (StatusCode::NOT_FOUND, "unknown job_id").into_response();
    }
    match fs::read(&status_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ProveJobStatus>(&bytes).ok())
    {
        Some(status) => Json(status).into_response(),
        None => {
            if let Some(index) = state.job_index.as_ref() {
                if let Ok(Some(status)) = index.get_status(&tenant.tenant_id, &parsed.to_string()) {
                    return Json(status).into_response();
                }
            }
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to read status").into_response()
        }
    }
}

// ---- Batch prove endpoint ----

#[derive(serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct BatchProveRequest {
    /// List of prove requests to submit as a batch.
    pub requests: Vec<ProveRequest>,
}

#[derive(serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct BatchProveResponse {
    /// Job IDs for each submitted request (in order).
    pub job_ids: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/prove/batch",
    request_body = BatchProveRequest,
    responses((status = 200, body = BatchProveResponse))
)]
async fn prove_batch(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(batch): Json<BatchProveRequest>,
) -> Result<Json<BatchProveResponse>, ApiError> {
    if batch.requests.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "batch must contain at least one request",
        ));
    }
    if batch.requests.len() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "batch exceeds maximum size of 100",
        ));
    }

    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return Err(e),
    };

    if !check_rate_limit(&state, &tenant.tenant_id, &tenant.plan, RateEndpoint::Prove) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "prove rate limit exceeded",
        ));
    }

    // Usage cap enforcement.
    let plan_limits = PlanLimits::for_plan(&tenant.plan);
    if let Some(ref usage) = state.usage_log {
        if let Ok(cost) = usage.monthly_cost_cents(&tenant.tenant_id, &tenant.plan) {
            if cost >= plan_limits.monthly_cap_cents {
                state.metrics.usage_cap_rejections.inc();
                return Err(ApiError {
                    status: StatusCode::PAYMENT_REQUIRED,
                    code: "usage_cap_reached",
                    message: "monthly usage cap reached".to_string(),
                });
            }
        }
    }

    // Check batch fits within remaining rate quota.
    let remaining = remaining_rate_quota(&state, &tenant.tenant_id, &tenant.plan, RateEndpoint::Prove);
    if (batch.requests.len() as u32) > remaining && remaining != u32::MAX {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!(
                "batch of {} exceeds remaining rate quota of {}",
                batch.requests.len(),
                remaining
            ),
        ));
    }

    let mut job_ids = Vec::with_capacity(batch.requests.len());

    for req in batch.requests {
        let job_id = Uuid::new_v4();

        // Server-side parameter caps.
        validate_prove_params(&req, &state.cfg)?;

        // Validate each request.
        if let Some(id) = req.workload_id.as_deref() {
            if !crate::workloads::known_workload(id) {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    format!("unknown workload_id: {id}"),
                ));
            }
        } else if !state.cfg.allow_custom_programs {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "custom programs are disabled; supply workload_id",
            ));
        }

        let job_dir = state
            .cfg
            .data_dir
            .join("jobs")
            .join(&tenant.tenant_id)
            .join(job_id.to_string());
        fs::create_dir_all(&job_dir).map_err(|err| ApiError::internal(err.to_string()))?;
        write_json_atomic(job_dir.join("request.json"), &req)
            .map_err(|err| ApiError::internal(err.to_string()))?;
        write_json_atomic(job_dir.join("status.json"), &ProveJobStatus::Pending)
            .map_err(|err| ApiError::internal(err.to_string()))?;

        if let Some(index) = state.job_index.as_ref() {
            let _ = index.upsert_request(
                &tenant.tenant_id,
                &job_id.to_string(),
                &req,
                &ProveJobStatus::Pending,
            );
        }

        let key = JobKey {
            tenant_id: tenant.tenant_id.clone(),
            job_id,
        };
        {
            let mut jobs = state
                .jobs
                .lock()
                .map_err(|_| ApiError::internal("job lock poisoned"))?;
            jobs.insert(
                key.clone(),
                JobState {
                    status: ProveJobStatus::Pending,
                    handle: None,
                    cancel: CancellationToken::new(),
                },
            );
        }

        spawn_prove_worker(&state, key, job_id, &tenant.tenant_id, &tenant.plan, &job_dir, req);
        state.metrics.jobs_inflight.inc();

        job_ids.push(job_id.to_string());
    }

    Ok(Json(BatchProveResponse { job_ids }))
}

// ---- Shared proof-loading helper ----

/// Load a completed proof for a tenant + job_id.
///
/// Checks in-memory jobs first, falls back to disk.
/// Returns 409 Conflict if the job exists but isn't succeeded, 404 if not found.
fn load_completed_proof(
    state: &AppState,
    tenant_id: &str,
    job_id: Uuid,
) -> Result<hc_sdk::types::ProofBytes, ApiError> {
    let key = JobKey {
        tenant_id: tenant_id.to_string(),
        job_id,
    };
    let status = if let Ok(jobs) = state.jobs.lock() {
        jobs.get(&key).map(|j| j.status.clone())
    } else {
        None
    };

    match status {
        Some(ProveJobStatus::Succeeded { proof }) => Ok(proof),
        Some(_) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_ready",
            "proof is not yet available",
        )),
        None => {
            let job_dir = state
                .cfg
                .data_dir
                .join("jobs")
                .join(tenant_id)
                .join(job_id.to_string());
            let status_path = job_dir.join("status.json");
            match fs::read(&status_path)
                .ok()
                .and_then(|b| serde_json::from_slice::<ProveJobStatus>(&b).ok())
            {
                Some(ProveJobStatus::Succeeded { proof }) => Ok(proof),
                Some(_) => Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "not_ready",
                    "proof is not yet available",
                )),
                None => Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "unknown job_id",
                )),
            }
        }
    }
}

// ---- Proof inspection endpoint ----

/// GET /prove/:job_id/inspect — detailed proof breakdown with verification summary.
#[utoipa::path(
    get,
    path = "/prove/{job_id}/inspect",
    params(("job_id" = String, Path, description = "prove job id")),
    responses(
        (status = 200, body = hc_sdk::types::ProofInspection),
        (status = 404, description = "Job not found"),
        (status = 409, description = "Proof not yet ready")
    )
)]
async fn prove_inspect(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<hc_sdk::types::ProofInspection>, ApiError> {
    let parsed = Uuid::parse_str(&job_id).map_err(|_| {
        ApiError::new(StatusCode::BAD_REQUEST, "bad_request", "invalid job_id")
    })?;
    let tenant = guarded_auth(&state, &headers)?;

    let proof_bytes = load_completed_proof(&state, &tenant.tenant_id, parsed)?;

    // Decode and verify with summary in a blocking task (CPU-bound).
    let inspection = tokio::task::spawn_blocking(move || -> Result<hc_sdk::types::ProofInspection, String> {
        let start = std::time::Instant::now();

        let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, true);
        if !result.ok {
            return Err(format!("verification failed: {}", result.error.unwrap_or_default()));
        }
        let verify_ms = start.elapsed().as_millis() as u64;

        // Decode proof to extract structural metadata.
        let decoded: serde_json::Value = serde_json::from_slice(&proof_bytes.bytes)
            .map_err(|e| format!("failed to decode proof: {e}"))?;

        let trace_length = decoded.get("trace_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let initial_acc = decoded.get("initial_acc")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let final_acc = decoded.get("final_acc")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Extract commitment digests (hex-encoded in proof JSON).
        let trace_commitment = decoded.get("trace_commitment")
            .and_then(|v| v.as_str())
            .unwrap_or("").to_string();
        let composition_commitment = decoded.get("composition_commitment")
            .and_then(|v| v.as_str())
            .unwrap_or("").to_string();

        let version = proof_bytes.version;
        let scheme = if version == 2 { "KZG" } else { "STARK" };

        Ok(hc_sdk::types::ProofInspection {
            trace_commitment_digest: trace_commitment.clone(),
            initial_acc,
            final_acc,
            trace_length,
            query_commitments: hc_sdk::types::QueryCommitmentsJson {
                trace_commitment,
                composition_commitment,
                fri_commitment: String::new(),
            },
            commitment_scheme: scheme.to_string(),
            version,
            verify_time_ms: verify_ms,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("inspection task failed: {e}")))?
    .map_err(|e| ApiError::internal(e))?;

    Ok(Json(inspection))
}

// ---- Calldata endpoint ----

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct CalldataResponse {
    /// Hex-encoded ABI calldata for on-chain verification.
    pub calldata: String,
    /// Size in bytes.
    pub size_bytes: usize,
}

#[utoipa::path(
    get,
    path = "/proof/{job_id}/calldata",
    params(("job_id" = String, Path, description = "prove job id")),
    responses((status = 200, body = CalldataResponse))
)]
async fn proof_calldata(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let parsed = match Uuid::parse_str(&job_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid job_id").into_response(),
    };
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let proof_bytes = match load_completed_proof(&state, &tenant.tenant_id, parsed) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    // Decode proof and produce EVM calldata.
    let output = match decode_proof_bytes(&proof_bytes) {
        Ok(o) => o,
        Err(err) => {
            return ApiError::internal(format!("failed to decode proof: {err}")).into_response()
        }
    };
    let evm_proof = match evm_proof::encode_evm_proof(&output) {
        Ok(p) => p,
        Err(err) => {
            return ApiError::internal(format!("failed to encode EVM proof: {err}")).into_response()
        }
    };
    let calldata = evm_proof::to_abi_calldata(&evm_proof);
    let hex_calldata = hex::encode(&calldata);

    Json(CalldataResponse {
        size_bytes: calldata.len(),
        calldata: format!("0x{hex_calldata}"),
    })
    .into_response()
}

// ---- Template discovery + template-based proving ----

/// Pick a sensible block_size based on program instruction count.
fn smart_block_size(program_len: usize) -> usize {
    match program_len {
        0..=16 => 2,
        17..=128 => 4,
        _ => 8,
    }
}

/// GET /templates — list all available proof templates (public, no auth).
#[utoipa::path(get, path = "/templates", responses((status = 200, body = TemplateListResponse)))]
async fn templates_list() -> Json<TemplateListResponse> {
    let templates = hc_workloads::templates::list_templates();
    let summaries: Vec<TemplateSummary> = templates
        .iter()
        .map(|t| TemplateSummary {
            id: t.id.to_string(),
            summary: t.summary.to_string(),
            tags: t.tags.iter().map(|s| s.to_string()).collect(),
            cost_category: t.cost_category.to_string(),
        })
        .collect();
    let count = summaries.len();
    Json(TemplateListResponse {
        templates: summaries,
        count,
    })
}

/// GET /templates/:template_id — get full template info with parameter schema (public, no auth).
#[utoipa::path(get, path = "/templates/{template_id}", params(("template_id" = String, Path, description = "Template identifier")), responses((status = 200), (status = 404)))]
async fn template_detail(
    Path(template_id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let tmpl = hc_workloads::templates::template_by_id(&template_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("unknown template: {template_id}"),
        )
    })?;
    let info = tmpl.to_info();
    Ok(Json(serde_json::to_value(info).unwrap_or_default()).into_response())
}

/// POST /prove/template/:template_id — submit a proof job using a named template.
#[utoipa::path(post, path = "/prove/template/{template_id}", params(("template_id" = String, Path, description = "Template identifier")), request_body = TemplateProveRequest, responses((status = 200, body = ProveSubmitResponse), (status = 400), (status = 429)))]
async fn prove_template(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(template_id): Path<String>,
    Json(req): Json<TemplateProveRequest>,
) -> Result<Json<ProveSubmitResponse>, ApiError> {
    state.metrics.prove_submitted.inc();

    let tenant = guarded_auth(&state, &headers)?;
    let tenant_id = tenant.tenant_id.clone();
    let tenant_plan = tenant.plan.clone();

    if !check_rate_limit(&state, &tenant_id, &tenant_plan, RateEndpoint::Prove) {
        state
            .metrics
            .rate_limit_rejections
            .with_label_values(&["prove"])
            .inc();
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "prove rate limit exceeded",
        ));
    }

    let plan_limits = PlanLimits::for_plan(&tenant_plan);
    let max_inflight = plan_limits.max_inflight.min(state.cfg.max_inflight_jobs);

    if let Some(ref usage) = state.usage_log {
        if let Ok(cost) = usage.monthly_cost_cents(&tenant_id, &tenant_plan) {
            if cost >= plan_limits.monthly_cap_cents {
                state.metrics.usage_cap_rejections.inc();
                return Err(ApiError::new(
                    StatusCode::PAYMENT_REQUIRED,
                    "usage_cap_reached",
                    "monthly usage cap reached",
                ));
            }
        }
    }

    let inflight = {
        let jobs = state
            .jobs
            .lock()
            .map_err(|_| ApiError::internal("job lock poisoned"))?;
        jobs.iter()
            .filter(|(k, j)| {
                k.tenant_id == tenant_id
                    && matches!(j.status, ProveJobStatus::Pending | ProveJobStatus::Running)
            })
            .count()
    };
    if inflight >= max_inflight {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_inflight",
            "too many in-flight prove jobs",
        ));
    }

    // Validate template and build program (fail fast on bad params).
    let build = hc_workloads::templates::build_from_template(&template_id, &req.params)
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("template build failed: {e}"),
            )
        })?;

    let zk = req.zk.unwrap_or(build.recommended_zk);
    let zk_mask_degree = if zk { Some(1) } else { None };
    let program_len = build.program.len();
    let block_size = req.block_size.unwrap_or_else(|| smart_block_size(program_len));
    let fri_final_poly_size = req.fri_final_poly_size.unwrap_or(2);

    // Build a ProveRequest for the worker pipeline.
    let prove_req = ProveRequest {
        workload_id: None,
        template_id: Some(template_id.clone()),
        template_params: Some(req.params.clone()),
        program: None,
        initial_acc: build.initial_acc,
        final_acc: build.final_acc,
        block_size,
        fri_final_poly_size,
        query_count: 80,
        lde_blowup_factor: 2,
        zk_mask_degree,
    };

    validate_prove_params(&prove_req, &state.cfg)?;

    let job_id = Uuid::new_v4();
    let job_dir = state
        .cfg
        .data_dir
        .join("jobs")
        .join(&tenant_id)
        .join(job_id.to_string());
    fs::create_dir_all(&job_dir).map_err(|err| ApiError::internal(err.to_string()))?;
    write_json_atomic(job_dir.join("request.json"), &prove_req)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    write_json_atomic(job_dir.join("status.json"), &ProveJobStatus::Pending)
        .map_err(|err| ApiError::internal(err.to_string()))?;
    if let Some(index) = state.job_index.as_ref() {
        let _ = index.upsert_request(
            &tenant_id,
            &job_id.to_string(),
            &prove_req,
            &ProveJobStatus::Pending,
        );
    }

    let key = JobKey {
        tenant_id: tenant_id.clone(),
        job_id,
    };
    {
        let mut jobs = state
            .jobs
            .lock()
            .map_err(|_| ApiError::internal("job lock poisoned"))?;
        jobs.insert(
            key.clone(),
            JobState {
                status: ProveJobStatus::Pending,
                handle: None,
                cancel: CancellationToken::new(),
            },
        );
    }

    spawn_prove_worker(
        &state,
        key,
        job_id,
        &tenant_id,
        &tenant_plan,
        &job_dir,
        prove_req,
    );
    state.metrics.jobs_inflight.inc();

    Ok(Json(ProveSubmitResponse {
        job_id: job_id.to_string(),
    }))
}

/// POST /estimate — estimate cost and resource requirements (public, no auth).
#[utoipa::path(post, path = "/estimate", request_body = EstimateRequest, responses((status = 200, body = EstimateResponse), (status = 400)))]
async fn estimate(Json(req): Json<EstimateRequest>) -> Result<Json<EstimateResponse>, ApiError> {
    let program_len = if let Some(ref tid) = req.template_id {
        let params = req.params.as_ref().ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "params required when template_id is set",
            )
        })?;
        let build = hc_workloads::templates::build_from_template(tid, params).map_err(|e| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("template build failed: {e}"),
            )
        })?;
        build.program.len()
    } else if let Some(len) = req.program_length {
        len
    } else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "must provide template_id or program_length",
        ));
    };

    let block_size = req.block_size.unwrap_or_else(|| smart_block_size(program_len));
    let trace_length = program_len.max(1).next_power_of_two() * block_size;
    let cost_cents = usage_log::price_cents_pub(trace_length);

    let tier = match trace_length {
        0..=9_999 => "Tiny",
        10_000..=99_999 => "Standard",
        100_000..=999_999 => "Large",
        1_000_000..=9_999_999 => "Enterprise",
        _ => "XL",
    };

    let base_time_ms = (trace_length as f64 * 0.5) as u64;
    let time_range = EstimateRange {
        min: (base_time_ms as f64 * 0.5).max(50.0) as u64,
        max: (base_time_ms as f64 * 2.0).max(200.0) as u64,
    };

    let base_size = (trace_length as f64).log2() as u64 * 2000 + 5000;
    let size_range = EstimateRange {
        min: (base_size as f64 * 0.7) as u64,
        max: (base_size as f64 * 1.5) as u64,
    };

    Ok(Json(EstimateResponse {
        estimated_trace_length: trace_length,
        tier: tier.to_string(),
        estimated_cost_cents: cost_cents,
        estimated_time_ms: time_range,
        estimated_proof_size_bytes: size_range,
    }))
}

// ---- Aggregate endpoint ----

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AggregateRequest {
    /// Job IDs of completed proofs to aggregate (1-100).
    pub job_ids: Vec<String>,
    /// Maximum recursion tree depth (default 4).
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Fan-in per aggregation level (default 8).
    #[serde(default)]
    pub fan_in: Option<usize>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct AggregateResponse {
    pub status: String,
    pub proof_count: usize,
    /// Hex-encoded Blake3 root digest of the aggregation tree.
    pub root_digest: String,
    /// Aggregation wall-clock time in milliseconds.
    pub aggregation_time_ms: u64,
    /// Per-proof verification summaries.
    pub summaries: Vec<AggregateProofSummary>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct AggregateProofSummary {
    pub trace_commitment_digest: String,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_length: usize,
}

#[utoipa::path(
    post,
    path = "/aggregate",
    request_body = AggregateRequest,
    responses(
        (status = 200, body = AggregateResponse),
        (status = 400, description = "Bad request"),
        (status = 409, description = "One or more proofs not ready")
    )
)]
async fn aggregate(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AggregateRequest>,
) -> Result<Json<AggregateResponse>, ApiError> {
    let tenant = guarded_auth(&state, &headers)?;

    if !check_rate_limit(&state, &tenant.tenant_id, &tenant.plan, RateEndpoint::Prove) {
        state
            .metrics
            .rate_limit_rejections
            .with_label_values(&["prove"])
            .inc();
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
        ));
    }

    if req.job_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "must provide at least one job_id",
        ));
    }
    if req.job_ids.len() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "aggregate batch exceeds maximum of 100 proofs",
        ));
    }

    // Load and decode all proofs into verifier Proof objects.
    let mut verifier_proofs = Vec::with_capacity(req.job_ids.len());
    for jid_str in &req.job_ids {
        let jid = Uuid::parse_str(jid_str).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid job_id: {jid_str}"),
            )
        })?;
        let proof_bytes = load_completed_proof(&state, &tenant.tenant_id, jid)?;
        let output = decode_proof_bytes(&proof_bytes).map_err(|e| {
            ApiError::internal(format!("failed to decode proof {jid_str}: {e}"))
        })?;

        verifier_proofs.push(hc_verifier::Proof {
            version: output.version,
            trace_commitment: output.trace_commitment,
            composition_commitment: output.composition_commitment,
            fri_proof: output.fri_proof,
            initial_acc: output.public_inputs.initial_acc,
            final_acc: output.public_inputs.final_acc,
            query_response: output.query_response,
            trace_length: output.trace_length,
            params: output.params,
        });
    }

    let spec = hc_recursion::RecursionSpec {
        max_depth: req.max_depth.unwrap_or(4),
        fan_in: req.fan_in.unwrap_or(8),
    };

    // Aggregation is CPU-intensive — run on blocking thread pool.
    let start = std::time::Instant::now();
    let aggregated = tokio::task::spawn_blocking(move || {
        hc_recursion::aggregate_with_spec(&spec, &verifier_proofs)
    })
    .await
    .map_err(|e| ApiError::internal(format!("aggregation task failed: {e}")))?
    .map_err(|e| ApiError::internal(format!("aggregation failed: {e}")))?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    let summaries: Vec<AggregateProofSummary> = aggregated
        .summaries
        .iter()
        .map(|s| {
            use hc_core::field::FieldElement;
            AggregateProofSummary {
                trace_commitment_digest: hex::encode(s.trace_commitment_digest.as_bytes()),
                initial_acc: s.initial_acc.to_u64(),
                final_acc: s.final_acc.to_u64(),
                trace_length: s.trace_length,
            }
        })
        .collect();

    // Record usage — bill aggregate based on total trace length.
    if let Some(ref usage) = state.usage_log {
        let total_trace: usize = aggregated.summaries.iter().map(|s| s.trace_length).sum();
        let _ = usage.record(
            &tenant.tenant_id,
            &format!("agg-{}", Uuid::new_v4()),
            total_trace,
            Some("aggregate"),
            elapsed_ms,
        );
    }

    Ok(Json(AggregateResponse {
        status: "completed".to_string(),
        proof_count: aggregated.total_proofs,
        root_digest: hex::encode(aggregated.digest.as_bytes()),
        aggregation_time_ms: elapsed_ms,
        summaries,
    }))
}

// ---- Job list/cancel/delete endpoints ----

#[derive(serde::Deserialize)]
struct JobListQuery {
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn prove_list(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<JobListQuery>,
) -> impl IntoResponse {
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let Some(index) = state.job_index.as_ref() else {
        return ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "job index is disabled",
        )
        .into_response();
    };
    let limit = query.limit.unwrap_or(50).min(200);
    let offset = query.offset.unwrap_or(0);
    match index.list_jobs(&tenant.tenant_id, query.status.as_deref(), limit, offset) {
        Ok((jobs, total)) => {
            let resp = hc_sdk::types::JobListResponse {
                jobs: jobs
                    .into_iter()
                    .map(|j| hc_sdk::types::JobSummary {
                        job_id: j.job_id,
                        status: j.status_tag,
                        updated_at_ms: j.updated_at_ms as u64,
                    })
                    .collect(),
                total,
            };
            Json(resp).into_response()
        }
        Err(err) => ApiError::internal(err.to_string()).into_response(),
    }
}

async fn prove_cancel(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let parsed = match Uuid::parse_str(&job_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid job_id").into_response(),
    };
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let key = JobKey {
        tenant_id: tenant.tenant_id.clone(),
        job_id: parsed,
    };
    let mut jobs = state.jobs.lock().expect("job lock");
    let Some(job) = jobs.get_mut(&key) else {
        return (StatusCode::NOT_FOUND, "unknown job_id").into_response();
    };
    match &job.status {
        ProveJobStatus::Pending | ProveJobStatus::Running => {
            job.cancel.cancel();
            job.status = ProveJobStatus::Failed {
                error: "cancelled by user".to_string(),
            };
            let status = job.status.clone();
            drop(jobs);
            state.metrics.jobs_inflight.dec();
            // Update on disk + index.
            let job_dir = state
                .cfg
                .data_dir
                .join("jobs")
                .join(&tenant.tenant_id)
                .join(parsed.to_string());
            let _ = write_json_atomic(job_dir.join("status.json"), &status);
            if let Some(index) = state.job_index.as_ref() {
                let _ = index.update_status(&tenant.tenant_id, &parsed.to_string(), &status);
            }
            Json(serde_json::json!({"status": "cancelled"})).into_response()
        }
        _ => ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "job is already in a terminal state",
        )
        .into_response(),
    }
}

async fn prove_delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let parsed = match Uuid::parse_str(&job_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid job_id").into_response(),
    };
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let key = JobKey {
        tenant_id: tenant.tenant_id.clone(),
        job_id: parsed,
    };

    // Only allow deletion of terminal jobs.
    let is_terminal = {
        let jobs = state.jobs.lock().expect("job lock");
        if let Some(job) = jobs.get(&key) {
            matches!(
                job.status,
                ProveJobStatus::Succeeded { .. } | ProveJobStatus::Failed { .. }
            )
        } else {
            true // Not in memory — check disk
        }
    };

    if !is_terminal {
        return ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "can only delete terminal jobs",
        )
        .into_response();
    }

    // Remove from in-memory map.
    {
        let mut jobs = state.jobs.lock().expect("job lock");
        jobs.remove(&key);
    }

    // Remove from disk.
    let job_dir = state
        .cfg
        .data_dir
        .join("jobs")
        .join(&tenant.tenant_id)
        .join(parsed.to_string());
    if job_dir.exists() {
        let _ = fs::remove_dir_all(&job_dir);
    }

    // Remove from index.
    if let Some(index) = state.job_index.as_ref() {
        let _ = index.delete_job(&tenant.tenant_id, &parsed.to_string());
    }

    Json(serde_json::json!({"deleted": true})).into_response()
}

// ---- Usage endpoint ----

#[derive(serde::Deserialize)]
struct UsageQuery {
    since: Option<u64>,
    until: Option<u64>,
}

#[utoipa::path(
    get,
    path = "/usage",
    params(
        ("since" = Option<u64>, Query, description = "start of period (epoch ms)"),
        ("until" = Option<u64>, Query, description = "end of period (epoch ms)")
    ),
    responses((status = 200, body = UsageSummary))
)]
async fn usage(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<UsageQuery>,
) -> impl IntoResponse {
    let tenant = match guarded_auth(&state, &headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let Some(ref usage_log) = state.usage_log else {
        return ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            "usage tracking is disabled",
        )
        .into_response();
    };

    // Default to current calendar month.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let since = query.since.unwrap_or_else(|| {
        // Approximate start of current month (good enough for billing windows).
        let secs = now_ms / 1000;
        let day_secs = secs % 86400;
        let days_since_epoch = secs / 86400;
        // Back up to ~day 1 of month.
        let mut remaining = days_since_epoch;
        let mut year = 1970u64;
        loop {
            let diy = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                366
            } else {
                365
            };
            if remaining < diy {
                break;
            }
            remaining -= diy;
            year += 1;
        }
        let month_days: &[u64] = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
            &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut dom = remaining;
        for &md in month_days {
            if dom < md {
                break;
            }
            dom -= md;
        }
        let month_start_secs = secs - (dom * 86400) - day_secs;
        month_start_secs * 1000
    });
    let until = query.until.unwrap_or(now_ms);

    match usage_log.query_usage(&tenant.tenant_id, &tenant.plan, since, until) {
        Ok(summary) => Json(summary).into_response(),
        Err(err) => ApiError::internal(err.to_string()).into_response(),
    }
}

pub fn parse_instructions(items: &[String]) -> anyhow::Result<Vec<Instruction>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let lower = item.trim().to_ascii_lowercase();
        let parts: Vec<&str> = lower.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "addimm" | "add_immediate" | "addimmediate" => {
                let arg = parts
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("missing arg for {item}"))?;
                let v: u64 = arg.parse()?;
                out.push(Instruction::AddImmediate(v));
            }
            _ => anyhow::bail!("unknown instruction {item}"),
        }
    }
    Ok(out)
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "code": self.code,
                "message": self.message,
            }
        });
        (self.status, Json(body)).into_response()
    }
}

fn write_json_atomic<T: serde::Serialize>(
    path: impl AsRef<FsPath>,
    value: &T,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

async fn prove_with_worker_process(
    job_dir: &FsPath,
    req: &ProveRequest,
    allow_custom_programs: bool,
    max: Duration,
    cancel: CancellationToken,
) -> anyhow::Result<hc_sdk::types::ProofBytes> {
    // Re-check server-side safety invariants before spawning the worker.
    if req.workload_id.is_none() && !allow_custom_programs {
        anyhow::bail!(
            "custom programs are disabled; supply workload_id (e.g. \"toy_add_1_2\") or enable HC_SERVER_ALLOW_CUSTOM_PROGRAMS"
        );
    }

    let request_path = PathBuf::from(job_dir).join("request.json");
    let out_path = PathBuf::from(job_dir).join("proof.json");

    let worker = worker_executable_path();
    let mut child = tokio::process::Command::new(worker)
        .arg("--request")
        .arg(&request_path)
        .arg("--out")
        .arg(&out_path)
        .env(
            "HC_SERVER_ALLOW_CUSTOM_PROGRAMS",
            if allow_custom_programs {
                "true"
            } else {
                "false"
            },
        )
        .spawn()
        .map_err(|err| anyhow::anyhow!("failed to spawn hc-worker: {err}"))?;

    let wait_fut = async {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                anyhow::bail!("prove cancelled");
            }
            status = child.wait() => {
                let status = status?;
                if !status.success() {
                    anyhow::bail!("hc-worker exited with status {status}");
                }
                Ok::<(), anyhow::Error>(())
            }
        }
    };

    timeout(max, wait_fut).await.map_err(|_| {
        // Kill on timeout to actually reclaim CPU.
        // Note: ignore kill errors (process may have already exited).
        // Best-effort cancellation is still a big improvement over spawn_blocking.
        anyhow::anyhow!("prove timeout")
    })??;

    let bytes = fs::read(&out_path).with_context(|| format!("read {}", out_path.display()))?;
    let proof: hc_sdk::types::ProofBytes =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", out_path.display()))?;
    Ok(proof)
}

fn worker_executable_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("HC_SERVER_WORKER_PATH") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    // Common production layout (Dockerfile): /app/hc-server and /app/hc-worker.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("hc-worker");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    // Fallback to PATH lookup.
    PathBuf::from("hc-worker")
}
