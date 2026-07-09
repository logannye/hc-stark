//! Production HTTP surface during the Plonky3 backend recovery.
//!
//! Historical server/prover code remains in `src/lib.rs` for offline research,
//! but this is the only library target compiled into production artifacts.

#![forbid(unsafe_code)]

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    maintenance_mode: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            // Production builds have no proving implementation to enable.
            maintenance_mode: true,
        }
    }
}

#[derive(Serialize)]
struct ReleaseInfo {
    service: &'static str,
    package_version: &'static str,
    release_sha: Option<String>,
    release_ref: Option<String>,
    build_url: Option<String>,
}

#[derive(Serialize)]
struct Capabilities {
    maintenance_mode: bool,
    service_status: &'static str,
    backend: &'static str,
    plonky3_version: &'static str,
    compatibility_profile: &'static str,
    proof_format: &'static str,
    verifier: &'static str,
    proving_available: bool,
    verification_available: bool,
    account_creation_enabled: bool,
    checkout_enabled: bool,
    legacy_verification: &'static str,
    benchmarking_available: bool,
    release: ReleaseInfo,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    error: &'static str,
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn release_info() -> ReleaseInfo {
    ReleaseInfo {
        service: "api",
        package_version: env!("CARGO_PKG_VERSION"),
        release_sha: nonempty_env("HC_RELEASE_SHA"),
        release_ref: nonempty_env("HC_RELEASE_REF"),
        build_url: nonempty_env("HC_RELEASE_BUILD_URL"),
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn version() -> Json<ReleaseInfo> {
    Json(release_info())
}

async fn capabilities(State(state): State<Arc<AppState>>) -> Json<Capabilities> {
    Json(Capabilities {
        maintenance_mode: state.maintenance_mode,
        service_status: "backend_recovery",
        backend: "plonky3",
        plonky3_version: "0.6.1",
        compatibility_profile: "tinyzkp-p3-goldilocks-v1",
        proof_format: "official_plonky3",
        verifier: "unmodified_official_plonky3",
        proving_available: false,
        verification_available: false,
        account_creation_enabled: false,
        checkout_enabled: false,
        legacy_verification: "offline_research_only",
        benchmarking_available: true,
        release: release_info(),
    })
}

async fn protocol_upgrade() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "protocol_upgrade",
            error: "hosted proving is disabled while the resource-bounded Plonky3 backend is independently reviewed",
        }),
    )
        .into_response()
}

async fn verify_unavailable(body: Bytes) -> Response {
    let version = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .pointer("/proof/version")
                .and_then(|value| value.as_u64())
        });
    if version.is_some_and(|version| version < 9) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorBody {
                code: "legacy_statement_unbound",
                error: "legacy v5/v7 proofs are not statement-bound and are rejected by hosted verification",
            }),
        )
            .into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "protocol_upgrade",
            error: "hosted verification is disabled during the Plonky3 backend review",
        }),
    )
        .into_response()
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/version", get(version))
        .route("/v1/capabilities", get(capabilities))
        .route("/verify", post(verify_unavailable))
        .route("/prove", any(protocol_upgrade))
        .route("/prove/*path", any(protocol_upgrade))
        .route("/proof/*path", any(protocol_upgrade))
        .route("/templates", any(protocol_upgrade))
        .route("/templates/*path", any(protocol_upgrade))
        .route("/estimate", any(protocol_upgrade))
        .route("/aggregate", any(protocol_upgrade))
        .route("/usage", any(protocol_upgrade))
        .route("/v1/*path", any(protocol_upgrade))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state))
}

pub fn test_state_maintenance(_temp_dir: std::path::PathBuf) -> AppState {
    AppState::default()
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let bind = std::env::var("HC_SERVER_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "TinyZKP maintenance API listening");
    axum::serve(listener, build_app(AppState::default()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
