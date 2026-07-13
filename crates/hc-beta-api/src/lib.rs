pub mod auth;
pub mod billing;
pub mod config;
pub mod error;
pub mod github;
pub mod idempotency;
pub mod models;
pub mod object_store;
pub mod public;
pub mod retention;
pub mod stripe;
pub mod worker_routes;

use crate::{
    config::Config, github::GithubClient, object_store::ObjectStore, stripe::StripeClient,
};
use anyhow::Context;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub object_store: ObjectStore,
    pub github: GithubClient,
    pub stripe: StripeClient,
    pub verify_slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Debug)]
pub struct Tenant {
    pub tenant_id: String,
    pub plan: String,
}

impl AppState {
    pub async fn create(config: Config) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(24)
            .acquire_timeout(Duration::from_secs(5))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    // PgBouncer's transaction pooling and PostgreSQL's extended
                    // query protocol reject multiple commands in one prepared
                    // statement. Keep each connection setting independent.
                    sqlx::query("SET statement_timeout = '10s'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET lock_timeout = '3s'")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&config.database_url)
            .await
            .context("connect to beta PostgreSQL")?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("apply beta migrations")?;
        let object_store = ObjectStore::new(
            config.r2_bucket.clone(),
            &config.r2_endpoint,
            &config.r2_region,
        )
        .await?;
        let github = GithubClient::new(
            config.github_client_id.clone(),
            config.github_client_secret.clone(),
            config.github_callback_url.clone(),
        );
        let stripe = StripeClient::new(
            config.stripe_secret_key.clone(),
            config.stripe_webhook_secret.clone(),
            config.stripe_portal_configuration.clone(),
            &config.stripe_prices_json,
        )?;
        Ok(Self {
            pool,
            config: Arc::new(config),
            object_store,
            github,
            stripe,
            verify_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        })
    }
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/discovery", get(discovery))
        .route("/v1/auth/github/start", get(public::github_start))
        .route("/v1/auth/github/callback", get(public::github_callback))
        .route("/v1/me", get(public::me))
        .route(
            "/v1/api-keys",
            get(public::list_api_keys).post(public::create_api_key),
        )
        .route("/v1/api-keys/:id", delete(public::revoke_api_key))
        .route("/v1/account", delete(public::delete_account))
        .route("/v1/air-packages", post(public::register_air))
        .route("/v1/uploads", post(public::create_upload))
        .route(
            "/v1/proof-jobs",
            get(public::list_jobs).post(public::create_job),
        )
        .route("/v1/proof-jobs/:id", get(public::get_job))
        .route("/v1/proof-jobs/:id/cancel", post(public::cancel_job))
        .route("/v1/proof-jobs/:id/bundle", get(public::get_bundle))
        .route("/v1/verify", post(public::verify))
        .route("/v1/billing/checkout-sessions", post(billing::checkout))
        .route("/v1/billing/portal-sessions", post(billing::portal))
        .route("/webhooks/stripe", post(billing::webhook))
        .layer(DefaultBodyLimit::max(110 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .with_state(state)
}

pub fn worker_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/internal/v1/workers/draining",
            post(worker_routes::draining),
        )
        .route(
            "/internal/v1/leases/startup-validate",
            post(worker_routes::startup_validate),
        )
        .route("/internal/v1/leases/claim", post(worker_routes::claim))
        .route(
            "/internal/v1/jobs/:id/heartbeat",
            post(worker_routes::heartbeat),
        )
        .route(
            "/internal/v1/jobs/:id/output-url",
            post(worker_routes::output_url),
        )
        .route(
            "/internal/v1/jobs/:id/complete",
            post(worker_routes::complete),
        )
        .route(
            "/internal/v1/jobs/:id/cancelled",
            post(worker_routes::cancelled),
        )
        .route(
            "/internal/v1/jobs/:id/failure",
            post(worker_routes::failure),
        )
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    let public_bind = config.public_bind;
    let worker_bind = config.worker_bind;
    let state = AppState::create(config).await?;
    let public = TcpListener::bind(public_bind).await?;
    let worker = TcpListener::bind(worker_bind).await?;
    tracing::info!(%public_bind, %worker_bind, release_sha = %state.config.release_sha, "hc-beta-api ready");
    let public_task = axum::serve(public, public_router(state.clone()));
    let worker_task = axum::serve(worker, worker_router(state.clone()));
    let billing_task = tokio::spawn(billing::run_event_processor(state));
    tokio::select! {
        result = public_task => result.context("public HTTP listener stopped")?,
        result = worker_task => result.context("worker HTTP listener stopped")?,
        result = billing_task => result.context("billing event processor stopped")?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Serialize)]
struct Discovery {
    service: &'static str,
    service_status: &'static str,
    release_sha: String,
    signup: bool,
    checkout: bool,
    hosted_proving: bool,
    disclosures: [&'static str; 4],
}

async fn discovery(State(state): State<AppState>) -> Json<Discovery> {
    let public = state.config.exposure == config::ExposureMode::PublicBeta;
    let writes = public && state.config.writes_enabled;
    Json(Discovery {
        service: "hc-beta-api",
        service_status: if public {
            "public_beta"
        } else {
            "operator_canary"
        },
        release_sha: state.config.release_sha.clone(),
        signup: writes,
        checkout: writes,
        hosted_proving: writes,
        disclosures: [
            "public beta",
            "not independently audited",
            "no SLA",
            "Goldilocks and frozen Plonky3 0.6.1 profile only",
        ],
    })
}
