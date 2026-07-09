use anyhow::Result;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    "mcp.tinyzkp.com",
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
];
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "https://tinyzkp.com",
    "https://www.tinyzkp.com",
    "https://mcp.tinyzkp.com",
];

#[derive(serde::Serialize)]
struct ReleaseInfo {
    service: &'static str,
    package_version: &'static str,
    release_sha: Option<String>,
    release_ref: Option<String>,
    build_url: Option<String>,
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn version() -> Json<ReleaseInfo> {
    Json(ReleaseInfo {
        service: "mcp",
        package_version: env!("CARGO_PKG_VERSION"),
        release_sha: nonempty_env("HC_RELEASE_SHA"),
        release_ref: nonempty_env("HC_RELEASE_REF"),
        build_url: nonempty_env("HC_RELEASE_BUILD_URL"),
    })
}

fn comma_separated_env(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn allowed_hosts() -> Vec<String> {
    let mut hosts = DEFAULT_ALLOWED_HOSTS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    hosts.extend(comma_separated_env("HC_MCP_ALLOWED_HOSTS"));
    hosts
}

fn allowed_origins() -> Vec<String> {
    let mut origins = DEFAULT_ALLOWED_ORIGINS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    origins.extend(comma_separated_env("HC_MCP_ALLOWED_ORIGINS"));
    origins
}

fn origin_allowed(origin: &HeaderValue, allowlist: &[String]) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    allowlist.iter().any(|allowed| origin == allowed)
}

async fn validate_origin(request: Request, next: Next) -> Response {
    if let Some(origin) = request.headers().get(axum::http::header::ORIGIN) {
        if !origin_allowed(origin, &allowed_origins()) {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    next.run(request).await
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let host = std::env::var("HC_MCP_HTTP_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("HC_MCP_HTTP_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3001);
    let cancellation = CancellationToken::new();
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(true)
        .with_json_response(false)
        .with_sse_keep_alive(Some(std::time::Duration::from_secs(30)))
        .with_cancellation_token(cancellation.child_token())
        .with_allowed_hosts(allowed_hosts());
    let service: StreamableHttpService<hc_mcp::HcMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(hc_mcp::HcMcpServer::new(hc_mcp::McpConfig::from_env())),
            Default::default(),
            config,
        );
    let router = axum::Router::new()
        .route("/version", get(version))
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(validate_origin));
    let bind = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "TinyZKP capability-only MCP listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancellation.cancel();
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_policy_is_exact_and_fail_closed() {
        let allowed = allowed_origins();
        assert!(origin_allowed(
            &HeaderValue::from_static("https://tinyzkp.com"),
            &allowed
        ));
        assert!(!origin_allowed(
            &HeaderValue::from_static("https://tinyzkp.com.attacker.example"),
            &allowed
        ));
    }
}
