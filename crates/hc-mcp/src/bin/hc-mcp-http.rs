use anyhow::Result;
use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Default Origin allowlist. Keep this conservative; deployments add to it via
/// HC_MCP_ALLOWED_ORIGINS (comma-separated). Browser-based MCP clients send an
/// Origin header; CLI / desktop clients (Claude Code, Claude Desktop, Cursor)
/// typically do not, so a missing Origin is allowed.
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "https://claude.ai",
    "https://www.claude.ai",
    "https://api.anthropic.com",
    "https://tinyzkp.com",
    "https://www.tinyzkp.com",
    "https://mcp.tinyzkp.com",
    "http://localhost",
    "http://127.0.0.1",
];

fn allowed_origins() -> Vec<String> {
    let mut out: Vec<String> = DEFAULT_ALLOWED_ORIGINS.iter().map(|s| s.to_string()).collect();
    if let Ok(extra) = std::env::var("HC_MCP_ALLOWED_ORIGINS") {
        for o in extra.split(',') {
            let o = o.trim();
            if !o.is_empty() {
                out.push(o.to_string());
            }
        }
    }
    out
}

fn origin_allowed(origin: &HeaderValue, allowlist: &[String]) -> bool {
    let Ok(s) = origin.to_str() else { return false };
    allowlist.iter().any(|allowed| {
        s == allowed.as_str()
            || s.starts_with(&format!("{}:", allowed))
            || s.starts_with(&format!("{}/", allowed))
    })
}

async fn validate_origin(req: Request, next: Next) -> Response {
    let allowlist = allowed_origins();
    if let Some(origin) = req.headers().get(axum::http::header::ORIGIN) {
        if !origin_allowed(origin, &allowlist) {
            tracing::warn!(?origin, "rejecting request: origin not in allowlist");
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    next.run(req).await
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let host = std::env::var("HC_MCP_HTTP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("HC_MCP_HTTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3001);

    let ct = CancellationToken::new();

    let config = StreamableHttpServerConfig {
        stateful_mode: true,
        json_response: false,
        sse_keep_alive: Some(std::time::Duration::from_secs(30)),
        cancellation_token: ct.child_token(),
        ..Default::default()
    };

    let service: StreamableHttpService<hc_mcp::HcMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            || {
                let mcp_config = hc_mcp::McpConfig::from_env();
                Ok(hc_mcp::HcMcpServer::new(mcp_config))
            },
            Default::default(),
            config,
        );

    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn(validate_origin));

    let addr = format!("{host}:{port}");
    let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("hc-stark MCP server (HTTP) listening on http://{addr}/mcp");

    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            ct.cancel();
        })
        .await?;

    Ok(())
}
