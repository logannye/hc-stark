use anyhow::Result;
use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use hc_server::auth::AuthConfig;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Default exact-match Origin allowlist. CLI / desktop clients (Claude Code,
/// Claude Desktop, Cursor) typically send no Origin header at all, so a missing
/// Origin is allowed. Deployments may add entries via HC_MCP_ALLOWED_ORIGINS
/// (comma-separated). Browser-based clients on any subdomain of anthropic.com
/// or claude.ai are accepted via the suffix list below — that covers Claude.ai,
/// Cowork, and any future Anthropic surface without a redeploy.
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "https://tinyzkp.com",
    "https://www.tinyzkp.com",
    "https://mcp.tinyzkp.com",
    "http://localhost",
    "http://127.0.0.1",
];

const ALLOWED_HOST_SUFFIXES: &[&str] = &[
    ".anthropic.com",
    ".claude.ai",
    "anthropic.com",
    "claude.ai",
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

    // Exact-match allowlist (with port/path tolerance)
    if allowlist.iter().any(|allowed| {
        s == allowed.as_str()
            || s.starts_with(&format!("{}:", allowed))
            || s.starts_with(&format!("{}/", allowed))
    }) {
        return true;
    }

    // Suffix-match for *.anthropic.com / *.claude.ai (https only)
    if let Some(rest) = s.strip_prefix("https://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return ALLOWED_HOST_SUFFIXES.iter().any(|suf| {
            host == suf.trim_start_matches('.') || host.ends_with(suf)
        });
    }

    false
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

/// Bearer-token authentication middleware.
///
/// Behavior is driven by `HC_MCP_REQUIRE_AUTH`:
/// - `true`: every request must carry a valid `Authorization: Bearer ...`.
///   Missing or invalid tokens get 401.
/// - `false` (default): authentication is optional. Requests with a valid
///   Bearer token attach a `TenantContext` and bypass the anonymous
///   global-cap lane; requests without the header fall through to the
///   anonymous path (existing public MCP behavior, bounded by
///   HC_MCP_MAX_INFLIGHT). Invalid tokens still get 401 — the only way to
///   ride the anonymous lane is to send no Authorization header at all.
///
/// On success, the tenant id (if any) is stamped onto the request as
/// `x-mcp-tenant` so downstream observability + per-tenant accounting can
/// pick it up without re-parsing the auth header.
async fn validate_auth(
    auth: Arc<AuthConfig>,
    require: bool,
    req: Request,
    next: Next,
) -> Response {
    let header_present = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .is_some();

    if !header_present {
        if require {
            tracing::warn!("rejecting request: HC_MCP_REQUIRE_AUTH=true but no Authorization header");
            return (StatusCode::UNAUTHORIZED, "missing Authorization header").into_response();
        }
        // Anonymous public lane.
        let mut req = req;
        req.headers_mut().remove("x-mcp-tenant");
        return next.run(req).await;
    }

    match auth.authenticate(req.headers()) {
        Ok(tenant) => {
            tracing::debug!(tenant_id = %tenant.tenant_id, plan = %tenant.plan, "mcp request authenticated");
            let mut req = req;
            // Stamp tenant id onto the request for downstream consumers.
            // Sanitize: only alphanumerics + hyphen + underscore make it
            // through, so a tenant id never injects header weirdness.
            let safe = tenant
                .tenant_id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect::<String>();
            if let Ok(v) = HeaderValue::from_str(&safe) {
                req.headers_mut().insert("x-mcp-tenant", v);
            }
            next.run(req).await
        }
        Err((code, msg)) => {
            tracing::warn!(%code, %msg, "rejecting request: auth failed");
            (code, msg).into_response()
        }
    }
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

    // Build auth config from the same sources hc-server uses, so a single
    // tenant.keys file or HC_SERVER_API_KEYS env governs both surfaces.
    // If neither is set, AuthConfig is empty; the optional-Bearer middleware
    // still works (it just rejects any non-empty token).
    let mut auth_cfg = AuthConfig::from_env()?;
    if let Ok(file_path) = std::env::var("HC_SERVER_API_KEYS_FILE") {
        let path = PathBuf::from(file_path);
        if path.exists() {
            let file_auth = AuthConfig::from_file(&path)?;
            auth_cfg.merge(&file_auth);
        }
    }
    let auth = Arc::new(auth_cfg);
    let require_auth = std::env::var("HC_MCP_REQUIRE_AUTH")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    if require_auth && !auth.is_enabled() {
        anyhow::bail!(
            "HC_MCP_REQUIRE_AUTH=true but no API keys are configured \
             (set HC_SERVER_API_KEYS or HC_SERVER_API_KEYS_FILE). \
             Refusing to start with closed-door auth and an empty key set."
        );
    }
    tracing::info!(
        require_auth,
        keys_configured = auth.is_enabled(),
        "mcp auth middleware initialized"
    );

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

    let auth_for_layer = auth.clone();
    let router = axum::Router::new()
        .nest_service("/mcp", service)
        // Order matters: auth runs first so an unauthorized request never
        // reaches the MCP service. validate_origin still applies to all
        // paths (browser-based clients).
        .layer(middleware::from_fn(move |req, next| {
            let auth = auth_for_layer.clone();
            async move { validate_auth(auth, require_auth, req, next).await }
        }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request as AxumRequest};
    use axum::routing::get;

    /// Build a small test router that runs validate_auth in front of an
    /// always-200 handler, then return a tower::ServiceExt-style call.
    async fn run(
        auth: AuthConfig,
        require: bool,
        bearer: Option<&str>,
    ) -> (StatusCode, Option<String>) {
        let auth = Arc::new(auth);
        let auth_layer = auth.clone();
        let app: axum::Router = axum::Router::new()
            .route(
                "/test",
                get(
                    |headers: axum::http::HeaderMap| async move {
                        let tenant = headers
                            .get("x-mcp-tenant")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        (StatusCode::OK, tenant.unwrap_or_default())
                    },
                ),
            )
            .layer(middleware::from_fn(move |req, next| {
                let a = auth_layer.clone();
                async move { validate_auth(a, require, req, next).await }
            }));

        let mut req = AxumRequest::builder()
            .method(Method::GET)
            .uri("/test");
        if let Some(b) = bearer {
            req = req.header(axum::http::header::AUTHORIZATION, format!("Bearer {b}"));
        }
        let req = req.body(Body::empty()).unwrap();

        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).ok();
        (status, body)
    }

    #[tokio::test]
    async fn anonymous_lane_passes_through_when_auth_is_optional() {
        let auth = AuthConfig::from_pairs(&[("acme", "tzk_test")]);
        let (status, body) = run(auth, false, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_deref(), Some("")); // no tenant stamped
    }

    #[tokio::test]
    async fn anonymous_lane_rejected_when_auth_required() {
        let auth = AuthConfig::from_pairs(&[("acme", "tzk_test")]);
        let (status, _) = run(auth, true, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_bearer_rejected_even_in_optional_mode() {
        // The only way to hit the anonymous lane is to send no Authorization
        // header at all. A header with a bogus token is a hard 401, never
        // a soft fall-through — otherwise an attacker could probe keys
        // without ever risking a 401.
        let auth = AuthConfig::from_pairs(&[("acme", "tzk_test")]);
        let (status, _) = run(auth, false, Some("tzk_wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_bearer_stamps_tenant_id() {
        let auth = AuthConfig::from_pairs(&[("acme", "tzk_test")]);
        let (status, body) = run(auth, false, Some("tzk_test")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn tenant_id_is_sanitized_for_header_safety() {
        // A tenant_id with weird characters must not be able to inject
        // header content. We restrict to [A-Za-z0-9-_].
        let auth = AuthConfig::from_pairs(&[("acme\r\nX-Evil: yes", "tzk_test")]);
        let (status, body) = run(auth, false, Some("tzk_test")).await;
        assert_eq!(status, StatusCode::OK);
        // The injected sequence is stripped.
        assert!(body.as_deref().unwrap().chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "got: {body:?}");
    }
}
