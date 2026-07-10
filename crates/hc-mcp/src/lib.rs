#![forbid(unsafe_code)]

pub mod error;
#[cfg(feature = "legacy-research")]
pub mod executor;
pub mod tools;
#[cfg(feature = "legacy-research")]
pub mod types;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::model::{
    CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{tool_handler, tool_router, ErrorData, ServerHandler};

#[cfg(feature = "legacy-research")]
use crate::executor::ProveExecutor;

pub const PRODUCTION_TOOL_NAMES: &[&str] = &["get_capabilities"];

/// Configuration for the maintenance-mode MCP server.
#[derive(Clone, Debug)]
pub struct McpConfig {
    pub max_inflight: usize,
}

impl McpConfig {
    pub fn from_env() -> Self {
        let max_inflight = std::env::var("HC_MCP_MAX_INFLIGHT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(2);
        Self { max_inflight }
    }
}

/// Maintenance-mode TinyZKP MCP server. Production discovery intentionally
/// exposes no proving, verification, polling, or receipt tools.
#[derive(Clone)]
pub struct HcMcpServer {
    pub config: McpConfig,
    #[cfg(feature = "legacy-research")]
    pub executor: std::sync::Arc<ProveExecutor>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HcMcpServer {
    pub fn new(config: McpConfig) -> Self {
        Self {
            #[cfg(feature = "legacy-research")]
            executor: std::sync::Arc::new(ProveExecutor::new(config.max_inflight)),
            config,
            tool_router: Self::tool_router(),
        }
    }

    #[rmcp::tool(
        description = "Get TinyZKP release identity, Plonky3 backend compatibility target, maintenance state, and the safe next action.",
        annotations(
            title = "Get TinyZKP Capabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_capabilities(&self) -> Result<CallToolResult, ErrorData> {
        self.get_capabilities_impl().await
    }
}

#[tool_handler]
impl ServerHandler for HcMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(Implementation::new("tinyzkp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "TinyZKP is in Plonky3 backend recovery. Hosted proving, verification, account creation, paid Compute, and historical receipt workflows are disabled. Only get_capabilities is exposed. Run the open-source benchmark or apply for a fixed-scope evaluation.",
            )
    }
}
