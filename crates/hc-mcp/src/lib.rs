#![forbid(unsafe_code)]

pub mod error;
pub mod executor;
pub mod tools;
pub mod types;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData, ServerHandler, tool_handler, tool_router};

use crate::executor::ProveExecutor;

/// Configuration for the MCP server.
#[derive(Clone, Debug)]
pub struct McpConfig {
    pub max_inflight: usize,
}

impl McpConfig {
    pub fn from_env() -> Self {
        let max_inflight = std::env::var("HC_MCP_MAX_INFLIGHT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        Self { max_inflight }
    }
}

/// The hc-stark MCP server.
#[derive(Clone)]
pub struct HcMcpServer {
    pub config: McpConfig,
    pub executor: std::sync::Arc<ProveExecutor>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HcMcpServer {
    pub fn new(config: McpConfig) -> Self {
        let executor = std::sync::Arc::new(ProveExecutor::new(config.max_inflight));
        Self {
            config,
            executor,
            tool_router: Self::tool_router(),
        }
    }

    #[rmcp::tool(
        description = "List all available proof templates with IDs, summaries, and tags. Use this to discover what kinds of proofs you can generate.",
        annotations(title = "List Proof Templates", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_templates(&self) -> Result<CallToolResult, ErrorData> {
        self.list_templates_impl().await
    }

    #[rmcp::tool(
        description = "List all registered workload IDs. Workloads are predefined proof programs.",
        annotations(title = "List Workloads", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn list_workloads(&self) -> Result<CallToolResult, ErrorData> {
        self.list_workloads_impl().await
    }

    #[rmcp::tool(
        description = "Get full parameter schema and example JSON for a specific proof template. Call this before prove_template to understand what parameters are needed.",
        annotations(title = "Describe Proof Template", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn describe_template(
        &self,
        params: Parameters<types::DescribeTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.describe_template_impl(params).await
    }

    #[rmcp::tool(
        description = "Get server capabilities, version, and recommended workflow. Start here if you're unsure what this server can do.",
        annotations(title = "Get Server Capabilities", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_capabilities(&self) -> Result<CallToolResult, ErrorData> {
        self.get_capabilities_impl().await
    }

    #[rmcp::tool(
        description = "Generate a zero-knowledge proof from a template ID and parameters. Returns a job_id — call poll_job to check progress. Consumes one proof from your monthly quota.",
        annotations(title = "Generate Proof from Template", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn prove_template(
        &self,
        params: Parameters<types::ProveTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.prove_template_impl(params).await
    }

    #[rmcp::tool(
        description = "Generate a proof from a registered workload ID. Returns a job_id — call poll_job to check progress. Consumes one proof from your monthly quota.",
        annotations(title = "Generate Proof from Workload", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn prove_workload(
        &self,
        params: Parameters<types::ProveWorkloadParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.prove_workload_impl(params).await
    }

    #[rmcp::tool(
        description = "Check the status of a proof job. Returns: pending, running, succeeded, or failed.",
        annotations(title = "Poll Proof Job Status", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn poll_job(
        &self,
        params: Parameters<types::PollJobParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.poll_job_impl(params).await
    }

    #[rmcp::tool(
        description = "Verify a proof independently. Pass the base64-encoded proof from get_proof. Returns {valid: true/false}. This is a pure cryptographic check — no quota consumed.",
        annotations(title = "Verify Proof", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn verify_proof(
        &self,
        params: Parameters<types::VerifyProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.verify_proof_impl(params).await
    }

    #[rmcp::tool(
        description = "Retrieve the base64-encoded proof bytes for a completed job. Pass the result to verify_proof for independent verification.",
        annotations(title = "Get Proof Bytes", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_proof(
        &self,
        params: Parameters<types::GetProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get_proof_impl(params).await
    }

    #[rmcp::tool(
        description = "Get a human-readable summary of what a proof job attests to, including template, public inputs, and status.",
        annotations(title = "Get Proof Summary", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn get_proof_summary(
        &self,
        params: Parameters<types::GetProofSummaryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get_proof_summary_impl(params).await
    }
}

#[tool_handler]
impl ServerHandler for HcMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_03_26,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "hc-stark".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                ..Default::default()
            },
            instructions: Some(
                "hc-stark ZK proving service. Workflow: \
                 (1) list_templates or get_capabilities to discover what's available, \
                 (2) describe_template to get parameter schema, \
                 (3) prove_template to submit a proof job, \
                 (4) poll_job until succeeded, \
                 (5) get_proof to retrieve the proof, \
                 (6) verify_proof to independently verify."
                    .to_string(),
            ),
        }
    }
}
