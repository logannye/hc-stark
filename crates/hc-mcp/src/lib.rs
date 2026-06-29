#![forbid(unsafe_code)]

pub mod error;
pub mod executor;
pub mod tools;
pub mod types;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{tool_handler, tool_router, ErrorData, ServerHandler};

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
    #[allow(dead_code)]
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
        description = "List supported proof templates exposed by this deployment with IDs, lifecycle status, summaries, and tags. Treat only live templates as generally available.",
        annotations(
            title = "List Proof Templates",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_templates(&self) -> Result<CallToolResult, ErrorData> {
        self.list_templates_impl().await
    }

    #[rmcp::tool(
        description = "List registered workload IDs for supported long-running or reviewed proving workflows.",
        annotations(
            title = "List Workloads",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn list_workloads(&self) -> Result<CallToolResult, ErrorData> {
        self.list_workloads_impl().await
    }

    #[rmcp::tool(
        description = "Get full parameter schema and example JSON for a specific proof template. Call this before prove_template to understand what parameters are needed.",
        annotations(
            title = "Describe Proof Template",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn describe_template(
        &self,
        params: Parameters<types::DescribeTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.describe_template_impl(params).await
    }

    #[rmcp::tool(
        description = "Get server capabilities, product boundary, version, and recommended proof-receipt workflow. Start here if you're unsure what this server can do.",
        annotations(
            title = "Get Server Capabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_capabilities(&self) -> Result<CallToolResult, ErrorData> {
        self.get_capabilities_impl().await
    }

    #[rmcp::tool(
        description = "Generate a state-transition receipt from a template ID and parameters. Returns a job_id — call poll_job to check progress. Billable prove job; verification remains free.",
        annotations(
            title = "Generate Proof from Template",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn prove_template(
        &self,
        params: Parameters<types::ProveTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.prove_template_impl(params).await
    }

    #[rmcp::tool(
        description = "Submit a supported workload or Compute proof job. Returns a job_id; call poll_job to check progress. Successful hosted proving is billable, and verification remains free.",
        annotations(
            title = "Generate Proof from Workload",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn prove_workload(
        &self,
        params: Parameters<types::ProveWorkloadParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.prove_workload_impl(params).await
    }

    #[rmcp::tool(
        description = "Check the status of a proof job. Returns: pending, running, succeeded, or failed.",
        annotations(
            title = "Poll Proof Job Status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn poll_job(
        &self,
        params: Parameters<types::PollJobParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.poll_job_impl(params).await
    }

    #[rmcp::tool(
        description = "Verify a proof independently. Pass the base64-encoded proof from get_proof. Returns {valid: true/false}. This is a pure cryptographic check — no quota consumed.",
        annotations(
            title = "Verify Proof",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn verify_proof(
        &self,
        params: Parameters<types::VerifyProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.verify_proof_impl(params).await
    }

    #[rmcp::tool(
        description = "Retrieve proof_b64 plus a tracked public verifier_url for a completed job, with receipt_url included when the proof fits the public share-link limit. Open the URL for browser verification, or pass proof_b64 to verify_proof for independent verification.",
        annotations(
            title = "Get Proof Bytes",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_proof(
        &self,
        params: Parameters<types::GetProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get_proof_impl(params).await
    }

    #[rmcp::tool(
        description = "Get a human-readable summary of what a proof job attests to, including template, public inputs, status, and a shareable verifier URL when the proof fits the public receipt-share limit.",
        annotations(
            title = "Get Proof Summary",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
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
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_03_26)
            .with_server_info(Implementation::new("hc-stark", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "TinyZKP proof-receipt service for supported transparent STARK state-transition workflows. \
                 Workflow: (1) get_capabilities or list_templates to discover live templates and limits, \
                 (2) describe_template to get the statement boundary and parameter schema, \
                 (3) prove_template to submit a proof-receipt job, \
                 (4) poll_job until succeeded, \
                 (5) get_proof or get_proof_summary to attach the receipt to the agent output, \
                 (6) verify_proof before trusting external receipts. Do not put secrets or private customer data into transparent parameters."
            )
    }
}
