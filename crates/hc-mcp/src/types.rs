use serde::{Deserialize, Serialize};

// ── Discovery request/response types ────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DescribeTemplateParams {
    #[schemars(description = "Template ID to describe. Call list_templates to see available IDs.")]
    pub template_id: String,
}

// ── Proving request/response types ──────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProveTemplateParams {
    #[schemars(description = "Template ID. Call list_templates to see available options.")]
    pub template_id: String,
    #[schemars(description = "Template parameters as JSON object. Call describe_template for the parameter schema.")]
    pub parameters: serde_json::Map<String, serde_json::Value>,
    #[schemars(description = "Enable zero-knowledge mode. Default: use template recommendation.")]
    pub zk: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProveWorkloadParams {
    #[schemars(description = "Registered workload ID. Call list_workloads to see available options.")]
    pub workload_id: String,
    #[schemars(description = "Initial accumulator value.")]
    pub initial_acc: u64,
    #[schemars(description = "Expected final accumulator value.")]
    pub final_acc: u64,
    #[schemars(description = "Block size for the prover (power of 2). Default: 2.")]
    pub block_size: Option<usize>,
}

// ── Job monitoring types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollJobParams {
    #[schemars(description = "Job ID returned by prove_template or prove_workload.")]
    pub job_id: String,
}

// ── Verification types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyProofParams {
    #[schemars(description = "Base64-encoded proof bytes (from get_proof).")]
    pub proof_b64: String,
}

// ── Output types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProofParams {
    #[schemars(description = "Job ID of a completed proof job.")]
    pub job_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetProofSummaryParams {
    #[schemars(description = "Job ID of a completed proof job.")]
    pub job_id: String,
}

// ── Internal types (not exposed via MCP schema) ─────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed { error: String },
}

impl JobStatus {
    pub fn label(&self) -> &'static str {
        match self {
            JobStatus::Pending => "pending",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed { .. } => "failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct JobEntry {
    pub status: JobStatus,
    pub proof_bytes: Option<hc_sdk::types::ProofBytes>,
    pub template_id: Option<String>,
    pub initial_acc: u64,
    pub final_acc: u64,
}
