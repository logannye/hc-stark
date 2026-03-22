use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// Opaque proof payload (currently JSON).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProofBytes {
    /// Proof format version.
    pub version: u32,
    /// Serialized proof bytes.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct VerifyRequest {
    pub proof: ProofBytes,
    /// Whether to allow legacy v2 proofs.
    pub allow_legacy_v2: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProveRequest {
    /// Optional built-in workload identifier.
    ///
    /// If provided, the server will ignore `program` and use a fixed workload shipped with the repo.
    #[serde(default)]
    pub workload_id: Option<String>,
    /// Optional proof template identifier (e.g. "range_proof", "accumulator_step").
    ///
    /// When set, `template_params` must also be provided. The template builds the program
    /// and determines initial_acc/final_acc automatically.
    #[serde(default)]
    pub template_id: Option<String>,
    /// JSON parameters for the proof template. Required when `template_id` is set.
    #[serde(default)]
    pub template_params: Option<serde_json::Map<String, serde_json::Value>>,
    /// Optional VM program instructions (toy workload).
    ///
    /// Production deployments should disable custom programs and require `workload_id`.
    #[serde(default)]
    pub program: Option<Vec<String>>,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub block_size: usize,
    pub fri_final_poly_size: usize,
    #[serde(default = "default_query_count")]
    pub query_count: usize,
    #[serde(default = "default_lde_blowup")]
    pub lde_blowup_factor: usize,
    /// Optional ZK masking degree (enables v4 ZK proofs when set > 0).
    #[serde(default)]
    pub zk_mask_degree: Option<usize>,
}

fn default_query_count() -> usize {
    80
}

fn default_lde_blowup() -> usize {
    2
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProveSubmitResponse {
    pub job_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ProveJobStatus {
    Pending,
    Running,
    Succeeded { proof: ProofBytes },
    Failed { error: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct VerifyResult {
    pub ok: bool,
    /// Human-readable error string on failure.
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JobSummary {
    pub job_id: String,
    pub status: String,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct JobListResponse {
    pub jobs: Vec<JobSummary>,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct UsageSummary {
    pub total_proofs: u64,
    pub total_verifies: u64,
    pub failed_proofs: u64,
    pub estimated_cost_cents: u64,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
}

// ── Template discovery types ─────────────────────────────────────────────────

/// Summary of a proof template (for listing).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TemplateSummary {
    pub id: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub cost_category: String,
}

/// Response for GET /templates.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateSummary>,
    pub count: usize,
}

/// Request body for POST /prove/template/:template_id.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TemplateProveRequest {
    /// Template parameters as a JSON object. Keys and types depend on the template.
    pub params: serde_json::Map<String, Value>,
    /// Override zero-knowledge mode. If omitted, uses the template's recommendation.
    #[serde(default)]
    pub zk: Option<bool>,
    /// Override block_size (must be power of 2). Omit for smart default.
    #[serde(default)]
    pub block_size: Option<usize>,
    /// Override FRI final polynomial size. Omit for smart default.
    #[serde(default)]
    pub fri_final_poly_size: Option<usize>,
}

// ── Cost estimation types ────────────────────────────────────────────────────

/// Request body for POST /estimate.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct EstimateRequest {
    /// Template ID (mutually exclusive with program_length).
    #[serde(default)]
    pub template_id: Option<String>,
    /// Template parameters (required if template_id is set).
    #[serde(default)]
    pub params: Option<serde_json::Map<String, Value>>,
    /// Raw program instruction count (alternative to template_id).
    #[serde(default)]
    pub program_length: Option<usize>,
    /// Block size override.
    #[serde(default)]
    pub block_size: Option<usize>,
}

/// Response for POST /estimate.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct EstimateResponse {
    pub estimated_trace_length: usize,
    pub tier: String,
    pub estimated_cost_cents: u64,
    pub estimated_time_ms: EstimateRange,
    pub estimated_proof_size_bytes: EstimateRange,
}

/// A min/max range for estimates.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct EstimateRange {
    pub min: u64,
    pub max: u64,
}

// ── Proof inspection types ───────────────────────────────────────────────────

/// Detailed proof breakdown returned by GET /prove/:job_id/inspect.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ProofInspection {
    /// Hex-encoded trace commitment digest (32 bytes).
    pub trace_commitment_digest: String,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_length: usize,
    pub query_commitments: QueryCommitmentsJson,
    pub commitment_scheme: String,
    pub version: u32,
    pub verify_time_ms: u64,
}

/// Query commitment digests (hex-encoded).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct QueryCommitmentsJson {
    pub trace_commitment: String,
    pub composition_commitment: String,
    pub fri_commitment: String,
}
