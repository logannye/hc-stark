use crate::object_store::SignedUrl;
use hc_plonky3::contracts::{
    AirPackageV1, AirProofBundleV1, HostedProofBundleV1, PublicInputsV1, TraceManifestV1,
};
use hc_stream::ResourceEstimate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    pub label: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub prefix: String,
    pub key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAirRequest {
    pub air: AirPackageV1,
    pub local_proof: AirProofBundleV1,
}

#[derive(Debug, Serialize)]
pub struct RegisterAirResponse {
    pub air_package_id: Uuid,
    pub air_digest_hex: String,
    pub release_sha: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUploadRequest {
    pub air_package_id: Uuid,
    pub manifest: TraceManifestV1,
}

#[derive(Debug, Serialize)]
pub struct UploadChunkUrl {
    pub index: u32,
    pub object_key: String,
    pub upload: SignedUrl,
}

#[derive(Debug, Serialize)]
pub struct CreateUploadResponse {
    pub upload_id: Uuid,
    pub expires_in_seconds: u64,
    pub chunks: Vec<UploadChunkUrl>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJobRequest {
    pub air_package_id: Uuid,
    pub upload_id: Uuid,
    pub public_inputs: PublicInputsV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdmissionEstimate {
    pub resources: ResourceEstimate,
    pub predicted_wall_time_ms: u64,
    pub quoted_charge_millicredits: u64,
    pub reservation_millicredits: u64,
}

#[derive(Debug, Serialize)]
pub struct CreateJobResponse {
    pub job_id: Uuid,
    pub status: String,
    pub estimate: AdmissionEstimate,
}

#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub job_id: Uuid,
    pub status: String,
    pub estimate: AdmissionEstimate,
    pub progress: Option<Value>,
    pub settled_millicredits: Option<u64>,
    pub error_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BundleResponse {
    pub download: SignedUrl,
    pub size_bytes: u64,
    pub blake3_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub bundle: HostedProofBundleV1,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub proof_digest_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    pub sku: String,
    pub success_url: String,
    pub cancel_url: String,
    #[serde(default)]
    pub synthetic_canary: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortalRequest {
    pub return_url: String,
}

#[derive(Debug, Serialize)]
pub struct RedirectResponse {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerClaimRequest {
    pub release_sha: String,
    pub free_scratch_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct WorkerClaimResponse {
    pub job_id: Uuid,
    pub attempt: u32,
    pub lease_epoch: u64,
    pub lease_seconds: u64,
    pub air: AirPackageV1,
    pub manifest: TraceManifestV1,
    pub public_inputs: PublicInputsV1,
    pub input_chunks: Vec<UploadChunkUrl>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerHeartbeatRequest {
    pub attempt: u32,
    pub lease_epoch: u64,
    pub free_scratch_bytes: u64,
    pub progress: Option<Value>,
    pub checkpoint_identity: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorkerHeartbeatResponse {
    pub lease_seconds: u64,
    pub cancel_requested: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerOutputUrlRequest {
    pub attempt: u32,
    pub lease_epoch: u64,
    pub content_length: u64,
    pub blake3_hex: String,
}

#[derive(Debug, Serialize)]
pub struct WorkerOutputUrlResponse {
    pub object_key: String,
    pub upload: SignedUrl,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerCompleteRequest {
    pub attempt: u32,
    pub lease_epoch: u64,
    pub object_key: String,
    pub content_length: u64,
    pub blake3_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkerFailureRequest {
    pub attempt: u32,
    pub lease_epoch: u64,
    pub code: String,
    pub retryable: bool,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub tenant_id: String,
    pub plan: String,
    pub subscription_millicredits: u64,
    pub purchased_millicredits: u64,
    pub reserved_millicredits: u64,
    pub paid_work_frozen: bool,
}
