use base64::Engine;
use rmcp::model::{CallToolResult, Content};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ErrorData;

use crate::types::VerifyProofParams;
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn verify_proof_impl(
        &self,
        Parameters(params): Parameters<VerifyProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&params.proof_b64)
            .map_err(|e| {
                ErrorData::invalid_params(
                    format!("Invalid base64 in proof_b64: {e}. Use the exact string returned by get_proof."),
                    None,
                )
            })?;

        let proof_bytes: hc_sdk::types::ProofBytes =
            serde_json::from_slice(&bytes).map_err(|e| {
                ErrorData::invalid_params(
                    format!("Invalid proof format: {e}. Use the exact bytes returned by get_proof."),
                    None,
                )
            })?;

        let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, false);
        let resp = serde_json::json!({
            "valid": result.ok,
            "error": result.error,
        });
        let json = Content::json(resp)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}
