use rmcp::model::{CallToolResult, Content};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::ErrorData;

use crate::types::PollJobParams;
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn poll_job_impl(
        &self,
        Parameters(params): Parameters<PollJobParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let status = self
            .executor
            .poll(&params.job_id)
            .await
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let resp = match &status {
            crate::types::JobStatus::Succeeded => serde_json::json!({
                "job_id": params.job_id,
                "status": status.label(),
                "hint": "Call get_proof to retrieve the proof bytes, or get_proof_summary for a human-readable summary.",
            }),
            crate::types::JobStatus::Failed { error } => serde_json::json!({
                "job_id": params.job_id,
                "status": status.label(),
                "error": error,
            }),
            _ => serde_json::json!({
                "job_id": params.job_id,
                "status": status.label(),
                "hint": "Call poll_job again in a moment.",
            }),
        };
        let json = Content::json(resp)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}
