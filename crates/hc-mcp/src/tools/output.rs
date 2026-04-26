use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::{GetProofParams, GetProofSummaryParams, JobStatus};
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn get_proof_impl(
        &self,
        Parameters(params): Parameters<GetProofParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let entry = self
            .executor
            .get_entry(&params.job_id)
            .await
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        match entry.status {
            JobStatus::Succeeded => {}
            _ => {
                return Err(ErrorData::invalid_params(
                    format!(
                        "Job '{}' is not complete (status: {}). Call poll_job first.",
                        params.job_id,
                        entry.status.label()
                    ),
                    None,
                ));
            }
        }

        let proof = entry.proof_bytes.ok_or_else(|| {
            ErrorData::internal_error("proof bytes missing for succeeded job".to_string(), None)
        })?;

        let json_bytes = serde_json::to_vec(&proof)
            .map_err(|e| ErrorData::internal_error(format!("serialize error: {e}"), None))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&json_bytes);

        let resp = serde_json::json!({
            "job_id": params.job_id,
            "proof_b64": b64,
            "proof_version": proof.version,
            "size_bytes": json_bytes.len(),
            "hint": "Pass proof_b64 to verify_proof to independently verify.",
        });
        let json = Content::json(resp)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn get_proof_summary_impl(
        &self,
        Parameters(params): Parameters<GetProofSummaryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let entry = self
            .executor
            .get_entry(&params.job_id)
            .await
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let status_label = entry.status.label();
        let template_desc = entry.template_id.as_deref().unwrap_or("custom workload");

        let summary = match &entry.status {
            JobStatus::Succeeded => {
                let proof = entry.proof_bytes.as_ref().unwrap();
                let size = serde_json::to_vec(proof).map(|b| b.len()).unwrap_or(0);
                format!(
                    "Proof job '{}' ({}) succeeded.\n\
                     Template: {}\n\
                     Public inputs: initial_acc={}, final_acc={}\n\
                     Proof version: {}, size: {} bytes\n\
                     The proof cryptographically attests that the computation \
                     with the given public inputs was executed correctly.",
                    params.job_id,
                    status_label,
                    template_desc,
                    entry.initial_acc,
                    entry.final_acc,
                    proof.version,
                    size
                )
            }
            JobStatus::Failed { error } => {
                format!(
                    "Proof job '{}' failed.\nTemplate: {}\nError: {}",
                    params.job_id, template_desc, error
                )
            }
            _ => {
                format!(
                    "Proof job '{}' is {}.\nTemplate: {}\nPublic inputs: initial_acc={}, final_acc={}",
                    params.job_id, status_label, template_desc,
                    entry.initial_acc, entry.final_acc
                )
            }
        };

        Ok(CallToolResult::success(vec![Content::text(summary)]))
    }
}
