use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::{GetProofParams, GetProofSummaryParams, JobStatus};
use crate::HcMcpServer;

const VERIFIER_URL: &str = "https://tinyzkp.com/verify";
const RECEIPT_SHARE_SOURCE: &str = "receipt_share";
const RECEIPT_SHARE_MEDIUM: &str = "mcp";
const RECEIPT_SHARE_INTENT: &str = "verify_receipt";
const MAX_RECEIPT_SHARE_ENCODED_CHARS: usize = 120_000;

struct ReceiptShareUrl {
    workflow: String,
    encoded_chars: usize,
    verifier_url: String,
    receipt_url: Option<String>,
    unavailable_reason: Option<&'static str>,
}

fn receipt_workflow(template_id: Option<&str>) -> String {
    let raw = template_id.unwrap_or("custom_workload");
    let mut value = String::with_capacity(raw.len().min(80));
    for ch in raw.chars().take(80) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            value.push(ch);
        } else {
            value.push('_');
        }
    }
    if value.is_empty() {
        "custom_workload".to_string()
    } else {
        value
    }
}

fn build_receipt_share_url(json_bytes: &[u8], template_id: Option<&str>) -> ReceiptShareUrl {
    let workflow = receipt_workflow(template_id);
    let verifier_url = format!(
        "{VERIFIER_URL}?source={RECEIPT_SHARE_SOURCE}&medium={RECEIPT_SHARE_MEDIUM}&workflow={workflow}&intent={RECEIPT_SHARE_INTENT}"
    );
    let proof_fragment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_bytes);
    let encoded_chars = proof_fragment.len();
    if encoded_chars > MAX_RECEIPT_SHARE_ENCODED_CHARS {
        return ReceiptShareUrl {
            workflow,
            encoded_chars,
            verifier_url,
            receipt_url: None,
            unavailable_reason: Some(
                "proof JSON exceeds the receipt-share URL size limit; share proof_b64 or proof JSON through a safe channel and verify at https://tinyzkp.com/verify",
            ),
        };
    }

    ReceiptShareUrl {
        receipt_url: Some(format!("{verifier_url}#proof={proof_fragment}")),
        verifier_url,
        workflow,
        encoded_chars,
        unavailable_reason: None,
    }
}

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
        let receipt_share = build_receipt_share_url(&json_bytes, entry.template_id.as_deref());
        let share_status = if receipt_share.receipt_url.is_some() {
            "ready"
        } else {
            "proof_too_large"
        };

        let resp = serde_json::json!({
            "job_id": params.job_id,
            "proof_b64": b64,
            "proof_version": proof.version,
            "size_bytes": json_bytes.len(),
            "public_verifier": VERIFIER_URL,
            "verifier_url": receipt_share.verifier_url,
            "receipt_url": receipt_share.receipt_url,
            "receipt_url_unavailable_reason": receipt_share.unavailable_reason,
            "receipt_share": {
                "status": share_status,
                "source": RECEIPT_SHARE_SOURCE,
                "medium": RECEIPT_SHARE_MEDIUM,
                "workflow": receipt_share.workflow,
                "intent": RECEIPT_SHARE_INTENT,
                "encoded_chars": receipt_share.encoded_chars,
                "max_encoded_chars": MAX_RECEIPT_SHARE_ENCODED_CHARS,
                "fragment_parameter": "proof",
                "encoding": "base64url",
                "browser_network_boundary": "The #proof URL fragment is not sent to TinyZKP or any HTTP server when the verifier page loads.",
            },
            "hint": "Open verifier_url/receipt_url to share this receipt, or pass proof_b64 to verify_proof to independently verify.",
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
                let json_bytes = serde_json::to_vec(proof).unwrap_or_default();
                let size = json_bytes.len();
                let receipt_share =
                    build_receipt_share_url(&json_bytes, entry.template_id.as_deref());
                let receipt_line = match receipt_share.receipt_url {
                    Some(url) => format!("Verifier URL: {url}\n"),
                    None => format!(
                        "Verifier URL: {}\nReceipt URL: unavailable ({})\n",
                        receipt_share.verifier_url,
                        receipt_share
                            .unavailable_reason
                            .unwrap_or("proof is too large for a share URL")
                    ),
                };
                format!(
                    "Proof job '{}' ({}) succeeded.\n\
                     Template: {}\n\
                     Public inputs: initial_acc={}, final_acc={}\n\
                     Proof version: {}, size: {} bytes\n\
                     {}\
                     Receipt attribution: source={}, medium={}, workflow={}, intent={}\n\
                     Share boundary: the #proof URL fragment stays client-side when the verifier page loads.\n\
                     The proof cryptographically attests that the computation \
                     with the given public inputs was executed correctly.",
                    params.job_id,
                    status_label,
                    template_desc,
                    entry.initial_acc,
                    entry.final_acc,
                    proof.version,
                    size,
                    receipt_line,
                    RECEIPT_SHARE_SOURCE,
                    RECEIPT_SHARE_MEDIUM,
                    receipt_share.workflow,
                    RECEIPT_SHARE_INTENT
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
