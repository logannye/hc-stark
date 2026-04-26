//! MCP tool implementations for zkML templates.
//!
//! These tools sit alongside the existing accumulator-VM template tools
//! (`list_templates`, `describe_template`, `prove_template`) but route
//! through the parallel `ZkmlTemplate` registry in `hc-workloads`. They
//! call the synchronous `prove_zkml_template` helper because the underlying
//! MatMul prover is fast enough that no job queue is required.

use base64::engine::{general_purpose::STANDARD as B64, Engine as _};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::{DescribeZkmlTemplateParams, ProveZkmlTemplateParams};
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn list_zkml_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let templates = hc_workloads::zkml_templates::list_zkml_template_infos();
        let listing: Vec<serde_json::Value> = templates
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                    "backend": t.backend,
                })
            })
            .collect();
        let json = Content::json(listing)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn describe_zkml_template_impl(
        &self,
        Parameters(params): Parameters<DescribeZkmlTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let info = hc_workloads::zkml_templates::describe_zkml_template(&params.template_id)
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "Unknown zkml template '{}'. Call list_zkml_templates to see options.",
                        params.template_id
                    ),
                    None,
                )
            })?;
        let json = Content::json(info)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn prove_zkml_template_impl(
        &self,
        Parameters(params): Parameters<ProveZkmlTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = hc_workloads::zkml_templates::prove_zkml_template(
            &params.template_id,
            &params.parameters,
        )
        .map_err(|e| {
            ErrorData::invalid_params(
                format!(
                    "zkml template '{}' run failed: {}. Call describe_zkml_template for the parameter schema.",
                    params.template_id, e
                ),
                None,
            )
        })?;
        let public_io_json = serde_json::to_value(&outcome.public_io)
            .map_err(|e| ErrorData::internal_error(format!("public_io serialize: {e}"), None))?;
        let response = serde_json::json!({
            "template_id": params.template_id,
            "envelope": {
                "version": outcome.proof.version,
                "bytes_b64": B64.encode(&outcome.proof.bytes),
            },
            "public_io": public_io_json,
            "model_commitment": {
                "architecture_digest_hex": hex_lower(&outcome.model_commitment.architecture_digest),
                "weights_digest_hex": hex_lower(&outcome.model_commitment.weights_digest),
            },
        });
        let json = Content::json(response)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
