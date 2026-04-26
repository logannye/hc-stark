//! MCP tool implementations for Spartan R1CS templates.
//!
//! Mirror of `tools/zkml.rs`. The R1CS sumcheck prover is bounded at
//! `m·n ≤ 2^18` for now (dense matrices) and finishes in well under a
//! second on commodity hardware, so the MCP path returns the proof
//! envelope synchronously rather than going through a job queue.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::{DescribeSpartanTemplateParams, ProveSpartanTemplateParams};
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn list_spartan_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let templates = hc_workloads::spartan_templates::list_spartan_template_infos();
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

    pub async fn describe_spartan_template_impl(
        &self,
        Parameters(params): Parameters<DescribeSpartanTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let info = hc_workloads::spartan_templates::describe_spartan_template(&params.template_id)
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "Unknown spartan template '{}'. Call list_spartan_templates to see options.",
                        params.template_id
                    ),
                    None,
                )
            })?;
        let json = Content::json(info)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn prove_spartan_template_impl(
        &self,
        Parameters(params): Parameters<ProveSpartanTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let envelope = hc_workloads::spartan_templates::prove_spartan_template(
            &params.template_id,
            &params.parameters,
        )
        .map_err(|e| {
            ErrorData::invalid_params(
                format!(
                    "spartan template '{}' run failed: {}. Call describe_spartan_template for the parameter schema.",
                    params.template_id, e
                ),
                None,
            )
        })?;
        let envelope_json = serde_json::to_value(&envelope)
            .map_err(|e| ErrorData::internal_error(format!("envelope serialize: {e}"), None))?;
        let response = serde_json::json!({
            "template_id": params.template_id,
            "kind": "spartan_r1cs_envelope",
            "envelope_version": envelope.version,
            "envelope": envelope_json,
        });
        let json = Content::json(response)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}
