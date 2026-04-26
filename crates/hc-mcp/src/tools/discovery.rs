use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::DescribeTemplateParams;
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn list_all_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let unified = hc_workloads::list_all_templates();
        let listing: Vec<serde_json::Value> = unified
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

    pub async fn list_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let templates = hc_workloads::templates::list_templates();
        let listing: Vec<serde_json::Value> = templates
            .iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                })
            })
            .collect();
        let json = Content::json(listing)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn list_workloads_impl(&self) -> Result<CallToolResult, ErrorData> {
        let ids = hc_workloads::list_workloads();
        let json = Content::json(ids)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn describe_template_impl(
        &self,
        Parameters(params): Parameters<DescribeTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let tmpl =
            hc_workloads::templates::template_by_id(&params.template_id).ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "Unknown template '{}'. Call list_templates to see available options.",
                        params.template_id
                    ),
                    None,
                )
            })?;
        let info = tmpl.to_info();
        let json = Content::json(info)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn get_capabilities_impl(&self) -> Result<CallToolResult, ErrorData> {
        let caps = serde_json::json!({
            "server": "hc-stark",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol_version": "2025-03-26",
            "features": {
                "templates": true,
                "workloads": true,
                "dsl_compilation": false,
                "zero_knowledge": true,
                "evm_calldata": false,
            },
            "limits": {
                "max_inflight_jobs": self.config.max_inflight,
            },
            "workflow": [
                "1. list_templates or get_capabilities to discover what's available",
                "2. describe_template to get parameter schema and example",
                "3. prove_template to submit a proof job",
                "4. poll_job until status is 'succeeded'",
                "5. get_proof to retrieve base64-encoded proof bytes",
                "6. verify_proof to independently verify the proof",
            ],
        });
        let json = Content::json(caps)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}
