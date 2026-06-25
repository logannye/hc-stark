use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::DescribeTemplateParams;
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn list_all_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let allow = hc_workloads::allow_unaudited_templates();
        let unified = hc_workloads::list_all_templates();
        let listing: Vec<serde_json::Value> = unified
            .iter()
            .filter(|t| hc_workloads::is_live(t.enforcement, t.audited, allow))
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                    "backend": t.backend,
                    "lifecycle": t.lifecycle.as_str(),
                })
            })
            .collect();
        let json = Content::json(listing)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn list_templates_impl(&self) -> Result<CallToolResult, ErrorData> {
        let allow = hc_workloads::allow_unaudited_templates();
        let templates = hc_workloads::templates::list_templates();
        let listing: Vec<serde_json::Value> = templates
            .iter()
            .filter(|t| hc_workloads::is_live(t.enforcement, t.audited, allow))
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                    "enforcement": match t.enforcement {
                        hc_workloads::Enforcement::Enforced => "enforced",
                        hc_workloads::Enforcement::StructureOnly => "structure_only",
                    },
                    "audited": t.audited,
                    "lifecycle": hc_workloads::TemplateLifecycle::from_axes(t.enforcement, t.audited).as_str(),
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
        let allow = hc_workloads::allow_unaudited_templates();
        let tmpl = hc_workloads::templates::template_by_id(&params.template_id)
            .filter(|t| hc_workloads::is_live(t.enforcement, t.audited, allow))
            .ok_or_else(|| {
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
                "5. get_proof to retrieve proof_b64 plus a tracked verifier_url and, when size allows, a proof-embedded receipt_url",
                "6. share the receipt_url/verifier_url or call verify_proof to independently verify the proof",
            ],
        });
        let json = Content::json(caps)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}

#[cfg(test)]
mod honest_catalog_mcp_tests {
    #[test]
    fn default_listing_includes_only_live_templates() {
        // Flag off: the MCP VM listing must include only LIVE templates
        // (Enforced AND audited). Only accumulator_step survives today; the
        // sound-but-unaudited range_proof stays hidden until the audit.
        let visible: Vec<&str> = hc_workloads::templates::list_templates()
            .into_iter()
            .filter(|t| hc_workloads::is_live(t.enforcement, t.audited, false))
            .map(|t| t.id)
            .collect();
        assert!(visible.contains(&"accumulator_step"));
        assert!(!visible.contains(&"range_proof"));
    }
}
