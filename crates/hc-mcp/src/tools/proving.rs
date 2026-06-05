use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::types::{ProveTemplateParams, ProveWorkloadParams};
use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn prove_template_impl(
        &self,
        Parameters(params): Parameters<ProveTemplateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if !hc_workloads::is_dispatchable(
            &params.template_id,
            hc_workloads::allow_unaudited_templates(),
        ) {
            return Err(ErrorData::invalid_params(
                format!(
                    "Template '{}' is not available in this deployment.",
                    params.template_id
                ),
                None,
            ));
        }
        let build_result = hc_workloads::templates::build_from_template(
            &params.template_id,
            &params.parameters,
        )
        .map_err(|e| {
            ErrorData::invalid_params(
                format!(
                    "Failed to build template '{}': {}. Call describe_template for the parameter schema.",
                    params.template_id, e
                ),
                None,
            )
        })?;

        // VM templates prove on the v5 accumulator path (ZK optional via the
        // trace-additive mask); AIR templates (e.g. range_proof) prove on the
        // sound v7 path, which is NOT zero-knowledge for degree-≥2 AIRs (ZK
        // deferred — see docs/security/zk_range.md), so zk_enabled is false.
        let (job_id, zk_enabled) = match build_result {
            hc_workloads::templates::TemplateBuildResult::Vm {
                program,
                initial_acc,
                final_acc,
                recommended_zk,
            } => {
                let zk = params.zk.unwrap_or(recommended_zk);
                let zk_mask_degree = if zk { Some(1) } else { None };
                let id = self
                    .executor
                    .submit(
                        program,
                        initial_acc,
                        final_acc,
                        Some(params.template_id.clone()),
                        zk_mask_degree,
                    )
                    .await
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
                (id, zk)
            }
            hc_workloads::templates::TemplateBuildResult::Air {
                air,
                trace,
                public_inputs,
                ..
            } => {
                let id = self
                    .executor
                    .submit_air(air, trace, public_inputs, Some(params.template_id.clone()))
                    .await
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
                (id, false)
            }
        };

        let resp = serde_json::json!({
            "job_id": job_id,
            "status": "running",
            "template_id": params.template_id,
            "zk_enabled": zk_enabled,
            "hint": "Call poll_job with this job_id to check progress.",
        });
        let json = Content::json(resp)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }

    pub async fn prove_workload_impl(
        &self,
        Parameters(params): Parameters<ProveWorkloadParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let block_size = params.block_size.unwrap_or(2);
        let req = hc_sdk::types::ProveRequest {
            workload_id: Some(params.workload_id.clone()),
            template_id: None,
            template_params: None,
            program: None,
            initial_acc: params.initial_acc,
            final_acc: params.final_acc,
            block_size,
            fri_final_poly_size: 2,
            query_count: 30,
            lde_blowup_factor: 2,
            zk_mask_degree: None,
        };

        let program = hc_workloads::program_for_request(&req).map_err(|e| {
            ErrorData::invalid_params(
                format!(
                    "Failed to build workload '{}': {}. Call list_workloads for available options.",
                    params.workload_id, e
                ),
                None,
            )
        })?;

        let job_id = self
            .executor
            .submit(program, params.initial_acc, params.final_acc, None, None)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let resp = serde_json::json!({
            "job_id": job_id,
            "status": "running",
            "workload_id": params.workload_id,
            "hint": "Call poll_job with this job_id to check progress.",
        });
        let json = Content::json(resp)
            .map_err(|e| ErrorData::internal_error(format!("JSON error: {e}"), None))?;
        Ok(CallToolResult::success(vec![json]))
    }
}
