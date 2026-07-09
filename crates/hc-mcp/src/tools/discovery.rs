use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData;

use crate::HcMcpServer;

impl HcMcpServer {
    pub async fn get_capabilities_impl(&self) -> Result<CallToolResult, ErrorData> {
        let capabilities = serde_json::json!({
            "server": "tinyzkp",
            "version": env!("CARGO_PKG_VERSION"),
            "service_status": "backend_recovery",
            "backend": "plonky3",
            "plonky3_version": "0.6.1",
            "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
            "proof_format": "official_plonky3",
            "verifier": "unmodified_official_plonky3",
            "features": {
                "templates": false,
                "workloads": false,
                "proving": false,
                "verification": false,
                "polling": false,
                "receipt_retrieval": false,
                "benchmarking": true,
                "zero_knowledge": false
            },
            "limits": {
                "max_inflight_jobs": self.config.max_inflight
            },
            "recommended_action": "Run the open-source component benchmark or apply for a memory-bounded Plonky3 evaluation. Do not submit proof jobs during maintenance.",
            "status_url": "https://tinyzkp.com/status"
        });
        let content = Content::json(capabilities)
            .map_err(|error| ErrorData::internal_error(format!("JSON error: {error}"), None))?;
        Ok(CallToolResult::success(vec![content]))
    }
}
