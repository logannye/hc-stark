//! Production-default MCP tests. Historical execution tools are absent from
//! the production router rather than present-but-disabled.

use hc_mcp::{HcMcpServer, McpConfig, PRODUCTION_TOOL_NAMES};

fn server() -> HcMcpServer {
    HcMcpServer::new(McpConfig { max_inflight: 4 })
}

fn extract_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let raw = serde_json::to_value(&result.content[0]).unwrap();
    serde_json::from_str(raw["text"].as_str().unwrap()).unwrap()
}

#[test]
fn production_discovery_exposes_only_capabilities() {
    assert_eq!(PRODUCTION_TOOL_NAMES, &["get_capabilities"]);
}

#[tokio::test]
async fn capabilities_are_explicitly_plonky3_and_unavailable() {
    let value = extract_json(&server().get_capabilities_impl().await.unwrap());
    assert_eq!(value["server"], "tinyzkp");
    assert_eq!(value["service_status"], "backend_recovery");
    assert_eq!(value["backend"], "plonky3");
    assert_eq!(value["plonky3_version"], "0.6.1");
    assert_eq!(value["compatibility_profile"], "tinyzkp-p3-goldilocks-v1");
    assert_eq!(value["proof_format"], "official_plonky3");
    assert_eq!(value["verifier"], "unmodified_official_plonky3");
    assert_eq!(value["features"]["proving"], false);
    assert_eq!(value["features"]["verification"], false);
    assert_eq!(value["features"]["polling"], false);
    assert_eq!(value["features"]["receipt_retrieval"], false);
    assert_eq!(value["features"]["benchmarking"], true);
}
