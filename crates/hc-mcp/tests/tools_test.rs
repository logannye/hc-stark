//! Integration tests for hc-mcp tool handlers.
//!
//! Tests call handler methods directly on `HcMcpServer`, bypassing MCP transport.

use hc_mcp::{HcMcpServer, McpConfig};
use rmcp::handler::server::wrapper::Parameters;
use serde_json::json;

fn server() -> HcMcpServer {
    HcMcpServer::new(McpConfig { max_inflight: 4 })
}

/// Helper: extract JSON value from CallToolResult's first content block.
fn extract_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let content = &result.content[0];
    // Content is Annotated<RawContent>; serialize to get the text, then parse.
    let raw = serde_json::to_value(content).unwrap();
    // Content serializes as {"type": "text", "text": "..."} for text/json
    let text = raw["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn extract_text(result: &rmcp::model::CallToolResult) -> String {
    let raw = serde_json::to_value(&result.content[0]).unwrap();
    raw["text"].as_str().unwrap().to_string()
}

// ── Discovery tools ─────────────────────────────────────────────────────────

#[tokio::test]
async fn list_templates_returns_enforced_templates_by_default() {
    let s = server();
    let result = s.list_templates_impl().await.unwrap();
    let val = extract_json(&result);
    let arr = val.as_array().unwrap();
    // With the enforcement gate active (default), only Enforced templates are
    // listed. The count will be less than the full catalog; just verify the
    // result is non-empty and that the known Enforced template is present.
    assert!(
        !arr.is_empty(),
        "expected at least one template in the default listing, got 0"
    );

    // Check that accumulator_step is in the list
    let has_acc = arr.iter().any(|t| t["id"] == "accumulator_step");
    assert!(has_acc, "accumulator_step template missing from listing");

    // StructureOnly templates must NOT appear in the default listing
    assert!(
        !arr.iter().any(|t| t["id"] == "range_proof"),
        "range_proof (StructureOnly) must not appear in the default listing"
    );
}

#[tokio::test]
async fn list_workloads_returns_ids() {
    let s = server();
    let result = s.list_workloads_impl().await.unwrap();
    let val = extract_json(&result);
    let arr = val.as_array().unwrap();
    assert!(!arr.is_empty(), "expected at least one workload");
    let has_toy = arr.iter().any(|v| v.as_str() == Some("toy_add_1_2"));
    assert!(has_toy, "toy_add_1_2 workload missing");
}

#[tokio::test]
async fn describe_template_returns_schema() {
    let s = server();
    let params = hc_mcp::types::DescribeTemplateParams {
        template_id: "accumulator_step".to_string(),
    };
    let result = s.describe_template_impl(Parameters(params)).await.unwrap();
    let val = extract_json(&result);
    assert_eq!(val["id"], "accumulator_step");
    assert!(val["parameters"].as_array().unwrap().len() >= 3);
    assert!(val["example"].is_object());
}

#[tokio::test]
async fn describe_unknown_template_returns_error() {
    let s = server();
    let params = hc_mcp::types::DescribeTemplateParams {
        template_id: "nonexistent_template".to_string(),
    };
    let err = s
        .describe_template_impl(Parameters(params))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("nonexistent_template"),
        "error should mention template name"
    );
}

#[tokio::test]
async fn get_capabilities_returns_expected_fields() {
    let s = server();
    let result = s.get_capabilities_impl().await.unwrap();
    let val = extract_json(&result);
    assert_eq!(val["server"], "hc-stark");
    assert!(val["features"]["templates"].as_bool().unwrap());
    assert!(val["features"]["zero_knowledge"].as_bool().unwrap());
    assert!(val["workflow"].as_array().unwrap().len() >= 5);
}

// ── Proving + polling roundtrip ────────────────────────────────────────────

#[tokio::test]
async fn prove_template_accumulator_roundtrip() {
    let s = server();

    // Submit proof job via template.
    //
    // Phase 1A: production proving now uses the SOUND v5 path with blowup ≥ 8,
    // which requires the padded trace length to be ≥ 8 (≈ ≥ 7 instructions).
    // Use an 8-delta chain (trace length 9 → padded 16) so the v5 prover and
    // the default-floor verifier are both satisfied.
    let params = hc_mcp::types::ProveTemplateParams {
        template_id: "accumulator_step".to_string(),
        parameters: serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(
            json!({"initial": 0, "final": 36, "deltas": [1, 2, 3, 4, 5, 6, 7, 8]}),
        )
        .unwrap(),
        zk: Some(false),
    };
    let result = s.prove_template_impl(Parameters(params)).await.unwrap();
    let val = extract_json(&result);
    let job_id = val["job_id"].as_str().unwrap().to_string();
    assert_eq!(val["status"], "running");

    // Poll until succeeded (with timeout)
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let poll_params = hc_mcp::types::PollJobParams {
            job_id: job_id.clone(),
        };
        let poll_result = s.poll_job_impl(Parameters(poll_params)).await.unwrap();
        let poll_val = extract_json(&poll_result);
        let status = poll_val["status"].as_str().unwrap();
        if status == "succeeded" {
            break;
        }
        if status == "failed" {
            panic!("proof job failed: {:?}", poll_val["error"]);
        }
        attempts += 1;
        assert!(
            attempts < 150,
            "proof job didn't complete within 30 seconds"
        );
    }

    // Get proof bytes
    let proof_params = hc_mcp::types::GetProofParams {
        job_id: job_id.clone(),
    };
    let proof_result = s.get_proof_impl(Parameters(proof_params)).await.unwrap();
    let proof_val = extract_json(&proof_result);
    let proof_b64 = proof_val["proof_b64"].as_str().unwrap();
    assert!(!proof_b64.is_empty());
    assert!(proof_val["size_bytes"].as_u64().unwrap() > 0);

    // Verify the proof
    let verify_params = hc_mcp::types::VerifyProofParams {
        proof_b64: proof_b64.to_string(),
    };
    let verify_result = s
        .verify_proof_impl(Parameters(verify_params))
        .await
        .unwrap();
    let verify_val = extract_json(&verify_result);
    assert_eq!(verify_val["valid"], true, "proof should verify");
}

#[tokio::test]
async fn prove_template_with_bad_params_returns_error() {
    let s = server();

    // Missing required 'deltas' parameter
    let params = hc_mcp::types::ProveTemplateParams {
        template_id: "accumulator_step".to_string(),
        parameters: serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(
            json!({"initial": 0, "final": 15}),
        )
        .unwrap(),
        zk: None,
    };
    let err = s.prove_template_impl(Parameters(params)).await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("deltas") || msg.contains("parameter"),
        "error should mention missing param"
    );
}

#[tokio::test]
async fn prove_unknown_template_returns_error() {
    let s = server();
    let params = hc_mcp::types::ProveTemplateParams {
        template_id: "nonexistent".to_string(),
        parameters: serde_json::Map::new(),
        zk: None,
    };
    let err = s.prove_template_impl(Parameters(params)).await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("nonexistent"),
        "error should mention template name"
    );
}

#[tokio::test]
async fn poll_unknown_job_returns_error() {
    let s = server();
    let params = hc_mcp::types::PollJobParams {
        job_id: "nonexistent-job-id".to_string(),
    };
    let err = s.poll_job_impl(Parameters(params)).await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("nonexistent-job-id"),
        "error should mention job ID"
    );
}

#[tokio::test]
async fn get_proof_summary_for_completed_job() {
    let s = server();

    // Submit and wait for a proof. Phase 1A: the sound v5 path (blowup ≥ 8)
    // needs padded trace length ≥ 8, so use an 8-delta chain.
    let params = hc_mcp::types::ProveTemplateParams {
        template_id: "accumulator_step".to_string(),
        parameters: serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(
            json!({"initial": 10, "final": 46, "deltas": [1, 2, 3, 4, 5, 6, 7, 8]}),
        )
        .unwrap(),
        zk: Some(false),
    };
    let result = s.prove_template_impl(Parameters(params)).await.unwrap();
    let val = extract_json(&result);
    let job_id = val["job_id"].as_str().unwrap().to_string();

    // Wait for completion
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let poll = s
            .poll_job_impl(Parameters(hc_mcp::types::PollJobParams {
                job_id: job_id.clone(),
            }))
            .await
            .unwrap();
        let pv = extract_json(&poll);
        if pv["status"] == "succeeded" {
            break;
        }
        if pv["status"] == "failed" {
            panic!("job failed: {:?}", pv["error"]);
        }
    }

    // Get human-readable summary
    let summary_params = hc_mcp::types::GetProofSummaryParams {
        job_id: job_id.clone(),
    };
    let summary_result = s
        .get_proof_summary_impl(Parameters(summary_params))
        .await
        .unwrap();
    let text = extract_text(&summary_result);
    assert!(text.contains("succeeded"), "summary should mention success");
    assert!(
        text.contains("accumulator_step"),
        "summary should mention template"
    );
}

#[tokio::test]
async fn verify_invalid_proof_returns_invalid() {
    let s = server();
    let params = hc_mcp::types::VerifyProofParams {
        proof_b64: "not-valid-base64!!!".to_string(),
    };
    let err = s.verify_proof_impl(Parameters(params)).await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("base64") || msg.contains("Invalid"),
        "should report base64 error"
    );
}
