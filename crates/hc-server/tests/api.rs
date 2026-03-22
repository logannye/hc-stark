use axum::http::header;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hc_sdk::types::{ProveJobStatus, ProveRequest, VerifyRequest};
use tower::ServiceExt;

#[tokio::test]
async fn healthz_is_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn prove_then_verify_roundtrip() {
    // Ensure the server can locate the worker binary when running under `cargo test`.
    // Cargo exposes bin paths via `CARGO_BIN_EXE_<name>`.
    let worker = std::env::var("CARGO_BIN_EXE_hc-worker")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_hc_worker"))
        .ok()
        .or_else(|| {
            // Fallback: workspace `target/debug/hc-worker` relative to this crate.
            let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let candidate = here.join("../../target/debug/hc-worker");
            candidate
                .exists()
                .then(|| candidate.to_string_lossy().to_string())
        });
    if let Some(worker) = worker {
        std::env::set_var("HC_SERVER_WORKER_PATH", worker);
    }

    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let submit: hc_sdk::types::ProveSubmitResponse = serde_json::from_slice(&body).unwrap();

    // Poll.
    let mut proof = None;
    for _ in 0..50 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/prove/{}", submit.job_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: ProveJobStatus = serde_json::from_slice(&body).unwrap();
        match status {
            ProveJobStatus::Succeeded { proof: p } => {
                proof = Some(p);
                break;
            }
            ProveJobStatus::Failed { error } => panic!("prove failed: {error}"),
            _ => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let proof = proof.expect("prove should complete");

    let verify_req = VerifyRequest {
        proof,
        allow_legacy_v2: true,
    };
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&verify_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: hc_sdk::types::VerifyResult = serde_json::from_slice(&body).unwrap();
    assert!(result.ok, "verify failed: {:?}", result.error);
}

#[tokio::test]
async fn unknown_workload_id_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("not_a_real_workload".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prove_rate_limit_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_rate_limits(
        tmp.path().to_path_buf(),
        hc_server::auth::AuthConfig::default(),
        1, // 1 prove/minute
        0,
    );
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_is_required_when_configured() {
    if let Some(worker) = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/hc-worker")
        .exists()
        .then(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/hc-worker")
        })
    {
        std::env::set_var(
            "HC_SERVER_WORKER_PATH",
            worker.to_string_lossy().to_string(),
        );
    }

    let tmp = tempfile::tempdir().unwrap();
    // Enable auth by configuring a key->tenant mapping.
    let auth = hc_server::auth::AuthConfig::from_pairs(&[("tenantA", "keyA")]);
    let state = hc_server::test_state_with_auth(tmp.path().to_path_buf(), auth);
    let app = hc_server::build_app(state);

    // Verify should reject missing Authorization when auth is enabled.
    let verify_req = VerifyRequest {
        proof: hc_sdk::types::ProofBytes {
            version: 3,
            bytes: vec![1, 2, 3],
        },
        allow_legacy_v2: true,
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&verify_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Prove should reject missing Authorization when auth is enabled.
    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn job_ids_are_tenant_scoped() {
    let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let worker = here.join("../../target/debug/hc-worker");
    if worker.exists() {
        std::env::set_var(
            "HC_SERVER_WORKER_PATH",
            worker.to_string_lossy().to_string(),
        );
    }

    let auth = hc_server::auth::AuthConfig::from_pairs(&[("tenantA", "keyA"), ("tenantB", "keyB")]);

    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_auth(tmp.path().to_path_buf(), auth);
    let app = hc_server::build_app(state);

    // Tenant A creates a prove job.
    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, "Bearer keyA")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let submit: hc_sdk::types::ProveSubmitResponse = serde_json::from_slice(&body).unwrap();

    // Tenant B should not be able to read Tenant A's job status.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/prove/{}", submit.job_id))
                .header(header::AUTHORIZATION, "Bearer keyB")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn request_body_limit_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_overrides(
        tmp.path().to_path_buf(),
        hc_server::auth::AuthConfig::default(),
        128, // max_body_bytes
        8,
        30_000,
    );
    let app = hc_server::build_app(state);

    // Create a body > 128 bytes.
    let big = vec![b'a'; 512];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(big))
                .unwrap(),
        )
        .await
        .unwrap();

    // Axum's default body limit returns 413.
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn verify_concurrency_limit_is_enforced() {
    std::env::set_var("HC_SERVER_TEST_HOOKS", "1");
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_overrides(
        tmp.path().to_path_buf(),
        hc_server::auth::AuthConfig::default(),
        2 * 1024 * 1024,
        1, // max_verify_inflight
        30_000,
    );
    let app = hc_server::build_app(state);

    let verify_req = VerifyRequest {
        proof: hc_sdk::types::ProofBytes {
            version: 3,
            bytes: vec![1, 2, 3],
        },
        allow_legacy_v2: true,
    };
    let body = serde_json::to_vec(&verify_req).unwrap();

    // First request: hold the permit by sleeping inside the verify task.
    let app1 = app.clone();
    let t1 = tokio::spawn(async move {
        app1.oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .header("x-hc-test-sleep-ms", "50")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    });

    // Give t1 a moment to acquire the permit.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // Second request should be rejected with 429 while the permit is held.
    let verify_req2 = VerifyRequest {
        proof: hc_sdk::types::ProofBytes {
            version: 3,
            bytes: vec![1, 2, 3],
        },
        allow_legacy_v2: true,
    };
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&verify_req2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

    let _ = t1.await.unwrap();
}

#[tokio::test]
async fn verify_timeout_is_enforced() {
    std::env::set_var("HC_SERVER_TEST_HOOKS", "1");
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_overrides(
        tmp.path().to_path_buf(),
        hc_server::auth::AuthConfig::default(),
        2 * 1024 * 1024,
        8,
        5, // verify_timeout_ms
    );
    let app = hc_server::build_app(state);

    let verify_req = VerifyRequest {
        proof: hc_sdk::types::ProofBytes {
            version: 3,
            bytes: vec![1, 2, 3],
        },
        allow_legacy_v2: true,
    };
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .header("x-hc-test-sleep-ms", "50")
                .body(Body::from(serde_json::to_vec(&verify_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn prove_rejects_insecure_query_count() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_server_caps(tmp.path().to_path_buf(), 1 << 20, 80);
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 1,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prove_rejects_non_power_of_two_block_size() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 7,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prove_rejects_oversized_block_size() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_with_server_caps(tmp.path().to_path_buf(), 1 << 20, 1);
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 1 << 24,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prove_wrong_auth_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let auth = hc_server::auth::AuthConfig::from_pairs(&[("tenantA", "keyA")]);
    let state = hc_server::test_state_with_auth(tmp.path().to_path_buf(), auth);
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, "Bearer wrongkey")
                .body(Body::from(serde_json::to_vec(&prove_req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn aggregate_returns_501() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let req_body = serde_json::json!({"job_ids": ["abc"]});
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/aggregate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn response_has_request_id_header() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().contains_key("x-request-id"),
        "response should have x-request-id header"
    );
}
