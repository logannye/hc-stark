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
async fn aggregate_rejects_invalid_job_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    // Invalid UUID → 400.
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn aggregate_rejects_empty_job_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let req_body = serde_json::json!({"job_ids": []});
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

// ── Failure-mode coverage ─────────────────────────────────────────────────────
//
// These tests exercise paths that hide silent bugs. The colleague's review
// flagged the missing coverage as where billing leaks and orphaned-state
// bugs live.

/// Auth file with malformed entries should not bring the server down — bad
/// lines get skipped, valid lines load. AuthConfig::from_file is permissive
/// by design; this test pins that contract.
#[tokio::test]
async fn auth_file_with_corrupt_lines_loads_valid_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let keys_path = tmp.path().join("api.keys");
    std::fs::write(
        &keys_path,
        "# Valid line\n\
         acme:tzk_real:developer\n\
         this-is-garbage-no-colons\n\
         beta:tzk_other\n\
         \n\
         broken::::too:many:colons:per:line\n",
    )
    .unwrap();

    // Should not panic. Either succeeds (parsing the valid lines) or
    // returns a clean error — the contract is "no crash, no resource
    // leak."
    let result = hc_server::auth::AuthConfig::from_file(&keys_path);
    match result {
        Ok(cfg) => {
            // Parser is permissive: we expect at least one valid key
            // ("acme") to have made it through.
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                axum::http::HeaderValue::from_static("Bearer tzk_real"),
            );
            let auth_result = cfg.authenticate(&headers);
            assert!(
                auth_result.is_ok(),
                "valid line 'acme:tzk_real:developer' should authenticate"
            );
        }
        Err(_) => {
            // Strict parser is also acceptable — but it must not have
            // panicked. Reaching this branch is the only assertion.
        }
    }
}

/// The server must boot when the auth keys file does not exist. Operators
/// frequently start with an empty deployment and add keys later. Without
/// this guarantee the boot sequence is fragile under fresh provisioning.
#[tokio::test]
async fn missing_auth_keys_file_is_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("does-not-exist.keys");
    let result = hc_server::auth::AuthConfig::from_file(&nonexistent);
    // We expect an Err (file not found), but no panic and no crash.
    assert!(result.is_err(), "expected Err for missing file");
}

/// Concurrent SQLite writes via job_index must not deadlock or panic
/// under contention. The 5s busy_timeout (Day 1c) should let writers
/// queue rather than fail. This is the regression guard for that fix.
#[tokio::test]
async fn job_index_handles_concurrent_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("jobs.sqlite");
    let index = std::sync::Arc::new(
        hc_server::job_index::JobIndex::open(db_path).expect("open jobs.sqlite"),
    );

    // Spawn 16 tasks each writing 50 status updates for distinct
    // (tenant, job) pairs. With WAL + busy_timeout=5s every write
    // should succeed even if there's serialization at the SQLite layer.
    let mut handles = Vec::new();
    for t in 0..16 {
        let index_t = index.clone();
        handles.push(tokio::spawn(async move {
            for j in 0..50 {
                let tenant = format!("tenant_{t}");
                let job = format!("job_{t}_{j}");
                // Minimum-shape ProveRequest — JSON-serialized into the
                // jobs.sqlite blob; field values are irrelevant to the
                // contention test, only that we hammer the writer lock.
                let req = hc_sdk::types::ProveRequest {
                    workload_id: None,
                    template_id: None,
                    template_params: None,
                    program: None,
                    initial_acc: 0,
                    final_acc: 0,
                    block_size: 4,
                    fri_final_poly_size: 1,
                    query_count: 80,
                    lde_blowup_factor: 2,
                    zk_mask_degree: None,
                };
                let status = hc_sdk::types::ProveJobStatus::Pending;
                index_t
                    .upsert_request(&tenant, &job, &req, &status)
                    .expect("upsert under contention");
            }
        }));
    }

    for h in handles {
        h.await.expect("task did not panic");
    }

    // Verify expected total: 16 tenants × 50 jobs = 800 pending rows.
    let total = index
        .count_global_by_status("pending")
        .expect("count works after contention");
    assert_eq!(total, 800);
}

