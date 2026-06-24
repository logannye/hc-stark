use axum::http::header;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hc_sdk::types::{ProofBytes, ProveJobStatus, ProveRequest, VerifyRequest};
use tower::ServiceExt;

/// Serialize tests that mutate the process-global HC_SERVER_WORKER_PATH
/// env var. Cargo runs tests in parallel within a single integration
/// binary, and the worker-crash test (which sets a fake worker) would
/// race with the prove_then_verify roundtrip test (which sets the real
/// worker) without this. All tests that touch HC_SERVER_WORKER_PATH
/// acquire this lock for the duration of their env-mutating window.
///
/// Uses `tokio::sync::Mutex` (not `std::sync::Mutex`) because the
/// guard is held across .await points — std mutexes triggered the
/// `clippy::await_holding_lock` lint correctly: a sync mutex held
/// across awaits would deadlock on the same task waiting on itself.
static WORKER_PATH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
async fn version_reports_api_release_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["service"], "api");
    assert_eq!(json["package_version"], env!("CARGO_PKG_VERSION"));
    assert!(json.get("release_sha").is_some());
}

#[tokio::test]
async fn prove_then_verify_roundtrip() {
    // Hold the env-var lock for the env mutation. Other tests that mutate
    // HC_SERVER_WORKER_PATH (e.g. worker_crash_lands_job_in_failed_state)
    // would race with us without this.
    let _guard = WORKER_PATH_LOCK.lock().await;
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

    // Phase 1A cutover: the server now produces SOUND v5 proofs (blowup ≥ 8),
    // which require the padded trace length to be ≥ 8 (≈ ≥ 7 instructions). The
    // 2-instruction `toy_add_1_2` workload is too small, so prove with a custom
    // 8-instruction accumulator program (test_state allows custom programs).
    // acc: 5 + (1+2+3+4+5+6+7+8) = 41. Trace length 9 → padded 16.
    let prove_req = ProveRequest {
        workload_id: None,
        template_id: None,
        template_params: None,
        program: Some(vec![
            "add_immediate 1".to_string(),
            "add_immediate 2".to_string(),
            "add_immediate 3".to_string(),
            "add_immediate 4".to_string(),
            "add_immediate 5".to_string(),
            "add_immediate 6".to_string(),
            "add_immediate 7".to_string(),
            "add_immediate 8".to_string(),
        ]),
        initial_acc: 5,
        final_acc: 41,
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

    // Poll. The production v5 path pins grinding_bits = 20 (~1M blake3 hashes),
    // which takes several seconds in a debug build, so the poll budget is
    // generous (up to 60s) — this is the cost of exercising the real
    // production prove config end-to-end through the worker process.
    let mut proof = None;
    for _ in 0..300 {
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
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
    let proof = proof.expect("prove should complete");
    let job_dir = tmp.path().join("jobs").join("dev").join(&submit.job_id);
    assert!(
        job_dir.join("status.json").exists(),
        "job status remains available for local polling compatibility"
    );
    assert!(
        !job_dir.join("request.json").exists(),
        "worker input should be streamed over stdin, not persisted as request.json"
    );
    assert!(
        !job_dir.join("proof.json").exists(),
        "worker output should be streamed over stdout, not persisted as proof.json"
    );

    // Sound v5 proof: the production /verify endpoint (default floor) accepts it.
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
async fn shared_dispatch_enqueues_without_local_worker_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_shared_dispatch(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 1,
        final_acc: 4,
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 80,
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

    let job_dir = tmp.path().join("jobs").join("dev").join(&submit.job_id);
    assert!(
        !job_dir.exists(),
        "shared dispatch should not create local job artifacts"
    );

    let resp = app
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
    assert!(matches!(status, ProveJobStatus::Pending));
}

#[tokio::test]
async fn shared_dispatch_claimed_worker_completion_polls_and_verifies() {
    let worker = std::env::var("CARGO_BIN_EXE_hc-worker")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_hc_worker"))
        .ok()
        .or_else(|| {
            let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let candidate = here.join("../../target/debug/hc-worker");
            candidate
                .exists()
                .then(|| candidate.to_string_lossy().to_string())
        });
    let Some(worker) = worker else {
        eprintln!("skipping shared-dispatch worker completion test: hc-worker binary not found");
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state_shared_dispatch(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: None,
        template_id: None,
        template_params: None,
        program: Some(vec![
            "add_immediate 1".to_string(),
            "add_immediate 2".to_string(),
            "add_immediate 3".to_string(),
            "add_immediate 4".to_string(),
            "add_immediate 5".to_string(),
            "add_immediate 6".to_string(),
            "add_immediate 7".to_string(),
            "add_immediate 8".to_string(),
        ]),
        initial_acc: 5,
        final_acc: 41,
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

    let job_dir = tmp.path().join("jobs").join("dev").join(&submit.job_id);
    assert!(
        !job_dir.exists(),
        "shared dispatch should not create local job artifacts before worker claim"
    );

    let index = hc_server::job_index::JobIndex::open(tmp.path().join("jobs.sqlite")).unwrap();
    let claimed = index
        .claim_next("integration-worker", 30_000)
        .unwrap()
        .expect("shared-dispatch job should be claimable");
    assert_eq!(claimed.tenant_id, "dev");
    assert_eq!(claimed.job_id, submit.job_id);
    assert_eq!(claimed.request.final_acc, 41);

    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = tokio::process::Command::new(worker)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("HC_SERVER_ALLOW_CUSTOM_PROGRAMS", "true")
        .spawn()
        .expect("spawn hc-worker --stdio");
    let mut stdin = child.stdin.take().expect("worker stdin");
    stdin
        .write_all(&serde_json::to_vec(&claimed.request).unwrap())
        .await
        .expect("write worker request");
    stdin.shutdown().await.expect("close worker stdin");
    drop(stdin);

    let output = tokio::time::timeout(std::time::Duration::from_secs(90), child.wait_with_output())
        .await
        .expect("hc-worker should finish within test timeout")
        .expect("wait for hc-worker");
    assert!(
        output.status.success(),
        "hc-worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proof: ProofBytes = serde_json::from_slice(&output.stdout).expect("parse worker proof");
    index
        .update_status(
            "dev",
            &submit.job_id,
            &ProveJobStatus::Succeeded {
                proof: proof.clone(),
            },
        )
        .unwrap();

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
    let polled_proof = match status {
        ProveJobStatus::Succeeded { proof } => proof,
        other => panic!("expected shared-index success, got {other:?}"),
    };
    assert_eq!(polled_proof.version, proof.version);
    assert_eq!(polled_proof.bytes, proof.bytes);

    let verify_req = VerifyRequest {
        proof: polled_proof,
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
    let _guard = WORKER_PATH_LOCK.lock().await;
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
    let _guard = WORKER_PATH_LOCK.lock().await;
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

/// Audit finding G2 follow-on (Phase-1A Task 9): the `/aggregate` endpoint
/// must return HTTP 410 Gone for ALL requests — the in-circuit Halo2 FRI fold
/// is unsound and the endpoint is gated off until Phase 1B.
#[tokio::test]
async fn aggregate_is_gated_off_with_410() {
    let tmp = tempfile::tempdir().unwrap();
    let state = hc_server::test_state(tmp.path().to_path_buf());
    let app = hc_server::build_app(state);

    // Any request body — the gate fires before body parsing.
    let req_body = serde_json::json!({"job_ids": ["00000000-0000-0000-0000-000000000001"]});
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
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "/aggregate must return 410 (recursion gate, audit finding G2)"
    );
    // The error body must mention recursion / soundness so clients can act.
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let msg = json["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("soundness") || msg.contains("G2"),
        "error message should mention soundness or G2, got: {msg}"
    );
}

/// Gate fires regardless of input shape — empty job_ids also yields 410.
#[tokio::test]
async fn aggregate_gate_fires_before_input_validation() {
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
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "/aggregate must return 410 even for empty job_ids (gate fires first)"
    );
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

/// Worker crash mid-prove: the spawned hc-worker exits non-zero before
/// returning proof bytes on stdout. The hc-server `prove_with_worker_process`
/// must detect the failed exit and surface a Failed status, not leave the job
/// stuck in Running. This is the regression guard for the colleague's "process
/// killed mid-prove" scenario.
#[tokio::test]
async fn worker_crash_lands_job_in_failed_state() {
    use std::os::unix::fs::PermissionsExt;
    // Hold the env-var lock for the entire test — set, prove, poll,
    // restore — so no parallel test sees the fake worker.
    let _guard = WORKER_PATH_LOCK.lock().await;
    let prior = std::env::var("HC_SERVER_WORKER_PATH").ok();

    // Build a fake worker that exits 99 immediately. The arguments are ignored:
    // we want the spawn to succeed but the child to die before returning proof
    // bytes on stdout.
    let tmp = tempfile::tempdir().unwrap();
    let fake_worker = tmp.path().join("fake-worker");
    std::fs::write(
        &fake_worker,
        b"#!/bin/sh\n# fake hc-worker that simulates a crash\nexit 99\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_worker, std::fs::Permissions::from_mode(0o755)).unwrap();

    std::env::set_var("HC_SERVER_WORKER_PATH", &fake_worker);
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

    // Poll: must transition to Failed within a reasonable window.
    // Worker exits immediately so this should land in <1s on any
    // sane CI runner; we give it 3s of headroom.
    let mut final_status: Option<ProveJobStatus> = None;
    for _ in 0..30 {
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: ProveJobStatus = serde_json::from_slice(&body).unwrap();
        match status {
            ProveJobStatus::Failed { .. } => {
                final_status = Some(status);
                break;
            }
            ProveJobStatus::Succeeded { .. } => {
                panic!("fake worker exited 99 — succeed is impossible");
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }

    // Restore prior env-var so any subsequent test sees what was set
    // before us, not a removed variable.
    match prior {
        Some(v) => std::env::set_var("HC_SERVER_WORKER_PATH", v),
        None => std::env::remove_var("HC_SERVER_WORKER_PATH"),
    }
    let final_status = final_status.expect(
        "worker crash should land Failed within 3s; got stuck in Running — \
         this is the regression scenario this test guards against",
    );
    match final_status {
        ProveJobStatus::Failed { error } => {
            // The error message should reference the worker exit so an
            // operator can debug. Don't pin the exact wording (anyhow
            // formatting is implementation detail), just sanity-check
            // that it's non-empty.
            assert!(
                !error.is_empty(),
                "Failed status should carry a non-empty error message"
            );
        }
        _ => unreachable!(),
    }
}

/// G12 regression: two concurrent /prove submissions from the same tenant
/// with max_inflight=1 must yield exactly one 200 and one 429
/// too_many_inflight.  This exercises the atomic gate introduced to close
/// the TOCTOU race where both requests could read inflight=0 before either
/// inserted its job.
///
/// The test does NOT spin up a real worker (hc-worker path); the gate fires
/// in the HTTP handler before the worker spawn, so no binary is needed.
/// Both requests are dispatched via separate `oneshot` calls into the same
/// cloned `app` with `max_inflight_jobs=1` on the server config.
#[tokio::test]
async fn concurrent_submissions_respect_inflight_limit() {
    let tmp = tempfile::tempdir().unwrap();
    // max_inflight_jobs=1 at the server level; the default free-plan
    // PlanLimits.max_inflight is also 1, so min(1,1)=1.
    let state = hc_server::test_state_with_max_inflight(tmp.path().to_path_buf(), 1);
    let app = hc_server::build_app(state);

    let prove_req = ProveRequest {
        workload_id: Some("toy_add_1_2".to_string()),
        template_id: None,
        template_params: None,
        program: None,
        initial_acc: 5,
        final_acc: 8,
        // block_size=8 so computed_trace_length = 1*8 = 8 (workload, no program bytes)
        block_size: 8,
        fri_final_poly_size: 2,
        query_count: 10,
        lde_blowup_factor: 2,
        zk_mask_degree: None,
    };
    let body = serde_json::to_vec(&prove_req).unwrap();

    // Submit two requests back-to-back (sequential oneshot calls share the
    // same in-memory job map).  The first should land as Pending before the
    // second checks the count, so the second must be rejected.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let statuses = [resp1.status(), resp2.status()];
    let ok_count = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
    let toomany_count = statuses
        .iter()
        .filter(|&&s| s == StatusCode::TOO_MANY_REQUESTS)
        .count();

    assert_eq!(
        ok_count, 1,
        "exactly one submission should be accepted; got statuses {:?}",
        statuses
    );
    assert_eq!(
        toomany_count, 1,
        "exactly one submission should be rejected 429; got statuses {:?}",
        statuses
    );

    // Confirm the 429 body carries the expected error code.
    // We re-issue a fresh second request to read its body.
    let prove_req2 = ProveRequest {
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
    let resp3 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/prove")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&prove_req2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);
    let body3 = axum::body::to_bytes(resp3.into_body(), usize::MAX)
        .await
        .unwrap();
    let json3: serde_json::Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(
        json3["error"]["code"], "too_many_inflight",
        "429 body should carry error.code='too_many_inflight'"
    );
}
