use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn health_version_and_capabilities_are_the_only_available_product_surface() {
    let state = hc_server::test_state_maintenance(tempfile::tempdir().unwrap().path().into());
    let app = hc_server::build_app(state);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let capabilities = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capabilities.status(), StatusCode::OK);
    let body = axum::body::to_bytes(capabilities.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["maintenance_mode"], true);
    assert_eq!(payload["service_status"], "backend_recovery");
    assert_eq!(payload["backend"], "plonky3");
    assert_eq!(payload["plonky3_version"], "0.6.1");
    assert_eq!(payload["proving_available"], false);
    assert_eq!(payload["verification_available"], false);
    assert_eq!(payload["release"]["service"], "api");
}

#[tokio::test]
async fn every_historical_proving_path_returns_protocol_upgrade() {
    let state = hc_server::test_state_maintenance(tempfile::tempdir().unwrap().path().into());
    let app = hc_server::build_app(state);
    for path in [
        "/prove",
        "/prove/batch",
        "/prove/template/range",
        "/proof/job/calldata",
        "/estimate",
        "/aggregate",
        "/templates",
        "/v1/inputs",
        "/v1/quotes",
        "/v1/proofs",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("protocol_upgrade"));
    }
}

#[tokio::test]
async fn legacy_hosted_verification_is_rejected_as_statement_unbound() {
    let state = hc_server::test_state_maintenance(tempfile::tempdir().unwrap().path().into());
    let app = hc_server::build_app(state);
    for version in [5, 7] {
        let body = serde_json::json!({"proof": {"version": version, "bytes": []}});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("legacy_statement_unbound"));
    }
}
