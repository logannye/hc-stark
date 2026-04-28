use hc_prover::config::{ProverConfig, SecurityFloor};

#[test]
fn invalid_block_size_rejected() {
    let result = ProverConfig::with_security_floor(0, 2, 80, 2, SecurityFloor::relaxed());
    assert!(result.is_err());
}

#[test]
fn non_power_of_2_rejected() {
    let result = ProverConfig::with_security_floor(5, 2, 80, 2, SecurityFloor::relaxed());
    assert!(result.is_err());
}

#[test]
fn security_floor_rejects_low_query_count() {
    let result = ProverConfig::with_full_config(8, 2, 10, 2);
    assert!(
        result.is_err(),
        "query_count=10 should be rejected by default floor"
    );
}

#[test]
fn relaxed_floor_allows_test_params() {
    let result = ProverConfig::with_security_floor(8, 2, 10, 2, SecurityFloor::relaxed());
    assert!(result.is_ok(), "relaxed floor should allow query_count=10");
}

#[test]
fn block_size_over_max_rejected() {
    let result = ProverConfig::with_full_config(1 << 24, 2, 80, 2);
    assert!(
        result.is_err(),
        "block_size 2^24 should exceed default max 2^20"
    );
}

#[test]
fn query_count_over_max_rejected() {
    let result = ProverConfig::with_full_config(8, 2, 300, 2);
    assert!(
        result.is_err(),
        "query_count=300 should exceed default max 200"
    );
}

#[test]
fn lde_blowup_over_max_rejected() {
    let result = ProverConfig::with_full_config(8, 2, 80, 32);
    assert!(
        result.is_err(),
        "lde_blowup=32 should exceed default max 16"
    );
}
