use hc_prover::config::{ProverConfig, SecurityFloor};

// ── Grinding config floor tests ─────────────────────────────────────────────

#[test]
fn default_config_has_grinding_bits_20() {
    let config = ProverConfig::with_security_floor(8, 2, 80, 2, SecurityFloor::relaxed()).unwrap();
    assert_eq!(
        config.grinding_bits, 20,
        "default grinding_bits must be 20"
    );
}

#[test]
fn default_floor_grinding_bits_is_20() {
    let floor = SecurityFloor::default();
    assert_eq!(floor.min_grinding_bits, 20);
}

#[test]
fn relaxed_floor_allows_zero_grinding_bits() {
    // relaxed() sets min_grinding_bits=0, so any grinding_bits value (including
    // the default 20) should pass. Verify the relaxed floor itself exposes 0.
    let floor = SecurityFloor::relaxed();
    assert_eq!(floor.min_grinding_bits, 0);
    let result = ProverConfig::with_security_floor(8, 2, 10, 2, floor);
    assert!(result.is_ok(), "relaxed floor must accept default grinding_bits=20");
}

#[test]
fn default_config_passes_default_floor() {
    // Default floor has min_grinding_bits=20 and the default ProverConfig has
    // grinding_bits=20, so construction must succeed.
    let result = ProverConfig::new(8, 2);
    assert!(
        result.is_ok(),
        "default ProverConfig (grinding_bits=20) must pass the default floor (min=20)"
    );
    assert_eq!(result.unwrap().grinding_bits, 20);
}

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
