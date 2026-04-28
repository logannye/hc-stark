use std::collections::HashSet;

use hc_hash::protocol;

#[test]
fn protocol_domains_are_unique() {
    let domains = [
        protocol::DOMAIN_MAIN_V2,
        protocol::DOMAIN_FRI_V2,
        protocol::DOMAIN_COMPOSITION_V2,
        protocol::DOMAIN_MAIN_V3,
        protocol::DOMAIN_FRI_V3,
        protocol::DOMAIN_MAIN_V4,
        protocol::DOMAIN_FRI_V4,
    ];

    let mut seen = HashSet::<Vec<u8>>::new();
    for d in domains {
        assert!(seen.insert(d.to_vec()), "duplicate domain: {d:?}");
    }
}

#[test]
fn protocol_labels_are_unique() {
    use protocol::label::*;

    // Keep this list explicit and centralized: if you add a new label constant,
    // add it here too. This makes accidental reuse (copy/paste) impossible to miss.
    let labels: &[&[u8]] = &[
        PUB_INITIAL_ACC,
        PUB_FINAL_ACC,
        PUB_TRACE_LENGTH,
        PARAM_QUERY_COUNT,
        PARAM_LDE_BLOWUP,
        PARAM_FRI_FINAL_SIZE,
        PARAM_FRI_FOLDING_RATIO,
        PARAM_HASH_ID,
        PARAM_ZK_ENABLED,
        PARAM_ZK_MASK_DEGREE,
        COMMIT_TRACE_ROOT,
        COMMIT_COMPOSITION_ROOT,
        COMMIT_FRI_LAYER_ROOT,
        COMMIT_FRI_FINAL_ROOT,
        COMMIT_TRACE_LDE_ROOT,
        COMMIT_QUOTIENT_ROOT,
        CHAL_OOD_POINT,
        CHAL_DEEP_ALPHA,
        CHAL_OOD_INDEX,
        COMMIT_OOD_OPENINGS,
        CHAL_QUERY_ROUND,
        CHAL_QUERY_INDEX,
        COMPOSITION_BLOCK,
        COMPOSITION_COEFF,
        COMPOSITION_ALPHA_BOUNDARY,
        COMPOSITION_ALPHA_TRANSITION,
        CHAL_FRI_BETA,
    ];

    let mut seen = HashSet::<Vec<u8>>::new();
    for label in labels {
        assert!(
            seen.insert(label.to_vec()),
            "duplicate label: {:?}",
            std::str::from_utf8(label).unwrap_or("<non-utf8>")
        );
    }
}
