//! Protocol-level constants and transcript label registry.
//!
//! These values are consensus-critical for proof compatibility.
//! Changing them will break verification unless both prover and verifier upgrade in lockstep.

use crate::hash::HashFunction;

/// Canonical protocol domains.
///
/// Bump these only when intentionally breaking proof compatibility.
pub const DOMAIN_MAIN_V2: &[u8] = b"hc-stark/v2";
pub const DOMAIN_FRI_V2: &[u8] = b"hc-stark/fri/v2";
pub const DOMAIN_COMPOSITION_V2: &[u8] = b"hc-stark/composition/v2";

/// DEEP-STARK protocol domains (v3).
///
/// These domains correspond to a STARK that commits to trace LDE oracles (Merkle),
/// builds a quotient/DEEP composition oracle on an LDE coset, and runs FRI on the
/// quotient oracle.
pub const DOMAIN_MAIN_V3: &[u8] = b"hc-stark/v3";
pub const DOMAIN_FRI_V3: &[u8] = b"hc-stark/fri/v3";

/// Zero-knowledge DEEP-STARK protocol domains (v4).
///
/// v4 is a backwards-incompatible extension of v3 that enables ZK masking.
pub const DOMAIN_MAIN_V4: &[u8] = b"hc-stark/v4";
pub const DOMAIN_FRI_V4: &[u8] = b"hc-stark/fri/v4";

/// Transcript labels (canonical).
///
/// Policy:
/// - Labels are stable API. Changing them breaks proof compatibility.
/// - Prefer structured names: `pub/`, `param/`, `commit/`, `chal/`, `query/`.
pub mod label {
    // Public inputs / parameters
    pub const PUB_INITIAL_ACC: &[u8] = b"pub/initial_acc";
    pub const PUB_FINAL_ACC: &[u8] = b"pub/final_acc";
    pub const PUB_TRACE_LENGTH: &[u8] = b"pub/trace_length";

    pub const PARAM_QUERY_COUNT: &[u8] = b"param/query_count";
    pub const PARAM_LDE_BLOWUP: &[u8] = b"param/lde_blowup";
    pub const PARAM_FRI_FINAL_SIZE: &[u8] = b"param/fri_final_size";
    pub const PARAM_FRI_FOLDING_RATIO: &[u8] = b"param/fri_folding_ratio";
    pub const PARAM_HASH_ID: &[u8] = b"param/hash_id";

    // ZK parameters (v4+)
    pub const PARAM_ZK_ENABLED: &[u8] = b"param/zk_enabled";
    pub const PARAM_ZK_MASK_DEGREE: &[u8] = b"param/zk_mask_degree";

    // Commitments
    pub const COMMIT_TRACE_ROOT: &[u8] = b"commit/trace_root";
    pub const COMMIT_COMPOSITION_ROOT: &[u8] = b"commit/composition_root";
    pub const COMMIT_FRI_LAYER_ROOT: &[u8] = b"commit/fri_layer_root";
    pub const COMMIT_FRI_FINAL_ROOT: &[u8] = b"commit/fri_final_root";

    // v3 DEEP-STARK commitments / challenges
    pub const COMMIT_TRACE_LDE_ROOT: &[u8] = b"commit/trace_lde_root";
    pub const COMMIT_QUOTIENT_ROOT: &[u8] = b"commit/quotient_root";
    pub const CHAL_OOD_POINT: &[u8] = b"chal/ood_point";
    pub const CHAL_DEEP_ALPHA: &[u8] = b"chal/deep_alpha";
    pub const CHAL_OOD_INDEX: &[u8] = b"chal/ood_index";
    pub const COMMIT_OOD_OPENINGS: &[u8] = b"commit/ood_openings";

    // Challenges / queries
    pub const CHAL_QUERY_ROUND: &[u8] = b"chal/query_round";
    pub const CHAL_QUERY_INDEX: &[u8] = b"chal/query_index";

    // Composition mixing coefficients
    pub const COMPOSITION_BLOCK: &[u8] = b"composition/block";
    pub const COMPOSITION_COEFF: &[u8] = b"composition/coeff";
    pub const COMPOSITION_ALPHA_BOUNDARY: &[u8] = b"composition/alpha_boundary";
    pub const COMPOSITION_ALPHA_TRANSITION: &[u8] = b"composition/alpha_transition";

    // FRI folding
    pub const CHAL_FRI_BETA: &[u8] = b"chal/fri_beta";
}

/// Helper to append a u64 in little-endian encoding.
pub fn append_u64<H: HashFunction>(t: &mut crate::Transcript<H>, label: &[u8], value: u64) {
    t.append_message(label, value.to_le_bytes());
}
