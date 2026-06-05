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

/// Soundness-hardened DEEP-STARK protocol domains (v5).
///
/// v5 extends v4 with a cryptographic grinding check and a configurable
/// challenge field, providing stronger soundness guarantees for the FRI
/// low-degree test.
pub const DOMAIN_MAIN_V5: &[u8] = b"hc-stark/v5";
pub const DOMAIN_FRI_V5: &[u8] = b"hc-stark/fri/v5";

/// Recursive-friendly soundness-hardened DEEP-STARK protocol domains (v6).
///
/// v6 extends v5 with optimisations targeting recursive composition.
pub const DOMAIN_MAIN_V6: &[u8] = b"hc-stark/v6";
pub const DOMAIN_FRI_V6: &[u8] = b"hc-stark/fri/v6";

/// General-AIR soundness-hardened DEEP-STARK protocol domains (v7).
///
/// v7 generalizes v5 from the hardcoded width-2 accumulator (`ToyAir`) to an
/// arbitrary [`hc_air`-style] AIR: a width-N trace and N constraints combined
/// via powers of a single composition challenge in `K` (`Σ αⁱ·cᵢ`). It also
/// carries a public-input vector instead of fixed `initial_acc`/`final_acc`.
pub const DOMAIN_MAIN_V7: &[u8] = b"hc-stark/v7";
pub const DOMAIN_FRI_V7: &[u8] = b"hc-stark/fri/v7";

/// Zero-knowledge general-AIR protocol domains (v8 = v7 + ZK masking over all
/// trace columns).
pub const DOMAIN_MAIN_V8: &[u8] = b"hc-stark/v8";
pub const DOMAIN_FRI_V8: &[u8] = b"hc-stark/fri/v8";

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

    // Grinding / challenge-field parameters (v5+)
    pub const PARAM_GRINDING_BITS: &[u8] = b"param/grinding_bits";
    pub const PARAM_CHALLENGE_FIELD: &[u8] = b"param/challenge_field";
    pub const FRI_GRINDING_NONCE: &[u8] = b"fri/grinding_nonce";

    // General-AIR seam (v7+). A SINGLE composition challenge whose powers mix all
    // constraints (`Σ αⁱ·cᵢ`), replacing the two v5 `composition/alpha_{boundary,
    // transition}` challenges. The trace width, the public-input vector, and the
    // AIR identity are all bound into the transcript so prover and verifier agree
    // on the constraint set and leaf arity.
    pub const COMPOSITION_ALPHA: &[u8] = b"composition/alpha";
    pub const PARAM_TRACE_WIDTH: &[u8] = b"param/trace_width";
    pub const AIR_ID: &[u8] = b"param/air_id";
    pub const PUB_INPUT_COUNT: &[u8] = b"pub/input_count";
    pub const PUB_INPUT_ELEM: &[u8] = b"pub/input_elem";
}

/// Helper to append a u64 in little-endian encoding.
pub fn append_u64<H: HashFunction>(t: &mut crate::Transcript<H>, label: &[u8], value: u64) {
    t.append_message(label, value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_v8_domains_present_and_distinct() {
        assert_eq!(DOMAIN_MAIN_V7, b"hc-stark/v7");
        assert_eq!(DOMAIN_FRI_V7, b"hc-stark/fri/v7");
        assert_eq!(DOMAIN_MAIN_V8, b"hc-stark/v8");
        assert_eq!(DOMAIN_FRI_V8, b"hc-stark/fri/v8");
        // v7 must differ from every prior main domain (consensus separation).
        for prior in [
            DOMAIN_MAIN_V2,
            DOMAIN_MAIN_V3,
            DOMAIN_MAIN_V4,
            DOMAIN_MAIN_V5,
            DOMAIN_MAIN_V6,
        ] {
            assert_ne!(DOMAIN_MAIN_V7, prior);
            assert_ne!(DOMAIN_MAIN_V8, prior);
        }
        assert_ne!(DOMAIN_MAIN_V7, DOMAIN_MAIN_V8);
    }

    #[test]
    fn v7_seam_labels_present() {
        assert_eq!(label::COMPOSITION_ALPHA, b"composition/alpha");
        assert_eq!(label::PARAM_TRACE_WIDTH, b"param/trace_width");
        assert_eq!(label::AIR_ID, b"param/air_id");
        assert_eq!(label::PUB_INPUT_COUNT, b"pub/input_count");
        assert_eq!(label::PUB_INPUT_ELEM, b"pub/input_elem");
        // The single v7 composition challenge is distinct from the two v5 ones.
        assert_ne!(label::COMPOSITION_ALPHA, label::COMPOSITION_ALPHA_BOUNDARY);
        assert_ne!(
            label::COMPOSITION_ALPHA,
            label::COMPOSITION_ALPHA_TRANSITION
        );
    }
}
