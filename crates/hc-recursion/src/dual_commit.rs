//! Dual-hash bridge: Blake3 (native) + Poseidon (circuit-friendly).
//!
//! During proving, the prover commits using Blake3 Merkle trees (fast natively).
//! For recursion, we also need Poseidon Merkle roots (cheap in-circuit).
//!
//! This module:
//! 1. Takes Blake3-committed proof data (trace/quotient evaluations).
//! 2. Recomputes Poseidon-Merkle roots from the same leaf data.
//! 3. Runs a Poseidon transcript to derive the same challenges the circuit
//!    will verify.
//! 4. Produces a `DualCommitment` that can be fed into the STARK verifier
//!    circuit as witness.
//!
//! The key invariant: the Poseidon-derived challenges must agree with the
//! Blake3-derived challenges on the same proof data. This is NOT automatically
//! true (different hash functions produce different outputs), but the verifier
//! circuit only checks Poseidon consistency. The Blake3 commitment provides
//! binding security natively, while the Poseidon commitment enables recursive
//! verification.

use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

use crate::circuit::poseidon;
use crate::poseidon_transcript::{poseidon_merkle_root, PoseidonTranscript};
use hc_hash::protocol;

/// A dual commitment pairing Blake3 and Poseidon roots.
#[derive(Clone, Debug)]
pub struct DualCommitment {
    /// Blake3-Merkle root (32 bytes, used in native verification).
    pub blake3_root: [u8; 32],
    /// Poseidon-Merkle root (BN254 Fr, used in recursive verification).
    pub poseidon_root: Fr,
}

/// Complete dual-hash witness for recursion.
///
/// Contains all the Poseidon-derived data needed to build a `StarkVerifierWitness`.
#[derive(Clone, Debug)]
pub struct DualHashWitness {
    /// Dual commitment for trace polynomial.
    pub trace: DualCommitment,
    /// Dual commitment for quotient polynomial.
    pub quotient: DualCommitment,
    /// Dual commitments for each FRI layer.
    pub fri_layers: Vec<DualCommitment>,
    /// Poseidon-derived challenges (matching the circuit's transcript).
    pub challenges: PoseidonChallenges,
}

/// Poseidon-derived challenges from the Fiat-Shamir transcript.
#[derive(Clone, Debug)]
pub struct PoseidonChallenges {
    /// Composition mixing coefficients.
    pub alpha_boundary: Fr,
    pub alpha_transition: Fr,
    /// FRI folding challenges (one per layer).
    pub fri_betas: Vec<Fr>,
    /// Transcript seed for FRI beta derivation.
    pub fri_seed: Fr,
}

/// Compute Poseidon-Merkle root from field element pairs (trace rows).
///
/// Each row is hashed as `Poseidon(acc, delta)` to produce a leaf,
/// then leaves are combined into a Poseidon-Merkle tree.
pub fn poseidon_trace_root(trace_pairs: &[[Fr; 2]]) -> Fr {
    let leaves: Vec<Fr> = trace_pairs
        .iter()
        .map(|pair| poseidon::hash(&[pair[0], pair[1]]))
        .collect();
    poseidon_merkle_root(&leaves)
}

/// Compute Poseidon-Merkle root from quotient evaluations.
///
/// Each quotient value is hashed individually to produce a leaf.
pub fn poseidon_quotient_root(quotient_evals: &[Fr]) -> Fr {
    let leaves: Vec<Fr> = quotient_evals
        .iter()
        .map(|v| poseidon::hash(&[*v]))
        .collect();
    poseidon_merkle_root(&leaves)
}

/// Compute Poseidon-Merkle root from FRI layer evaluations.
///
/// Each coset pair (v0, v1) is hashed as `Poseidon(v0, v1)` to produce a leaf.
pub fn poseidon_fri_layer_root(coset_pairs: &[(Fr, Fr)]) -> Fr {
    let leaves: Vec<Fr> = coset_pairs
        .iter()
        .map(|(v0, v1)| poseidon::hash(&[*v0, *v1]))
        .collect();
    poseidon_merkle_root(&leaves)
}

/// Build the full dual-hash witness from proof data.
///
/// This is the main entry point for the dual-hash bridge:
/// 1. Recomputes Poseidon-Merkle roots from evaluation data.
/// 2. Runs a Poseidon Fiat-Shamir transcript to derive challenges.
/// 3. Returns a `DualHashWitness` ready for the STARK verifier circuit.
///
/// # Arguments
/// - `blake3_trace_root` — The Blake3-Merkle root from native proving.
/// - `blake3_quotient_root` — The Blake3-Merkle root for the quotient.
/// - `blake3_fri_roots` — Blake3-Merkle roots for each FRI layer.
/// - `trace_pairs` — Trace evaluation pairs (acc, delta) for Poseidon root.
/// - `quotient_evals` — Quotient polynomial evaluations.
/// - `fri_coset_pairs` — Per-layer coset pairs for FRI.
/// - `initial_acc`, `final_acc` — Public inputs.
/// - `padded_trace_length` — Padded trace length (power of 2).
pub fn build_dual_hash_witness(
    blake3_trace_root: [u8; 32],
    blake3_quotient_root: [u8; 32],
    blake3_fri_roots: &[[u8; 32]],
    trace_pairs: &[[Fr; 2]],
    quotient_evals: &[Fr],
    fri_coset_pairs: &[Vec<(Fr, Fr)>],
    initial_acc: u64,
    final_acc: u64,
    padded_trace_length: u64,
) -> DualHashWitness {
    // Step 1: Compute Poseidon-Merkle roots.
    let poseidon_trace = poseidon_trace_root(trace_pairs);
    let poseidon_quotient = poseidon_quotient_root(quotient_evals);

    let mut fri_duals = Vec::with_capacity(blake3_fri_roots.len());
    for (i, blake3_root) in blake3_fri_roots.iter().enumerate() {
        let poseidon_root = if i < fri_coset_pairs.len() {
            poseidon_fri_layer_root(&fri_coset_pairs[i])
        } else {
            Fr::ZERO
        };
        fri_duals.push(DualCommitment {
            blake3_root: *blake3_root,
            poseidon_root,
        });
    }

    // Step 2: Run Poseidon transcript to derive challenges.
    let mut transcript = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);

    // Absorb public inputs.
    transcript.append_u64(protocol::label::PUB_INITIAL_ACC, initial_acc);
    transcript.append_u64(protocol::label::PUB_FINAL_ACC, final_acc);
    transcript.append_u64(protocol::label::PUB_TRACE_LENGTH, padded_trace_length);

    // Absorb trace commitment (Poseidon root).
    transcript.append_fr(protocol::label::COMMIT_TRACE_LDE_ROOT, poseidon_trace);

    // Derive composition challenges.
    let alpha_boundary = transcript.challenge(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
    let alpha_transition = transcript.challenge(protocol::label::COMPOSITION_ALPHA_TRANSITION);

    // Absorb quotient commitment.
    transcript.append_fr(protocol::label::COMMIT_QUOTIENT_ROOT, poseidon_quotient);

    // Derive FRI seed and betas.
    let fri_seed = transcript.challenge(protocol::label::CHAL_FRI_BETA);

    let fri_roots: Vec<Fr> = fri_duals.iter().map(|d| d.poseidon_root).collect();
    let fri_betas = crate::circuit::fri_chain::derive_fri_betas(&fri_roots, fri_seed);

    let challenges = PoseidonChallenges {
        alpha_boundary,
        alpha_transition,
        fri_betas,
        fri_seed,
    };

    DualHashWitness {
        trace: DualCommitment {
            blake3_root: blake3_trace_root,
            poseidon_root: poseidon_trace,
        },
        quotient: DualCommitment {
            blake3_root: blake3_quotient_root,
            poseidon_root: poseidon_quotient,
        },
        fri_layers: fri_duals,
        challenges,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_commit_trace_root_deterministic() {
        let pairs = vec![
            [Fr::from(1u64), Fr::from(2u64)],
            [Fr::from(3u64), Fr::from(4u64)],
            [Fr::from(5u64), Fr::from(6u64)],
            [Fr::from(7u64), Fr::from(8u64)],
        ];
        let r1 = poseidon_trace_root(&pairs);
        let r2 = poseidon_trace_root(&pairs);
        assert_eq!(r1, r2);
        assert_ne!(r1, Fr::ZERO);
    }

    #[test]
    fn dual_commit_different_data_different_root() {
        let pairs1 = vec![[Fr::from(1u64), Fr::from(2u64)]];
        let pairs2 = vec![[Fr::from(3u64), Fr::from(4u64)]];
        assert_ne!(poseidon_trace_root(&pairs1), poseidon_trace_root(&pairs2));
    }

    #[test]
    fn build_dual_hash_witness_produces_consistent_betas() {
        let trace_pairs = vec![
            [Fr::from(5u64), Fr::from(3u64)],
            [Fr::from(8u64), Fr::from(2u64)],
            [Fr::from(10u64), Fr::from(1u64)],
            [Fr::from(11u64), Fr::from(0u64)],
        ];
        let quotient_evals = vec![Fr::from(100u64), Fr::from(200u64)];
        let fri_cosets = vec![vec![
            (Fr::from(1u64), Fr::from(2u64)),
            (Fr::from(3u64), Fr::from(4u64)),
        ]];
        let blake3_trace = [0xAAu8; 32];
        let blake3_quot = [0xBBu8; 32];
        let blake3_fri = vec![[0xCCu8; 32]];

        let witness = build_dual_hash_witness(
            blake3_trace,
            blake3_quot,
            &blake3_fri,
            &trace_pairs,
            &quotient_evals,
            &fri_cosets,
            5,  // initial_acc
            11, // final_acc
            4,  // padded_trace_length
        );

        // Verify structural properties.
        assert_ne!(witness.trace.poseidon_root, Fr::ZERO);
        assert_ne!(witness.quotient.poseidon_root, Fr::ZERO);
        assert_eq!(witness.fri_layers.len(), 1);
        assert_eq!(witness.challenges.fri_betas.len(), 1);
        assert_ne!(witness.challenges.alpha_boundary, Fr::ZERO);
        assert_ne!(witness.challenges.alpha_transition, Fr::ZERO);

        // Verify betas match independent derivation.
        let fri_roots: Vec<Fr> = witness.fri_layers.iter().map(|d| d.poseidon_root).collect();
        let independent_betas =
            crate::circuit::fri_chain::derive_fri_betas(&fri_roots, witness.challenges.fri_seed);
        assert_eq!(witness.challenges.fri_betas, independent_betas);
    }

    #[test]
    fn dual_hash_witness_deterministic() {
        let trace_pairs = vec![[Fr::from(1u64), Fr::from(2u64)]];
        let quotient_evals = vec![Fr::from(10u64)];
        let fri_cosets: Vec<Vec<(Fr, Fr)>> = vec![];
        let blake3_trace = [0u8; 32];
        let blake3_quot = [1u8; 32];

        let w1 = build_dual_hash_witness(
            blake3_trace,
            blake3_quot,
            &[],
            &trace_pairs,
            &quotient_evals,
            &fri_cosets,
            1,
            2,
            2,
        );
        let w2 = build_dual_hash_witness(
            blake3_trace,
            blake3_quot,
            &[],
            &trace_pairs,
            &quotient_evals,
            &fri_cosets,
            1,
            2,
            2,
        );

        assert_eq!(w1.trace.poseidon_root, w2.trace.poseidon_root);
        assert_eq!(w1.challenges.alpha_boundary, w2.challenges.alpha_boundary);
        assert_eq!(w1.challenges.fri_seed, w2.challenges.fri_seed);
    }
}
