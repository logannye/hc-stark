use hc_commit::merkle::MerklePath;
use hc_core::field::{FieldElement, QuadExtension};
use hc_fri::FriProof;

use crate::{
    commitment::{Commitment, CommitmentScheme},
    metrics::ProverMetrics,
    PublicInputs, TraceRow,
};

/// Protocol parameters that should be carried alongside a proof artifact.
///
/// This makes proofs self-describing and is required for stable serialization.
#[derive(Clone, Copy, Debug)]
pub struct ProofParams {
    pub query_count: usize,
    pub lde_blowup_factor: usize,
    pub fri_final_poly_size: usize,
    pub fri_folding_ratio: usize,
    /// Consensus-critical proof format / transcript version.
    pub protocol_version: u32,
    /// Whether ZK masking is enabled for this proof.
    pub zk_enabled: bool,
    /// Masking degree bound (meaningful only when `zk_enabled`).
    pub zk_mask_degree: usize,
    /// Number of bits of proof-of-work grinding performed by the v5 prover.
    /// Zero for v3 proofs (no grinding). Populated by the v5 prover (Task 7b).
    pub grinding_bits: u32,
}

/// Query response containing both trace and FRI query answers
#[derive(Clone, Debug)]
pub struct QueryResponse<F: FieldElement> {
    pub trace_queries: Vec<TraceQuery<F>>,
    pub composition_queries: Vec<CompositionQuery<F>>,
    pub fri_queries: Vec<FriQuery<F>>,
    /// Mandatory boundary openings for soundness of the toy AIR.
    ///
    /// These enforce the initial and final accumulator constraints (and also bind the
    /// first transition via the composition oracle at index 0).
    pub boundary: Option<BoundaryOpenings<F>>,
    /// Optional OOD-style openings used by DEEP-STARK v3.
    pub ood: Option<OodOpenings<F>>,
}

#[derive(Clone, Debug)]
pub struct OodOpenings<F: FieldElement> {
    pub index: usize,
    pub trace: TraceQuery<F>,
    pub quotient: CompositionQuery<F>,
}

#[derive(Clone, Debug)]
pub struct BoundaryOpenings<F: FieldElement> {
    /// Trace opening at index 0 (and `next` should provide index 1).
    pub first_trace: TraceQuery<F>,
    /// Trace opening at index `trace_length - 1`.
    pub last_trace: TraceQuery<F>,
    /// Composition opening at index 0.
    pub first_composition: CompositionQuery<F>,
    /// Composition opening at index `trace_length - 1`.
    pub last_composition: CompositionQuery<F>,
}

/// Response to a trace query
#[derive(Clone, Debug)]
pub struct TraceQuery<F: FieldElement> {
    pub index: usize,
    pub evaluation: TraceRow<F>,
    pub witness: TraceWitness,
    /// Optional next-row opening needed to enforce transition constraints at index `i`.
    pub next: Option<NextTraceRow<F>>,
}

#[derive(Clone, Debug)]
pub struct NextTraceRow<F: FieldElement> {
    pub index: usize,
    pub evaluation: TraceRow<F>,
    pub witness: MerklePath,
}

/// Response to a composition oracle query (one value per trace row).
#[derive(Clone, Debug)]
pub struct CompositionQuery<F: FieldElement> {
    pub index: usize,
    pub value: F,
    pub witness: MerklePath,
}

#[derive(Clone, Debug)]
pub enum TraceWitness {
    Merkle(MerklePath),
    Kzg(KzgTraceWitness),
}

#[derive(Clone, Debug)]
pub struct KzgTraceWitness {
    pub point: Vec<u8>,
    pub proofs: Vec<KzgColumnProof>,
    pub evaluations: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct KzgColumnProof {
    pub column: usize,
    pub proof: Vec<u8>,
}

/// Response to a FRI layer query
#[derive(Clone, Debug)]
pub struct FriQuery<F: FieldElement> {
    pub layer_index: usize,
    pub query_index: usize,
    /// Opened coset pair at indices `query_index` and `query_index + 1`.
    ///
    /// For the current folding ratio (2), the next-layer value at index `query_index / 2`
    /// must equal `values[0] + beta * values[1]`, where `beta` is transcript-derived.
    pub values: [F; 2],
    pub merkle_paths: [MerklePath; 2],
}

#[derive(Clone, Debug)]
pub struct ProverOutput<F: FieldElement> {
    pub version: u32,
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    pub fri_proof: FriProof<F>,
    pub public_inputs: PublicInputs<F>,
    pub query_response: Option<QueryResponse<F>>,
    pub metrics: ProverMetrics,
    pub trace_length: usize,
    pub commitment_scheme: CommitmentScheme,
    pub params: ProofParams,
}

/// OOD-style opening for the v5 proof: the trace opening stays in the base field
/// `F`, while the quotient (composition) opening is **`K`-valued** (Phase 1A.2 —
/// the composition challenges + quotient are in `K = QuadExtension<F>`).
///
/// ADDITIVE counterpart to [`OodOpenings`] (which stays fully F for v3).
#[derive(Clone, Debug)]
pub struct OodOpeningsV5<F: FieldElement> {
    pub index: usize,
    pub trace: TraceQuery<F>,
    pub quotient: CompositionQuery<QuadExtension<F>>,
}

/// Boundary openings for the v5 proof: trace openings in `F`, composition
/// (quotient) openings in **`K`** (Phase 1A.2). ADDITIVE counterpart to
/// [`BoundaryOpenings`] (which stays fully F for v3). Currently always `None` in
/// the v5 path (the OOD + base-query composition openings cover soundness), but
/// kept so the v5 query response mirrors the v3 shape.
#[derive(Clone, Debug)]
pub struct BoundaryOpeningsV5<F: FieldElement> {
    pub first_trace: TraceQuery<F>,
    pub last_trace: TraceQuery<F>,
    pub first_composition: CompositionQuery<QuadExtension<F>>,
    pub last_composition: CompositionQuery<QuadExtension<F>>,
}

/// Query response for the soundness-hardened v5 proof (Phase 1A FRI rebuild).
///
/// ADDITIVE counterpart to [`QueryResponse`]: the trace openings stay in the base
/// field `F` (reused from the v3 path), while the composition (quotient) openings
/// and the FRI openings are **`K`-valued** (`K = QuadExtension<F>`, Phase 1A.2 —
/// composition challenges + quotient in K). Produced by the antipodal commit
/// phase ([`crate::pipeline::phase2_fri::run_fri_v5`]) + answered by
/// [`crate::pipeline::phase3_queries::answer_fri_queries_v5`].
///
/// Consumed by the Task 8 v5 verifier.
#[derive(Clone, Debug)]
pub struct QueryResponseV5<F: FieldElement> {
    pub trace_queries: Vec<TraceQuery<F>>,
    /// `K`-valued quotient (composition) openings.
    pub composition_queries: Vec<CompositionQuery<QuadExtension<F>>>,
    /// `K`-valued FRI openings (antipodal pairs over the extension field).
    pub fri_queries: Vec<FriQuery<QuadExtension<F>>>,
    pub boundary: Option<BoundaryOpeningsV5<F>>,
    pub ood: Option<OodOpeningsV5<F>>,
}

/// Soundness-hardened v5 proof (Phase 1A FRI rebuild).
///
/// ADDITIVE counterpart to the verifier's `Proof`/the prover's [`ProverOutput`]:
/// the FRI proof is `K`-valued (carries `final_coeffs`), and the proof carries a
/// proof-of-work `grinding_nonce` (with `params.grinding_bits` set from config).
///
/// Consumed by the Task 8 v5 verifier.
#[derive(Clone, Debug)]
pub struct ProofV5<F: FieldElement> {
    /// 5 (native) or 6 (ZK).
    pub version: u32,
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    /// `K`-valued FRI proof; carries `final_coeffs`.
    pub fri_proof: FriProof<QuadExtension<F>>,
    pub initial_acc: F,
    pub final_acc: F,
    pub query_response: QueryResponseV5<F>,
    pub trace_length: usize,
    /// Protocol parameters; `params.grinding_bits` is set from config.
    pub params: ProofParams,
    /// Proof-of-work nonce satisfying the grinding check (see Task 8 verifier).
    pub grinding_nonce: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ProofParams construct-and-read test (manual serde — not derive). Verifies the
    /// new grinding_bits field round-trips through a plain Rust value.
    #[test]
    fn proof_params_grinding_bits_field() {
        let p = ProofParams {
            query_count: 40,
            lde_blowup_factor: 4,
            fri_final_poly_size: 2,
            fri_folding_ratio: 2,
            protocol_version: 3,
            zk_enabled: false,
            zk_mask_degree: 0,
            grinding_bits: 0,
        };
        assert_eq!(p.grinding_bits, 0, "v3 params must have grinding_bits = 0");

        let p_nonzero = ProofParams {
            grinding_bits: 16,
            ..p
        };
        assert_eq!(p_nonzero.grinding_bits, 16);
    }
}
