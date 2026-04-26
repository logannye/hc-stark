use hc_commit::merkle::MerklePath;
use hc_core::field::FieldElement;
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
