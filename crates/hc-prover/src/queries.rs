use hc_commit::merkle::MerklePath;
use hc_core::field::FieldElement;
use hc_fri::FriProof;

use crate::{
    commitment::{Commitment, CommitmentScheme},
    metrics::ProverMetrics,
    PublicInputs, TraceRow,
};

/// Query response containing both trace and FRI query answers
#[derive(Clone, Debug)]
pub struct QueryResponse<F: FieldElement> {
    pub trace_queries: Vec<TraceQuery<F>>,
    pub fri_queries: Vec<FriQuery<F>>,
}

/// Response to a trace query
#[derive(Clone, Debug)]
pub struct TraceQuery<F: FieldElement> {
    pub index: usize,
    pub evaluation: TraceRow<F>,
    pub witness: TraceWitness,
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
    pub evaluation: F,
    pub merkle_path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct ProverOutput<F: FieldElement> {
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    pub fri_proof: FriProof<F>,
    pub public_inputs: PublicInputs<F>,
    pub query_response: Option<QueryResponse<F>>,
    pub metrics: ProverMetrics,
    pub trace_length: usize,
    pub commitment_scheme: CommitmentScheme,
}
