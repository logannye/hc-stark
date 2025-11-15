use hc_commit::merkle::MerklePath;
use hc_core::field::FieldElement;
use hc_fri::FriProof;
use hc_hash::hash::HashDigest;

use crate::{metrics::ProverMetrics, PublicInputs, TraceRow};

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
    pub merkle_path: MerklePath,
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
    pub trace_root: HashDigest,
    pub fri_proof: FriProof<F>,
    pub public_inputs: PublicInputs<F>,
    pub query_response: Option<QueryResponse<F>>,
    pub metrics: ProverMetrics,
    pub trace_length: usize,
}
