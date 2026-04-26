use hc_core::error::HcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("invalid public inputs")]
    InvalidPublicInputs,
    #[error("fri verification failed")]
    FriFailure,
    #[error("missing query responses")]
    MissingQueryResponses,
    #[error("query indices from transcript do not match provided responses")]
    QueryIndexMismatch,
    #[error("trace query Merkle path does not verify")]
    TraceQueryMerkleMismatch,
    #[error("missing next-row trace witness for transition check")]
    TraceNextRowMissing,
    #[error("composition query Merkle path does not verify")]
    CompositionQueryMerkleMismatch,
    #[error("composition query value mismatch")]
    CompositionQueryValueMismatch,
    #[error("missing boundary openings")]
    BoundaryOpeningsMissing,
    #[error("boundary opening index mismatch")]
    BoundaryIndexMismatch,
    #[error("boundary constraint mismatch")]
    BoundaryConstraintMismatch,
    #[error("fri query layer mismatch")]
    FriQueryIndexMismatch,
    #[error("fri query evaluation mismatch")]
    FriQueryEvaluationMismatch,
    #[error("unexpected number of fri queries")]
    FriQueryCountMismatch,
    #[error("fri query Merkle path does not verify")]
    FriQueryMerkleMismatch,
    #[error("trace witness type not supported in this verifier")]
    TraceWitnessUnsupported,
    #[error("missing KZG trace commitment")]
    TraceKzgCommitmentMissing,
    #[error("expected KZG trace witness")]
    TraceKzgWitnessMissing,
    #[error("kzg witness references unknown column {0}")]
    KzgUnknownColumn(usize),
    #[error("kzg witness evaluation point mismatch")]
    KzgPointMismatch,
    #[error("kzg proof invalid")]
    KzgProofInvalid,
    #[error("proof params do not match proof version")]
    ProofParamsVersionMismatch,
}

impl From<VerifierError> for HcError {
    fn from(value: VerifierError) -> Self {
        HcError::message(value.to_string())
    }
}
