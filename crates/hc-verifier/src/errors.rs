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
    #[error("fri query layer mismatch")]
    FriQueryIndexMismatch,
    #[error("fri query evaluation mismatch")]
    FriQueryEvaluationMismatch,
    #[error("unexpected number of fri queries")]
    FriQueryCountMismatch,
}

impl From<VerifierError> for HcError {
    fn from(value: VerifierError) -> Self {
        HcError::message(value.to_string())
    }
}
