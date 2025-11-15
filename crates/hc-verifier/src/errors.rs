use hc_core::error::HcError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("invalid public inputs")]
    InvalidPublicInputs,
    #[error("fri verification failed")]
    FriFailure,
}

impl From<VerifierError> for HcError {
    fn from(value: VerifierError) -> Self {
        HcError::message(value.to_string())
    }
}
