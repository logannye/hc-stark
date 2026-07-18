use anyhow::Error;
use std::io::Write;
use tinyzkp_contracts::{EngineErrorEnvelopeV1, EngineProgressEventV1, ReasonCodeV1, ReasonV1};

#[derive(Debug, thiserror::Error)]
#[error("{reason:?}")]
pub struct ProtocolFailure {
    pub reason: ReasonV1,
    pub resumable: bool,
    pub checkpoint_present: bool,
}

impl ProtocolFailure {
    pub fn new(code: ReasonCodeV1) -> Self {
        Self {
            reason: ReasonV1::new(code),
            resumable: false,
            checkpoint_present: false,
        }
    }

    pub fn interrupted(checkpoint_present: bool) -> Self {
        Self {
            reason: ReasonV1::new(ReasonCodeV1::InterruptedResumable),
            resumable: checkpoint_present,
            checkpoint_present,
        }
    }
}

pub fn failure_from_anyhow(error: &Error) -> ProtocolFailure {
    if let Some(protocol) = error.downcast_ref::<ProtocolFailure>() {
        return ProtocolFailure {
            reason: protocol.reason.clone(),
            resumable: protocol.resumable,
            checkpoint_present: protocol.checkpoint_present,
        };
    }
    ProtocolFailure::new(ReasonCodeV1::InternalError)
}

pub fn write_error(error: &ProtocolFailure) -> u8 {
    let envelope = EngineErrorEnvelopeV1::new(
        hc_plonky3::release_identity(),
        error.reason.clone(),
        error.resumable,
        error.checkpoint_present,
    );
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &envelope).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        return 70;
    }
    envelope.error.exit_code
}

pub fn emit_progress(event: &EngineProgressEventV1) {
    let mut stderr = std::io::stderr().lock();
    if serde_json::to_writer(&mut stderr, event).is_ok() {
        let _ = stderr.write_all(b"\n");
        let _ = stderr.flush();
    }
}
