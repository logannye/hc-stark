use hc_hash::{blake3::Blake3, Transcript};

pub type VerifierTranscript = Transcript<Blake3>;
