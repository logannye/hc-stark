//! Witness, public IO, and proof envelope types for zkML.

use crate::tensor::Tensor;
use serde::{Deserialize, Serialize};

/// Inference witness: the input tensor plus optional intermediate activations
/// for layers the prover wants to commit to (used by ZK-masked mode to
/// re-randomize).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InferenceWitness {
    /// The input tensor. `None` is permitted only for the empty graph (used
    /// by tests and parameter-validation paths).
    pub input: Option<Tensor>,
    /// Optional intermediate-activation commitments produced by the frontend.
    /// Each entry corresponds 1:1 with a layer index in the graph.
    pub activations: Vec<Tensor>,
}

impl InferenceWitness {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Public IO accompanying a proof: the input commitment, the output tensor,
/// and the model commitment that the prover claims was applied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicIo {
    /// Hash of the canonical-serialized input tensor (32 bytes). Always
    /// included so the verifier can bind a proof to a specific input.
    pub input_digest: [u8; 32],
    /// Output tensor in the clear. The verifier checks that the prover's
    /// inference produced exactly this output.
    pub output: Tensor,
}

/// Opaque zkML proof envelope. The internal layout is owned by the prover
/// implementation; consumers should treat it as a sealed byte-string except
/// to serialize/deserialize.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkmlProof {
    /// Wire-format version. Bumped whenever the binary layout changes.
    pub version: u8,
    /// Serialized proof body.
    pub bytes: Vec<u8>,
}

impl ZkmlProof {
    /// Current proof format version.
    pub const VERSION: u8 = 1;
}
