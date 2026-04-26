#![forbid(unsafe_code)]

//! `hc-zkml` — verifiable AI inference over the height-compressed STARK prover.
//!
//! ## Why this crate exists
//!
//! Neural-network inference is a deterministic DAG of large arithmetic
//! reductions (matrix multiplication, convolution, dot products) wrapped in
//! pointwise non-linearities (ReLU, GELU, softmax). Today's zkML systems
//! materialize the full activation tensor at every layer and run a monolithic
//! prover over it — peak memory is `O(sum of layer activation bytes)`, which
//! pushes realistic models out of reach on commodity hardware.
//!
//! Inference is, however, the *canonical* height-compressible computation:
//!
//! - Matrix multiplication `C = A · B` is an associative summation tree over
//!   `K` partial products. The summation tree is balanced and binary by
//!   construction, so the height-compression discipline applies directly.
//! - Activations are pointwise functions of the previous layer — they have
//!   trivial per-tile checkpoints (the input slice is the checkpoint).
//! - The full inference DAG is itself a deterministic computation tree whose
//!   intermediate tensors can be replayed from the input + weights instead of
//!   stored.
//!
//! We therefore expose inference proving as a *layered* API on top of the
//! existing `hc-prover` streaming engine. Each layer is converted into an AIR
//! that the prover already knows how to handle in `O(√T)` memory, and the
//! activation-tensor handoff between layers is a constant-size checkpoint
//! (commitment + tile boundary).
//!
//! ## Surface stability
//!
//! The types and signatures in this crate are intended to be the long-term
//! public API. The cryptographic body is staged behind
//! [`HcError::unimplemented`] returns until the underlying AIR work lands.
//! Tests in this crate lock the *type-level contract* so future implementation
//! work cannot silently change the public shape.

pub mod graph;
pub mod matmul;
pub mod proof;
pub mod streaming;
pub mod tensor;

pub use graph::{Layer, ModelGraph, ModelGraphBuilder};
pub use proof::{InferenceWitness, PublicIo, ZkmlProof};
pub use tensor::{Quantization, Shape, Tensor};

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Tunables for the zkML prover.
///
/// The defaults pick conservative values appropriate for a 32-GB-RAM commodity
/// host. Operators with more memory should raise `tile_dim` to amortize
/// per-tile overhead; operators with less memory or running concurrent jobs
/// should lower it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HcZkmlConfig {
    /// Side length of a square matmul tile, in elements. Must be a power of
    /// two. Memory pressure scales as `O(tile_dim^2)`; replay overhead scales
    /// as `O(K / tile_dim)`.
    pub tile_dim: usize,
    /// Maximum quantization bit-width allowed for activations and weights.
    /// Larger values cost more field operations per multiply; smaller values
    /// risk inference accuracy regressions vs. the unquantized model.
    pub max_quant_bits: u8,
    /// Whether to apply ZK masking (proof hides intermediate activations from
    /// the verifier as well as the input).
    pub zk_masked: bool,
    /// Deterministic seed for any randomness inside the prover (e.g., FRI
    /// transcript domain separation). The verifier never sees this value.
    pub deterministic_seed: u64,
}

impl Default for HcZkmlConfig {
    fn default() -> Self {
        Self {
            tile_dim: 64,
            max_quant_bits: 8,
            zk_masked: false,
            deterministic_seed: 0,
        }
    }
}

impl HcZkmlConfig {
    /// Validate the configuration. Returns an [`HcError::invalid_argument`]
    /// describing the first violation, if any.
    pub fn validate(&self) -> HcResult<()> {
        if !self.tile_dim.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "tile_dim must be a power of two, got {}",
                self.tile_dim
            )));
        }
        if self.tile_dim < 4 {
            return Err(HcError::invalid_argument(format!(
                "tile_dim must be at least 4, got {}",
                self.tile_dim
            )));
        }
        if !(1..=32).contains(&self.max_quant_bits) {
            return Err(HcError::invalid_argument(format!(
                "max_quant_bits must be in 1..=32, got {}",
                self.max_quant_bits
            )));
        }
        Ok(())
    }
}

/// Generate a proof that `output = model(input)` for the given quantized
/// model and witness.
///
/// ## Current support
///
/// Single-layer `Layer::MatMul` graphs are routed through the streaming
/// pipeline in [`streaming::prove_single_matmul`] and return a real,
/// deterministic envelope. Multi-layer graphs and other layer kinds still
/// return [`HcError::unimplemented`] pending Phase 1.5 (FRI lowering) and
/// Phase 1.6 (multi-layer composition).
///
/// The function signature is the long-term contract: when the FRI lowering
/// lands, this function continues to return `ZkmlProof` with the same
/// envelope shape, version-bumped once.
pub fn prove_inference(
    model: &ModelGraph,
    witness: &InferenceWitness,
    config: &HcZkmlConfig,
) -> HcResult<ZkmlProof> {
    config.validate()?;
    model.validate_against(witness)?;

    // Single-layer MatMul: delegate to the streaming pipeline.
    if model.layers.len() == 1 && matches!(&model.layers[0], graph::Layer::MatMul { .. }) {
        let outcome = streaming::prove_single_matmul(model, witness, config)?;
        return Ok(outcome.proof);
    }

    Err(HcError::unimplemented(
        "hc-zkml: only single-layer MatMul is wired through prove_inference today; \
         multi-layer + non-MatMul layers land in Phase 1.6 (see ROADMAP_EXTENSIONS.md)",
    ))
}

/// Verify a zkML proof against public IO.
///
/// ## Current support
///
/// Performs *structural* verification (envelope version, length, output
/// digest binding). Cryptographic soundness over the matmul transition
/// constraints arrives with Phase 1.5 (FRI). The function signature is
/// stable across that upgrade.
pub fn verify_inference(
    model_commitment: &graph::ModelCommitment,
    public_io: &PublicIo,
    proof: &ZkmlProof,
) -> HcResult<bool> {
    let _ = model_commitment;
    streaming::verify_envelope_structural(public_io, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        HcZkmlConfig::default().validate().unwrap();
    }

    #[test]
    fn config_rejects_non_power_of_two_tile() {
        let mut cfg = HcZkmlConfig::default();
        cfg.tile_dim = 48;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_quant_bits() {
        let mut cfg = HcZkmlConfig::default();
        cfg.max_quant_bits = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn prove_inference_unsupported_graph_returns_unimplemented() {
        // Empty graph passes validation (no layers ⇒ no input_shape required)
        // but isn't a single MatMul, so prove_inference should report it as
        // unsupported rather than panic or silently succeed.
        let model = ModelGraph::empty();
        let witness = InferenceWitness::empty();
        let cfg = HcZkmlConfig::default();
        let err = prove_inference(&model, &witness, &cfg).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("hc-zkml"));
    }

    #[test]
    fn prove_inference_routes_single_matmul_through_streaming() {
        use crate::graph::{Layer, ModelGraphBuilder};
        use crate::tensor::{Quantization, Shape, Tensor};
        let model = ModelGraphBuilder::new()
            .input(Shape::matrix(2, 3))
            .push(Layer::MatMul {
                lhs: Shape::matrix(2, 3),
                rhs: Shape::matrix(3, 2),
                out: Shape::matrix(2, 2),
            })
            .output(Shape::matrix(2, 2))
            .build();
        let q = Quantization::int8(1.0);
        let witness = InferenceWitness {
            input: Some(Tensor::new(Shape::matrix(2, 3), q, vec![1, 2, 3, 4, 5, 6]).unwrap()),
            activations: vec![Tensor::new(Shape::matrix(3, 2), q, vec![1, 0, 0, 1, 1, 1]).unwrap()],
        };
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let proof = prove_inference(&model, &witness, &cfg).unwrap();
        assert_eq!(proof.version, streaming::ENVELOPE_VERSION);
        assert_eq!(proof.bytes.len(), streaming::ENVELOPE_BYTES);
    }
}
