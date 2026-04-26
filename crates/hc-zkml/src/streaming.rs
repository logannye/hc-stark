//! Streaming inference pipeline for the MatMul-only single-layer case.
//!
//! This is the first body that replaces a `prove_inference` stub with real
//! deterministic work. It runs the height-compressed tiled matmul evaluator,
//! hashes every tile boundary into a Fiat-Shamir transcript, and produces a
//! versioned envelope whose layout is stable across protocol upgrades.
//!
//! ## What the envelope is — and isn't
//!
//! The envelope produced here is a *deterministic commitment* to the
//! streaming computation: tile checkpoints + output tensor, hashed into a
//! transcript. It is **not** zero-knowledge and it is **not** succinct;
//! cryptographic soundness lands when the FRI/STARK lowering of the matmul
//! AIR (Phase 1.5) attaches its proof bytes to the same envelope. Customers
//! who integrate against `prove_inference` today will continue to work
//! unchanged when that lowering ships — the envelope shape, version field,
//! and `verify_inference` shape are stable.
//!
//! ## Why this is still useful pre-FRI
//!
//! - It removes `HcError::unimplemented` from the hot path so the API
//!   surface is exercisable end-to-end.
//! - The transcript root is a deterministic fingerprint of the computation
//!   that can drive billing, caching, and replay across the broader
//!   TinyZKP infrastructure.
//! - The `verify_inference` path performs structural validation (version,
//!   length, digest binding) so existing client tooling does the right thing
//!   when `(version, bytes)` is later expanded to include FRI.

use crate::graph::{Layer, ModelCommitment, ModelGraph};
use crate::matmul::{
    dense_matrix_a_from_tensor, dense_matrix_b_from_tensor, evaluate_streaming, MatMulSpec,
};
use crate::proof::{InferenceWitness, PublicIo, ZkmlProof};
use crate::tensor::{Quantization, Shape, Tensor};
use crate::HcZkmlConfig;
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, HashDigest, HashFunction, Transcript, DIGEST_LEN};

/// Domain-separation tag for the zkML transcript.
const TRANSCRIPT_DOMAIN: &[u8] = b"hc-zkml/streaming/v1";

/// Stable wire-format version for the envelope produced by this module.
pub const ENVELOPE_VERSION: u8 = 1;

/// Fixed envelope size: `1 + 8 + 32 + 32 = 73` bytes.
pub const ENVELOPE_BYTES: usize = 1 + 8 + DIGEST_LEN + DIGEST_LEN;

/// Result of a streaming inference run: the output tensor plus the proof
/// envelope (suitable for clients to publish or aggregate).
#[derive(Clone, Debug)]
pub struct StreamingOutcome {
    pub output: Tensor,
    pub proof: ZkmlProof,
    pub public_io: PublicIo,
    pub model_commitment: ModelCommitment,
}

/// Drive the streaming MatMul-only pipeline end-to-end.
///
/// Currently supports the single-layer case `model.layers == [Layer::MatMul]`
/// with the witness providing `input` (matrix A) and `activations[0]`
/// (matrix B, the weights). Multi-layer support lands incrementally as the
/// other layer kinds are constrained.
pub fn prove_single_matmul(
    model: &ModelGraph,
    witness: &InferenceWitness,
    config: &HcZkmlConfig,
) -> HcResult<StreamingOutcome> {
    config.validate()?;
    model.validate_against(witness)?;

    let layer = require_single_matmul_layer(model)?;
    let (a_shape, b_shape, _out_shape) = match layer {
        Layer::MatMul { lhs, rhs, out } => (lhs, rhs, out),
        _ => unreachable!("require_single_matmul_layer enforces this"),
    };

    let input = witness.input.as_ref().ok_or_else(|| {
        HcError::invalid_argument("witness.input is required for prove_single_matmul")
    })?;
    let weights = witness.activations.first().ok_or_else(|| {
        HcError::invalid_argument(
            "witness.activations[0] (weights tensor) is required for prove_single_matmul",
        )
    })?;

    if &input.shape != a_shape {
        return Err(HcError::invalid_argument(format!(
            "input shape {:?} does not match MatMul lhs {:?}",
            input.shape, a_shape
        )));
    }
    if &weights.shape != b_shape {
        return Err(HcError::invalid_argument(format!(
            "weights shape {:?} does not match MatMul rhs {:?}",
            weights.shape, b_shape
        )));
    }

    let m = a_shape.0[0];
    let k_a = a_shape.0[1];
    let k_b = b_shape.0[0];
    let n = b_shape.0[1];
    if k_a != k_b {
        return Err(HcError::invalid_argument(format!(
            "MatMul inner dims do not agree: lhs[1]={k_a}, rhs[0]={k_b}"
        )));
    }
    let k = k_a;

    let spec = MatMulSpec::new(m, n, k, config.tile_dim)?;
    let a_mat = dense_matrix_a_from_tensor(input)?;
    let b_mat = dense_matrix_b_from_tensor(weights)?;

    // ── Streaming evaluation ──────────────────────────────────────────────
    // The current evaluator returns the full output vector at the end. For
    // the AIR lowering we'll thread a transcript hook through the evaluator
    // so each tile boundary appends to the transcript without ever holding
    // more than a tile of data live; for now the transcript inputs are the
    // (much smaller) output entries plus the canonical commitments to the
    // input and weight tensors. Soundness is restored when FRI attaches.
    let output_field = evaluate_streaming(&spec, &a_mat, &b_mat)?;

    // ── Lower output back to a quantized tensor ───────────────────────────
    // Output quantization mirrors the input quantization for now (no
    // per-channel rescale); a real lowering would rescale by
    // `input.scale * weights.scale`.
    let output_quant = derive_output_quantization(input.quant, weights.quant);
    let mut output_data = Vec::with_capacity(output_field.len());
    for &f in &output_field {
        output_data.push(field_to_i32_clamped(f, output_quant.bit_width));
    }
    let output = Tensor::new(Shape::matrix(m, n), output_quant, output_data)?;

    // ── Commit to model + public IO ───────────────────────────────────────
    let model_commitment = commit_model(model, weights);
    let input_digest = hash_tensor(input).to_bytes();
    let public_io = PublicIo {
        input_digest,
        output: output.clone(),
    };

    // ── Build the streaming transcript ────────────────────────────────────
    let mut transcript: Transcript<Blake3> = Transcript::new(TRANSCRIPT_DOMAIN);
    transcript.append_message(b"model.architecture", &model_commitment.architecture_digest);
    transcript.append_message(b"model.weights", &model_commitment.weights_digest);
    transcript.append_message(b"public.input_digest", &public_io.input_digest);

    // Append every output entry as a tile-boundary checkpoint. When the AIR
    // lowering lands, this is replaced with per-tile partial-sum
    // checkpoints emitted from inside the evaluator.
    let mut tmp = [0u8; 8];
    transcript.append_message(b"matmul.spec.m", &(m as u64).to_le_bytes());
    transcript.append_message(b"matmul.spec.n", &(n as u64).to_le_bytes());
    transcript.append_message(b"matmul.spec.k", &(k as u64).to_le_bytes());
    transcript.append_message(b"matmul.spec.tile_dim", &(spec.tile_dim as u64).to_le_bytes());
    for entry in &output_field {
        tmp.copy_from_slice(&entry.0.to_le_bytes());
        transcript.append_message(b"matmul.entry", &tmp);
    }

    let output_digest_full = hash_tensor(&output);
    transcript.append_message(b"public.output_digest", output_digest_full.as_bytes());

    let transcript_root = transcript.challenge_bytes(b"hc-zkml.transcript_root");

    // ── Serialize the envelope ────────────────────────────────────────────
    let num_tiles = (spec.tiles_per_chain() as u64) * (spec.output_entries() as u64);
    let bytes = serialize_envelope(num_tiles, &transcript_root, &output_digest_full);

    Ok(StreamingOutcome {
        output,
        proof: ZkmlProof {
            version: ENVELOPE_VERSION,
            bytes,
        },
        public_io,
        model_commitment,
    })
}

/// Structural verification of a zkML envelope.
///
/// Today this checks the wire format, version, and that the public output
/// digest matches the envelope's claim. **It does not yet establish
/// cryptographic soundness over the matmul transition constraints** — that
/// arrives with the Phase 1.5 FRI lowering. Use this entry point in your
/// integration tests now; it will graduate to a sound verifier without an
/// API change.
pub fn verify_envelope_structural(
    public_io: &PublicIo,
    proof: &ZkmlProof,
) -> HcResult<bool> {
    if proof.version != ENVELOPE_VERSION {
        return Err(HcError::invalid_argument(format!(
            "unsupported zkML envelope version {} (this build supports {})",
            proof.version, ENVELOPE_VERSION
        )));
    }
    if proof.bytes.len() != ENVELOPE_BYTES {
        return Err(HcError::invalid_argument(format!(
            "zkML envelope must be {} bytes, got {}",
            ENVELOPE_BYTES,
            proof.bytes.len()
        )));
    }
    let (_num_tiles, _transcript_root, output_digest) = parse_envelope(&proof.bytes)?;
    let public_output_digest = hash_tensor(&public_io.output);
    if output_digest.as_bytes() != public_output_digest.as_bytes() {
        return Ok(false);
    }
    Ok(true)
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn require_single_matmul_layer(model: &ModelGraph) -> HcResult<&Layer> {
    if model.layers.len() != 1 {
        return Err(HcError::invalid_argument(format!(
            "prove_single_matmul currently supports exactly one layer; got {}",
            model.layers.len()
        )));
    }
    let l = &model.layers[0];
    if !matches!(l, Layer::MatMul { .. }) {
        return Err(HcError::invalid_argument(
            "prove_single_matmul currently supports only Layer::MatMul",
        ));
    }
    Ok(l)
}

fn derive_output_quantization(a: Quantization, b: Quantization) -> Quantization {
    // Heuristic: output is quantized at the larger of the two input
    // bit-widths so partial sums don't overflow the integer range.
    Quantization {
        scale: a.scale * b.scale,
        zero_point: 0,
        bit_width: a.bit_width.max(b.bit_width).max(16),
    }
}

fn field_to_i32_clamped(f: hc_core::field::GoldilocksField, bit_width: u8) -> i32 {
    // Map field elements > p/2 to negative integers so the dequantized
    // value reflects signed semantics.
    let modulus = hc_core::field::GOLDILOCKS_MODULUS;
    let half = modulus / 2;
    let signed: i64 = if f.0 > half {
        -((modulus - f.0) as i64)
    } else {
        f.0 as i64
    };
    let max = (1i64 << (bit_width as i64 - 1)) - 1;
    let min = -(1i64 << (bit_width as i64 - 1));
    signed.clamp(min, max) as i32
}

fn commit_model(model: &ModelGraph, weights: &Tensor) -> ModelCommitment {
    let arch = Blake3::hash(&serde_json::to_vec(model).unwrap_or_default()).to_bytes();
    let w = Blake3::hash(&serde_json::to_vec(weights).unwrap_or_default()).to_bytes();
    ModelCommitment::new(arch, w)
}

fn hash_tensor(t: &Tensor) -> HashDigest {
    Blake3::hash(&serde_json::to_vec(t).unwrap_or_default())
}

fn serialize_envelope(num_tiles: u64, transcript_root: &HashDigest, output_digest: &HashDigest) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_BYTES);
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(&num_tiles.to_le_bytes());
    out.extend_from_slice(transcript_root.as_bytes());
    out.extend_from_slice(output_digest.as_bytes());
    out
}

fn parse_envelope(bytes: &[u8]) -> HcResult<(u64, HashDigest, HashDigest)> {
    if bytes.len() != ENVELOPE_BYTES {
        return Err(HcError::serialization(format!(
            "envelope length {} != expected {}",
            bytes.len(),
            ENVELOPE_BYTES
        )));
    }
    let version = bytes[0];
    if version != ENVELOPE_VERSION {
        return Err(HcError::serialization(format!(
            "envelope version {version} != expected {ENVELOPE_VERSION}"
        )));
    }
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&bytes[1..9]);
    let num_tiles = u64::from_le_bytes(len_buf);
    let transcript_root = HashDigest::from_slice(&bytes[9..9 + DIGEST_LEN])
        .ok_or_else(|| HcError::serialization("transcript_root parse failed"))?;
    let output_digest = HashDigest::from_slice(&bytes[9 + DIGEST_LEN..])
        .ok_or_else(|| HcError::serialization("output_digest parse failed"))?;
    Ok((num_tiles, transcript_root, output_digest))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::ModelGraphBuilder;
    use crate::tensor::Quantization;

    fn build_matmul_model(m: usize, k: usize, n: usize) -> ModelGraph {
        ModelGraphBuilder::new()
            .input(Shape::matrix(m, k))
            .push(Layer::MatMul {
                lhs: Shape::matrix(m, k),
                rhs: Shape::matrix(k, n),
                out: Shape::matrix(m, n),
            })
            .output(Shape::matrix(m, n))
            .build()
    }

    fn small_matmul_witness(m: usize, k: usize, n: usize, seed: i32) -> InferenceWitness {
        let q = Quantization::int8(1.0);
        let a_data: Vec<i32> = (0..m * k).map(|i| ((i as i32 + seed) % 17) - 8).collect();
        let b_data: Vec<i32> = (0..k * n).map(|i| ((i as i32 * 3 + seed) % 13) - 6).collect();
        InferenceWitness {
            input: Some(Tensor::new(Shape::matrix(m, k), q, a_data).unwrap()),
            activations: vec![Tensor::new(Shape::matrix(k, n), q, b_data).unwrap()],
        }
    }

    #[test]
    fn prove_single_matmul_produces_envelope() {
        let model = build_matmul_model(4, 8, 5);
        let witness = small_matmul_witness(4, 8, 5, 1);
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let outcome = prove_single_matmul(&model, &witness, &cfg).unwrap();
        assert_eq!(outcome.proof.version, ENVELOPE_VERSION);
        assert_eq!(outcome.proof.bytes.len(), ENVELOPE_BYTES);
        assert_eq!(outcome.output.shape.0, vec![4, 5]);
    }

    #[test]
    fn structural_verifier_accepts_valid_envelope() {
        let model = build_matmul_model(3, 4, 2);
        let witness = small_matmul_witness(3, 4, 2, 7);
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let outcome = prove_single_matmul(&model, &witness, &cfg).unwrap();
        assert!(verify_envelope_structural(&outcome.public_io, &outcome.proof).unwrap());
    }

    #[test]
    fn structural_verifier_rejects_tampered_output() {
        let model = build_matmul_model(2, 4, 2);
        let witness = small_matmul_witness(2, 4, 2, 3);
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let outcome = prove_single_matmul(&model, &witness, &cfg).unwrap();
        let mut tampered_io = outcome.public_io.clone();
        // Flip a single output element so the digest changes.
        if let Some(slot) = tampered_io.output.data.first_mut() {
            *slot = slot.wrapping_add(1);
        }
        assert!(!verify_envelope_structural(&tampered_io, &outcome.proof).unwrap());
    }

    #[test]
    fn structural_verifier_rejects_bad_version() {
        let model = build_matmul_model(2, 4, 2);
        let witness = small_matmul_witness(2, 4, 2, 9);
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let mut outcome = prove_single_matmul(&model, &witness, &cfg).unwrap();
        outcome.proof.version = 99;
        outcome.proof.bytes[0] = 99;
        let err = verify_envelope_structural(&outcome.public_io, &outcome.proof).unwrap_err();
        assert!(format!("{err}").contains("version"));
    }

    #[test]
    fn rejects_multi_layer_model() {
        let model = ModelGraphBuilder::new()
            .input(Shape::matrix(2, 2))
            .push(Layer::Relu {
                shape: Shape::matrix(2, 2),
            })
            .push(Layer::Relu {
                shape: Shape::matrix(2, 2),
            })
            .output(Shape::matrix(2, 2))
            .build();
        let witness = InferenceWitness::default();
        let cfg = HcZkmlConfig::default();
        assert!(prove_single_matmul(&model, &witness, &cfg).is_err());
    }

    #[test]
    fn rejects_shape_mismatch() {
        let model = build_matmul_model(2, 4, 3);
        // Wrong inner dim on the witness B tensor.
        let q = Quantization::int8(1.0);
        let a = Tensor::new(Shape::matrix(2, 4), q, vec![0; 8]).unwrap();
        let bad_b = Tensor::new(Shape::matrix(5, 3), q, vec![0; 15]).unwrap();
        let witness = InferenceWitness {
            input: Some(a),
            activations: vec![bad_b],
        };
        let cfg = HcZkmlConfig::default();
        let err = prove_single_matmul(&model, &witness, &cfg).unwrap_err();
        assert!(format!("{err}").contains("does not match MatMul rhs"));
    }

    #[test]
    fn determinism_same_inputs_same_envelope() {
        let model = build_matmul_model(3, 4, 2);
        let witness = small_matmul_witness(3, 4, 2, 42);
        let cfg = HcZkmlConfig {
            tile_dim: 4,
            ..Default::default()
        };
        let a = prove_single_matmul(&model, &witness, &cfg).unwrap();
        let b = prove_single_matmul(&model, &witness, &cfg).unwrap();
        assert_eq!(a.proof.bytes, b.proof.bytes);
        assert_eq!(a.output.data, b.output.data);
    }
}
