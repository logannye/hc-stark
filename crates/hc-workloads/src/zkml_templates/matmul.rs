//! `zkml_matmul` template — verifiable matrix multiplication.
//!
//! Customer-facing surface: a single template ID that takes a (M, N, K)
//! matmul over int8-quantized weights+input and produces a zkML envelope
//! through [`hc_zkml::prove_inference`].
//!
//! The template is intentionally narrow — single layer, dense matmul, int8
//! symmetric quantization. Multi-layer model templates (`zkml_inference`)
//! ship in Phase 1.6.

use super::{StaticParam, ZkmlBuildResult, ZkmlTemplate};
use anyhow::{anyhow, Result};
use hc_zkml::graph::{Layer, ModelGraphBuilder};
use hc_zkml::proof::InferenceWitness;
use hc_zkml::tensor::{Quantization, Shape, Tensor};
use hc_zkml::HcZkmlConfig;
use serde_json::Value as JsonValue;

fn require_usize(params: &serde_json::Map<String, JsonValue>, name: &str) -> Result<usize> {
    params
        .get(name)
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .ok_or_else(|| {
            anyhow!("missing or invalid parameter '{name}': expected non-negative integer")
        })
}

fn require_i32_array(params: &serde_json::Map<String, JsonValue>, name: &str) -> Result<Vec<i32>> {
    let arr = params
        .get(name)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing or invalid parameter '{name}': expected array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_i64()
                .filter(|n| (-128..=127).contains(n))
                .map(|n| n as i32)
                .ok_or_else(|| anyhow!("parameter '{name}[{i}]': expected int8 (-128..=127)"))
        })
        .collect()
}

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<ZkmlBuildResult> {
    let m = require_usize(params, "m")?;
    let n = require_usize(params, "n")?;
    let k = require_usize(params, "k")?;
    if m == 0 || n == 0 || k == 0 {
        return Err(anyhow!("zkml_matmul: m, n, k must all be > 0"));
    }
    if m * k > 1 << 20 || k * n > 1 << 20 {
        return Err(anyhow!(
            "zkml_matmul: input or weights tensor exceeds the per-template cap (2^20 elements). \
             Use the zkml_inference workload for larger models."
        ));
    }

    let input_data = require_i32_array(params, "input")?;
    let weights_data = require_i32_array(params, "weights")?;
    if input_data.len() != m * k {
        return Err(anyhow!(
            "zkml_matmul: 'input' length {} does not match m*k = {}",
            input_data.len(),
            m * k
        ));
    }
    if weights_data.len() != k * n {
        return Err(anyhow!(
            "zkml_matmul: 'weights' length {} does not match k*n = {}",
            weights_data.len(),
            k * n
        ));
    }

    let scale = params
        .get("scale")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32)
        .unwrap_or(1.0);
    if !(scale.is_finite() && scale > 0.0) {
        return Err(anyhow!(
            "zkml_matmul: 'scale' must be a positive finite float"
        ));
    }
    let q = Quantization::int8(scale);

    let input = Tensor::new(Shape::matrix(m, k), q, input_data)
        .map_err(|e| anyhow!("zkml_matmul: input tensor: {e}"))?;
    let weights = Tensor::new(Shape::matrix(k, n), q, weights_data)
        .map_err(|e| anyhow!("zkml_matmul: weights tensor: {e}"))?;

    let graph = ModelGraphBuilder::new()
        .input(Shape::matrix(m, k))
        .push(Layer::MatMul {
            lhs: Shape::matrix(m, k),
            rhs: Shape::matrix(k, n),
            out: Shape::matrix(m, n),
        })
        .output(Shape::matrix(m, n))
        .build();

    let witness = InferenceWitness {
        input: Some(input),
        activations: vec![weights],
    };

    // Auto-tune tile_dim ≈ √k, clamped to a power-of-two and to the
    // [4, 256] range that the prover expects.
    let tile_dim = pick_tile_dim(k);
    let config = HcZkmlConfig {
        tile_dim,
        ..Default::default()
    };

    Ok(ZkmlBuildResult {
        graph,
        witness,
        config,
        recommended_zk: false,
    })
}

fn pick_tile_dim(k: usize) -> usize {
    // sqrt(k) rounded down to a power of two, clamped to [4, 256].
    let approx = (k as f64).sqrt() as usize;
    let pot = approx.next_power_of_two();
    // next_power_of_two on a perfect power returns that power; if approx is
    // strictly less than its rounded-up power, halve to round *down*.
    let pot_floor = if pot > approx { pot / 2 } else { pot };
    pot_floor.clamp(4, 256)
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "m",
        description: "Rows of input / output (positive integer).",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "n",
        description: "Columns of weights / output (positive integer).",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "k",
        description: "Inner dimension; columns of input and rows of weights.",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "input",
        description: "Row-major input matrix as a flat int8 array of length m*k.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "weights",
        description: "Row-major weights matrix as a flat int8 array of length k*n.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "scale",
        description: "Optional positive float scale (default 1.0). Output \
                      quantization is the product of input and weight scales.",
        param_type: "number",
        required: false,
    },
];

static TAGS: &[&str] = &["zkml", "matmul", "inference", "ai", "attestation"];

inventory::submit!(ZkmlTemplate {
    id: "zkml_matmul",
    summary: "Prove a matrix multiplication on quantized int8 inputs",
    description: "Produces a zkML envelope attesting that output = input · weights \
                  for the given int8-quantized matrices. Use this for verifiable \
                  AI inference of single-layer dense networks, attention QKV \
                  projections, or any workload that lowers cleanly to a single \
                  matmul. Multi-layer support ships via the zkml_inference \
                  template in Phase 1.6.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "medium",
    example_json: r#"{
  "m": 2, "n": 2, "k": 3,
  "input":   [1, 2, 3, 4, 5, 6],
  "weights": [1, 0, 0, 1, 1, 1],
  "scale": 1.0
}"#,
    build,
});

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_example_params() -> serde_json::Map<String, JsonValue> {
        let v: JsonValue = serde_json::from_str(
            r#"{
                "m": 2, "n": 2, "k": 3,
                "input":   [1, 2, 3, 4, 5, 6],
                "weights": [1, 0, 0, 1, 1, 1]
            }"#,
        )
        .unwrap();
        v.as_object().unwrap().clone()
    }

    #[test]
    fn build_succeeds_on_valid_params() {
        let params = parse_example_params();
        let r = build(&params).unwrap();
        assert_eq!(r.graph.layers.len(), 1);
        assert!(matches!(r.graph.layers[0], Layer::MatMul { .. }));
        assert!(r.witness.input.is_some());
        assert_eq!(r.witness.activations.len(), 1);
    }

    #[test]
    fn build_rejects_wrong_input_length() {
        let mut p = parse_example_params();
        p.insert(
            "input".into(),
            serde_json::json!([1, 2, 3]), // m*k = 6 expected, gave 3
        );
        let err = build(&p).unwrap_err();
        assert!(format!("{err}").contains("does not match m*k"));
    }

    #[test]
    fn build_rejects_out_of_range_int8() {
        let mut p = parse_example_params();
        p.insert("input".into(), serde_json::json!([200, 0, 0, 0, 0, 0]));
        let err = build(&p).unwrap_err();
        assert!(format!("{err}").contains("int8"));
    }

    #[test]
    fn pick_tile_dim_sane() {
        assert_eq!(pick_tile_dim(1), 4); // clamped to floor 4
        assert_eq!(pick_tile_dim(15), 4); // sqrt≈3 → next_pot=4 → halve=2 → clamped 4
        assert_eq!(pick_tile_dim(64), 8);
        assert_eq!(pick_tile_dim(1024), 32);
        assert_eq!(pick_tile_dim(1 << 20), 256); // clamped to ceiling
    }

    #[test]
    fn end_to_end_through_prove_inference() {
        let params = parse_example_params();
        let r = build(&params).unwrap();
        let proof = hc_zkml::prove_inference(&r.graph, &r.witness, &r.config).unwrap();
        assert_eq!(proof.version, hc_zkml::streaming::ENVELOPE_VERSION);
        assert_eq!(proof.bytes.len(), hc_zkml::streaming::ENVELOPE_BYTES);
    }
}
