//! `spartan_r1cs` template — Spartan-style R1CS proof.
//!
//! Customer-facing surface: a single template ID that takes
//! `(m, n, A, B, C, w, tau)` over Goldilocks and produces an R1CS proof
//! through `hc_sumcheck_spartan::prove_r1cs`.

use super::{SpartanBuildResult, SpartanTemplate, StaticParam};
use anyhow::{anyhow, Result};
use hc_core::field::GoldilocksField as F;
use hc_sumcheck_spartan::{HcSpartanConfig, R1cs};
use serde_json::Value as JsonValue;

fn require_usize(params: &serde_json::Map<String, JsonValue>, name: &str) -> Result<usize> {
    params
        .get(name)
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .ok_or_else(|| anyhow!("missing or invalid parameter '{name}': expected non-negative integer"))
}

fn require_u64_array(
    params: &serde_json::Map<String, JsonValue>,
    name: &str,
) -> Result<Vec<u64>> {
    let arr = params
        .get(name)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing or invalid parameter '{name}': expected array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_u64()
                .ok_or_else(|| anyhow!("parameter '{name}[{i}]': expected non-negative integer"))
        })
        .collect()
}

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<SpartanBuildResult> {
    let m = require_usize(params, "m")?;
    let n = require_usize(params, "n")?;
    if !m.is_power_of_two() || !n.is_power_of_two() {
        return Err(anyhow!(
            "spartan_r1cs: m and n must both be powers of two (m={m}, n={n})"
        ));
    }
    if m * n > (1 << 18) {
        return Err(anyhow!(
            "spartan_r1cs: m*n must be at most 2^18 elements (sparse-matrix variant lands in a follow-on)"
        ));
    }

    let a_raw = require_u64_array(params, "A")?;
    let b_raw = require_u64_array(params, "B")?;
    let c_raw = require_u64_array(params, "C")?;
    let w_raw = require_u64_array(params, "w")?;
    let tau_raw = require_u64_array(params, "tau")?;

    let expected_mn = m * n;
    if a_raw.len() != expected_mn || b_raw.len() != expected_mn || c_raw.len() != expected_mn {
        return Err(anyhow!(
            "spartan_r1cs: A, B, C must each have m*n = {expected_mn} entries (got {}, {}, {})",
            a_raw.len(),
            b_raw.len(),
            c_raw.len()
        ));
    }
    if w_raw.len() != n {
        return Err(anyhow!(
            "spartan_r1cs: 'w' length {} does not match n = {n}",
            w_raw.len()
        ));
    }
    let log_m = m.trailing_zeros() as usize;
    if tau_raw.len() != log_m {
        return Err(anyhow!(
            "spartan_r1cs: 'tau' length {} does not match log_2(m) = {log_m}",
            tau_raw.len()
        ));
    }

    let a = a_raw.into_iter().map(F::new).collect();
    let b = b_raw.into_iter().map(F::new).collect();
    let c = c_raw.into_iter().map(F::new).collect();
    let w = w_raw.into_iter().map(F::new).collect();
    let tau = tau_raw.into_iter().map(F::new).collect();

    let r1cs = R1cs::new(m, n, a, b, c, w).map_err(|e| anyhow!("R1cs construction: {e}"))?;
    if !r1cs.is_satisfied() {
        return Err(anyhow!(
            "spartan_r1cs: the supplied (A, B, C, w) does not satisfy the R1CS relation \
             ((Aw) ⊙ (Bw) - Cw must be the zero vector)"
        ));
    }

    Ok(SpartanBuildResult {
        r1cs,
        tau,
        config: HcSpartanConfig::default(),
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "m",
        description: "Number of constraints (rows of A, B, C). Must be a power of two.",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "n",
        description: "Witness length / columns of A, B, C. Must be a power of two.",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "A",
        description: "Row-major dense matrix A as a flat array of length m*n.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "B",
        description: "Row-major dense matrix B as a flat array of length m*n.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "C",
        description: "Row-major dense matrix C as a flat array of length m*n.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "w",
        description: "Witness vector of length n.",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "tau",
        description: "Random challenge point of length log_2(m). \
                      In production this is sampled from a Fiat-Shamir transcript.",
        param_type: "array",
        required: true,
    },
];

static TAGS: &[&str] = &["spartan", "r1cs", "sumcheck", "snark"];

inventory::submit!(SpartanTemplate {
    id: "spartan_r1cs",
    summary: "Prove a satisfied R1CS instance via Spartan-style sumcheck",
    description: "Produces a sumcheck proof that (A·w) ⊙ (B·w) - C·w = 0 \
                  for the supplied dense R1CS matrices and witness, using \
                  hc-sumcheck-spartan. Round messages have degree 3. The \
                  verifier reconstructs eq_τ at the sampled challenges and \
                  checks the final-point bind. Sparse-matrix support and \
                  polynomial-commitment witness binding ship in a follow-on.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "medium",
    example_json: r#"{
  "m": 1, "n": 4,
  "A": [0, 1, 0, 0],
  "B": [0, 0, 1, 0],
  "C": [0, 0, 0, 1],
  "w": [1, 7, 11, 77],
  "tau": []
}"#,
    build,
});

#[cfg(test)]
mod tests {
    use super::*;

    fn xyz_params() -> serde_json::Map<String, JsonValue> {
        let v: JsonValue = serde_json::from_str(
            r#"{
                "m": 1, "n": 4,
                "A": [0, 1, 0, 0],
                "B": [0, 0, 1, 0],
                "C": [0, 0, 0, 1],
                "w": [1, 7, 11, 77],
                "tau": []
            }"#,
        )
        .unwrap();
        v.as_object().unwrap().clone()
    }

    #[test]
    fn build_succeeds_on_satisfied_instance() {
        let params = xyz_params();
        let r = build(&params).unwrap();
        assert_eq!(r.r1cs.m, 1);
        assert_eq!(r.r1cs.n, 4);
        assert!(r.r1cs.is_satisfied());
    }

    #[test]
    fn build_rejects_unsatisfied_witness() {
        let mut params = xyz_params();
        // 7 * 11 != 78, so this witness is invalid.
        params.insert("w".into(), serde_json::json!([1, 7, 11, 78]));
        let err = build(&params).unwrap_err();
        assert!(format!("{err}").contains("does not satisfy"));
    }

    #[test]
    fn build_rejects_non_pot_dimensions() {
        let mut params = xyz_params();
        params.insert("m".into(), serde_json::json!(3));
        let err = build(&params).unwrap_err();
        assert!(format!("{err}").contains("powers of two"));
    }

    #[test]
    fn build_rejects_wrong_matrix_length() {
        let mut params = xyz_params();
        params.insert("A".into(), serde_json::json!([0, 1, 0]));
        let err = build(&params).unwrap_err();
        assert!(format!("{err}").contains("m*n"));
    }

    #[test]
    fn end_to_end_through_prove_spartan_template() {
        let params = xyz_params();
        let proof = super::super::prove_spartan_template("spartan_r1cs", &params).unwrap();
        // Single-constraint instance ⇒ zero-round sumcheck.
        assert_eq!(proof.sumcheck.rounds.len(), 0);
    }
}
