//! Python bindings for hc-stark via PyO3.
//!
//! Provides `hc_stark.prove()`, `hc_stark.verify()`, and `hc_stark.ProverConfig`
//! as a native Python module.
//!
//! # Usage
//!
//! ```python
//! import hc_stark
//!
//! # Configure the prover.
//! config = hc_stark.ProverConfig(block_size=2, fri_final_poly_size=2)
//!
//! # Prove a simple computation.
//! proof = hc_stark.prove(
//!     config=config,
//!     program=["add_immediate 1", "add_immediate 2"],
//!     initial_acc=5,
//!     final_acc=8,
//! )
//!
//! # Verify the proof.
//! result = hc_stark.verify(proof)
//! assert result.ok
//! ```

#![forbid(unsafe_code)]

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Python-visible prover configuration.
#[pyclass]
#[derive(Clone, Debug)]
pub struct ProverConfig {
    #[pyo3(get, set)]
    pub block_size: usize,
    #[pyo3(get, set)]
    pub fri_final_poly_size: usize,
    #[pyo3(get, set)]
    pub query_count: usize,
    #[pyo3(get, set)]
    pub lde_blowup_factor: usize,
    #[pyo3(get, set)]
    pub protocol_version: u32,
    #[pyo3(get, set)]
    pub zk_mask_degree: usize,
}

#[pymethods]
impl ProverConfig {
    #[new]
    #[pyo3(signature = (block_size=2, fri_final_poly_size=2, query_count=30, lde_blowup_factor=2, protocol_version=3, zk_mask_degree=0))]
    fn new(
        block_size: usize,
        fri_final_poly_size: usize,
        query_count: usize,
        lde_blowup_factor: usize,
        protocol_version: u32,
        zk_mask_degree: usize,
    ) -> Self {
        Self {
            block_size,
            fri_final_poly_size,
            query_count,
            lde_blowup_factor,
            protocol_version,
            zk_mask_degree,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ProverConfig(block_size={}, fri_final_poly_size={}, query_count={}, lde_blowup_factor={}, protocol_version={}, zk_mask_degree={})",
            self.block_size, self.fri_final_poly_size, self.query_count, self.lde_blowup_factor, self.protocol_version, self.zk_mask_degree
        )
    }
}

/// Python-visible proof object (opaque bytes + version).
#[pyclass]
#[derive(Clone, Debug)]
pub struct Proof {
    #[pyo3(get)]
    pub version: u32,
    inner_bytes: Vec<u8>,
}

#[pymethods]
impl Proof {
    /// Return the serialized proof as bytes.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner_bytes)
    }

    /// Return the serialized proof as a JSON string.
    fn to_json(&self) -> PyResult<String> {
        String::from_utf8(self.inner_bytes.clone())
            .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))
    }

    /// Deserialize a proof from bytes.
    #[staticmethod]
    fn from_bytes(version: u32, data: &[u8]) -> Self {
        Self {
            version,
            inner_bytes: data.to_vec(),
        }
    }

    /// Deserialize a proof from a JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))?;
        let version = parsed
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;
        Ok(Self {
            version,
            inner_bytes: json.as_bytes().to_vec(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Proof(version={}, size={})",
            self.version,
            self.inner_bytes.len()
        )
    }
}

/// Python-visible verification result.
#[pyclass]
#[derive(Clone, Debug)]
pub struct VerifyResult {
    #[pyo3(get)]
    pub ok: bool,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl VerifyResult {
    fn __repr__(&self) -> String {
        if self.ok {
            "VerifyResult(ok=True)".to_string()
        } else {
            format!(
                "VerifyResult(ok=False, error={:?})",
                self.error.as_deref().unwrap_or("unknown")
            )
        }
    }

    fn __bool__(&self) -> bool {
        self.ok
    }
}

/// Prove a computation.
///
/// Args:
///     config: ProverConfig with prover parameters.
///     program: List of instruction strings (e.g., ["add_immediate 1", "add_immediate 2"]).
///     initial_acc: Starting accumulator value.
///     final_acc: Expected final accumulator value.
///
/// Returns:
///     Proof object containing the serialized proof.
#[pyfunction]
#[pyo3(signature = (config, program, initial_acc, final_acc))]
fn prove(config: &ProverConfig, program: Vec<String>, initial_acc: u64, final_acc: u64) -> PyResult<Proof> {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::PublicInputs;
    use hc_vm::{Instruction, Program};

    let instructions: Vec<Instruction> = program
        .iter()
        .map(|s| parse_instruction(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| pyo3::exceptions::PyValueError::new_err(err))?;

    let vm_program = Program::new(instructions);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(final_acc),
    };

    let mut prover_config =
        hc_prover::config::ProverConfig::new(config.block_size, config.fri_final_poly_size)
            .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))?;

    if config.protocol_version >= 3 {
        prover_config = prover_config.with_protocol_version(config.protocol_version);
    }
    if config.zk_mask_degree > 0 {
        prover_config = prover_config.with_zk_masking(config.zk_mask_degree);
    }

    let output = hc_prover::prove(prover_config, vm_program, inputs)
        .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;

    let proof_bytes = hc_sdk::proof::encode_proof_bytes(&output)
        .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(err.to_string()))?;

    Ok(Proof {
        version: proof_bytes.version,
        inner_bytes: proof_bytes.bytes,
    })
}

/// Verify a STARK proof.
///
/// Args:
///     proof: A Proof object returned by `prove()` or created via `Proof.from_bytes()`.
///
/// Returns:
///     VerifyResult with `ok=True` on success or `ok=False` with an error message.
#[pyfunction]
fn verify(proof: &Proof) -> VerifyResult {
    let proof_bytes = hc_sdk::types::ProofBytes {
        version: proof.version,
        bytes: proof.inner_bytes.clone(),
    };

    let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, true);
    VerifyResult {
        ok: result.ok,
        error: result.error,
    }
}

/// Verify a STARK proof from a JSON string.
///
/// Args:
///     json: JSON string in the SDK proof format.
///
/// Returns:
///     VerifyResult with `ok=True` on success.
#[pyfunction]
fn verify_json(json: &str) -> PyResult<VerifyResult> {
    let proof = Proof::from_json(json)?;
    Ok(verify(&proof))
}

/// Return the library version.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn parse_instruction(s: &str) -> Result<hc_vm::Instruction, String> {
    let s = s.trim();
    let parts: Vec<&str> = s.splitn(2, ' ').collect();
    match parts[0].to_lowercase().as_str() {
        "add_immediate" | "addimmediate" | "add" => {
            let value = parts
                .get(1)
                .ok_or_else(|| "add_immediate requires a value".to_string())?
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("invalid integer: {err}"))?;
            Ok(hc_vm::Instruction::AddImmediate(value))
        }
        _ => Err(format!("unknown instruction: {}", parts[0])),
    }
}

/// The hc_stark Python module.
#[pymodule]
fn hc_stark(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ProverConfig>()?;
    m.add_class::<Proof>()?;
    m.add_class::<VerifyResult>()?;
    m.add_function(wrap_pyfunction!(prove, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(verify_json, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_add_immediate() {
        let instr = parse_instruction("add_immediate 5").unwrap();
        assert!(matches!(instr, hc_vm::Instruction::AddImmediate(5)));
    }

    #[test]
    fn parse_add_shorthand() {
        let instr = parse_instruction("add 10").unwrap();
        assert!(matches!(instr, hc_vm::Instruction::AddImmediate(10)));
    }

    #[test]
    fn parse_unknown_fails() {
        assert!(parse_instruction("subtract 1").is_err());
    }

    #[test]
    fn parse_missing_value_fails() {
        assert!(parse_instruction("add_immediate").is_err());
    }
}
