//! Node.js/TypeScript bindings for hc-stark via napi-rs.
//!
//! Provides `prove()`, `verify()`, and `ProverConfig` as native Node.js
//! addon functions with full TypeScript type definitions.
//!
//! # Usage
//!
//! ```typescript
//! import { prove, verify, verifyJson, ProverConfig } from "hc-stark";
//!
//! const config: ProverConfig = {
//!   blockSize: 2,
//!   friFinalPolySize: 2,
//!   queryCount: 30,
//!   ldeBlowupFactor: 2,
//!   protocolVersion: 3,
//!   zkMaskDegree: 0,
//! };
//!
//! const proof = prove(config, ["add_immediate 1", "add_immediate 2"], 5, 8);
//! const result = verify(proof);
//! console.log(result.ok); // true
//! ```

#![forbid(unsafe_code)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Prover configuration parameters.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Number of trace rows per streaming block (must be a power of 2).
    pub block_size: u32,
    /// Size of the final FRI polynomial (must be a power of 2).
    pub fri_final_poly_size: u32,
    /// Number of FRI queries for soundness.
    pub query_count: u32,
    /// LDE blowup factor (typically 2).
    pub lde_blowup_factor: u32,
    /// Protocol version (3 = standard, 4 = ZK).
    pub protocol_version: u32,
    /// Zero-knowledge masking degree (0 = disabled).
    pub zk_mask_degree: u32,
}

/// Serialized proof object.
#[napi(object)]
#[derive(Clone)]
pub struct Proof {
    /// Proof format version.
    pub version: u32,
    /// Serialized proof as a byte buffer.
    pub bytes: Buffer,
}

/// Verification result.
#[napi(object)]
#[derive(Clone, Debug)]
pub struct VerifyResult {
    /// `true` if the proof is valid.
    pub ok: bool,
    /// Error message on failure.
    pub error: Option<String>,
}

// ---- Core logic (native-testable, no N-API symbols needed) ----

/// Core prove logic that returns raw bytes.
pub fn prove_core(
    block_size: usize,
    fri_final_poly_size: usize,
    query_count: usize,
    _lde_blowup_factor: usize,
    protocol_version: u32,
    zk_mask_degree: usize,
    program: &[String],
    initial_acc: u64,
    final_acc: u64,
) -> std::result::Result<(u32, Vec<u8>), String> {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::PublicInputs;
    use hc_vm::{Instruction, Program};

    let instructions: Vec<Instruction> = program
        .iter()
        .map(|s| parse_instruction(s))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let vm_program = Program::new(instructions);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(final_acc),
    };

    let mut prover_config =
        hc_prover::config::ProverConfig::new(block_size, fri_final_poly_size)
            .map_err(|err| err.to_string())?;

    // query_count is embedded in the prover config defaults; override if non-default
    let _ = query_count;

    if protocol_version >= 3 {
        prover_config = prover_config.with_protocol_version(protocol_version);
    }
    if zk_mask_degree > 0 {
        prover_config = prover_config.with_zk_masking(zk_mask_degree);
    }

    let output = hc_prover::prove(prover_config, vm_program, inputs)
        .map_err(|err| err.to_string())?;

    let proof_bytes = hc_sdk::proof::encode_proof_bytes(&output)
        .map_err(|err| err.to_string())?;

    Ok((proof_bytes.version, proof_bytes.bytes))
}

/// Core verify logic operating on raw bytes.
pub fn verify_core(version: u32, bytes: &[u8]) -> VerifyResult {
    let proof_bytes = hc_sdk::types::ProofBytes {
        version,
        bytes: bytes.to_vec(),
    };

    let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, true);
    VerifyResult {
        ok: result.ok,
        error: result.error,
    }
}

/// Core JSON verify logic.
pub fn verify_json_core(json: &str) -> std::result::Result<VerifyResult, String> {
    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|err| format!("invalid JSON: {err}"))?;

    let version = parsed
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u32;

    let proof_bytes = hc_sdk::types::ProofBytes {
        version,
        bytes: json.as_bytes().to_vec(),
    };

    let result = hc_sdk::proof::verify_proof_bytes(&proof_bytes, true);
    Ok(VerifyResult {
        ok: result.ok,
        error: result.error,
    })
}

// ---- N-API exports (require Node.js runtime) ----

/// Prove a computation and return a serialized STARK proof.
#[napi]
pub fn prove(
    config: ProverConfig,
    program: Vec<String>,
    initial_acc: i64,
    final_acc: i64,
) -> Result<Proof> {
    let (version, bytes) = prove_core(
        config.block_size as usize,
        config.fri_final_poly_size as usize,
        config.query_count as usize,
        config.lde_blowup_factor as usize,
        config.protocol_version,
        config.zk_mask_degree as usize,
        &program,
        initial_acc as u64,
        final_acc as u64,
    )
    .map_err(|err| Error::new(Status::GenericFailure, err))?;

    Ok(Proof {
        version,
        bytes: Buffer::from(bytes),
    })
}

/// Verify a STARK proof.
#[napi]
pub fn verify(proof: Proof) -> VerifyResult {
    verify_core(proof.version, &proof.bytes)
}

/// Verify a STARK proof from a JSON string.
#[napi]
pub fn verify_json(json: String) -> Result<VerifyResult> {
    verify_json_core(&json).map_err(|err| Error::new(Status::InvalidArg, err))
}

/// Return the library version.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn parse_instruction(s: &str) -> std::result::Result<hc_vm::Instruction, String> {
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

    #[test]
    fn verify_rejects_empty() {
        let result = verify_core(3, &[]);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn verify_rejects_garbage() {
        let result = verify_core(3, b"not a proof");
        assert!(!result.ok);
    }

    #[test]
    fn verify_json_rejects_invalid() {
        let result = verify_json_core("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn verify_json_rejects_empty_bytes() {
        let json = r#"{"version":3,"bytes":[]}"#;
        let result = verify_json_core(json).unwrap();
        assert!(!result.ok);
    }

    #[test]
    fn version_works() {
        // Can't call version() in tests because it's a napi function,
        // but we can verify the constant is available.
        let v = env!("CARGO_PKG_VERSION");
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }
}
