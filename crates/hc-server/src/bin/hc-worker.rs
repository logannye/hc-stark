use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, PublicInputs};
use hc_sdk::{
    proof::{encode_proof_v5, encode_proof_v7},
    types::{ProofBytes, ProveRequest},
};
use hc_vm::Program;
use hc_workloads::templates::TemplateBuildResult;

/// Minimal "prove worker" process.
///
/// The server spawns this as a separate OS process so timeouts can actually
/// cancel work (by killing the child), instead of letting a `spawn_blocking`
/// thread continue running in the background.
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let allow_custom = std::env::var("HC_SERVER_ALLOW_CUSTOM_PROGRAMS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if mode == "--stdio" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .context("read request from stdin")?;
        let req: ProveRequest =
            serde_json::from_slice(&bytes).context("parse request from stdin")?;
        let proof = prove_request(&req, allow_custom)?;
        let serialized = serde_json::to_vec(&proof)?;
        std::io::stdout()
            .lock()
            .write_all(&serialized)
            .context("write proof to stdout")?;
        return Ok(());
    }

    if mode != "--request" {
        anyhow::bail!("usage: hc-worker (--stdio | --request <request.json> --out <proof.json>)");
    }
    let req_path: PathBuf = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request path"))?
        .into();
    let out_flag = args.next().unwrap_or_default();
    if out_flag != "--out" {
        anyhow::bail!("usage: hc-worker (--stdio | --request <request.json> --out <proof.json>)");
    }
    let out_path: PathBuf = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing out path"))?
        .into();

    let bytes = fs::read(&req_path).with_context(|| format!("read {}", req_path.display()))?;
    let req: ProveRequest =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", req_path.display()))?;
    let proof = prove_request(&req, allow_custom)?;

    let serialized = serde_json::to_vec_pretty(&proof)?;
    fs::write(&out_path, serialized).with_context(|| format!("write {}", out_path.display()))?;
    Ok(())
}

fn prove_request(req: &ProveRequest, allow_custom: bool) -> anyhow::Result<ProofBytes> {
    // Resolve and prove from one of three sources: template, workload, or
    // custom program. Templates may build EITHER a VM program (sound v5
    // accumulator path) OR a general AIR (sound v7 path); workload/custom
    // sources are always VM/v5. The output is a self-describing `ProofBytes`
    // (envelope version 5/6 for v5, 7 for v7) that re-verifies under
    // `verify_proof_bytes` (which routes ≥7 to the v7 verifier, ≥5 to v5).
    let proof = if let Some(tid) = req.template_id.as_deref() {
        let params = req
            .template_params
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("template_params required when template_id is set"))?;
        let build = hc_workloads::templates::build_from_template(tid, params)
            .with_context(|| format!("template '{tid}' build failed"))?;
        match build {
            TemplateBuildResult::Vm {
                program,
                initial_acc,
                final_acc,
                ..
            } => prove_v5_bytes(req, program, initial_acc, final_acc)?,
            TemplateBuildResult::Air {
                air,
                trace,
                public_inputs,
                ..
            } => {
                // Sound v7 (general-AIR). ZK (v8) is deferred for degree-≥2 AIRs
                // — range booleanity is degree 2, where the trace-additive mask
                // breaks the FRI bound (see docs/security/zk_range.md) — so the
                // v7 path proves SOUND with `zk_mask_degree = None`.
                let config = ProverConfig::production_v7(
                    req.block_size,
                    req.fri_final_poly_size,
                    req.query_count,
                    req.lde_blowup_factor,
                    None,
                )?;
                let proof_v7 = hc_prover::prove_v7(&*air, &trace, &public_inputs, &config)?;
                encode_proof_v7(&proof_v7)?
            }
        }
    } else if let Some(_id) = req.workload_id.as_deref() {
        let prog = hc_server::workloads::program_for_request(req)?;
        prove_v5_bytes(req, prog, req.initial_acc, req.final_acc)?
    } else {
        if !allow_custom {
            anyhow::bail!(
                "custom programs are disabled; supply workload_id, template_id, or enable HC_SERVER_ALLOW_CUSTOM_PROGRAMS"
            );
        }
        let items: &[String] = req
            .program
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing program (custom programs enabled)"))?;
        let instr = hc_server::parse_instructions(items)?;
        prove_v5_bytes(req, Program::new(instr), req.initial_acc, req.final_acc)?
    };
    Ok(proof)
}

/// Prove a VM program on the SOUND v5 accumulator path and encode it.
///
/// `production_v5` clamps the request-derived params UP to the v5 verifier floor
/// (blowup ≥ 8, query_count ≥ 40, grinding_bits = 20) and pins the protocol
/// version to 5 (or 6 for ZK). The request's `block_size`/`fri_final_poly_size`
/// are honored as-is; `query_count`/`lde_blowup_factor` are treated as lower
/// bounds. The result re-verifies under the default v5 floor in
/// `verify_proof_bytes`.
fn prove_v5_bytes(
    req: &ProveRequest,
    program: Program,
    initial_acc: u64,
    final_acc: u64,
) -> anyhow::Result<ProofBytes> {
    let config = ProverConfig::production_v5(
        req.block_size,
        req.fri_final_poly_size,
        req.query_count,
        req.lde_blowup_factor,
        req.zk_mask_degree,
    )?;
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(final_acc),
    };
    let proof_v5 = hc_prover::prove_v5(config, program, inputs)?;
    encode_proof_v5(&proof_v5)
}
