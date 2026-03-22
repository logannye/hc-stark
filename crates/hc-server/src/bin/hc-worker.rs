use std::{fs, path::PathBuf};

use anyhow::Context;
use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, PublicInputs};
use hc_sdk::{proof::encode_proof_bytes, types::ProveRequest};
use hc_vm::Program;

/// Minimal "prove worker" process.
///
/// The server spawns this as a separate OS process so timeouts can actually
/// cancel work (by killing the child), instead of letting a `spawn_blocking`
/// thread continue running in the background.
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    if mode != "--request" {
        anyhow::bail!("usage: hc-worker --request <request.json> --out <proof.json>");
    }
    let req_path: PathBuf = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request path"))?
        .into();
    let out_flag = args.next().unwrap_or_default();
    if out_flag != "--out" {
        anyhow::bail!("usage: hc-worker --request <request.json> --out <proof.json>");
    }
    let out_path: PathBuf = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing out path"))?
        .into();

    let allow_custom = std::env::var("HC_SERVER_ALLOW_CUSTOM_PROGRAMS")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let bytes = fs::read(&req_path).with_context(|| format!("read {}", req_path.display()))?;
    let req: ProveRequest =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", req_path.display()))?;

    // Resolve the program from one of three sources: template, workload, or custom program.
    let (program, initial_acc, final_acc) = if let Some(tid) = req.template_id.as_deref() {
        let params = req
            .template_params
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("template_params required when template_id is set"))?;
        let build = hc_workloads::templates::build_from_template(tid, params)
            .with_context(|| format!("template '{tid}' build failed"))?;
        (build.program, build.initial_acc, build.final_acc)
    } else if let Some(_id) = req.workload_id.as_deref() {
        let prog = hc_server::workloads::program_for_request(&req)?;
        (prog, req.initial_acc, req.final_acc)
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
        (Program::new(instr), req.initial_acc, req.final_acc)
    };

    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(final_acc),
    };
    let config = ProverConfig::with_security_floor(
        req.block_size,
        req.fri_final_poly_size,
        req.query_count,
        req.lde_blowup_factor,
        hc_prover::config::SecurityFloor::relaxed(),
    )?;
    let config = match req.zk_mask_degree {
        Some(deg) if deg > 0 => config.with_zk_masking(deg),
        _ => config,
    };

    let output = hc_prover::prove(config, program, inputs)?;
    let proof = encode_proof_bytes(&output)?;
    let serialized = serde_json::to_vec_pretty(&proof)?;
    fs::write(&out_path, serialized).with_context(|| format!("write {}", out_path.display()))?;
    Ok(())
}
