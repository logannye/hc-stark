use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_recursion::{
    artifact::{build_recursive_artifact, AggregatedProofArtifact},
    circuit::halo2::Halo2RecursiveProof,
    RecursionSchedule, RecursionSpec,
};
use serde::Serialize;

use super::prove::{read_proof, to_verifier_proof};

pub struct RecursionArgs {
    pub proofs: Vec<PathBuf>,
    pub fan_in: Option<usize>,
    pub max_depth: Option<usize>,
    pub artifact_path: Option<PathBuf>,
    pub metrics_path: Option<PathBuf>,
}

pub fn run_recursion(args: RecursionArgs) -> Result<()> {
    if args.proofs.len() < 2 {
        anyhow::bail!("recursion requires at least two proof files");
    }

    let mut prover_outputs = Vec::with_capacity(args.proofs.len());
    for path in &args.proofs {
        prover_outputs.push(read_proof(path)?);
    }
    let proofs = prover_outputs
        .iter()
        .map(to_verifier_proof)
        .collect::<Vec<_>>();

    let mut spec = RecursionSpec::default();
    if let Some(max_depth) = args.max_depth {
        spec.max_depth = max_depth;
    }
    if let Some(fan_in) = args.fan_in {
        spec.fan_in = fan_in.max(2);
    }

    let artifact =
        build_recursive_artifact(&spec, &proofs).context("failed to build recursive artifact")?;
    artifact
        .verify()
        .context("recursive artifact self-check failed")?;

    println!("recursive digest: {}", artifact.digest());
    println!(
        "witness commitment: {} ({} fields)",
        artifact.witness.commitment(),
        artifact.witness.field_count()
    );
    println!(
        "schedule depth: {} ({} batches)",
        artifact.aggregated.schedule.depth(),
        artifact.aggregated.schedule.total_batches()
    );
    println!(
        "halo2 recursion proof: k={}, {} bytes",
        artifact.circuit_proof.k,
        artifact.circuit_proof.proof.len()
    );

    if let Some(path) = args.metrics_path {
        write_metrics(&path, &artifact)?;
        println!("metrics written to {}", path.display());
    }

    if let Some(path) = args.artifact_path {
        write_artifact(&path, &artifact)?;
        println!("artifact written to {}", path.display());
    }

    Ok(())
}

fn write_metrics(path: &PathBuf, artifact: &AggregatedProofArtifact) -> Result<()> {
    let metrics = RecursionMetrics::from_artifact(artifact);
    let data = serde_json::to_vec_pretty(&metrics)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_artifact(path: &PathBuf, artifact: &AggregatedProofArtifact) -> Result<()> {
    let serializable = RecursionArtifactFile::from_artifact(artifact);
    let data = serde_json::to_vec_pretty(&serializable)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[derive(Serialize)]
struct RecursionMetrics {
    digest: String,
    total_proofs: usize,
    schedule_depth: usize,
    schedule_batches: usize,
    witness_fields: usize,
    witness_commitment: String,
    recursive_k: u32,
    recursive_proof_bytes: usize,
}

impl RecursionMetrics {
    fn from_artifact(artifact: &AggregatedProofArtifact) -> Self {
        Self {
            digest: format!("{}", artifact.digest()),
            total_proofs: artifact.aggregated.total_proofs,
            schedule_depth: artifact.aggregated.schedule.depth(),
            schedule_batches: artifact.aggregated.schedule.total_batches(),
            witness_fields: artifact.witness.field_count(),
            witness_commitment: format!("{}", artifact.witness.commitment()),
            recursive_k: artifact.circuit_proof.k,
            recursive_proof_bytes: artifact.circuit_proof.proof.len(),
        }
    }
}

#[derive(Serialize)]
struct RecursionArtifactFile {
    digest: String,
    total_proofs: usize,
    summaries: Vec<SerializableSummary>,
    witness: SerializableWitness,
    recursive_proof: SerializableRecursiveProof,
    schedule: SerializableSchedule,
}

impl RecursionArtifactFile {
    fn from_artifact(artifact: &AggregatedProofArtifact) -> Self {
        let summaries = artifact
            .aggregated
            .summaries
            .iter()
            .map(SerializableSummary::from_summary)
            .collect();
        let witness = SerializableWitness::from_witness(&artifact.witness);
        let recursive_proof = SerializableRecursiveProof::from_proof(&artifact.circuit_proof);
        let schedule = SerializableSchedule::from_schedule(&artifact.aggregated.schedule);
        Self {
            digest: format!("{}", artifact.digest()),
            total_proofs: artifact.aggregated.total_proofs,
            summaries,
            witness,
            recursive_proof,
            schedule,
        }
    }
}

#[derive(Serialize)]
struct SerializableSummary {
    trace_commitment_digest: String,
    initial_acc: u64,
    final_acc: u64,
    trace_length: usize,
    trace_commitment: String,
    fri_commitment: String,
    circuit_digest: u64,
}

impl SerializableSummary {
    fn from_summary(summary: &hc_recursion::ProofSummary<GoldilocksField>) -> Self {
        Self {
            trace_commitment_digest: format!("{}", summary.trace_commitment_digest),
            initial_acc: summary.initial_acc.to_u64(),
            final_acc: summary.final_acc.to_u64(),
            trace_length: summary.trace_length,
            trace_commitment: format!("{}", summary.query_commitments.trace_commitment),
            fri_commitment: format!("{}", summary.query_commitments.fri_commitment),
            circuit_digest: summary.circuit_digest.to_u64(),
        }
    }
}

#[derive(Serialize)]
struct SerializableWitness {
    commitment: String,
    total_fields: usize,
    encodings: Vec<Vec<u64>>,
}

impl SerializableWitness {
    fn from_witness(witness: &hc_recursion::RecursiveWitness) -> Self {
        let encodings = witness
            .encodings()
            .iter()
            .map(|encoding| {
                encoding
                    .as_fields()
                    .into_iter()
                    .map(|f| f.to_u64())
                    .collect()
            })
            .collect();
        Self {
            commitment: format!("{}", witness.commitment()),
            total_fields: witness.field_count(),
            encodings,
        }
    }
}

#[derive(Serialize)]
struct SerializableRecursiveProof {
    k: u32,
    proof_len: usize,
    proof_hex: String,
}

impl SerializableRecursiveProof {
    fn from_proof(proof: &Halo2RecursiveProof) -> Self {
        Self {
            k: proof.k,
            proof_len: proof.proof.len(),
            proof_hex: hex::encode(&proof.proof),
        }
    }
}

#[derive(Serialize)]
struct SerializableSchedule {
    total_inputs: usize,
    depth: usize,
    root: usize,
    levels: Vec<SerializableLevel>,
}

#[derive(Serialize)]
struct SerializableLevel {
    level_index: usize,
    batches: Vec<SerializableBatch>,
}

#[derive(Serialize)]
struct SerializableBatch {
    inputs: Vec<usize>,
    output: usize,
}

impl SerializableSchedule {
    fn from_schedule(schedule: &RecursionSchedule) -> Self {
        let levels = schedule
            .levels
            .iter()
            .map(|level| SerializableLevel {
                level_index: level.level_index,
                batches: level
                    .batches
                    .iter()
                    .map(|batch| SerializableBatch {
                        inputs: batch.inputs.clone(),
                        output: batch.output,
                    })
                    .collect(),
            })
            .collect();
        Self {
            total_inputs: schedule.total_inputs,
            depth: schedule.depth(),
            root: schedule.root,
            levels,
        }
    }
}
