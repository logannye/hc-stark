use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ark_bn254::{G1Affine, G1Projective};
use ark_serialize::CanonicalSerialize;
use clap::ValueEnum;
use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{
    block_tuner::{
        default_history_path, detect_hardware_profile, recommend_block_size_with_feedback,
        AutoBlockConfig, AutoStrategy, HardwareProfile, TunerHistory, TunerHistoryEntry,
    },
    commitment::{Commitment, CommitmentScheme},
    config::ProverConfig,
    metrics::ProverMetrics,
    prove, PublicInputs,
};
use hc_verifier::Proof;
use hc_vm::{Instruction, Program};
use serde::{Deserialize, Serialize};

// Used by the (de)serialize derives below for human-readable proof
// dumps in the CLI's `prove --inspect` flow; clippy can't see the
// derive's internal construction sites.
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct SerializableProofParams {
    query_count: usize,
    lde_blowup: usize,
    fri_final_size: usize,
    fri_folding_ratio: usize,
    hash_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum AutoProfile {
    #[default]
    Balanced,
    Memory,
    Latency,
}

impl From<AutoProfile> for AutoStrategy {
    fn from(value: AutoProfile) -> Self {
        match value {
            AutoProfile::Balanced => AutoStrategy::Balanced,
            AutoProfile::Memory => AutoStrategy::Memory,
            AutoProfile::Latency => AutoStrategy::Latency,
        }
    }
}

impl AutoProfile {
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "balanced" => Some(AutoProfile::Balanced),
            "memory" => Some(AutoProfile::Memory),
            "latency" => Some(AutoProfile::Latency),
            "laptop" => Some(AutoProfile::Balanced),
            "server" => Some(AutoProfile::Latency),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
pub enum CommitmentFlag {
    #[default]
    Stark,
    Kzg,
}

impl From<CommitmentFlag> for CommitmentScheme {
    fn from(value: CommitmentFlag) -> Self {
        match value {
            CommitmentFlag::Stark => CommitmentScheme::Stark,
            CommitmentFlag::Kzg => CommitmentScheme::Kzg,
        }
    }
}

impl CommitmentFlag {
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "stark" | "merkle" => Some(CommitmentFlag::Stark),
            "kzg" => Some(CommitmentFlag::Kzg),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProveOptions {
    pub block_size: Option<usize>,
    pub auto_block: bool,
    pub trace_length_hint: Option<usize>,
    pub target_rss_mb: Option<usize>,
    pub profile: AutoProfile,
    pub hardware_detect: bool,
    pub tuner_cache: Option<PathBuf>,
    pub disable_tuner_cache: bool,
    pub commitment: CommitmentFlag,
    pub zk_mask_degree: Option<usize>,
}

impl Default for ProveOptions {
    fn default() -> Self {
        Self {
            block_size: None,
            auto_block: false,
            trace_length_hint: None,
            target_rss_mb: None,
            profile: AutoProfile::Balanced,
            hardware_detect: false,
            tuner_cache: None,
            disable_tuner_cache: false,
            commitment: CommitmentFlag::Stark,
            zk_mask_degree: None,
        }
    }
}

pub fn run_prove(opts: &ProveOptions) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let (block_size, cache_handle) = select_block_size(opts)?;
    println!(
        "using block size {} (auto={}, profile={:?}, commitment={:?})",
        block_size, opts.auto_block, opts.profile, opts.commitment
    );
    let config = ProverConfig::new(block_size, 2)?.with_commitment(opts.commitment.into());
    let config = match opts.zk_mask_degree {
        Some(deg) if deg > 0 => config.with_zk_masking(deg),
        _ => config,
    };
    let output = prove(config, program, inputs)?;
    if let Some(handle) = cache_handle {
        handle
            .persist(output.trace_length, block_size, &output.metrics)
            .context("failed to update tuner cache")?;
    }
    Ok(output)
}

pub fn describe_commitment(commitment: &Commitment) -> String {
    match commitment {
        Commitment::Stark { root } => format!("{root}"),
        Commitment::Kzg { points } => {
            if points.is_empty() {
                "kzg:empty".to_string()
            } else {
                format!(
                    "kzg:{} points (first={})",
                    points.len(),
                    g1_to_hex(&points[0])
                )
            }
        }
    }
}

fn select_block_size(opts: &ProveOptions) -> Result<(usize, Option<TunerCacheHandle>)> {
    let cache_handle = resolve_cache_handle(opts);
    if !opts.auto_block {
        return Ok((opts.block_size.unwrap_or(2), cache_handle));
    }
    let length_hint = opts.trace_length_hint.unwrap_or(1 << 20);
    let mut tuner = AutoBlockConfig::default().with_strategy(opts.profile.into());
    if let Some(target) = opts.target_rss_mb {
        tuner = tuner.with_target_rss(target.max(64));
    }
    if opts.hardware_detect {
        if let Some(profile) = detect_hardware_profile() {
            tuner = apply_hardware_hints(tuner, &profile, opts.target_rss_mb.is_none());
        }
    }
    let history_snapshot = cache_handle
        .as_ref()
        .and_then(|handle| handle.snapshot(length_hint));
    let block =
        recommend_block_size_with_feedback(length_hint, tuner, None, history_snapshot.as_ref())
            .map_err(|err| {
                anyhow::anyhow!(format!(
                    "failed to auto-select block size (hint={length_hint}): {err}"
                ))
            })?;
    Ok((block, cache_handle))
}

fn apply_hardware_hints(
    cfg: AutoBlockConfig,
    profile: &HardwareProfile,
    should_overwrite_rss: bool,
) -> AutoBlockConfig {
    let mut tuned = if should_overwrite_rss {
        let rss_hint = (profile.total_mem_mb / 4).max(64);
        cfg.with_target_rss(rss_hint)
    } else {
        cfg
    };
    if let Some(l3) = profile.l3_cache_kb {
        // Convert cache size to an approximate row cap (very conservative).
        let max_block = ((l3 / 2) / 16).max(cfg.min_block);
        tuned = tuned.with_max_block(max_block);
    }
    tuned
}

fn resolve_cache_handle(opts: &ProveOptions) -> Option<TunerCacheHandle> {
    if opts.disable_tuner_cache {
        return None;
    }
    let path = opts.tuner_cache.clone().or_else(default_history_path);
    path.map(|path| TunerCacheHandle::new(path, opts.profile.into()))
}

struct TunerCacheHandle {
    path: PathBuf,
    history: TunerHistory,
    strategy: AutoStrategy,
}

impl TunerCacheHandle {
    fn new(path: PathBuf, strategy: AutoStrategy) -> Self {
        let history = TunerHistory::load(&path);
        Self {
            path,
            history,
            strategy,
        }
    }

    fn snapshot(&self, trace_length: usize) -> Option<TunerHistoryEntry> {
        self.history.entry(self.strategy, trace_length).cloned()
    }

    fn persist(
        mut self,
        trace_length: usize,
        block_size: usize,
        metrics: &ProverMetrics,
    ) -> Result<()> {
        self.history
            .record(self.strategy, trace_length, block_size, metrics);
        self.history
            .save(&self.path)
            .map_err(|err| anyhow::anyhow!(err.to_string()))
    }
}

pub fn to_verifier_proof(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Proof<GoldilocksField> {
    Proof::<GoldilocksField> {
        version: output.version,
        trace_commitment: output.trace_commitment.clone(),
        composition_commitment: output.composition_commitment.clone(),
        fri_proof: output.fri_proof.clone(),
        initial_acc: output.public_inputs.initial_acc,
        final_acc: output.public_inputs.final_acc,
        query_response: output.query_response.clone(),
        trace_length: output.trace_length,
        params: output.params,
    }
}

pub fn write_proof(
    path: &Path,
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<()> {
    hc_sdk::proof::write_proof_json(path, output)
}

pub fn read_proof(path: &Path) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    hc_sdk::proof::read_proof_json(path)
}

fn g1_to_hex(point: &G1Projective) -> String {
    let affine = G1Affine::from(*point);
    let mut bytes = Vec::with_capacity(96);
    affine
        .serialize_compressed(&mut bytes)
        .expect("serialization should succeed");
    hex::encode(bytes)
}

// Proof JSON encoding/decoding is implemented in `hc-sdk`.
// The CLI delegates file IO to `hc_sdk::proof::{read_proof_json, write_proof_json}`.

#[cfg(test)]
mod tests {
    use super::AutoProfile;

    #[test]
    fn auto_profile_parses_labels() {
        assert_eq!(AutoProfile::from_label("memory"), Some(AutoProfile::Memory));
        assert_eq!(
            AutoProfile::from_label("LATENCY"),
            Some(AutoProfile::Latency)
        );
        assert_eq!(
            AutoProfile::from_label("balanced"),
            Some(AutoProfile::Balanced)
        );
        assert_eq!(AutoProfile::from_label("unknown"), None);
    }
}
