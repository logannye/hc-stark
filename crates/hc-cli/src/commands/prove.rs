use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use ark_bn254::{G1Affine, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::ValueEnum;
use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_fri::{
    layer::{FriFinalLayer, FriLayer},
    queries::FriProof,
};
use hc_hash::hash::{HashDigest, DIGEST_LEN};
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
        trace_commitment: output.trace_commitment.clone(),
        composition_commitment: output.composition_commitment.clone(),
        fri_proof: output.fri_proof.clone(),
        initial_acc: output.public_inputs.initial_acc,
        final_acc: output.public_inputs.final_acc,
        query_response: output.query_response.clone(),
        trace_length: output.trace_length,
    }
}

pub fn write_proof(
    path: &Path,
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<()> {
    let serializable = SerializableProof::from_output(output);
    let data = serde_json::to_vec_pretty(&serializable)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn read_proof(path: &Path) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let serializable: SerializableProof = serde_json::from_slice(&data)?;
    serializable.into_output()
}

#[derive(Serialize, Deserialize)]
struct SerializableLayer {
    beta: u64,
    evaluations: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableProof {
    commitment_scheme: String,
    trace_commitment: SerializableCommitment,
    composition_commitment: SerializableCommitment,
    layers: Vec<SerializableLayer>,
    final_layer: Vec<u64>,
    initial_acc: u64,
    final_acc: u64,
    metrics: SerializableMetrics,
    query_response: Option<SerializableQueryResponse>,
    trace_length: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum SerializableCommitment {
    Stark { root: String },
    Kzg { points: Vec<String> },
}

#[derive(Serialize, Deserialize)]
struct SerializableQueryResponse {
    trace_queries: Vec<SerializableTraceQuery>,
    fri_queries: Vec<SerializableFriQuery>,
}

#[derive(Serialize, Deserialize)]
struct SerializableTraceQuery {
    index: usize,
    evaluation: [u64; 2],
    witness: SerializableTraceWitness,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum SerializableTraceWitness {
    Merkle {
        path: SerializableMerklePath,
    },
    Kzg {
        point: String,
        proofs: Vec<SerializableKzgProof>,
        #[serde(default)]
        evaluations: Vec<SerializableKzgEvaluation>,
    },
}

#[derive(Serialize, Deserialize)]
struct SerializableFriQuery {
    layer_index: usize,
    query_index: usize,
    evaluation: u64,
    merkle_path: SerializableMerklePath,
}

#[derive(Serialize, Deserialize)]
struct SerializableMerklePath {
    nodes: Vec<SerializablePathNode>,
}

#[derive(Serialize, Deserialize)]
struct SerializablePathNode {
    sibling: String,
    sibling_is_left: bool,
}

#[derive(Serialize, Deserialize)]
struct SerializableKzgProof {
    column: usize,
    proof: String,
}

#[derive(Serialize, Deserialize)]
struct SerializableKzgEvaluation {
    column: usize,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct SerializableMetrics {
    trace_blocks_loaded: usize,
    fri_blocks_loaded: usize,
    composition_blocks_loaded: usize,
    fri_query_batches: usize,
    fri_queries_answered: usize,
    fri_query_duration_ms: u64,
}

impl SerializableProof {
    fn from_output(output: &hc_prover::queries::ProverOutput<GoldilocksField>) -> Self {
        let layers = output
            .fri_proof
            .layers
            .iter()
            .map(|layer| SerializableLayer {
                beta: layer.beta.to_u64(),
                evaluations: layer
                    .oracle
                    .values()
                    .as_ref()
                    .iter()
                    .map(|value| value.to_u64())
                    .collect(),
            })
            .collect();
        let final_layer = output
            .fri_proof
            .final_layer
            .evaluations()
            .iter()
            .map(|value| value.to_u64())
            .collect();
        let metrics = SerializableMetrics::from_metrics(&output.metrics);

        let query_response = output
            .query_response
            .as_ref()
            .map(|qr| SerializableQueryResponse {
                trace_queries: qr
                    .trace_queries
                    .iter()
                    .map(|tq| SerializableTraceQuery {
                        index: tq.index,
                        evaluation: [tq.evaluation[0].to_u64(), tq.evaluation[1].to_u64()],
                        witness: match &tq.witness {
                            hc_prover::queries::TraceWitness::Merkle(path) => {
                                SerializableTraceWitness::Merkle {
                                    path: serialize_merkle_path(path),
                                }
                            }
                            hc_prover::queries::TraceWitness::Kzg(kzg) => {
                                SerializableTraceWitness::Kzg {
                                    point: hex::encode(&kzg.point),
                                    proofs: kzg
                                        .proofs
                                        .iter()
                                        .map(|proof| SerializableKzgProof {
                                            column: proof.column,
                                            proof: hex::encode(&proof.proof),
                                        })
                                        .collect(),
                                    evaluations: kzg
                                        .evaluations
                                        .iter()
                                        .enumerate()
                                        .map(|(column, value)| SerializableKzgEvaluation {
                                            column,
                                            value: hex::encode(value),
                                        })
                                        .collect(),
                                }
                            }
                        },
                    })
                    .collect(),
                fri_queries: qr
                    .fri_queries
                    .iter()
                    .map(|fq| SerializableFriQuery {
                        layer_index: fq.layer_index,
                        query_index: fq.query_index,
                        evaluation: fq.evaluation.to_u64(),
                        merkle_path: serialize_merkle_path(&fq.merkle_path),
                    })
                    .collect(),
            });

        Self {
            commitment_scheme: format!("{:?}", output.commitment_scheme).to_ascii_lowercase(),
            trace_commitment: SerializableCommitment::from_commitment(&output.trace_commitment),
            composition_commitment: SerializableCommitment::from_commitment(
                &output.composition_commitment,
            ),
            layers,
            final_layer,
            initial_acc: output.public_inputs.initial_acc.to_u64(),
            final_acc: output.public_inputs.final_acc.to_u64(),
            metrics,
            query_response,
            trace_length: output.trace_length,
        }
    }

    fn into_output(self) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
        let scheme = CommitmentScheme::from_label(&self.commitment_scheme).ok_or_else(|| {
            anyhow::anyhow!("unknown commitment scheme {}", self.commitment_scheme)
        })?;
        let layers = self
            .layers
            .into_iter()
            .map(|layer| {
                let beta = GoldilocksField::from_u64(layer.beta);
                let values: Arc<Vec<_>> = Arc::new(
                    layer
                        .evaluations
                        .into_iter()
                        .map(GoldilocksField::from_u64)
                        .collect(),
                );
                FriLayer::from_values(beta, values).map_err(|err| anyhow::anyhow!(err.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        let final_layer_values: Arc<Vec<_>> = Arc::new(
            self.final_layer
                .into_iter()
                .map(GoldilocksField::from_u64)
                .collect(),
        );
        let final_layer = FriFinalLayer::from_values(final_layer_values)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let fri_proof = FriProof::new(layers, final_layer);
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::from_u64(self.initial_acc),
            final_acc: GoldilocksField::from_u64(self.final_acc),
        };

        let query_response = if let Some(qr) = self.query_response {
            let trace_queries = qr
                .trace_queries
                .into_iter()
                .map(|tq| {
                    let witness = match tq.witness {
                        SerializableTraceWitness::Merkle { path } => {
                            hc_prover::queries::TraceWitness::Merkle(deserialize_merkle_path(path)?)
                        }
                        SerializableTraceWitness::Kzg {
                            point,
                            proofs,
                            evaluations,
                        } => {
                            let point_bytes = hex::decode(&point).map_err(|err| {
                                anyhow::anyhow!("invalid hex-encoded KZG point: {err}")
                            })?;
                            let decoded_proofs = proofs
                                .into_iter()
                                .map(|proof| {
                                    let bytes = hex::decode(&proof.proof).map_err(|err| {
                                        anyhow::anyhow!("invalid hex-encoded KZG proof: {err}")
                                    })?;
                                    Ok(hc_prover::queries::KzgColumnProof {
                                        column: proof.column,
                                        proof: bytes,
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?;
                            let mut decoded_values = vec![Vec::new(); decoded_proofs.len().max(1)];
                            for value in evaluations {
                                let bytes = hex::decode(&value.value).map_err(|err| {
                                    anyhow::anyhow!("invalid hex-encoded KZG eval: {err}")
                                })?;
                                if value.column >= decoded_values.len() {
                                    return Err(anyhow::anyhow!(
                                        "kzg evaluation column {} out of range",
                                        value.column
                                    ));
                                }
                                decoded_values[value.column] = bytes;
                            }
                            hc_prover::queries::TraceWitness::Kzg(
                                hc_prover::queries::KzgTraceWitness {
                                    point: point_bytes,
                                    proofs: decoded_proofs,
                                    evaluations: decoded_values,
                                },
                            )
                        }
                    };
                    Ok(hc_prover::queries::TraceQuery {
                        index: tq.index,
                        evaluation: [
                            GoldilocksField::from_u64(tq.evaluation[0]),
                            GoldilocksField::from_u64(tq.evaluation[1]),
                        ],
                        witness,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let fri_queries = qr
                .fri_queries
                .into_iter()
                .map(|fq| {
                    Ok(hc_prover::queries::FriQuery {
                        layer_index: fq.layer_index,
                        query_index: fq.query_index,
                        evaluation: GoldilocksField::from_u64(fq.evaluation),
                        merkle_path: deserialize_merkle_path(fq.merkle_path)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Some(hc_prover::queries::QueryResponse {
                trace_queries,
                fri_queries,
            })
        } else {
            None
        };

        let trace_commitment = self.trace_commitment.to_commitment()?;
        let composition_commitment = self.composition_commitment.to_commitment()?;
        Ok(hc_prover::queries::ProverOutput {
            trace_commitment,
            composition_commitment,
            fri_proof,
            public_inputs,
            query_response,
            metrics: self.metrics.into_metrics(),
            trace_length: self.trace_length,
            commitment_scheme: scheme,
        })
    }
}

impl SerializableCommitment {
    fn from_commitment(value: &Commitment) -> Self {
        match value {
            Commitment::Stark { root } => SerializableCommitment::Stark {
                root: format!("{root}"),
            },
            Commitment::Kzg { points } => SerializableCommitment::Kzg {
                points: points.iter().map(g1_to_hex).collect(),
            },
        }
    }

    fn to_commitment(&self) -> Result<Commitment> {
        match self {
            SerializableCommitment::Stark { root } => Ok(Commitment::Stark {
                root: digest_from_hex(root)?,
            }),
            SerializableCommitment::Kzg { points } => {
                let decoded: Result<Vec<_>, _> = points.iter().map(|hex| hex_to_g1(hex)).collect();
                Ok(Commitment::Kzg { points: decoded? })
            }
        }
    }
}

fn digest_from_hex(input: &str) -> Result<HashDigest> {
    let bytes = hex::decode(input)?;
    let array: [u8; DIGEST_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid digest length"))?;
    Ok(HashDigest::from(array))
}

fn serialize_merkle_path(path: &hc_commit::merkle::MerklePath) -> SerializableMerklePath {
    SerializableMerklePath {
        nodes: path
            .nodes()
            .iter()
            .map(|node| SerializablePathNode {
                sibling: format!("{}", node.sibling),
                sibling_is_left: node.sibling_is_left,
            })
            .collect(),
    }
}

fn deserialize_merkle_path(path: SerializableMerklePath) -> Result<hc_commit::merkle::MerklePath> {
    let nodes = path
        .nodes
        .into_iter()
        .map(|node| {
            Ok(hc_commit::merkle::PathNode {
                sibling: digest_from_hex(&node.sibling)?,
                sibling_is_left: node.sibling_is_left,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(hc_commit::merkle::MerklePath::new(nodes))
}

impl SerializableMetrics {
    fn from_metrics(metrics: &ProverMetrics) -> Self {
        Self {
            trace_blocks_loaded: metrics.trace_blocks_loaded,
            fri_blocks_loaded: metrics.fri_blocks_loaded,
            composition_blocks_loaded: metrics.composition_blocks_loaded,
            fri_query_batches: metrics.fri_query_batches,
            fri_queries_answered: metrics.fri_queries_answered,
            fri_query_duration_ms: metrics.fri_query_duration_ms,
        }
    }

    fn into_metrics(self) -> ProverMetrics {
        ProverMetrics {
            trace_blocks_loaded: self.trace_blocks_loaded,
            fri_blocks_loaded: self.fri_blocks_loaded,
            composition_blocks_loaded: self.composition_blocks_loaded,
            fri_query_batches: self.fri_query_batches,
            fri_queries_answered: self.fri_queries_answered,
            fri_query_duration_ms: self.fri_query_duration_ms,
        }
    }
}

fn g1_to_hex(point: &G1Projective) -> String {
    let affine = G1Affine::from(*point);
    let mut bytes = Vec::with_capacity(96);
    affine
        .serialize_compressed(&mut bytes)
        .expect("serialization should succeed");
    hex::encode(bytes)
}

fn hex_to_g1(data: &str) -> Result<G1Projective> {
    let bytes = hex::decode(data)
        .map_err(|err| anyhow::anyhow!("invalid hex-encoded commitment: {err}"))?;
    let mut cursor = &bytes[..];
    let affine = G1Affine::deserialize_compressed(&mut cursor)
        .map_err(|err| anyhow::anyhow!("failed to decode KZG commitment: {err}"))?;
    Ok(G1Projective::from(affine))
}

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
