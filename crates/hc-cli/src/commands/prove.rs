use std::{fs, path::Path, sync::Arc};

use anyhow::{Context, Result};
use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_fri::{layer::FriLayer, oracles::InMemoryFriOracle, queries::FriProof};
use hc_hash::hash::{HashDigest, DIGEST_LEN};
use hc_prover::{config::ProverConfig, metrics::ProverMetrics, prove, PublicInputs};
use hc_verifier::Proof;
use hc_vm::{Instruction, Program};
use serde::{Deserialize, Serialize};

pub fn run_prove() -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2)?;
    Ok(prove(config, program, inputs)?)
}

pub fn to_verifier_proof(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Proof<GoldilocksField> {
    Proof::<GoldilocksField> {
        trace_root: output.trace_root,
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
    trace_root: String,
    layers: Vec<SerializableLayer>,
    final_layer: Vec<u64>,
    initial_acc: u64,
    final_acc: u64,
    metrics: SerializableMetrics,
    query_response: Option<SerializableQueryResponse>,
    trace_length: usize,
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
    merkle_path: SerializableMerklePath,
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
                        merkle_path: SerializableMerklePath {
                            nodes: tq
                                .merkle_path
                                .nodes()
                                .iter()
                                .map(|node| SerializablePathNode {
                                    sibling: format!("{}", node.sibling),
                                    sibling_is_left: node.sibling_is_left,
                                })
                                .collect(),
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
                        merkle_path: SerializableMerklePath {
                            nodes: fq
                                .merkle_path
                                .nodes()
                                .iter()
                                .map(|node| SerializablePathNode {
                                    sibling: format!("{}", node.sibling),
                                    sibling_is_left: node.sibling_is_left,
                                })
                                .collect(),
                        },
                    })
                    .collect(),
            });

        Self {
            trace_root: format!("{}", output.trace_root),
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
        let trace_root = digest_from_hex(&self.trace_root)?;
        let layers = self
            .layers
            .into_iter()
            .map(|layer| {
                let beta = GoldilocksField::from_u64(layer.beta);
                let values: Vec<_> = layer
                    .evaluations
                    .into_iter()
                    .map(GoldilocksField::from_u64)
                    .collect();
                FriLayer {
                    beta,
                    oracle: InMemoryFriOracle::new(Arc::new(values)),
                }
            })
            .collect();
        let final_layer = self
            .final_layer
            .into_iter()
            .map(GoldilocksField::from_u64)
            .collect();
        let fri_proof = FriProof::new(layers, final_layer);
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::from_u64(self.initial_acc),
            final_acc: GoldilocksField::from_u64(self.final_acc),
        };

        let query_response = self
            .query_response
            .map(|qr| hc_prover::queries::QueryResponse {
                trace_queries: qr
                    .trace_queries
                    .into_iter()
                    .map(|tq| hc_prover::queries::TraceQuery {
                        index: tq.index,
                        evaluation: [
                            GoldilocksField::from_u64(tq.evaluation[0]),
                            GoldilocksField::from_u64(tq.evaluation[1]),
                        ],
                        merkle_path: hc_commit::merkle::MerklePath::new(
                            tq.merkle_path
                                .nodes
                                .into_iter()
                                .map(|node| hc_commit::merkle::PathNode {
                                    sibling: digest_from_hex(&node.sibling).unwrap(),
                                    sibling_is_left: node.sibling_is_left,
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
                fri_queries: qr
                    .fri_queries
                    .into_iter()
                    .map(|fq| hc_prover::queries::FriQuery {
                        layer_index: fq.layer_index,
                        query_index: fq.query_index,
                        evaluation: GoldilocksField::from_u64(fq.evaluation),
                        merkle_path: hc_commit::merkle::MerklePath::new(
                            fq.merkle_path
                                .nodes
                                .into_iter()
                                .map(|node| hc_commit::merkle::PathNode {
                                    sibling: digest_from_hex(&node.sibling).unwrap(),
                                    sibling_is_left: node.sibling_is_left,
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
            });

        Ok(hc_prover::queries::ProverOutput {
            trace_root,
            fri_proof,
            public_inputs,
            query_response,
            metrics: self.metrics.into_metrics(),
            trace_length: self.trace_length,
        })
    }
}

fn digest_from_hex(input: &str) -> Result<HashDigest> {
    let bytes = hex::decode(input)?;
    let array: [u8; DIGEST_LEN] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid digest length"))?;
    Ok(HashDigest::from(array))
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
