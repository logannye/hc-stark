use std::{fs, path::Path};

use anyhow::{Context, Result};
use ark_bn254::{G1Affine, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hc_core::{field::prime_field::GoldilocksField, field::FieldElement};
use hc_fri::FriProof;
use hc_hash::{HashDigest, DIGEST_LEN};
use hc_prover::{metrics::ProverMetrics, queries::ProofParams};
use hc_prover::{Commitment, CommitmentScheme, PublicInputs};
use serde::{Deserialize, Serialize};

use crate::types::{ProofBytes, VerifyResult};

fn default_proof_version() -> u32 {
    1
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct SerializableProofParams {
    query_count: usize,
    lde_blowup: usize,
    fri_final_size: usize,
    fri_folding_ratio: usize,
    hash_id: String,
    #[serde(default)]
    protocol_version: u32,
    #[serde(default)]
    zk_enabled: bool,
    #[serde(default)]
    zk_mask_degree: usize,
}

#[derive(Serialize, Deserialize)]
struct SerializableLayer {
    beta: u64,
    evaluations: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableProof {
    #[serde(default = "default_proof_version")]
    version: u32,
    #[serde(default)]
    params: SerializableProofParams,
    commitment_scheme: String,
    trace_commitment: SerializableCommitment,
    composition_commitment: SerializableCommitment,
    #[serde(default)]
    fri_layer_roots: Vec<String>,
    #[serde(default)]
    fri_final_layer: Vec<u64>,
    #[serde(default)]
    fri_final_root: String,
    #[serde(default)]
    layers: Vec<SerializableLayer>,
    #[serde(default)]
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
    #[serde(default)]
    composition_queries: Vec<SerializableCompositionQuery>,
    fri_queries: Vec<SerializableFriQuery>,
    #[serde(default)]
    boundary: Option<SerializableBoundaryOpenings>,
    #[serde(default)]
    ood: Option<SerializableOodOpenings>,
}

#[derive(Serialize, Deserialize)]
struct SerializableOodOpenings {
    index: usize,
    trace: SerializableTraceQuery,
    quotient: SerializableCompositionQuery,
}

#[derive(Serialize, Deserialize)]
struct SerializableBoundaryOpenings {
    first_trace: SerializableTraceQuery,
    last_trace: SerializableTraceQuery,
    first_composition: SerializableCompositionQuery,
    last_composition: SerializableCompositionQuery,
}

#[derive(Serialize, Deserialize)]
struct SerializableTraceQuery {
    index: usize,
    evaluation: [u64; 2],
    witness: SerializableTraceWitness,
    #[serde(default)]
    next: Option<SerializableNextTraceRow>,
}

#[derive(Serialize, Deserialize)]
struct SerializableNextTraceRow {
    index: usize,
    evaluation: [u64; 2],
    witness: SerializableMerklePath,
}

#[derive(Serialize, Deserialize)]
struct SerializableCompositionQuery {
    index: usize,
    value: u64,
    witness: SerializableMerklePath,
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
    values: [u64; 2],
    merkle_paths: [SerializableMerklePath; 2],
}

#[derive(Serialize, Deserialize, Clone)]
struct SerializableMerklePath {
    nodes: Vec<SerializablePathNode>,
}

#[derive(Serialize, Deserialize, Clone)]
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

pub fn write_proof_json(
    path: &Path,
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<()> {
    let serializable = SerializableProof::from_output(output);
    let data = serde_json::to_vec_pretty(&serializable)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn read_proof_json(path: &Path) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let serializable: SerializableProof = serde_json::from_slice(&data)?;
    serializable.into_output()
}

pub fn encode_proof_bytes(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<ProofBytes> {
    let serializable = SerializableProof::from_output(output);
    let bytes = serde_json::to_vec(&serializable)?;
    Ok(ProofBytes {
        version: output.version,
        bytes,
    })
}

pub fn decode_proof_bytes(
    proof: &ProofBytes,
) -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let serializable: SerializableProof = serde_json::from_slice(&proof.bytes)?;
    if serializable.version != proof.version {
        anyhow::bail!(
            "proof version mismatch: envelope {} vs payload {}",
            proof.version,
            serializable.version
        );
    }
    serializable.into_output()
}

pub fn verify_proof_bytes(proof: &ProofBytes, allow_legacy_v2: bool) -> VerifyResult {
    let decoded = match decode_proof_bytes(proof) {
        Ok(p) => p,
        Err(err) => {
            return VerifyResult {
                ok: false,
                error: Some(err.to_string()),
            }
        }
    };
    if decoded.version < 3 && !allow_legacy_v2 {
        return VerifyResult {
            ok: false,
            error: Some("legacy v2 proofs require allow_legacy_v2".to_string()),
        };
    }
    let proof_obj = hc_verifier::Proof {
        version: decoded.version,
        trace_commitment: decoded.trace_commitment.clone(),
        composition_commitment: decoded.composition_commitment.clone(),
        fri_proof: decoded.fri_proof.clone(),
        initial_acc: decoded.public_inputs.initial_acc,
        final_acc: decoded.public_inputs.final_acc,
        query_response: decoded.query_response.clone(),
        trace_length: decoded.trace_length,
        params: decoded.params,
    };
    match hc_verifier::verify(&proof_obj) {
        Ok(_) => VerifyResult {
            ok: true,
            error: None,
        },
        Err(err) => VerifyResult {
            ok: false,
            error: Some(err.to_string()),
        },
    }
}

impl SerializableProof {
    fn from_output(output: &hc_prover::queries::ProverOutput<GoldilocksField>) -> Self {
        let fri_layer_roots = output
            .fri_proof
            .layer_roots
            .iter()
            .map(|digest| format!("{digest}"))
            .collect::<Vec<_>>();
        let fri_final_layer = output
            .fri_proof
            .final_layer
            .iter()
            .map(|value| value.to_u64())
            .collect::<Vec<_>>();
        let fri_final_root = format!("{}", output.fri_proof.final_root);
        let layers = Vec::new();
        let final_layer = Vec::new();
        let metrics = SerializableMetrics::from_metrics(&output.metrics);

        let query_response = output.query_response.as_ref().map(serialize_query_response);

        Self {
            version: output.version,
            params: SerializableProofParams {
                query_count: output.params.query_count,
                lde_blowup: output.params.lde_blowup_factor,
                fri_final_size: output.params.fri_final_poly_size,
                fri_folding_ratio: output.params.fri_folding_ratio,
                hash_id: "blake3".to_string(),
                protocol_version: output.params.protocol_version,
                zk_enabled: output.params.zk_enabled,
                zk_mask_degree: output.params.zk_mask_degree,
            },
            commitment_scheme: format!("{:?}", output.commitment_scheme).to_ascii_lowercase(),
            trace_commitment: SerializableCommitment::from_commitment(&output.trace_commitment),
            composition_commitment: SerializableCommitment::from_commitment(
                &output.composition_commitment,
            ),
            fri_layer_roots,
            fri_final_layer,
            fri_final_root,
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

        let params = if self.version >= 2 {
            if !self.params.hash_id.eq_ignore_ascii_case("blake3") {
                anyhow::bail!("v2+ proofs require blake3 hash_id");
            }
            if self.params.query_count == 0
                || self.params.lde_blowup == 0
                || self.params.fri_final_size == 0
                || self.params.fri_folding_ratio == 0
            {
                anyhow::bail!("v2+ proof parameters must be non-zero");
            }
            ProofParams {
                query_count: self.params.query_count,
                lde_blowup_factor: self.params.lde_blowup,
                fri_final_poly_size: self.params.fri_final_size,
                fri_folding_ratio: self.params.fri_folding_ratio,
                protocol_version: if self.params.protocol_version == 0 {
                    self.version
                } else {
                    self.params.protocol_version
                },
                zk_enabled: self.params.zk_enabled,
                zk_mask_degree: self.params.zk_mask_degree,
            }
        } else {
            ProofParams {
                query_count: 30,
                lde_blowup_factor: 2,
                fri_final_poly_size: 2,
                fri_folding_ratio: hc_fri::get_folding_ratio(),
                protocol_version: self.version,
                zk_enabled: false,
                zk_mask_degree: 0,
            }
        };

        let (fri_layer_roots, fri_final_layer) = if !self.fri_layer_roots.is_empty() {
            (self.fri_layer_roots, self.fri_final_layer)
        } else {
            if self.version >= 2 {
                anyhow::bail!("missing fri_layer_roots in v2+ proof");
            }
            let mut roots = Vec::with_capacity(self.layers.len());
            for layer in &self.layers {
                let values = layer
                    .evaluations
                    .iter()
                    .copied()
                    .map(GoldilocksField::from_u64)
                    .collect::<Vec<_>>();
                let hashes = hc_fri::layer::compute_leaf_hashes(values.as_slice());
                let root = hc_fri::layer::merkle_root_from_hashes(&hashes)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                roots.push(format!("{root}"));
            }
            (roots, self.final_layer)
        };

        let decoded_roots = fri_layer_roots
            .into_iter()
            .map(|root| digest_from_hex(&root))
            .collect::<Result<Vec<_>>>()?;
        let fri_final_len = fri_final_layer.len();
        let final_values = fri_final_layer
            .into_iter()
            .map(GoldilocksField::from_u64)
            .collect::<Vec<_>>();
        let final_hashes = hc_fri::layer::compute_leaf_hashes(final_values.as_slice());
        let computed_final_root = hc_fri::layer::merkle_root_from_hashes(&final_hashes)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;

        let final_root = if !self.fri_final_root.is_empty() {
            digest_from_hex(&self.fri_final_root)?
        } else {
            if self.version >= 2 {
                anyhow::bail!("missing fri_final_root in v2+ proof");
            }
            computed_final_root
        };

        if self.version >= 2 && fri_final_len != params.fri_final_poly_size {
            anyhow::bail!(
                "final FRI layer size {} does not match params.fri_final_size {}",
                fri_final_len,
                params.fri_final_poly_size
            );
        }

        let fri_proof = FriProof::new(decoded_roots, final_values, final_root);
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::from_u64(self.initial_acc),
            final_acc: GoldilocksField::from_u64(self.final_acc),
        };
        let query_response = self
            .query_response
            .map(deserialize_query_response)
            .transpose()?;
        let trace_commitment = self.trace_commitment.to_commitment()?;
        let composition_commitment = self.composition_commitment.to_commitment()?;
        Ok(hc_prover::queries::ProverOutput {
            version: self.version,
            trace_commitment,
            composition_commitment,
            fri_proof,
            public_inputs,
            query_response,
            metrics: self.metrics.into_metrics(),
            trace_length: self.trace_length,
            commitment_scheme: scheme,
            params,
        })
    }
}

fn serialize_query_response(
    qr: &hc_prover::queries::QueryResponse<GoldilocksField>,
) -> SerializableQueryResponse {
    SerializableQueryResponse {
        trace_queries: qr.trace_queries.iter().map(serialize_trace_query).collect(),
        composition_queries: qr
            .composition_queries
            .iter()
            .map(serialize_composition_query)
            .collect(),
        fri_queries: qr
            .fri_queries
            .iter()
            .map(|fq| SerializableFriQuery {
                layer_index: fq.layer_index,
                query_index: fq.query_index,
                values: [fq.values[0].to_u64(), fq.values[1].to_u64()],
                merkle_paths: [
                    serialize_merkle_path(&fq.merkle_paths[0]),
                    serialize_merkle_path(&fq.merkle_paths[1]),
                ],
            })
            .collect(),
        boundary: qr.boundary.as_ref().map(|b| SerializableBoundaryOpenings {
            first_trace: serialize_trace_query(&b.first_trace),
            last_trace: serialize_trace_query(&b.last_trace),
            first_composition: serialize_composition_query(&b.first_composition),
            last_composition: serialize_composition_query(&b.last_composition),
        }),
        ood: qr.ood.as_ref().map(|ood| SerializableOodOpenings {
            index: ood.index,
            trace: serialize_trace_query(&ood.trace),
            quotient: serialize_composition_query(&ood.quotient),
        }),
    }
}

fn deserialize_query_response(
    qr: SerializableQueryResponse,
) -> Result<hc_prover::queries::QueryResponse<GoldilocksField>> {
    let trace_queries = qr
        .trace_queries
        .into_iter()
        .map(deserialize_trace_query)
        .collect::<Result<Vec<_>>>()?;
    let composition_queries = qr
        .composition_queries
        .into_iter()
        .map(deserialize_composition_query)
        .collect::<Result<Vec<_>>>()?;
    let boundary = qr
        .boundary
        .map(
            |b| -> Result<hc_prover::queries::BoundaryOpenings<GoldilocksField>> {
                Ok(hc_prover::queries::BoundaryOpenings {
                    first_trace: deserialize_trace_query(b.first_trace)?,
                    last_trace: deserialize_trace_query(b.last_trace)?,
                    first_composition: deserialize_composition_query(b.first_composition)?,
                    last_composition: deserialize_composition_query(b.last_composition)?,
                })
            },
        )
        .transpose()?;
    let ood = qr
        .ood
        .map(
            |ood| -> Result<hc_prover::queries::OodOpenings<GoldilocksField>> {
                Ok(hc_prover::queries::OodOpenings {
                    index: ood.index,
                    trace: deserialize_trace_query(ood.trace)?,
                    quotient: deserialize_composition_query(ood.quotient)?,
                })
            },
        )
        .transpose()?;
    let fri_queries = qr
        .fri_queries
        .into_iter()
        .map(|fq| {
            Ok(hc_prover::queries::FriQuery {
                layer_index: fq.layer_index,
                query_index: fq.query_index,
                values: [
                    GoldilocksField::from_u64(fq.values[0]),
                    GoldilocksField::from_u64(fq.values[1]),
                ],
                merkle_paths: [
                    deserialize_merkle_path(fq.merkle_paths[0].clone())?,
                    deserialize_merkle_path(fq.merkle_paths[1].clone())?,
                ],
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(hc_prover::queries::QueryResponse {
        trace_queries,
        composition_queries,
        fri_queries,
        boundary,
        ood,
    })
}

fn serialize_trace_query(
    tq: &hc_prover::queries::TraceQuery<GoldilocksField>,
) -> SerializableTraceQuery {
    SerializableTraceQuery {
        index: tq.index,
        evaluation: [tq.evaluation[0].to_u64(), tq.evaluation[1].to_u64()],
        witness: match &tq.witness {
            hc_prover::queries::TraceWitness::Merkle(path) => SerializableTraceWitness::Merkle {
                path: serialize_merkle_path(path),
            },
            hc_prover::queries::TraceWitness::Kzg(kzg) => SerializableTraceWitness::Kzg {
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
            },
        },
        next: tq.next.as_ref().map(|n| SerializableNextTraceRow {
            index: n.index,
            evaluation: [n.evaluation[0].to_u64(), n.evaluation[1].to_u64()],
            witness: serialize_merkle_path(&n.witness),
        }),
    }
}

fn serialize_composition_query(
    cq: &hc_prover::queries::CompositionQuery<GoldilocksField>,
) -> SerializableCompositionQuery {
    SerializableCompositionQuery {
        index: cq.index,
        value: cq.value.to_u64(),
        witness: serialize_merkle_path(&cq.witness),
    }
}

fn deserialize_trace_query(
    tq: SerializableTraceQuery,
) -> Result<hc_prover::queries::TraceQuery<GoldilocksField>> {
    let witness = match tq.witness {
        SerializableTraceWitness::Merkle { path } => {
            hc_prover::queries::TraceWitness::Merkle(deserialize_merkle_path(path)?)
        }
        SerializableTraceWitness::Kzg {
            point,
            proofs,
            evaluations,
        } => {
            let point_bytes = hex::decode(&point)
                .map_err(|err| anyhow::anyhow!("invalid hex-encoded KZG point: {err}"))?;
            let decoded_proofs = proofs
                .into_iter()
                .map(|proof| {
                    let bytes = hex::decode(&proof.proof)
                        .map_err(|err| anyhow::anyhow!("invalid hex-encoded KZG proof: {err}"))?;
                    Ok(hc_prover::queries::KzgColumnProof {
                        column: proof.column,
                        proof: bytes,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mut decoded_values = vec![Vec::new(); decoded_proofs.len().max(1)];
            for value in evaluations {
                let bytes = hex::decode(&value.value)
                    .map_err(|err| anyhow::anyhow!("invalid hex-encoded KZG eval: {err}"))?;
                if value.column >= decoded_values.len() {
                    anyhow::bail!("kzg evaluation column {} out of range", value.column);
                }
                decoded_values[value.column] = bytes;
            }
            hc_prover::queries::TraceWitness::Kzg(hc_prover::queries::KzgTraceWitness {
                point: point_bytes,
                proofs: decoded_proofs,
                evaluations: decoded_values,
            })
        }
    };
    Ok(hc_prover::queries::TraceQuery {
        index: tq.index,
        evaluation: [
            GoldilocksField::from_u64(tq.evaluation[0]),
            GoldilocksField::from_u64(tq.evaluation[1]),
        ],
        witness,
        next: match tq.next {
            Some(n) => Some(hc_prover::queries::NextTraceRow {
                index: n.index,
                evaluation: [
                    GoldilocksField::from_u64(n.evaluation[0]),
                    GoldilocksField::from_u64(n.evaluation[1]),
                ],
                witness: deserialize_merkle_path(n.witness)?,
            }),
            None => None,
        },
    })
}

fn deserialize_composition_query(
    cq: SerializableCompositionQuery,
) -> Result<hc_prover::queries::CompositionQuery<GoldilocksField>> {
    Ok(hc_prover::queries::CompositionQuery {
        index: cq.index,
        value: GoldilocksField::from_u64(cq.value),
        witness: deserialize_merkle_path(cq.witness)?,
    })
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
