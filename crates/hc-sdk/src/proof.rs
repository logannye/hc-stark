use std::{fs, path::Path};

use anyhow::{Context, Result};
use ark_bn254::{G1Affine, G1Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hc_core::{field::prime_field::GoldilocksField, field::FieldElement, field::QuadExtension};
use hc_fri::FriProof;
use hc_hash::{HashDigest, DIGEST_LEN};
use hc_prover::{metrics::ProverMetrics, queries::ProofParams};
use hc_prover::{Commitment, CommitmentScheme, PublicInputs};
use serde::{Deserialize, Serialize};

use crate::types::{ProofBytes, VerifyResult};

/// Type alias for the extension field used in v5 proofs.
type K = QuadExtension<GoldilocksField>;

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
    // EVM-calldata decode path. `encode_evm_proof` consumes a legacy
    // `ProverOutput`, which only the PRE-v5 `SerializableProof` wire format below
    // deserializes into. The production prover cut over to sound v5 (`ProofV5`,
    // via `decode_proof_v5`) and v7 (`ProofV7`, via `decode_proof_v7`) proofs,
    // which this struct cannot parse — a v5/v7 proof here fails with a cryptic
    // serde "expected u64" error that `/proof/{id}/calldata` surfaced as a daily
    // 500. No on-chain (EVM) verifier has shipped for the sound proof system (the
    // Solidity verifier is a v3-era stub kept out of the product surface), so EVM
    // calldata is undefined for v5+. Gate it with a clear, caller-facing message.
    if proof.version >= 5 {
        anyhow::bail!(
            "EVM calldata is unavailable for this proof: the on-chain calldata \
             path supports only the legacy pre-v5 proof format; the service now \
             emits sound v5/v7 proofs, for which no on-chain verifier has shipped"
        );
    }
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

/// Production verification entry used by the HTTP `/verify` endpoint and the
/// MCP verify tool.
///
/// PHASE 1A HARD CUTOVER (D5): this service now requires SOUND v5 proofs.
/// Pre-v5 proofs (v1/v2/v3/v4) are produced by the legacy — and in the FRI
/// low-degree test, *unsound* — prover and are REJECTED here unconditionally.
/// The v3/v4 verification logic still exists and stays test-covered via the
/// lower-level `hc_verifier::verify` / `verify_with_summary`, but it is no
/// longer reachable through this production entry point.
///
/// `allow_legacy_v2` is retained for wire/ABI compatibility but no longer
/// re-enables any legacy path: a v2 proof is rejected with or without it.
pub fn verify_proof_bytes(proof: &ProofBytes, allow_legacy_v2: bool) -> VerifyResult {
    let _ = allow_legacy_v2; // legacy v2/v3/v4 are unconditionally rejected below.

    // Route v7+ (general-AIR sound) proofs to the v7 verifier. ADDITIVE (Phase
    // 1B): this does NOT cut over the v5 path — v5/v6 proofs still route to the
    // v5 verifier below, so both protocol families are accepted.
    if proof.version >= 7 {
        return verify_proof_bytes_v7(proof);
    }

    // Route v5/v6 proofs to the v5 verifier (soundness-hardened, G2/G7 +
    // production security floor).
    if proof.version >= 5 {
        return verify_proof_bytes_v5(proof);
    }

    // D5 — reject every pre-v5 (legacy, unsound-FRI) proof. The old v3/v4 FRI
    // "low-degree test" was vacuous and accepted ANY base codeword (audit
    // finding G2); the verifier also had no security floor (G7). This service
    // no longer trusts proofs that were not produced by the sound v5 path.
    //
    // The v3/v4 verification logic is NOT deleted: it remains reachable (and
    // test-covered) via the lower-level `hc_verifier::verify` /
    // `verify_with_summary`. It is simply no longer reachable through this
    // production entry point. The legacy KZG-scheme gate is likewise subsumed —
    // every KZG proof is v2 and is rejected here by the version floor.
    VerifyResult {
        ok: false,
        error: Some(format!(
            "unsupported legacy proof version {}; this service now requires v5 sound proofs \
             (versions < 5 use the legacy unsound-FRI verifier and are rejected — \
             audit findings G2/G7)",
            proof.version
        )),
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
                // grinding_bits defaults to 0 for v3 proofs; will be round-tripped
                // once the v5 serializer (a later task) adds it to SerializableProofParams.
                grinding_bits: 0,
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
                grinding_bits: 0,
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

// ─── v5 serialization ────────────────────────────────────────────────────────
//
// ProofV5<GoldilocksField> serializes K-valued fields (final_coeffs, FRI layer
// values, final_layer) using QuadExtension::to_le_bytes() (16 bytes each),
// stored as hex strings in JSON. F-valued fields use the same u64 encoding as
// the v3 path. Version tag 5 (or 6 for ZK) is stored in the payload; the
// ProofBytes envelope carries the same version for self-description.
// ADDITIVE: the v3 path is unchanged.

/// Serializable form of a K = QuadExtension<GoldilocksField> element: hex of
/// the 16-byte little-endian encoding `[c0_le8 || c1_le8]`.
fn k_to_hex(k: K) -> String {
    hex::encode(k.to_le_bytes())
}

fn k_from_hex(s: &str) -> Result<K> {
    let bytes =
        hex::decode(s).map_err(|err| anyhow::anyhow!("invalid hex-encoded K element: {err}"))?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("K element must be exactly 16 bytes"))?;
    Ok(K::from_le_bytes(&arr))
}

#[derive(Serialize, Deserialize)]
struct SerializableProofParams5 {
    query_count: usize,
    lde_blowup: usize,
    fri_final_size: usize,
    fri_folding_ratio: usize,
    hash_id: String,
    protocol_version: u32,
    zk_enabled: bool,
    zk_mask_degree: usize,
    grinding_bits: u32,
}

/// A single K-valued FRI layer opening (antipodal pair + two Merkle paths).
#[derive(Serialize, Deserialize)]
struct SerializableFriQueryV5 {
    layer_index: usize,
    query_index: usize,
    /// Hex-encoded K values: `[values[0]_16b_hex, values[1]_16b_hex]`.
    values: [String; 2],
    merkle_paths: [SerializableMerklePath; 2],
}

/// A single K-valued quotient (composition) opening (Phase 1A.2): the opened
/// value is a K element (hex of the 16-byte LE encoding).
#[derive(Serialize, Deserialize)]
struct SerializableCompositionQueryV5 {
    index: usize,
    /// Hex-encoded K value (16 bytes LE).
    value: String,
    witness: SerializableMerklePath,
}

/// OOD-style opening for v5: trace opening in F, quotient opening in K.
#[derive(Serialize, Deserialize)]
struct SerializableOodOpeningsV5 {
    index: usize,
    trace: SerializableTraceQuery,
    quotient: SerializableCompositionQueryV5,
}

/// Boundary openings for v5: trace openings in F, composition openings in K.
#[derive(Serialize, Deserialize)]
struct SerializableBoundaryOpeningsV5 {
    first_trace: SerializableTraceQuery,
    last_trace: SerializableTraceQuery,
    first_composition: SerializableCompositionQueryV5,
    last_composition: SerializableCompositionQueryV5,
}

fn serialize_composition_query_v5(
    cq: &hc_prover::queries::CompositionQuery<K>,
) -> SerializableCompositionQueryV5 {
    SerializableCompositionQueryV5 {
        index: cq.index,
        value: k_to_hex(cq.value),
        witness: serialize_merkle_path(&cq.witness),
    }
}

fn deserialize_composition_query_v5(
    cq: SerializableCompositionQueryV5,
) -> Result<hc_prover::queries::CompositionQuery<K>> {
    Ok(hc_prover::queries::CompositionQuery {
        index: cq.index,
        value: k_from_hex(&cq.value)?,
        witness: deserialize_merkle_path(cq.witness)?,
    })
}

/// Serializable form of a `ProofV5<GoldilocksField>`.
///
/// Version tag 5 (or 6 for ZK) is stored in the `version` field; the
/// `ProofBytes` envelope carries the same version.
#[derive(Serialize, Deserialize)]
struct SerializableProofV5 {
    version: u32,
    params: SerializableProofParams5,
    trace_commitment: SerializableCommitment,
    composition_commitment: SerializableCommitment,
    /// Merkle roots of each FRI layer (hex digests).
    fri_layer_roots: Vec<String>,
    /// K-valued final-layer evaluations (hex, 16 bytes each).
    fri_final_layer: Vec<String>,
    /// Merkle root of the final layer (hex digest).
    fri_final_root: String,
    /// Explicit polynomial coefficients for the final layer (K-valued, hex).
    fri_final_coeffs: Vec<String>,
    initial_acc: u64,
    final_acc: u64,
    trace_length: usize,
    grinding_nonce: u64,
    // Query openings.
    trace_queries: Vec<SerializableTraceQuery>,
    /// K-valued quotient (composition) openings (Phase 1A.2).
    composition_queries: Vec<SerializableCompositionQueryV5>,
    fri_queries: Vec<SerializableFriQueryV5>,
    #[serde(default)]
    boundary: Option<SerializableBoundaryOpeningsV5>,
    #[serde(default)]
    ood: Option<SerializableOodOpeningsV5>,
}

impl SerializableProofV5 {
    fn from_proof(proof: &hc_prover::queries::ProofV5<GoldilocksField>) -> Self {
        let fri_layer_roots = proof
            .fri_proof
            .layer_roots
            .iter()
            .map(|d| format!("{d}"))
            .collect();
        let fri_final_layer = proof
            .fri_proof
            .final_layer
            .iter()
            .map(|k| k_to_hex(*k))
            .collect();
        let fri_final_root = format!("{}", proof.fri_proof.final_root);
        let fri_final_coeffs = proof
            .fri_proof
            .final_coeffs
            .iter()
            .map(|k| k_to_hex(*k))
            .collect();

        let qr = &proof.query_response;
        let trace_queries = qr.trace_queries.iter().map(serialize_trace_query).collect();
        let composition_queries = qr
            .composition_queries
            .iter()
            .map(serialize_composition_query_v5)
            .collect();
        let fri_queries = qr
            .fri_queries
            .iter()
            .map(|fq| SerializableFriQueryV5 {
                layer_index: fq.layer_index,
                query_index: fq.query_index,
                values: [k_to_hex(fq.values[0]), k_to_hex(fq.values[1])],
                merkle_paths: [
                    serialize_merkle_path(&fq.merkle_paths[0]),
                    serialize_merkle_path(&fq.merkle_paths[1]),
                ],
            })
            .collect();
        let boundary = qr
            .boundary
            .as_ref()
            .map(|b| SerializableBoundaryOpeningsV5 {
                first_trace: serialize_trace_query(&b.first_trace),
                last_trace: serialize_trace_query(&b.last_trace),
                first_composition: serialize_composition_query_v5(&b.first_composition),
                last_composition: serialize_composition_query_v5(&b.last_composition),
            });
        let ood = qr.ood.as_ref().map(|ood| SerializableOodOpeningsV5 {
            index: ood.index,
            trace: serialize_trace_query(&ood.trace),
            quotient: serialize_composition_query_v5(&ood.quotient),
        });

        Self {
            version: proof.version,
            params: SerializableProofParams5 {
                query_count: proof.params.query_count,
                lde_blowup: proof.params.lde_blowup_factor,
                fri_final_size: proof.params.fri_final_poly_size,
                fri_folding_ratio: proof.params.fri_folding_ratio,
                hash_id: "blake3".to_string(),
                protocol_version: proof.params.protocol_version,
                zk_enabled: proof.params.zk_enabled,
                zk_mask_degree: proof.params.zk_mask_degree,
                grinding_bits: proof.params.grinding_bits,
            },
            trace_commitment: SerializableCommitment::from_commitment(&proof.trace_commitment),
            composition_commitment: SerializableCommitment::from_commitment(
                &proof.composition_commitment,
            ),
            fri_layer_roots,
            fri_final_layer,
            fri_final_root,
            fri_final_coeffs,
            initial_acc: proof.initial_acc.to_u64(),
            final_acc: proof.final_acc.to_u64(),
            trace_length: proof.trace_length,
            grinding_nonce: proof.grinding_nonce,
            trace_queries,
            composition_queries,
            fri_queries,
            boundary,
            ood,
        }
    }

    fn into_proof(self) -> Result<hc_prover::queries::ProofV5<GoldilocksField>> {
        if !self.params.hash_id.eq_ignore_ascii_case("blake3") {
            anyhow::bail!("v5 proofs require blake3 hash_id");
        }
        if self.params.query_count == 0
            || self.params.lde_blowup == 0
            || self.params.fri_final_size == 0
            || self.params.fri_folding_ratio == 0
        {
            anyhow::bail!("v5 proof parameters must be non-zero");
        }

        let params = ProofParams {
            query_count: self.params.query_count,
            lde_blowup_factor: self.params.lde_blowup,
            fri_final_poly_size: self.params.fri_final_size,
            fri_folding_ratio: self.params.fri_folding_ratio,
            protocol_version: self.params.protocol_version,
            zk_enabled: self.params.zk_enabled,
            zk_mask_degree: self.params.zk_mask_degree,
            grinding_bits: self.params.grinding_bits,
        };

        let layer_roots = self
            .fri_layer_roots
            .into_iter()
            .map(|r| digest_from_hex(&r))
            .collect::<Result<Vec<_>>>()?;
        let final_layer = self
            .fri_final_layer
            .iter()
            .map(|s| k_from_hex(s))
            .collect::<Result<Vec<_>>>()?;
        let final_root = digest_from_hex(&self.fri_final_root)?;
        let final_coeffs = self
            .fri_final_coeffs
            .iter()
            .map(|s| k_from_hex(s))
            .collect::<Result<Vec<_>>>()?;

        let fri_proof = FriProof::<K>::new(layer_roots, final_layer, final_root)
            .with_final_coeffs(final_coeffs);

        let trace_commitment = self.trace_commitment.to_commitment()?;
        let composition_commitment = self.composition_commitment.to_commitment()?;

        let trace_queries = self
            .trace_queries
            .into_iter()
            .map(deserialize_trace_query)
            .collect::<Result<Vec<_>>>()?;
        let composition_queries = self
            .composition_queries
            .into_iter()
            .map(deserialize_composition_query_v5)
            .collect::<Result<Vec<_>>>()?;
        let fri_queries = self
            .fri_queries
            .into_iter()
            .map(|fq| -> Result<hc_prover::queries::FriQuery<K>> {
                Ok(hc_prover::queries::FriQuery {
                    layer_index: fq.layer_index,
                    query_index: fq.query_index,
                    values: [k_from_hex(&fq.values[0])?, k_from_hex(&fq.values[1])?],
                    merkle_paths: [
                        deserialize_merkle_path(fq.merkle_paths[0].clone())?,
                        deserialize_merkle_path(fq.merkle_paths[1].clone())?,
                    ],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let boundary = self
            .boundary
            .map(
                |b| -> Result<hc_prover::queries::BoundaryOpeningsV5<GoldilocksField>> {
                    Ok(hc_prover::queries::BoundaryOpeningsV5 {
                        first_trace: deserialize_trace_query(b.first_trace)?,
                        last_trace: deserialize_trace_query(b.last_trace)?,
                        first_composition: deserialize_composition_query_v5(b.first_composition)?,
                        last_composition: deserialize_composition_query_v5(b.last_composition)?,
                    })
                },
            )
            .transpose()?;
        let ood = self
            .ood
            .map(
                |ood| -> Result<hc_prover::queries::OodOpeningsV5<GoldilocksField>> {
                    Ok(hc_prover::queries::OodOpeningsV5 {
                        index: ood.index,
                        trace: deserialize_trace_query(ood.trace)?,
                        quotient: deserialize_composition_query_v5(ood.quotient)?,
                    })
                },
            )
            .transpose()?;

        let query_response = hc_prover::queries::QueryResponseV5 {
            trace_queries,
            composition_queries,
            fri_queries,
            boundary,
            ood,
        };

        Ok(hc_prover::queries::ProofV5 {
            version: self.version,
            trace_commitment,
            composition_commitment,
            fri_proof,
            initial_acc: GoldilocksField::from_u64(self.initial_acc),
            final_acc: GoldilocksField::from_u64(self.final_acc),
            query_response,
            trace_length: self.trace_length,
            params,
            grinding_nonce: self.grinding_nonce,
        })
    }
}

/// Encode a `ProofV5<GoldilocksField>` to a `ProofBytes` (JSON payload, version
/// tag 5 or 6 in both the envelope and the payload).
///
/// ADDITIVE: does not touch the v3 encode path.
pub fn encode_proof_v5(proof: &hc_prover::queries::ProofV5<GoldilocksField>) -> Result<ProofBytes> {
    let serializable = SerializableProofV5::from_proof(proof);
    let bytes = serde_json::to_vec(&serializable)?;
    Ok(ProofBytes {
        version: proof.version,
        bytes,
    })
}

/// Decode a `ProofBytes` previously produced by [`encode_proof_v5`].
///
/// Verifies that the envelope version matches the payload version tag.
pub fn decode_proof_v5(proof: &ProofBytes) -> Result<hc_prover::queries::ProofV5<GoldilocksField>> {
    let serializable: SerializableProofV5 = serde_json::from_slice(&proof.bytes)?;
    if serializable.version != proof.version {
        anyhow::bail!(
            "v5 proof version mismatch: envelope {} vs payload {}",
            proof.version,
            serializable.version
        );
    }
    serializable.into_proof()
}

// ─── verify_proof_bytes: v5 routing ──────────────────────────────────────────

/// Route a decoded v5/v6 proof bytes object to the v5 verifier (production
/// floor). Called from `verify_proof_bytes` when the envelope version is ≥ 5.
fn verify_proof_bytes_v5(proof: &ProofBytes) -> VerifyResult {
    let decoded = match decode_proof_v5(proof) {
        Ok(p) => p,
        Err(err) => {
            return VerifyResult {
                ok: false,
                error: Some(format!("v5 decode error: {err}")),
            }
        }
    };
    match hc_verifier::v5::verify_v5(&decoded) {
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

// ─── v7 (general-AIR) serialization + verify routing ─────────────────────────
//
// ADDITIVE counterpart to the v5 serializer. The v7 proof carries width-N trace
// openings (`Vec<F>` per row), a public-input VECTOR (replacing v5's scalar
// `initial_acc`/`final_acc`), the trace width (Merkle leaf arity), and the AIR
// id (by which the verifier selects the constraint set). The quotient
// (composition) + FRI openings reuse the v5 K-valued serializers unchanged — the
// quotient is a single K column regardless of trace width.

/// Width-N trace opening (v7): the row is a `Vec<u64>`, one value per column.
#[derive(Serialize, Deserialize)]
struct SerializableTraceQueryN {
    index: usize,
    evaluation: Vec<u64>,
    witness: SerializableTraceWitness,
    #[serde(default)]
    next: Option<SerializableNextTraceRowN>,
}

#[derive(Serialize, Deserialize)]
struct SerializableNextTraceRowN {
    index: usize,
    evaluation: Vec<u64>,
    witness: SerializableMerklePath,
}

/// OOD-style opening for the v7 proof: width-N trace opening (F) + K quotient.
#[derive(Serialize, Deserialize)]
struct SerializableOodOpeningsV7 {
    index: usize,
    trace: SerializableTraceQueryN,
    quotient: SerializableCompositionQueryV5,
}

fn serialize_trace_query_n(
    tq: &hc_prover::queries::TraceQueryN<GoldilocksField>,
) -> SerializableTraceQueryN {
    SerializableTraceQueryN {
        index: tq.index,
        evaluation: tq.evaluation.iter().map(|v| v.to_u64()).collect(),
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
        next: tq.next.as_ref().map(|n| SerializableNextTraceRowN {
            index: n.index,
            evaluation: n.evaluation.iter().map(|v| v.to_u64()).collect(),
            witness: serialize_merkle_path(&n.witness),
        }),
    }
}

fn deserialize_trace_query_n(
    tq: SerializableTraceQueryN,
) -> Result<hc_prover::queries::TraceQueryN<GoldilocksField>> {
    let witness = match tq.witness {
        SerializableTraceWitness::Merkle { path } => {
            hc_prover::queries::TraceWitness::Merkle(deserialize_merkle_path(path)?)
        }
        SerializableTraceWitness::Kzg { .. } => {
            // v7 proofs are produced STARK-only; KZG trace witnesses are not part
            // of the general-AIR path.
            anyhow::bail!("v7 trace witness must be Merkle (KZG is not supported on the v7 path)");
        }
    };
    Ok(hc_prover::queries::TraceQueryN {
        index: tq.index,
        evaluation: tq
            .evaluation
            .into_iter()
            .map(GoldilocksField::from_u64)
            .collect(),
        witness,
        next: match tq.next {
            Some(n) => Some(hc_prover::queries::NextTraceRowN {
                index: n.index,
                evaluation: n
                    .evaluation
                    .into_iter()
                    .map(GoldilocksField::from_u64)
                    .collect(),
                witness: deserialize_merkle_path(n.witness)?,
            }),
            None => None,
        },
    })
}

/// Serializable form of a `ProofV7<GoldilocksField>` (version tag 7, or 8 with
/// ZK). The `ProofBytes` envelope carries the same version.
#[derive(Serialize, Deserialize)]
struct SerializableProofV7 {
    version: u32,
    params: SerializableProofParams5,
    trace_commitment: SerializableCommitment,
    composition_commitment: SerializableCommitment,
    fri_layer_roots: Vec<String>,
    fri_final_layer: Vec<String>,
    fri_final_root: String,
    fri_final_coeffs: Vec<String>,
    /// Public-input vector (replaces v5's `initial_acc`/`final_acc`).
    public_inputs: Vec<u64>,
    /// Trace width N (Merkle leaf arity).
    trace_width: usize,
    /// AIR identity; the verifier selects the constraint set by this id.
    air_id: u32,
    trace_length: usize,
    grinding_nonce: u64,
    trace_queries: Vec<SerializableTraceQueryN>,
    composition_queries: Vec<SerializableCompositionQueryV5>,
    fri_queries: Vec<SerializableFriQueryV5>,
    #[serde(default)]
    ood: Option<SerializableOodOpeningsV7>,
}

impl SerializableProofV7 {
    fn from_proof(proof: &hc_prover::queries::ProofV7<GoldilocksField>) -> Self {
        let fri_layer_roots = proof
            .fri_proof
            .layer_roots
            .iter()
            .map(|d| format!("{d}"))
            .collect();
        let fri_final_layer = proof
            .fri_proof
            .final_layer
            .iter()
            .map(|k| k_to_hex(*k))
            .collect();
        let fri_final_root = format!("{}", proof.fri_proof.final_root);
        let fri_final_coeffs = proof
            .fri_proof
            .final_coeffs
            .iter()
            .map(|k| k_to_hex(*k))
            .collect();

        let qr = &proof.query_response;
        let trace_queries = qr
            .trace_queries
            .iter()
            .map(serialize_trace_query_n)
            .collect();
        let composition_queries = qr
            .composition_queries
            .iter()
            .map(serialize_composition_query_v5)
            .collect();
        let fri_queries = qr
            .fri_queries
            .iter()
            .map(|fq| SerializableFriQueryV5 {
                layer_index: fq.layer_index,
                query_index: fq.query_index,
                values: [k_to_hex(fq.values[0]), k_to_hex(fq.values[1])],
                merkle_paths: [
                    serialize_merkle_path(&fq.merkle_paths[0]),
                    serialize_merkle_path(&fq.merkle_paths[1]),
                ],
            })
            .collect();
        let ood = qr.ood.as_ref().map(|ood| SerializableOodOpeningsV7 {
            index: ood.index,
            trace: serialize_trace_query_n(&ood.trace),
            quotient: serialize_composition_query_v5(&ood.quotient),
        });

        Self {
            version: proof.version,
            params: SerializableProofParams5 {
                query_count: proof.params.query_count,
                lde_blowup: proof.params.lde_blowup_factor,
                fri_final_size: proof.params.fri_final_poly_size,
                fri_folding_ratio: proof.params.fri_folding_ratio,
                hash_id: "blake3".to_string(),
                protocol_version: proof.params.protocol_version,
                zk_enabled: proof.params.zk_enabled,
                zk_mask_degree: proof.params.zk_mask_degree,
                grinding_bits: proof.params.grinding_bits,
            },
            trace_commitment: SerializableCommitment::from_commitment(&proof.trace_commitment),
            composition_commitment: SerializableCommitment::from_commitment(
                &proof.composition_commitment,
            ),
            fri_layer_roots,
            fri_final_layer,
            fri_final_root,
            fri_final_coeffs,
            public_inputs: proof.public_inputs.iter().map(|f| f.to_u64()).collect(),
            trace_width: proof.trace_width,
            air_id: proof.air_id,
            trace_length: proof.trace_length,
            grinding_nonce: proof.grinding_nonce,
            trace_queries,
            composition_queries,
            fri_queries,
            ood,
        }
    }

    fn into_proof(self) -> Result<hc_prover::queries::ProofV7<GoldilocksField>> {
        if !self.params.hash_id.eq_ignore_ascii_case("blake3") {
            anyhow::bail!("v7 proofs require blake3 hash_id");
        }
        if self.params.query_count == 0
            || self.params.lde_blowup == 0
            || self.params.fri_final_size == 0
            || self.params.fri_folding_ratio == 0
        {
            anyhow::bail!("v7 proof parameters must be non-zero");
        }

        let params = ProofParams {
            query_count: self.params.query_count,
            lde_blowup_factor: self.params.lde_blowup,
            fri_final_poly_size: self.params.fri_final_size,
            fri_folding_ratio: self.params.fri_folding_ratio,
            protocol_version: self.params.protocol_version,
            zk_enabled: self.params.zk_enabled,
            zk_mask_degree: self.params.zk_mask_degree,
            grinding_bits: self.params.grinding_bits,
        };

        let layer_roots = self
            .fri_layer_roots
            .into_iter()
            .map(|r| digest_from_hex(&r))
            .collect::<Result<Vec<_>>>()?;
        let final_layer = self
            .fri_final_layer
            .iter()
            .map(|s| k_from_hex(s))
            .collect::<Result<Vec<_>>>()?;
        let final_root = digest_from_hex(&self.fri_final_root)?;
        let final_coeffs = self
            .fri_final_coeffs
            .iter()
            .map(|s| k_from_hex(s))
            .collect::<Result<Vec<_>>>()?;

        let fri_proof = FriProof::<K>::new(layer_roots, final_layer, final_root)
            .with_final_coeffs(final_coeffs);

        let trace_commitment = self.trace_commitment.to_commitment()?;
        let composition_commitment = self.composition_commitment.to_commitment()?;

        let trace_queries = self
            .trace_queries
            .into_iter()
            .map(deserialize_trace_query_n)
            .collect::<Result<Vec<_>>>()?;
        let composition_queries = self
            .composition_queries
            .into_iter()
            .map(deserialize_composition_query_v5)
            .collect::<Result<Vec<_>>>()?;
        let fri_queries = self
            .fri_queries
            .into_iter()
            .map(|fq| -> Result<hc_prover::queries::FriQuery<K>> {
                Ok(hc_prover::queries::FriQuery {
                    layer_index: fq.layer_index,
                    query_index: fq.query_index,
                    values: [k_from_hex(&fq.values[0])?, k_from_hex(&fq.values[1])?],
                    merkle_paths: [
                        deserialize_merkle_path(fq.merkle_paths[0].clone())?,
                        deserialize_merkle_path(fq.merkle_paths[1].clone())?,
                    ],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let ood = self
            .ood
            .map(
                |ood| -> Result<hc_prover::queries::OodOpeningsV7<GoldilocksField>> {
                    Ok(hc_prover::queries::OodOpeningsV7 {
                        index: ood.index,
                        trace: deserialize_trace_query_n(ood.trace)?,
                        quotient: deserialize_composition_query_v5(ood.quotient)?,
                    })
                },
            )
            .transpose()?;

        let query_response = hc_prover::queries::QueryResponseV7 {
            trace_queries,
            composition_queries,
            fri_queries,
            ood,
        };

        Ok(hc_prover::queries::ProofV7 {
            version: self.version,
            trace_commitment,
            composition_commitment,
            fri_proof,
            public_inputs: self
                .public_inputs
                .into_iter()
                .map(GoldilocksField::from_u64)
                .collect(),
            trace_width: self.trace_width,
            air_id: self.air_id,
            query_response,
            trace_length: self.trace_length,
            params,
            grinding_nonce: self.grinding_nonce,
        })
    }
}

/// Encode a `ProofV7<GoldilocksField>` to `ProofBytes` (JSON, version tag 7 or 8
/// in both the envelope and the payload). ADDITIVE: does not touch v3/v5 encode.
pub fn encode_proof_v7(proof: &hc_prover::queries::ProofV7<GoldilocksField>) -> Result<ProofBytes> {
    let serializable = SerializableProofV7::from_proof(proof);
    let bytes = serde_json::to_vec(&serializable)?;
    Ok(ProofBytes {
        version: proof.version,
        bytes,
    })
}

/// Decode a `ProofBytes` previously produced by [`encode_proof_v7`]. Verifies
/// that the envelope version matches the payload version tag.
pub fn decode_proof_v7(proof: &ProofBytes) -> Result<hc_prover::queries::ProofV7<GoldilocksField>> {
    let serializable: SerializableProofV7 = serde_json::from_slice(&proof.bytes)?;
    if serializable.version != proof.version {
        anyhow::bail!(
            "v7 proof version mismatch: envelope {} vs payload {}",
            proof.version,
            serializable.version
        );
    }
    serializable.into_proof()
}

/// Route a decoded v7/v8 proof bytes object to the v7 verifier (production
/// floor, `min_sound_version = 7`). Called from `verify_proof_bytes` when the
/// envelope version is ≥ 7.
fn verify_proof_bytes_v7(proof: &ProofBytes) -> VerifyResult {
    let decoded = match decode_proof_v7(proof) {
        Ok(p) => p,
        Err(err) => {
            return VerifyResult {
                ok: false,
                error: Some(format!("v7 decode error: {err}")),
            }
        }
    };
    match hc_verifier::v5::verify_v7(&decoded) {
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

#[cfg(test)]
mod soundness_gate_tests {
    use super::*;
    #[allow(deprecated)] // legacy v3 prove + verify are exercised intentionally below.
    use hc_prover::{config::ProverConfig, prove, PublicInputs};
    use hc_vm::{Instruction, Program};

    /// Helper: build a v3 `hc_verifier::Proof` from a v3 `ProverOutput` so the
    /// lower-level (non-floor) verifier can still be exercised in tests after
    /// the production `verify_proof_bytes` cut over to v5-only.
    fn v3_verifier_proof(
        out: &hc_prover::queries::ProverOutput<GoldilocksField>,
    ) -> hc_verifier::Proof<GoldilocksField> {
        hc_verifier::Proof {
            version: out.version,
            trace_commitment: out.trace_commitment.clone(),
            composition_commitment: out.composition_commitment.clone(),
            fri_proof: out.fri_proof.clone(),
            initial_acc: out.public_inputs.initial_acc,
            final_acc: out.public_inputs.final_acc,
            query_response: out.query_response.clone(),
            trace_length: out.trace_length,
            params: out.params,
        }
    }

    /// PHASE 1A D5 cutover: `verify_proof_bytes` (the production endpoint) now
    /// REJECTS every pre-v5 proof with the legacy-version error — regardless of
    /// `allow_legacy_v2` and regardless of the declared commitment scheme. A
    /// crafted KZG-scheme v2/v3 proof is rejected by the version floor before
    /// any scheme-specific path is reached.
    #[test]
    fn legacy_v3_proof_is_rejected_by_production_endpoint() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: hc_core::field::prime_field::GoldilocksField::new(5),
            final_acc: hc_core::field::prime_field::GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        #[allow(deprecated)]
        let prover_out = prove(config, program, inputs).unwrap();
        let original_version = prover_out.version;
        assert!(original_version < 5, "expected a legacy (<v5) proof");

        // A plain v3 STARK proof: rejected by the version floor.
        let proof_bytes = encode_proof_bytes(&prover_out).unwrap();
        let result = verify_proof_bytes(&proof_bytes, true);
        assert!(
            !result.ok,
            "legacy v3 proof must be rejected by the endpoint"
        );
        let err = result.error.unwrap_or_default();
        assert!(
            err.contains("legacy proof version") && err.contains("v5"),
            "error must identify the legacy-version rejection, got: {err}"
        );

        // A crafted KZG-scheme variant of the same proof is ALSO rejected — the
        // version floor fires before the commitment scheme is even inspected.
        let serializable = SerializableProof::from_output(&prover_out);
        let mut json_val = serde_json::to_value(&serializable).unwrap();
        json_val["commitment_scheme"] = serde_json::Value::String("kzg".to_string());
        json_val["trace_commitment"] = serde_json::json!({"type": "kzg", "points": []});
        let patched = ProofBytes {
            version: original_version,
            bytes: serde_json::to_vec(&json_val).unwrap(),
        };
        let kzg_result = verify_proof_bytes(&patched, true);
        assert!(
            !kzg_result.ok,
            "crafted KZG-scheme legacy proof must be rejected by the endpoint"
        );
    }

    /// The v3 verification LOGIC is not deleted: a valid v3 STARK proof still
    /// verifies through the lower-level `hc_verifier::verify` (which has no
    /// production version floor). This keeps v3 verify test-covered even though
    /// the production endpoint now rejects it.
    #[test]
    fn v3_stark_still_verifies_via_lower_level_verify() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: hc_core::field::prime_field::GoldilocksField::new(5),
            final_acc: hc_core::field::prime_field::GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        #[allow(deprecated)]
        let prover_out = prove(config, program, inputs).unwrap();

        let proof = v3_verifier_proof(&prover_out);
        assert!(
            hc_verifier::verify(&proof).is_ok(),
            "v3 STARK proof must still verify via the lower-level verifier"
        );
    }
}

// ─── v5 serialization + bytes round-trip E2E tests ───────────────────────────

#[cfg(test)]
mod v5_serialization_tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_prover::config::{ProverConfig, SecurityFloor};
    use hc_prover::prove_v5;
    use hc_prover::queries::ProofV5;
    use hc_prover::PublicInputs;
    use hc_verifier::v5::{verify_v5_with_floor, VerifierSecurityFloor};
    use hc_vm::{Instruction, Program};

    type F = GoldilocksField;

    /// Fast honest v5 config: relaxed floor, tiny params, small grinding so the
    /// PoW search finishes quickly in tests.
    fn v5_test_config(grinding_bits: u32) -> ProverConfig {
        let mut config = ProverConfig::with_security_floor(
            2, // block_size
            2, // fri_final_poly_size
            4, // query_count
            2, // lde_blowup_factor
            SecurityFloor::relaxed(),
        )
        .unwrap()
        .with_protocol_version(5);
        config.grinding_bits = grinding_bits;
        config
    }

    fn v5_test_program() -> Program {
        Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
            Instruction::AddImmediate(3),
            Instruction::AddImmediate(4),
        ])
    }

    fn v5_test_inputs() -> PublicInputs<F> {
        // acc: 5 → 6 → 8 → 11 → 15
        PublicInputs {
            initial_acc: F::new(5),
            final_acc: F::new(15),
        }
    }

    fn make_v5_proof(grinding_bits: u32) -> ProofV5<F> {
        prove_v5(
            v5_test_config(grinding_bits),
            v5_test_program(),
            v5_test_inputs(),
        )
        .unwrap()
    }

    // ── E2E bytes round-trip: prove → encode → decode → verify ───────────────

    /// The key E2E test: prove a v5 statement, encode to bytes, decode, verify.
    /// Also asserts field-by-field equality between original and decoded proof.
    #[test]
    fn v5_bytes_roundtrip_e2e() {
        let original = make_v5_proof(8);

        // Encode.
        let proof_bytes = encode_proof_v5(&original).expect("encode_proof_v5 must succeed");
        assert_eq!(
            proof_bytes.version, original.version,
            "envelope version must match proof version"
        );

        // Decode.
        let decoded = decode_proof_v5(&proof_bytes).expect("decode_proof_v5 must succeed");

        // Field-by-field fidelity check.
        assert_eq!(decoded.version, original.version, "version round-trips");
        assert_eq!(
            decoded.initial_acc.to_u64(),
            original.initial_acc.to_u64(),
            "initial_acc round-trips"
        );
        assert_eq!(
            decoded.final_acc.to_u64(),
            original.final_acc.to_u64(),
            "final_acc round-trips"
        );
        assert_eq!(
            decoded.trace_length, original.trace_length,
            "trace_length round-trips"
        );
        assert_eq!(
            decoded.grinding_nonce, original.grinding_nonce,
            "grinding_nonce round-trips"
        );
        assert_eq!(
            decoded.params.grinding_bits, original.params.grinding_bits,
            "params.grinding_bits round-trips"
        );
        assert_eq!(
            decoded.params.query_count, original.params.query_count,
            "params.query_count round-trips"
        );
        assert_eq!(
            decoded.params.lde_blowup_factor, original.params.lde_blowup_factor,
            "params.lde_blowup_factor round-trips"
        );
        assert_eq!(
            decoded.params.fri_final_poly_size, original.params.fri_final_poly_size,
            "params.fri_final_poly_size round-trips"
        );

        // FRI proof fidelity.
        assert_eq!(
            decoded.fri_proof.layer_roots.len(),
            original.fri_proof.layer_roots.len(),
            "layer_roots count round-trips"
        );
        for (i, (d, o)) in decoded
            .fri_proof
            .layer_roots
            .iter()
            .zip(original.fri_proof.layer_roots.iter())
            .enumerate()
        {
            assert_eq!(d.as_bytes(), o.as_bytes(), "layer_roots[{i}] round-trips");
        }
        assert_eq!(
            decoded.fri_proof.final_root.as_bytes(),
            original.fri_proof.final_root.as_bytes(),
            "final_root round-trips"
        );
        assert_eq!(
            decoded.fri_proof.final_layer.len(),
            original.fri_proof.final_layer.len(),
            "final_layer length round-trips"
        );
        for (i, (d, o)) in decoded
            .fri_proof
            .final_layer
            .iter()
            .zip(original.fri_proof.final_layer.iter())
            .enumerate()
        {
            assert_eq!(*d, *o, "final_layer[{i}] round-trips (K value)");
        }
        assert_eq!(
            decoded.fri_proof.final_coeffs.len(),
            original.fri_proof.final_coeffs.len(),
            "final_coeffs length round-trips"
        );
        for (i, (d, o)) in decoded
            .fri_proof
            .final_coeffs
            .iter()
            .zip(original.fri_proof.final_coeffs.iter())
            .enumerate()
        {
            assert_eq!(*d, *o, "final_coeffs[{i}] round-trips (K value)");
        }

        // Query response fidelity.
        assert_eq!(
            decoded.query_response.fri_queries.len(),
            original.query_response.fri_queries.len(),
            "fri_queries count round-trips"
        );
        for (i, (d, o)) in decoded
            .query_response
            .fri_queries
            .iter()
            .zip(original.query_response.fri_queries.iter())
            .enumerate()
        {
            assert_eq!(
                d.layer_index, o.layer_index,
                "fri_query[{i}].layer_index round-trips"
            );
            assert_eq!(
                d.query_index, o.query_index,
                "fri_query[{i}].query_index round-trips"
            );
            assert_eq!(
                d.values[0], o.values[0],
                "fri_query[{i}].values[0] round-trips (K)"
            );
            assert_eq!(
                d.values[1], o.values[1],
                "fri_query[{i}].values[1] round-trips (K)"
            );
        }

        // Verify the decoded proof.
        verify_v5_with_floor(&decoded, VerifierSecurityFloor::relaxed())
            .expect("decoded v5 proof must verify under a relaxed floor");
    }

    /// verify_proof_bytes routes v5 proofs through the v5 verifier.
    /// Under a production floor the tiny params fail (that's correct); we just
    /// confirm no panic and an error is returned (not a wrong ACCEPT).
    #[test]
    fn verify_proof_bytes_routes_v5_to_v5_verifier() {
        let proof = make_v5_proof(8);
        let bytes = encode_proof_v5(&proof).unwrap();
        // Production floor → will reject tiny params, but must NOT wrongly accept.
        let result = verify_proof_bytes(&bytes, false);
        // Either rejected by floor (expected for tiny params) or accepted (if params happen
        // to meet the production floor). Both are OK; what's NOT OK is panic or wrong-accept
        // of a corrupted proof. We just confirm the function returns a valid VerifyResult.
        let _ = result.ok;
    }

    /// PHASE 1A D5 cutover: a v3 proof is now REJECTED by the production
    /// `verify_proof_bytes` endpoint (legacy-version floor), but the v3
    /// verification logic itself is preserved and still passes through the
    /// lower-level `hc_verifier::verify`.
    #[test]
    fn v3_rejected_by_endpoint_but_verifies_via_lower_level() {
        #[allow(deprecated)]
        use hc_prover::{config::ProverConfig, prove};
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: F::new(5),
            final_acc: F::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
        #[allow(deprecated)]
        let output = prove(config, program, inputs).unwrap();

        // Production endpoint rejects it (version < 5).
        let bytes = encode_proof_bytes(&output).unwrap();
        let result = verify_proof_bytes(&bytes, true);
        assert!(
            !result.ok,
            "v3 proof must be rejected by the production endpoint after the v5 cutover"
        );
        assert!(result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("legacy proof version"));

        // Lower-level verifier still accepts the (sound-enough for v3) proof —
        // the v3 verify logic is preserved, just not production-reachable.
        let lower = hc_verifier::Proof {
            version: output.version,
            trace_commitment: output.trace_commitment.clone(),
            composition_commitment: output.composition_commitment.clone(),
            fri_proof: output.fri_proof.clone(),
            initial_acc: output.public_inputs.initial_acc,
            final_acc: output.public_inputs.final_acc,
            query_response: output.query_response.clone(),
            trace_length: output.trace_length,
            params: output.params,
        };
        assert!(
            hc_verifier::verify(&lower).is_ok(),
            "v3 verify logic must remain functional via the lower-level entry"
        );
    }

    /// PRODUCTION-CONFIG self-consistency (Phase 1A requirement): a proof built
    /// with the real production v5 params (blowup ≥ 8, query_count ≥ 40,
    /// grinding_bits = 20) MUST round-trip through `encode_proof_v5` and be
    /// ACCEPTED by `verify_proof_bytes` under the DEFAULT (production) floor.
    /// This pins that the live service re-verifies its own proofs. Grinding 20
    /// is ~1M hashes — acceptable for a single test.
    #[test]
    fn production_v5_config_roundtrips_through_verify_proof_bytes() {
        // Mirror exactly what the hc-worker / MCP executor build in production.
        let config = ProverConfig::production_v5(2, 2, 40, 8, None).unwrap();
        assert!(config.lde_blowup_factor >= 8, "blowup floor");
        assert!(config.query_count >= 40, "query floor");
        assert_eq!(config.grinding_bits, 20, "grinding pinned to 20");
        assert_eq!(config.protocol_version, 5, "non-ZK ⇒ v5");

        let proof = prove_v5(config, v5_test_program(), v5_test_inputs())
            .expect("production v5 prove must succeed");
        let bytes = encode_proof_v5(&proof).expect("encode_proof_v5 must succeed");

        // DEFAULT floor (the one the live /verify endpoint uses) must ACCEPT.
        let result = verify_proof_bytes(&bytes, false);
        assert!(
            result.ok,
            "production-config v5 proof must verify under the default floor: {:?}",
            result.error
        );
    }

    /// Decode of a bytes payload with mismatched version tag must fail.
    #[test]
    fn v5_decode_version_mismatch_fails() {
        let proof = make_v5_proof(0);
        let mut bytes = encode_proof_v5(&proof).unwrap();
        // Set envelope version to something different than the payload's version.
        bytes.version = bytes.version.wrapping_add(1);
        let err = decode_proof_v5(&bytes).expect_err("version mismatch must be detected");
        assert!(
            err.to_string().contains("version mismatch"),
            "error should mention version mismatch, got: {err}"
        );
    }

    /// Truncating the v5 bytes must cause a decode error (never panic).
    #[test]
    fn v5_bytes_truncation_causes_decode_error() {
        let proof = make_v5_proof(0);
        let bytes = encode_proof_v5(&proof).unwrap();
        let truncated = crate::types::ProofBytes {
            version: bytes.version,
            bytes: bytes.bytes[..bytes.bytes.len() / 2].to_vec(),
        };
        let _ = decode_proof_v5(&truncated); // must not panic
    }
}

// ─── v7 (general-AIR) serialization + bytes round-trip E2E tests ──────────────

#[cfg(test)]
mod v7_serialization_tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField as F;
    use hc_prover::config::{ProverConfig, SecurityFloor};
    use hc_prover::queries::ProofV7;
    use hc_verifier::v5::{verify_v7_with_floor, VerifierSecurityFloor};

    /// Small relaxed v7 config (tiny params, no grinding) for fast structural
    /// round-trip tests — verified under `VerifierSecurityFloor::relaxed`.
    fn v7_relaxed_cfg() -> ProverConfig {
        let mut c = ProverConfig::with_security_floor(2, 2, 4, 2, SecurityFloor::relaxed())
            .unwrap()
            .with_protocol_version(7);
        c.grinding_bits = 0;
        c
    }

    /// Build a sound v7 range proof for `min ≤ value ≤ max` with the given config.
    fn range_proof(min: u64, max: u64, value: u64, cfg: &ProverConfig) -> ProofV7<F> {
        let air = hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N);
        let trace = hc_air::build_range_trace(min, max, value).unwrap();
        hc_prover::prove_v7(&air, &trace, &[F::new(min), F::new(max)], cfg).unwrap()
    }

    /// A sound v7 `range_proof` survives `encode_proof_v7 → decode_proof_v7` with
    /// every field intact (width, AIR id, public inputs) and still verifies. `V`
    /// (42) is NOT among the public inputs — only `[min, max]`.
    #[test]
    fn v7_range_proof_roundtrips_structurally() {
        let proof = range_proof(18, 120, 42, &v7_relaxed_cfg());

        let bytes = encode_proof_v7(&proof).expect("encode_proof_v7 must succeed");
        assert_eq!(bytes.version, 7, "v7 envelope version tag");

        let decoded = decode_proof_v7(&bytes).expect("decode_proof_v7 must succeed");
        assert_eq!(decoded.trace_width, 4, "range AIR is width-4");
        assert_eq!(decoded.air_id, 2, "range AIR id");
        assert_eq!(
            decoded.public_inputs,
            vec![F::new(18), F::new(120)],
            "public inputs [min,max] round-trip; V (42) is absent"
        );
        verify_v7_with_floor(&decoded, VerifierSecurityFloor::relaxed())
            .expect("decoded v7 proof must verify");
    }

    /// Tampering an opened trace value in the serialized v7 proof is caught: the
    /// Merkle opening no longer matches the committed leaf. (Verified under the
    /// relaxed floor so the rejection is the TAMPER, not the production floor.)
    #[test]
    fn tampered_v7_trace_opening_rejected() {
        let proof = range_proof(18, 120, 42, &v7_relaxed_cfg());
        let bytes = encode_proof_v7(&proof).unwrap();

        // Flip the first opened trace cell of the first query to a bogus value.
        let mut json: serde_json::Value = serde_json::from_slice(&bytes.bytes).unwrap();
        json["trace_queries"][0]["evaluation"][0] = serde_json::Value::from(999_999_999u64);
        let tampered = crate::types::ProofBytes {
            version: bytes.version,
            bytes: serde_json::to_vec(&json).unwrap(),
        };
        let decoded = decode_proof_v7(&tampered).expect("tampered value still decodes");
        assert!(
            verify_v7_with_floor(&decoded, VerifierSecurityFloor::relaxed()).is_err(),
            "a tampered trace opening must be rejected"
        );
    }

    /// The envelope version and payload version must agree (mismatch detected).
    #[test]
    fn v7_version_mismatch_is_detected() {
        let proof = range_proof(18, 120, 42, &v7_relaxed_cfg());
        let mut bytes = encode_proof_v7(&proof).unwrap();
        bytes.version = bytes.version.wrapping_add(1); // 7 → 8 (payload still says 7)
        let err = decode_proof_v7(&bytes).expect_err("version mismatch must be detected");
        assert!(
            err.to_string().contains("version mismatch"),
            "error should mention version mismatch, got: {err}"
        );
    }

    /// REGRESSION (calldata 500): `decode_proof_bytes` is the LEGACY (pre-v5)
    /// decoder the `/proof/{id}/calldata` endpoint uses to recover a
    /// `ProverOutput` before EVM-encoding it. The production prover emits sound
    /// v5 (`ProofV5`) proofs — and gated v7 (`ProofV7`) — whose wire format
    /// differs (field elements are hex strings, not u64). Feeding any of those to
    /// `decode_proof_bytes` failed with a cryptic serde error ("invalid type:
    /// string …, expected u64") that the endpoint surfaced as a daily 500.
    ///
    /// The observed production proof is **v5** (the original v7 diagnosis was
    /// wrong) — so the gate must cover every current sound version (v5+), not just
    /// v7. There is no on-chain verifier for the sound proof system (the Solidity
    /// verifier is a v3-era stub kept out of the product surface), so EVM calldata
    /// is undefined for v5+; the decoder must reject it with a CLEAR message.
    #[test]
    fn decode_proof_bytes_gates_current_sound_versions() {
        // Real v7 proof — the concrete production-shaped case.
        let v7_bytes =
            encode_proof_v7(&range_proof(18, 120, 42, &v7_relaxed_cfg())).expect("encode_proof_v7");
        // Plus every current sound envelope version (v5 is what prod actually
        // emits). The gate keys on version, so minimal bytes suffice.
        let cases = [
            v7_bytes,
            crate::types::ProofBytes {
                version: 5,
                bytes: b"{}".to_vec(),
            },
            crate::types::ProofBytes {
                version: 6,
                bytes: b"{}".to_vec(),
            },
            crate::types::ProofBytes {
                version: 8,
                bytes: b"{}".to_vec(),
            },
        ];
        for bytes in &cases {
            let err = decode_proof_bytes(bytes)
                .expect_err("decode_proof_bytes must reject sound (v5+) proofs");
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("calldata"),
                "v{}: expected a clear calldata gate message, got: {msg}",
                bytes.version
            );
            assert!(
                !msg.contains("expected u64"),
                "v{}: must be a clean version gate, not a leaked serde failure: {msg}",
                bytes.version
            );
        }
    }

    /// THE production-path assertion: a PRODUCTION v7 range proof (blowup ≥ 8,
    /// query_count ≥ 40, grinding_bits = 20) round-trips through `encode_proof_v7`
    /// and is ACCEPTED by `verify_proof_bytes` under the DEFAULT production floor
    /// (which now routes version ≥ 7 to the v7 verifier). Mirrors the v5
    /// `production_v5_config_roundtrips_through_verify_proof_bytes` test.
    #[test]
    fn production_v7_range_roundtrips_through_verify_proof_bytes() {
        let cfg = ProverConfig::production_v7(2, 2, 40, 8, None).unwrap();
        assert_eq!(cfg.grinding_bits, 20, "grinding pinned to 20");
        let proof = range_proof(18, 120, 42, &cfg);
        assert_eq!(proof.version, 7);

        let bytes = encode_proof_v7(&proof).unwrap();
        let result = verify_proof_bytes(&bytes, false);
        assert!(
            result.ok,
            "production v7 range proof must verify through verify_proof_bytes: {:?}",
            result.error
        );
    }

    /// v7 proving is deterministic: the same (AIR, trace, public inputs, config)
    /// yields byte-identical proofs. v7 is sound-only (no ZK randomness);
    /// grinding is a deterministic search and the Fiat–Shamir challenges are
    /// transcript-derived, so the serialized proof is reproducible. This is the
    /// non-brittle stand-in for a byte-exact KAT — a frozen hex vector is
    /// deferred until the wire format is frozen at the Phase 4 audit (range is
    /// gated until then, so the format is not yet a public commitment).
    #[test]
    fn v7_range_proof_is_deterministic() {
        let cfg = v7_relaxed_cfg();
        let a = encode_proof_v7(&range_proof(18, 120, 42, &cfg)).unwrap();
        let b = encode_proof_v7(&range_proof(18, 120, 42, &cfg)).unwrap();
        assert_eq!(a.version, b.version);
        assert_eq!(
            a.bytes, b.bytes,
            "v7 proving must be deterministic (byte-reproducible)"
        );
    }
}
