//! ABI-encoded calldata-optimized proof format for on-chain verification.
//!
//! The standard `ProofBytes` uses JSON, which is human-readable but expensive
//! for calldata (zeroes/non-zeroes both cost gas, and JSON carries ~40% overhead
//! from keys, quotes, and formatting).
//!
//! This module provides a compact binary format that maps directly to Solidity's
//! `abi.decode`, minimizing calldata cost.
//!
//! ## Format (EvmProofV1)
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ magic: [u8; 4]       "HCST"                    │
//! │ version: u32                                    │
//! │ protocol_version: u32                           │
//! │ trace_length: u64                               │
//! │ query_count: u32                                │
//! │ lde_blowup: u32                                 │
//! │ fri_final_size: u32                             │
//! │ initial_acc: u64                                │
//! │ final_acc: u64                                  │
//! │ trace_root: [u8; 32]                            │
//! │ composition_root: [u8; 32]                      │
//! │ fri_layer_count: u32                            │
//! │ fri_layer_roots: [[u8; 32]; fri_layer_count]    │
//! │ fri_final_root: [u8; 32]                        │
//! │ fri_final_poly: [u64; fri_final_size]           │
//! │ query_data_len: u32                             │
//! │ query_data: [u8; query_data_len]                │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! Query data is a packed sequence of query responses — each trace query,
//! composition query, and FRI query is encoded as tightly as possible.

use anyhow::{bail, Context, Result};
use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_hash::{HashDigest, DIGEST_LEN};

/// Magic bytes identifying an hc-stark EVM proof.
const MAGIC: [u8; 4] = *b"HCST";

/// EVM-optimized proof blob.
#[derive(Clone, Debug)]
pub struct EvmProof {
    pub bytes: Vec<u8>,
}

/// Encode a `ProverOutput` into the compact EVM proof format.
pub fn encode_evm_proof(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<EvmProof> {
    let mut buf = Vec::with_capacity(4096);

    // Magic + version header.
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&output.version.to_be_bytes());
    buf.extend_from_slice(&output.params.protocol_version.to_be_bytes());

    // Trace length.
    buf.extend_from_slice(&(output.trace_length as u64).to_be_bytes());

    // Params.
    buf.extend_from_slice(&(output.params.query_count as u32).to_be_bytes());
    buf.extend_from_slice(&(output.params.lde_blowup_factor as u32).to_be_bytes());
    buf.extend_from_slice(&(output.params.fri_final_poly_size as u32).to_be_bytes());

    // Public inputs.
    buf.extend_from_slice(&output.public_inputs.initial_acc.to_u64().to_be_bytes());
    buf.extend_from_slice(&output.public_inputs.final_acc.to_u64().to_be_bytes());

    // Trace commitment root.
    let trace_root = extract_stark_root(&output.trace_commitment)?;
    buf.extend_from_slice(trace_root.as_bytes());

    // Composition commitment root.
    let composition_root = extract_stark_root(&output.composition_commitment)?;
    buf.extend_from_slice(composition_root.as_bytes());

    // FRI layer roots.
    let layer_count = output.fri_proof.layer_roots.len() as u32;
    buf.extend_from_slice(&layer_count.to_be_bytes());
    for root in &output.fri_proof.layer_roots {
        buf.extend_from_slice(root.as_bytes());
    }

    // FRI final root + polynomial.
    buf.extend_from_slice(output.fri_proof.final_root.as_bytes());
    for val in &output.fri_proof.final_layer {
        buf.extend_from_slice(&val.to_u64().to_be_bytes());
    }

    // Query data (packed).
    let query_data = encode_query_data(output)?;
    buf.extend_from_slice(&(query_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&query_data);

    Ok(EvmProof { bytes: buf })
}

/// Decode the compact EVM proof format back into component parts for verification.
pub fn decode_evm_proof(data: &[u8]) -> Result<EvmProofParts> {
    let mut cursor = 0usize;

    // Magic.
    if data.len() < 4 {
        bail!("proof too short for magic bytes");
    }
    if data[0..4] != MAGIC {
        bail!("invalid magic bytes");
    }
    cursor += 4;

    let version = read_u32(data, &mut cursor)?;
    let protocol_version = read_u32(data, &mut cursor)?;
    let trace_length = read_u64(data, &mut cursor)?;
    let query_count = read_u32(data, &mut cursor)?;
    let lde_blowup = read_u32(data, &mut cursor)?;
    let fri_final_size = read_u32(data, &mut cursor)?;
    let initial_acc = read_u64(data, &mut cursor)?;
    let final_acc = read_u64(data, &mut cursor)?;

    let trace_root = read_digest(data, &mut cursor)?;
    let composition_root = read_digest(data, &mut cursor)?;

    let layer_count = read_u32(data, &mut cursor)? as usize;
    let mut fri_layer_roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        fri_layer_roots.push(read_digest(data, &mut cursor)?);
    }

    let fri_final_root = read_digest(data, &mut cursor)?;

    let mut fri_final_poly = Vec::with_capacity(fri_final_size as usize);
    for _ in 0..fri_final_size {
        fri_final_poly.push(read_u64(data, &mut cursor)?);
    }

    let query_data_len = read_u32(data, &mut cursor)? as usize;
    if cursor + query_data_len > data.len() {
        bail!("query data extends past end of proof");
    }
    let query_data = data[cursor..cursor + query_data_len].to_vec();

    Ok(EvmProofParts {
        version,
        protocol_version,
        trace_length,
        query_count,
        lde_blowup,
        fri_final_size,
        initial_acc,
        final_acc,
        trace_root,
        composition_root,
        fri_layer_roots,
        fri_final_root,
        fri_final_poly,
        query_data,
    })
}

/// Decoded EVM proof components.
#[derive(Clone, Debug)]
pub struct EvmProofParts {
    pub version: u32,
    pub protocol_version: u32,
    pub trace_length: u64,
    pub query_count: u32,
    pub lde_blowup: u32,
    pub fri_final_size: u32,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_root: HashDigest,
    pub composition_root: HashDigest,
    pub fri_layer_roots: Vec<HashDigest>,
    pub fri_final_root: HashDigest,
    pub fri_final_poly: Vec<u64>,
    pub query_data: Vec<u8>,
}

/// Generate Solidity-compatible ABI-encoded calldata from an EVM proof.
///
/// This produces the `bytes` parameter for `StarkVerifier.verifyProof(bytes)`.
pub fn to_abi_calldata(proof: &EvmProof) -> Vec<u8> {
    // For direct calldata submission, the proof bytes are already packed.
    // Wrap in ABI encoding: offset (32 bytes) + length (32 bytes) + data (padded to 32).
    let mut calldata = Vec::with_capacity(64 + proof.bytes.len().div_ceil(32) * 32);

    // ABI dynamic bytes: offset = 32.
    calldata.extend_from_slice(&[0u8; 28]);
    calldata.extend_from_slice(&32u32.to_be_bytes());

    // Length.
    calldata.extend_from_slice(&[0u8; 28]);
    calldata.extend_from_slice(&(proof.bytes.len() as u32).to_be_bytes());

    // Data (padded to 32-byte boundary).
    calldata.extend_from_slice(&proof.bytes);
    let padding = (32 - (proof.bytes.len() % 32)) % 32;
    calldata.extend_from_slice(&vec![0u8; padding]);

    calldata
}

// ---- Helpers ----

fn extract_stark_root(commitment: &hc_prover::Commitment) -> Result<HashDigest> {
    match commitment {
        hc_prover::Commitment::Stark { root } => Ok(*root),
        hc_prover::Commitment::Kzg { .. } => {
            bail!("EVM proof encoding only supports STARK commitments (Merkle roots)")
        }
    }
}

fn encode_query_data(
    output: &hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<Vec<u8>> {
    let qr = match &output.query_response {
        Some(qr) => qr,
        None => return Ok(Vec::new()),
    };

    let mut buf = Vec::with_capacity(8192);

    // Trace queries.
    buf.extend_from_slice(&(qr.trace_queries.len() as u32).to_be_bytes());
    for tq in &qr.trace_queries {
        buf.extend_from_slice(&(tq.index as u32).to_be_bytes());
        buf.extend_from_slice(&tq.evaluation[0].to_u64().to_be_bytes());
        buf.extend_from_slice(&tq.evaluation[1].to_u64().to_be_bytes());
        encode_witness(&tq.witness, &mut buf)?;
        // Next row (optional).
        match &tq.next {
            Some(next) => {
                buf.push(1);
                buf.extend_from_slice(&(next.index as u32).to_be_bytes());
                buf.extend_from_slice(&next.evaluation[0].to_u64().to_be_bytes());
                buf.extend_from_slice(&next.evaluation[1].to_u64().to_be_bytes());
                encode_merkle_path(&next.witness, &mut buf);
            }
            None => buf.push(0),
        }
    }

    // Composition queries.
    buf.extend_from_slice(&(qr.composition_queries.len() as u32).to_be_bytes());
    for cq in &qr.composition_queries {
        buf.extend_from_slice(&(cq.index as u32).to_be_bytes());
        buf.extend_from_slice(&cq.value.to_u64().to_be_bytes());
        encode_merkle_path(&cq.witness, &mut buf);
    }

    // FRI queries.
    buf.extend_from_slice(&(qr.fri_queries.len() as u32).to_be_bytes());
    for fq in &qr.fri_queries {
        buf.extend_from_slice(&(fq.layer_index as u32).to_be_bytes());
        buf.extend_from_slice(&(fq.query_index as u32).to_be_bytes());
        buf.extend_from_slice(&fq.values[0].to_u64().to_be_bytes());
        buf.extend_from_slice(&fq.values[1].to_u64().to_be_bytes());
        encode_merkle_path(&fq.merkle_paths[0], &mut buf);
        encode_merkle_path(&fq.merkle_paths[1], &mut buf);
    }

    // Boundary openings (optional).
    match &qr.boundary {
        Some(b) => {
            buf.push(1);
            encode_trace_query_packed(&b.first_trace, &mut buf)?;
            encode_trace_query_packed(&b.last_trace, &mut buf)?;
            encode_composition_query_packed(&b.first_composition, &mut buf);
            encode_composition_query_packed(&b.last_composition, &mut buf);
        }
        None => buf.push(0),
    }

    // OOD openings (optional).
    match &qr.ood {
        Some(ood) => {
            buf.push(1);
            buf.extend_from_slice(&(ood.index as u32).to_be_bytes());
            encode_trace_query_packed(&ood.trace, &mut buf)?;
            encode_composition_query_packed(&ood.quotient, &mut buf);
        }
        None => buf.push(0),
    }

    Ok(buf)
}

fn encode_trace_query_packed(
    tq: &hc_prover::queries::TraceQuery<GoldilocksField>,
    buf: &mut Vec<u8>,
) -> Result<()> {
    buf.extend_from_slice(&(tq.index as u32).to_be_bytes());
    buf.extend_from_slice(&tq.evaluation[0].to_u64().to_be_bytes());
    buf.extend_from_slice(&tq.evaluation[1].to_u64().to_be_bytes());
    encode_witness(&tq.witness, buf)?;
    match &tq.next {
        Some(next) => {
            buf.push(1);
            buf.extend_from_slice(&(next.index as u32).to_be_bytes());
            buf.extend_from_slice(&next.evaluation[0].to_u64().to_be_bytes());
            buf.extend_from_slice(&next.evaluation[1].to_u64().to_be_bytes());
            encode_merkle_path(&next.witness, buf);
        }
        None => buf.push(0),
    }
    Ok(())
}

fn encode_composition_query_packed(
    cq: &hc_prover::queries::CompositionQuery<GoldilocksField>,
    buf: &mut Vec<u8>,
) {
    buf.extend_from_slice(&(cq.index as u32).to_be_bytes());
    buf.extend_from_slice(&cq.value.to_u64().to_be_bytes());
    encode_merkle_path(&cq.witness, buf);
}

fn encode_witness(witness: &hc_prover::queries::TraceWitness, buf: &mut Vec<u8>) -> Result<()> {
    match witness {
        hc_prover::queries::TraceWitness::Merkle(path) => {
            buf.push(0); // tag: Merkle
            encode_merkle_path(path, buf);
        }
        hc_prover::queries::TraceWitness::Kzg(_) => {
            bail!("KZG witnesses are not supported in EVM proof format");
        }
    }
    Ok(())
}

fn encode_merkle_path(path: &hc_commit::merkle::MerklePath, buf: &mut Vec<u8>) {
    let nodes = path.nodes();
    buf.extend_from_slice(&(nodes.len() as u16).to_be_bytes());

    // Pack sibling_is_left bits into a bitfield.
    let bit_bytes = nodes.len().div_ceil(8);
    let mut bits = vec![0u8; bit_bytes];
    for (i, node) in nodes.iter().enumerate() {
        if node.sibling_is_left {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    buf.extend_from_slice(&bits);

    // Sibling hashes (32 bytes each).
    for node in nodes {
        buf.extend_from_slice(node.sibling.as_bytes());
    }
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > data.len() {
        bail!("unexpected end of proof at offset {cursor}");
    }
    let val = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    Ok(val)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Result<u64> {
    if *cursor + 8 > data.len() {
        bail!("unexpected end of proof at offset {cursor}");
    }
    let val = u64::from_be_bytes(data[*cursor..*cursor + 8].try_into().unwrap());
    *cursor += 8;
    Ok(val)
}

fn read_digest(data: &[u8], cursor: &mut usize) -> Result<HashDigest> {
    if *cursor + DIGEST_LEN > data.len() {
        bail!("unexpected end of proof at offset {cursor}");
    }
    let bytes: [u8; DIGEST_LEN] = data[*cursor..*cursor + DIGEST_LEN]
        .try_into()
        .context("digest slice")?;
    *cursor += DIGEST_LEN;
    Ok(HashDigest::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_correct() {
        assert_eq!(&MAGIC, b"HCST");
    }

    #[test]
    fn roundtrip_u32() {
        let data = 42u32.to_be_bytes();
        let mut cursor = 0;
        assert_eq!(read_u32(&data, &mut cursor).unwrap(), 42);
        assert_eq!(cursor, 4);
    }

    #[test]
    fn roundtrip_u64() {
        let data = 0xDEADBEEF_CAFEBABEu64.to_be_bytes();
        let mut cursor = 0;
        assert_eq!(read_u64(&data, &mut cursor).unwrap(), 0xDEADBEEF_CAFEBABE);
        assert_eq!(cursor, 8);
    }

    #[test]
    fn roundtrip_digest() {
        let digest = HashDigest::from([0xAB; DIGEST_LEN]);
        let data = digest.as_bytes().to_vec();
        let mut cursor = 0;
        let decoded = read_digest(&data, &mut cursor).unwrap();
        assert_eq!(decoded, digest);
    }

    #[test]
    fn abi_calldata_alignment() {
        let proof = EvmProof {
            bytes: vec![1, 2, 3, 4, 5],
        };
        let calldata = to_abi_calldata(&proof);
        // offset (32) + length (32) + data padded to 32 = 96
        assert_eq!(calldata.len(), 96);
        // Check offset = 32.
        assert_eq!(calldata[31], 32);
        // Check length = 5.
        assert_eq!(calldata[63], 5);
        // Check data.
        assert_eq!(&calldata[64..69], &[1, 2, 3, 4, 5]);
        // Check padding is zeros.
        assert!(calldata[69..96].iter().all(|&b| b == 0));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let data = b"BADXrest_of_data_here_padding_00";
        let result = decode_evm_proof(data);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        let result = decode_evm_proof(b"HC");
        assert!(result.is_err());
    }
}
