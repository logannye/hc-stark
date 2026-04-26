use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

use crate::aggregator::ProofSummary;

pub mod fri_chain;
pub mod halo2;
pub mod poseidon;
pub mod poseidon_chip;
pub mod stark_verifier;
pub mod transcript_gadget;
pub mod verify_air;
pub mod verify_fri;
pub mod verify_merkle;
#[derive(Clone, Debug)]
pub struct SummaryEncoding {
    pub trace_digest_words: [GoldilocksField; 4],
    pub initial_acc: GoldilocksField,
    pub final_acc: GoldilocksField,
    pub trace_length: GoldilocksField,
    pub query_trace_commitment_words: [GoldilocksField; 4],
    pub query_composition_commitment_words: [GoldilocksField; 4],
    pub fri_commitment_words: [GoldilocksField; 4],
}

impl SummaryEncoding {
    pub fn as_fields(&self) -> Vec<GoldilocksField> {
        let mut out = Vec::with_capacity(19);
        out.extend(self.trace_digest_words);
        out.push(self.initial_acc);
        out.push(self.final_acc);
        out.push(self.trace_length);
        out.extend(self.query_trace_commitment_words);
        out.extend(self.query_composition_commitment_words);
        out.extend(self.fri_commitment_words);
        out
    }
}

pub fn encode_summary(summary: &ProofSummary<GoldilocksField>) -> SummaryEncoding {
    SummaryEncoding {
        trace_digest_words: digest_to_words(summary.trace_commitment_digest),
        initial_acc: summary.initial_acc,
        final_acc: summary.final_acc,
        trace_length: GoldilocksField::from_u64(summary.trace_length as u64),
        query_trace_commitment_words: digest_to_words(summary.query_commitments.trace_commitment),
        query_composition_commitment_words: digest_to_words(
            summary.query_commitments.composition_commitment,
        ),
        fri_commitment_words: digest_to_words(summary.query_commitments.fri_commitment),
    }
}

pub fn verify_query_commitments(summary: &ProofSummary<GoldilocksField>) -> bool {
    let encoding = encode_summary(summary);
    let trace_digest = words_to_digest(&encoding.query_trace_commitment_words);
    let composition_digest = words_to_digest(&encoding.query_composition_commitment_words);
    let fri_digest = words_to_digest(&encoding.fri_commitment_words);
    trace_digest == summary.query_commitments.trace_commitment
        && composition_digest == summary.query_commitments.composition_commitment
        && fri_digest == summary.query_commitments.fri_commitment
}

pub fn summary_challenge(summary: &ProofSummary<GoldilocksField>) -> HashDigest {
    let encoding = encode_summary(summary);
    let mut buffer = Vec::new();
    for field in encoding.as_fields() {
        buffer.extend_from_slice(&field.to_u64().to_le_bytes());
    }
    Blake3::hash(&buffer)
}

fn digest_to_words(digest: HashDigest) -> [GoldilocksField; 4] {
    let mut words = [GoldilocksField::ZERO; 4];
    for (idx, chunk) in digest.as_bytes().chunks_exact(8).enumerate() {
        words[idx] = GoldilocksField::from_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
    }
    words
}

fn words_to_digest(words: &[GoldilocksField; 4]) -> HashDigest {
    let mut bytes = [0u8; 32];
    for (idx, word) in words.iter().enumerate() {
        let start = idx * 8;
        bytes[start..start + 8].copy_from_slice(&word.to_u64().to_le_bytes());
    }
    HashDigest::from(bytes)
}

#[cfg(test)]
mod tests {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_hash::blake3::Blake3;

    use super::*;
    use crate::aggregator::ProofSummary;
    use hc_verifier::QueryCommitments;

    #[test]
    fn encoding_round_trip_verifies_commitments() {
        let summary = ProofSummary {
            trace_commitment_digest: Blake3::hash(b"trace"),
            initial_acc: GoldilocksField::from_u64(5),
            final_acc: GoldilocksField::from_u64(42),
            trace_length: 64,
            query_commitments: QueryCommitments {
                trace_commitment: Blake3::hash(b"trace_queries"),
                composition_commitment: Blake3::hash(b"composition_queries"),
                fri_commitment: Blake3::hash(b"fri_queries"),
            },
            circuit_digest: GoldilocksField::from_u64(0),
        };
        assert!(verify_query_commitments(&summary));
        let encoding = encode_summary(&summary);
        assert_eq!(encoding.as_fields().len(), 19);
        let _challenge = summary_challenge(&summary);
    }
}
