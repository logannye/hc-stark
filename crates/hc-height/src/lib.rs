#![forbid(unsafe_code)]

use hc_core::error::{HcError, HcResult};
use hc_replay::{trace_replay::TraceReplay, traits::BlockProducer};

mod kzg;
mod merkle;

pub use kzg::StreamingKzgCommitment;
pub use merkle::StarkMerkleCommitment;

/// Trait implemented by streaming commitment builders.
pub trait StreamingCommitment<F> {
    type Output;

    fn absorb_block(&mut self, block_index: usize, data: &[F]) -> HcResult<()>;
    fn finalize(self) -> HcResult<Self::Output>;
}

/// Helper for committing to a replayed sequence using a streaming builder.
pub fn commit_streaming<F, P, C>(
    replay: &mut TraceReplay<P, F>,
    mut builder: C,
) -> HcResult<C::Output>
where
    F: Clone,
    P: BlockProducer<F>,
    C: StreamingCommitment<F>,
{
    for block_index in 0..replay.num_blocks() {
        let block = replay.fetch_block(block_index)?;
        builder.absorb_block(block_index, block).map_err(|err| {
            HcError::message(format!("failed to absorb block {block_index}: {err}"))
        })?;
    }
    builder.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ec::Group;
    use ark_ff::PrimeField;
    use hc_commit::merkle::standard::MerkleTree;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_hash::blake3::Blake3;
    use hc_replay::{block_range::BlockRange, config::ReplayConfig, traits::BlockProducer};

    struct VecProducer<T> {
        data: Vec<T>,
    }

    impl<T: Clone + Send + Sync> BlockProducer<T> for VecProducer<T> {
        fn produce(&self, range: BlockRange) -> HcResult<Vec<T>> {
            Ok(self.data[range.start..range.end()].to_vec())
        }
    }

    #[test]
    fn stark_merkle_matches_standard_tree() {
        let values: Vec<GoldilocksField> =
            (0..32).map(|i| GoldilocksField::new(i as u64)).collect();
        let block_size = 5;
        let producer = VecProducer {
            data: values.clone(),
        };
        let config = ReplayConfig::new(block_size, values.len()).unwrap();
        let mut replay = TraceReplay::new(config, producer).unwrap();
        let builder = StarkMerkleCommitment::new();
        let root = commit_streaming(&mut replay, builder).unwrap();

        let leaves: Vec<_> = values
            .iter()
            .map(StarkMerkleCommitment::hash_field)
            .collect();
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves).unwrap();
        assert_eq!(root, tree.root());
    }

    #[test]
    fn streaming_kzg_matches_batch_sum() {
        let values: Vec<Fr> = (0..16).map(|i| Fr::from(i as u64 + 1)).collect();
        let block_size = 4;
        let producer = VecProducer {
            data: values.clone(),
        };
        let config = ReplayConfig::new(block_size, values.len()).unwrap();
        let mut replay = TraceReplay::new(config, producer).unwrap();
        let builder = StreamingKzgCommitment::new_with_tau(Fr::from(5u64));
        let commitment = commit_streaming(&mut replay, builder).unwrap();

        let mut scalar_acc = Fr::from(0u64);
        let mut tau_power = Fr::from(1u64);
        let tau = Fr::from(5u64);
        for coeff in values {
            scalar_acc += coeff * tau_power;
            tau_power *= tau;
        }
        let expected = StreamingKzgCommitment::g1_generator().mul_bigint(scalar_acc.into_bigint());
        assert_eq!(commitment, expected);
    }
}
