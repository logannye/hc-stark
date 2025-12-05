use std::marker::PhantomData;

use hc_core::error::{HcError, HcResult};

use crate::{block_range::BlockRange, config::ReplayConfig, traits::BlockProducer};

pub struct TraceReplay<P, T> {
    config: ReplayConfig,
    producer: P,
    last_block_index: Option<usize>,
    last_block: Vec<T>,
    _marker: PhantomData<T>,
}

impl<P, T> TraceReplay<P, T>
where
    P: BlockProducer<T>,
    T: Clone,
{
    pub fn new(config: ReplayConfig, producer: P) -> HcResult<Self> {
        Ok(Self {
            config,
            producer,
            last_block_index: None,
            last_block: Vec::new(),
            _marker: PhantomData,
        })
    }

    pub fn block_size(&self) -> usize {
        self.config.block_size
    }

    pub fn trace_length(&self) -> usize {
        self.config.trace_length
    }

    pub fn num_blocks(&self) -> usize {
        if self.config.trace_length == 0 {
            0
        } else {
            self.config
                .trace_length
                .div_ceil(self.config.block_size)
        }
    }

    pub fn fetch_block(&mut self, block_index: usize) -> HcResult<&[T]> {
        if self.last_block_index == Some(block_index) {
            return Ok(&self.last_block);
        }
        let start = block_index * self.config.block_size;
        if start >= self.config.trace_length {
            return Err(HcError::invalid_argument("block index out of range"));
        }
        let remaining = self.config.trace_length - start;
        let len = remaining.min(self.config.block_size);
        let range = BlockRange::new(start, len);
        self.last_block = self.producer.produce(range)?;
        self.last_block_index = Some(block_index);
        Ok(&self.last_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::BlockProducer;
    use hc_core::error::HcResult;

    struct VecProducer {
        data: Vec<u64>,
    }

    impl BlockProducer<u64> for VecProducer {
        fn produce(&self, range: BlockRange) -> HcResult<Vec<u64>> {
            Ok(self.data[range.start..range.end()].to_vec())
        }
    }

    #[test]
    fn replay_fetches_consistent_blocks() {
        let producer = VecProducer {
            data: (0..10).collect(),
        };
        let config = ReplayConfig::new(4, 10).unwrap();
        let mut replay = TraceReplay::new(config, producer).unwrap();
        let block0 = replay.fetch_block(0).unwrap().to_vec();
        let block1 = replay.fetch_block(1).unwrap().to_vec();
        let block2 = replay.fetch_block(2).unwrap().to_vec();
        assert_eq!(block0, vec![0, 1, 2, 3]);
        assert_eq!(block1, vec![4, 5, 6, 7]);
        assert_eq!(block2, vec![8, 9]);
    }
}
