use hc_core::error::HcResult;

use crate::block_range::BlockRange;

pub trait BlockProducer<T>: Send + Sync {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<T>>;
}
