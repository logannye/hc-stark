use std::sync::Arc;

use hc_core::error::HcResult;

use crate::block_range::BlockRange;

pub trait BlockProducer<T>: Send + Sync {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<T>>;
}

#[derive(Clone)]
pub struct VecBlockProducer<T: Clone + Send + Sync + 'static> {
    data: Arc<Vec<T>>,
}

impl<T: Clone + Send + Sync + 'static> VecBlockProducer<T> {
    pub fn new(data: Vec<T>) -> Self {
        Self {
            data: Arc::new(data),
        }
    }

    pub fn from_arc(data: Arc<Vec<T>>) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T: Clone + Send + Sync + 'static> BlockProducer<T> for VecBlockProducer<T> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<T>> {
        Ok(self.data[range.start..range.end()].to_vec())
    }
}
