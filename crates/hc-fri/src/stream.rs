use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_replay::trace_replay::TraceReplay;

#[derive(Clone, Copy, Debug, Default)]
pub struct StreamingStats {
    pub blocks_loaded: usize,
}

pub struct ReplayValueStream<'a, P, F>
where
    P: hc_replay::traits::BlockProducer<F>,
    F: FieldElement,
{
    replay: &'a mut TraceReplay<P, F>,
    len: usize,
    index: usize,
    current_block_index: Option<usize>,
    current_block: Vec<F>,
    block_base: usize,
    block_fetches: usize,
}

impl<'a, P, F> ReplayValueStream<'a, P, F>
where
    P: hc_replay::traits::BlockProducer<F>,
    F: FieldElement,
{
    pub fn new(replay: &'a mut TraceReplay<P, F>) -> Self {
        let len = replay.trace_length();
        Self {
            replay,
            len,
            index: 0,
            current_block_index: None,
            current_block: Vec::new(),
            block_base: 0,
            block_fetches: 0,
        }
    }

    pub fn next(&mut self) -> HcResult<Option<F>> {
        if self.index >= self.len {
            return Ok(None);
        }
        let block_size = self.replay.block_size();
        let block_index = self.index / block_size;
        if self.current_block_index != Some(block_index) {
            let slice = self.replay.fetch_block(block_index)?;
            self.current_block.clear();
            self.current_block.extend_from_slice(slice);
            self.current_block_index = Some(block_index);
            self.block_base = block_index * block_size;
            self.block_fetches += 1;
        }
        let offset = self.index - self.block_base;
        let value = self.current_block[offset];
        self.index += 1;
        Ok(Some(value))
    }

    pub fn stats(&self) -> StreamingStats {
        StreamingStats {
            blocks_loaded: self.block_fetches,
        }
    }
}

pub fn fold_layer_streaming<F, P>(
    source: &mut TraceReplay<P, F>,
    beta: F,
) -> HcResult<(Vec<F>, StreamingStats)>
where
    F: FieldElement,
    P: hc_replay::traits::BlockProducer<F>,
{
    let len = source.trace_length();
    if len % 2 != 0 {
        return Err(HcError::invalid_argument(
            "FRI layer size must be even for folding",
        ));
    }
    let mut iter = ReplayValueStream::new(source);
    let mut next = Vec::with_capacity((len + 1) / 2);
    while let Some(a) = iter.next()? {
        let b = match iter.next()? {
            Some(value) => value,
            None => F::ZERO,
        };
        next.push(a.add(beta.mul(b)));
    }
    Ok((next, iter.stats()))
}
