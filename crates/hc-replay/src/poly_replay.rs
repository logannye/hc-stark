use crate::{config::ReplayConfig, trace_replay::TraceReplay, traits::BlockProducer};

pub type PolyReplay<P, T> = TraceReplay<P, T>;

pub fn new_poly_replay<P, T>(
    config: ReplayConfig,
    producer: P,
) -> hc_core::error::HcResult<PolyReplay<P, T>>
where
    P: BlockProducer<T>,
    T: Clone,
{
    TraceReplay::new(config, producer)
}
