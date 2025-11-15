use crate::{config::ReplayConfig, trace_replay::TraceReplay, traits::BlockProducer};

pub type CommitReplay<P, T> = TraceReplay<P, T>;

pub fn new_commit_replay<P, T>(
    config: ReplayConfig,
    producer: P,
) -> hc_core::error::HcResult<CommitReplay<P, T>>
where
    P: BlockProducer<T>,
    T: Clone,
{
    TraceReplay::new(config, producer)
}
