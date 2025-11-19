use std::time::Instant;

use hc_commit::merkle::{height_dfs::StreamingMerkle, reconstruct_path_from_replay, MerkleTree};
use hc_core::error::{HcError, HcResult};
use hc_hash::{blake3::Blake3, hash::HashDigest, HashFunction};
use serde_json::json;

pub fn bench_merkle_paths(
    leaves: usize,
    queries: usize,
    fanout: usize,
) -> HcResult<serde_json::Value> {
    if leaves == 0 {
        return Err(HcError::invalid_argument(
            "merkle benchmark requires at least one leaf",
        ));
    }
    if queries == 0 {
        return Err(HcError::invalid_argument(
            "merkle benchmark requires at least one query",
        ));
    }
    if fanout < 2 {
        return Err(HcError::invalid_argument(
            "merkle benchmark fanout must be >= 2",
        ));
    }

    let leaf_values = generate_leaves(leaves);
    let producer = |idx: usize| leaf_values[idx];

    let streaming_duration = measure_streaming_paths(&leaf_values, fanout, queries, &producer)?;
    let in_memory_duration = measure_in_memory_paths(&leaf_values, queries)?;

    Ok(json!({
        "mode": "merkle_paths",
        "leaves": leaves,
        "queries": queries,
        "fanout": fanout,
        "streaming_ms": streaming_duration,
        "in_memory_ms": in_memory_duration,
    }))
}

fn generate_leaves(count: usize) -> Vec<HashDigest> {
    (0..count)
        .map(|i| Blake3::hash(&(i as u64).to_le_bytes()))
        .collect()
}

fn measure_streaming_paths<P>(
    leaves: &[HashDigest],
    fanout: usize,
    queries: usize,
    producer: &P,
) -> HcResult<f64>
where
    P: Fn(usize) -> HashDigest,
{
    let mut builder_for_root = StreamingMerkle::<Blake3>::with_fanout(fanout);
    for leaf in leaves {
        builder_for_root.push(*leaf);
    }
    let root = builder_for_root
        .finalize()
        .ok_or_else(|| HcError::message("failed to build streaming root"))?;

    let indices = query_schedule(leaves.len(), queries);
    let start = Instant::now();
    for &index in &indices {
        let path =
            reconstruct_path_from_replay::<Blake3, _>(index, leaves.len(), fanout, producer)?;
        debug_assert!(path.verify::<Blake3>(root, leaves[index]));
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    Ok(elapsed)
}

fn measure_in_memory_paths(leaves: &[HashDigest], queries: usize) -> HcResult<f64> {
    let tree = MerkleTree::<Blake3>::from_leaves(leaves)?;
    let indices = query_schedule(leaves.len(), queries);
    let start = Instant::now();
    for &index in &indices {
        let path = tree.open(index)?;
        debug_assert!(path.verify::<Blake3>(tree.root(), leaves[index]));
    }
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn query_schedule(domain: usize, queries: usize) -> Vec<usize> {
    (0..queries).map(|i| ((i * 1_048_583) % domain)).collect()
}
