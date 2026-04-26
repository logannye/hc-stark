use hc_core::error::HcResult;
use hc_hash::hash::{HashDigest, HashFunction};

use super::hash_pair;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathNode {
    pub sibling: HashDigest,
    pub sibling_is_left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MerklePath {
    nodes: Vec<PathNode>,
}

impl MerklePath {
    pub fn new(nodes: Vec<PathNode>) -> Self {
        Self { nodes }
    }

    pub fn nodes(&self) -> &[PathNode] {
        &self.nodes
    }

    pub fn verify<H>(&self, root: HashDigest, leaf: HashDigest) -> bool
    where
        H: hc_hash::hash::HashFunction,
    {
        let mut acc = leaf;
        for node in &self.nodes {
            acc = if node.sibling_is_left {
                hash_pair::<H>(&node.sibling, &acc)
            } else {
                hash_pair::<H>(&acc, &node.sibling)
            };
        }
        acc == root
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Reconstruct a Merkle path by replaying leaf production up to the target index.
/// Supports arbitrary fanouts by mirroring the streaming builder's reduction
/// order (deterministic left folds without padding).
pub fn reconstruct_path_from_replay<H, P>(
    leaf_index: usize,
    leaf_count: usize,
    fanout: usize,
    producer: &P,
) -> HcResult<MerklePath>
where
    H: HashFunction,
    P: Fn(usize) -> HashDigest,
{
    if leaf_index >= leaf_count {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf index out of range",
        ));
    }

    if fanout < 2 {
        return Err(hc_core::error::HcError::invalid_argument(
            "fanout must be at least 2",
        ));
    }

    let mut stack: Vec<Vec<(HashDigest, bool)>> = Vec::new();
    let mut path_nodes: Vec<PathNode> = Vec::new();

    for idx in 0..leaf_count {
        let mut current = producer(idx);
        let mut contains_target = idx == leaf_index;
        let mut level = 0;

        loop {
            if stack.len() <= level {
                stack.push(Vec::new());
            }

            stack[level].push((current, contains_target));
            if stack[level].len() < fanout {
                break;
            }

            let chunk = stack[level].drain(..).collect::<Vec<_>>();
            let combined = fold_chunk::<H>(chunk, &mut path_nodes, true);
            current = combined.0;
            contains_target = combined.1;
            level += 1;
        }
    }

    let mut carry: Option<(HashDigest, bool)> = None;
    let total_levels = stack.len();
    for (idx, mut level_nodes) in stack.into_iter().enumerate() {
        if level_nodes.is_empty() && carry.is_none() {
            continue;
        }

        let had_carry = carry.is_some();
        if let Some(carry_node) = carry.take() {
            level_nodes.push(carry_node);
        }

        if level_nodes.is_empty() {
            continue;
        }

        let is_top_level = idx + 1 == total_levels;
        let duplicate_single = !(is_top_level && level_nodes.len() == 1 && !had_carry);
        carry = Some(fold_chunk::<H>(
            level_nodes,
            &mut path_nodes,
            duplicate_single,
        ));
    }

    Ok(MerklePath::new(path_nodes))
}

/// Like [`reconstruct_path_from_replay`], but allows the leaf producer to fail.
pub fn reconstruct_path_from_replay_result<H, P>(
    leaf_index: usize,
    leaf_count: usize,
    fanout: usize,
    producer: &P,
) -> HcResult<MerklePath>
where
    H: HashFunction,
    P: Fn(usize) -> HcResult<HashDigest>,
{
    if leaf_index >= leaf_count {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf index out of range",
        ));
    }

    if fanout < 2 {
        return Err(hc_core::error::HcError::invalid_argument(
            "fanout must be at least 2",
        ));
    }

    let mut stack: Vec<Vec<(HashDigest, bool)>> = Vec::new();
    let mut path_nodes: Vec<PathNode> = Vec::new();

    for idx in 0..leaf_count {
        let mut current = producer(idx)?;
        let mut contains_target = idx == leaf_index;
        let mut level = 0;

        loop {
            if stack.len() <= level {
                stack.push(Vec::new());
            }

            stack[level].push((current, contains_target));
            if stack[level].len() < fanout {
                break;
            }

            let chunk = stack[level].drain(..).collect::<Vec<_>>();
            let combined = fold_chunk::<H>(chunk, &mut path_nodes, true);
            current = combined.0;
            contains_target = combined.1;
            level += 1;
        }
    }

    let mut carry: Option<(HashDigest, bool)> = None;
    let total_levels = stack.len();
    for (idx, mut level_nodes) in stack.into_iter().enumerate() {
        if level_nodes.is_empty() && carry.is_none() {
            continue;
        }

        let had_carry = carry.is_some();
        if let Some(carry_node) = carry.take() {
            level_nodes.push(carry_node);
        }

        if level_nodes.is_empty() {
            continue;
        }

        let is_top_level = idx + 1 == total_levels;
        let duplicate_single = !(is_top_level && level_nodes.len() == 1 && !had_carry);
        carry = Some(fold_chunk::<H>(
            level_nodes,
            &mut path_nodes,
            duplicate_single,
        ));
    }

    Ok(MerklePath::new(path_nodes))
}

/// Like [`reconstruct_path_from_replay_result`], but accepts a mutable producer (`FnMut`).
///
/// This is useful when leaf production is backed by an internal replay cache.
pub fn reconstruct_path_from_replay_mut<H, P>(
    leaf_index: usize,
    leaf_count: usize,
    fanout: usize,
    producer: &mut P,
) -> HcResult<MerklePath>
where
    H: HashFunction,
    P: FnMut(usize) -> HcResult<HashDigest>,
{
    if leaf_index >= leaf_count {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf index out of range",
        ));
    }

    if fanout < 2 {
        return Err(hc_core::error::HcError::invalid_argument(
            "fanout must be at least 2",
        ));
    }

    let mut stack: Vec<Vec<(HashDigest, bool)>> = Vec::new();
    let mut path_nodes: Vec<PathNode> = Vec::new();

    for idx in 0..leaf_count {
        let mut current = producer(idx)?;
        let mut contains_target = idx == leaf_index;
        let mut level = 0;

        loop {
            if stack.len() <= level {
                stack.push(Vec::new());
            }

            stack[level].push((current, contains_target));
            if stack[level].len() < fanout {
                break;
            }

            let chunk = stack[level].drain(..).collect::<Vec<_>>();
            let combined = fold_chunk::<H>(chunk, &mut path_nodes, true);
            current = combined.0;
            contains_target = combined.1;
            level += 1;
        }
    }

    let mut carry: Option<(HashDigest, bool)> = None;
    let total_levels = stack.len();
    for (idx, mut level_nodes) in stack.into_iter().enumerate() {
        if level_nodes.is_empty() && carry.is_none() {
            continue;
        }

        let had_carry = carry.is_some();
        if let Some(carry_node) = carry.take() {
            level_nodes.push(carry_node);
        }

        if level_nodes.is_empty() {
            continue;
        }

        let is_top_level = idx + 1 == total_levels;
        let duplicate_single = !(is_top_level && level_nodes.len() == 1 && !had_carry);
        carry = Some(fold_chunk::<H>(
            level_nodes,
            &mut path_nodes,
            duplicate_single,
        ));
    }

    Ok(MerklePath::new(path_nodes))
}

/// Reconstruct Merkle paths for multiple leaves in a single streaming pass over the leaves.
///
/// This is the same reduction order as [`reconstruct_path_from_replay_mut`], but tracks a small set
/// of target leaves and emits a path for each.
///
/// Requirements:
/// - `leaf_indices` must be non-empty, unique, and each < `leaf_count`
/// - `leaf_indices.len()` must be <= 64 (tracked via a bitmask)
pub fn reconstruct_paths_from_replay_mut<H, P>(
    leaf_indices: &[usize],
    leaf_count: usize,
    fanout: usize,
    producer: &mut P,
) -> HcResult<Vec<MerklePath>>
where
    H: HashFunction,
    P: FnMut(usize) -> HcResult<HashDigest>,
{
    if leaf_indices.is_empty() {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf_indices must be non-empty",
        ));
    }
    if leaf_indices.len() > 64 {
        return Err(hc_core::error::HcError::invalid_argument(
            "leaf_indices must contain at most 64 entries",
        ));
    }
    if fanout < 2 {
        return Err(hc_core::error::HcError::invalid_argument(
            "fanout must be at least 2",
        ));
    }

    // Build index -> bit position mapping, rejecting duplicates.
    let mut mapping: std::collections::HashMap<usize, u32> =
        std::collections::HashMap::with_capacity(leaf_indices.len());
    for (pos, &idx) in leaf_indices.iter().enumerate() {
        if idx >= leaf_count {
            return Err(hc_core::error::HcError::invalid_argument(
                "leaf index out of range",
            ));
        }
        if mapping.insert(idx, pos as u32).is_some() {
            return Err(hc_core::error::HcError::invalid_argument(
                "leaf_indices must be unique",
            ));
        }
    }

    let mut stack: Vec<Vec<(HashDigest, u64)>> = Vec::new();
    let mut path_nodes_by_target: Vec<Vec<PathNode>> = vec![Vec::new(); leaf_indices.len()];

    for idx in 0..leaf_count {
        let mut current = producer(idx)?;
        let mut mask: u64 = 0;
        if let Some(&pos) = mapping.get(&idx) {
            mask = 1u64 << pos;
        }
        let mut level = 0;

        loop {
            if stack.len() <= level {
                stack.push(Vec::new());
            }

            stack[level].push((current, mask));
            if stack[level].len() < fanout {
                break;
            }

            let chunk = stack[level].drain(..).collect::<Vec<_>>();
            let combined = fold_chunk_masked::<H>(chunk, &mut path_nodes_by_target, true);
            current = combined.0;
            mask = combined.1;
            level += 1;
        }
    }

    let mut carry: Option<(HashDigest, u64)> = None;
    let total_levels = stack.len();
    for (idx, mut level_nodes) in stack.into_iter().enumerate() {
        if level_nodes.is_empty() && carry.is_none() {
            continue;
        }

        let had_carry = carry.is_some();
        if let Some(carry_node) = carry.take() {
            level_nodes.push(carry_node);
        }

        if level_nodes.is_empty() {
            continue;
        }

        let is_top_level = idx + 1 == total_levels;
        let duplicate_single = !(is_top_level && level_nodes.len() == 1 && !had_carry);
        carry = Some(fold_chunk_masked::<H>(
            level_nodes,
            &mut path_nodes_by_target,
            duplicate_single,
        ));
    }

    Ok(path_nodes_by_target
        .into_iter()
        .map(MerklePath::new)
        .collect())
}

fn fold_chunk_masked<H: HashFunction>(
    chunk: Vec<(HashDigest, u64)>,
    path_nodes_by_target: &mut [Vec<PathNode>],
    duplicate_single: bool,
) -> (HashDigest, u64) {
    debug_assert!(!chunk.is_empty(), "chunk should contain at least one node");
    if chunk.is_empty() {
        return (HashDigest::new([0u8; 32]), 0);
    }
    if chunk.len() == 1 && duplicate_single {
        let entry = chunk[0];
        let duplicate = (entry.0, 0u64);
        return fold_pair_masked::<H>(entry, duplicate, path_nodes_by_target);
    } else if chunk.len() == 1 {
        return chunk[0];
    }

    let mut iter = chunk.into_iter();
    let mut acc = iter.next().unwrap();
    for node in iter {
        acc = fold_pair_masked::<H>(acc, node, path_nodes_by_target);
    }
    acc
}

fn fold_pair_masked<H: HashFunction>(
    left: (HashDigest, u64),
    right: (HashDigest, u64),
    path_nodes_by_target: &mut [Vec<PathNode>],
) -> (HashDigest, u64) {
    // Record sibling nodes for every target that flows through this fold.
    let mut left_mask = left.1;
    while left_mask != 0 {
        let bit = left_mask.trailing_zeros() as usize;
        left_mask &= left_mask - 1;
        path_nodes_by_target[bit].push(PathNode {
            sibling: right.0,
            sibling_is_left: false,
        });
    }
    let mut right_mask = right.1;
    while right_mask != 0 {
        let bit = right_mask.trailing_zeros() as usize;
        right_mask &= right_mask - 1;
        path_nodes_by_target[bit].push(PathNode {
            sibling: left.0,
            sibling_is_left: true,
        });
    }

    (hash_pair::<H>(&left.0, &right.0), left.1 | right.1)
}

fn fold_chunk<H: HashFunction>(
    chunk: Vec<(HashDigest, bool)>,
    path_nodes: &mut Vec<PathNode>,
    duplicate_single: bool,
) -> (HashDigest, bool) {
    debug_assert!(!chunk.is_empty(), "chunk should contain at least one node");
    if chunk.is_empty() {
        return (HashDigest::new([0u8; 32]), false);
    }
    if chunk.len() == 1 && duplicate_single {
        let entry = chunk[0];
        let duplicate = (entry.0, false);
        return fold_pair::<H>(entry, duplicate, path_nodes);
    } else if chunk.len() == 1 {
        return chunk[0];
    }

    let mut iter = chunk.into_iter();
    let mut acc = iter.next().unwrap();

    for node in iter {
        acc = fold_pair::<H>(acc, node, path_nodes);
    }

    acc
}

fn fold_pair<H: HashFunction>(
    left: (HashDigest, bool),
    right: (HashDigest, bool),
    path_nodes: &mut Vec<PathNode>,
) -> (HashDigest, bool) {
    if left.1 ^ right.1 {
        path_nodes.push(PathNode {
            sibling: if left.1 { right.0 } else { left.0 },
            sibling_is_left: !left.1,
        });
    }

    (hash_pair::<H>(&left.0, &right.0), left.1 || right.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::standard::MerkleTree;
    use hc_hash::blake3::Blake3;

    #[test]
    fn reconstructs_paths_for_non_power_of_two() {
        let leaves: Vec<_> = (0u8..5).map(|i| Blake3::hash(&[i])).collect();
        let producer = |idx: usize| leaves[idx];
        let path =
            reconstruct_path_from_replay::<Blake3, _>(4, leaves.len(), 2, &producer).unwrap();
        let tree = MerkleTree::<Blake3>::from_leaves(&leaves).unwrap();
        assert!(path.verify::<Blake3>(tree.root(), leaves[4]));
    }

    #[test]
    fn reconstructs_paths_for_custom_fanout() {
        let leaves: Vec<_> = (0u8..9).map(|i| Blake3::hash(&[i])).collect();
        let producer = |idx: usize| leaves[idx];
        let path =
            reconstruct_path_from_replay::<Blake3, _>(3, leaves.len(), 3, &producer).unwrap();

        // Build an equivalent streaming tree to obtain the root.
        let mut streaming = super::super::height_dfs::StreamingMerkle::<Blake3>::with_fanout(3);
        for leaf in &leaves {
            streaming.push(*leaf);
        }
        let root = streaming.finalize().unwrap();
        assert!(path.verify::<Blake3>(root, leaves[3]));
    }
}
