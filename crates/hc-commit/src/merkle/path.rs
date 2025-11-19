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
        carry = Some(fold_chunk::<H>(level_nodes, &mut path_nodes, duplicate_single));
    }

    Ok(MerklePath::new(path_nodes))
}

fn fold_chunk<H: HashFunction>(
    chunk: Vec<(HashDigest, bool)>,
    path_nodes: &mut Vec<PathNode>,
    duplicate_single: bool,
) -> (HashDigest, bool) {
    if chunk.is_empty() {
        panic!("chunk should contain at least one node");
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
