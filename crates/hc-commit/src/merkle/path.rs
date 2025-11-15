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
/// This is used when the full Merkle tree is not stored in memory.
pub fn reconstruct_path_from_replay<H, P>(
    leaf_index: usize,
    leaf_count: usize,
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

    let mut stack: Vec<Option<HashDigest>> = Vec::new();
    let mut stack_contains_target: Vec<bool> = Vec::new();
    let mut path_nodes: Vec<PathNode> = Vec::new();

    for idx in 0..leaf_count {
        let mut current = producer(idx);
        let mut contains_target = idx == leaf_index;
        let mut level = 0;

        loop {
            if stack.len() <= level {
                stack.push(Some(current));
                stack_contains_target.push(contains_target);
                break;
            }

            if let Some(existing) = stack[level].take() {
                let existing_contains = stack_contains_target[level];
                stack_contains_target[level] = false;

                if existing_contains ^ contains_target {
                    let (sibling, sibling_is_left) = if existing_contains {
                        (current, false)
                    } else {
                        (existing, true)
                    };
                    path_nodes.push(PathNode {
                        sibling,
                        sibling_is_left,
                    });
                }

                current = hash_pair::<H>(&existing, &current);
                contains_target = existing_contains || contains_target;
                level += 1;
                continue;
            }

            stack[level] = Some(current);
            stack_contains_target[level] = contains_target;
            break;
        }
    }

    let mut acc: Option<HashDigest> = None;
    let mut acc_contains_target = false;
    for (node_opt, node_contains) in stack.into_iter().zip(stack_contains_target.into_iter()) {
        if let Some(node) = node_opt {
            if let Some(prev) = acc.take() {
                if acc_contains_target ^ node_contains {
                    let (sibling, sibling_is_left) = if node_contains {
                        (prev, false)
                    } else {
                        (node, true)
                    };
                    path_nodes.push(PathNode {
                        sibling,
                        sibling_is_left,
                    });
                }

                acc = Some(hash_pair::<H>(&node, &prev));
                acc_contains_target = acc_contains_target || node_contains;
            } else {
                acc = Some(node);
                acc_contains_target = node_contains;
            }
        }
    }

    Ok(MerklePath::new(path_nodes))
}
