use hc_hash::hash::HashDigest;

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
