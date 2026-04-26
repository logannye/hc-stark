//! Transaction batching for rollup state transitions.
//!
//! A batch collects multiple transactions and produces a state transition
//! proof: `(state_root_before, transactions, state_root_after)`.

use crate::state::SparseMerkleTree;
use anyhow::{bail, Result};
use hc_hash::HashDigest;
use serde::{Deserialize, Serialize};

/// A single state transition transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Target slot in the state tree.
    pub key: u32,
    /// New value to write (None = delete).
    pub value: Option<[u8; 32]>,
}

/// A batch of transactions forming a state transition.
#[derive(Clone, Debug)]
pub struct Batch {
    pub transactions: Vec<Transaction>,
}

/// The result of applying a batch to a state tree.
#[derive(Clone, Debug)]
pub struct BatchResult {
    /// State root before applying the batch.
    pub pre_state_root: HashDigest,
    /// State root after applying the batch.
    pub post_state_root: HashDigest,
    /// Number of transactions applied.
    pub tx_count: usize,
    /// The transaction batch that was applied.
    pub transactions: Vec<Transaction>,
}

/// Public inputs for the state transition proof.
///
/// These values are exposed to the verifier and bind the proof
/// to a specific state transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransitionPublicInputs {
    /// Root hash of the state tree before applying transactions.
    pub pre_state_root: [u8; 32],
    /// Root hash of the state tree after applying transactions.
    pub post_state_root: [u8; 32],
    /// Hash of the transaction batch (commitment to the transactions).
    pub tx_batch_hash: [u8; 32],
    /// Number of transactions in the batch.
    pub tx_count: u32,
}

impl Batch {
    /// Create a new batch from a list of transactions.
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self { transactions }
    }

    /// Apply this batch to a state tree and return the transition result.
    pub fn apply(&self, state: &mut SparseMerkleTree) -> BatchResult {
        let pre_state_root = state.root();

        for tx in &self.transactions {
            match &tx.value {
                Some(value) => state.insert(tx.key, *value),
                None => state.remove(tx.key),
            }
        }

        let post_state_root = state.root();

        BatchResult {
            pre_state_root,
            post_state_root,
            tx_count: self.transactions.len(),
            transactions: self.transactions.clone(),
        }
    }

    /// Compute a commitment hash over the transaction batch.
    pub fn batch_hash(&self) -> HashDigest {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(b"hc-rollup-batch");
        hasher.update(&(self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            hasher.update(&tx.key.to_le_bytes());
            match &tx.value {
                Some(val) => {
                    hasher.update(&[1u8]);
                    hasher.update(val);
                }
                None => {
                    hasher.update(&[0u8]);
                }
            }
        }
        let hash = hasher.finalize();
        let bytes: [u8; 32] = hash.as_bytes()[..32].try_into().unwrap();
        HashDigest::from(bytes)
    }

    /// Validate that the batch is well-formed.
    pub fn validate(&self) -> Result<()> {
        if self.transactions.is_empty() {
            bail!("batch must contain at least one transaction");
        }
        if self.transactions.len() > 10_000 {
            bail!("batch exceeds maximum size of 10,000 transactions");
        }
        Ok(())
    }
}

impl BatchResult {
    /// Generate the public inputs for proof generation.
    pub fn public_inputs(&self, batch: &Batch) -> StateTransitionPublicInputs {
        let batch_hash = batch.batch_hash();
        StateTransitionPublicInputs {
            pre_state_root: *self.pre_state_root.as_bytes(),
            post_state_root: *self.post_state_root.as_bytes(),
            tx_batch_hash: *batch_hash.as_bytes(),
            tx_count: self.tx_count as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_batch_rejected() {
        let batch = Batch::new(vec![]);
        assert!(batch.validate().is_err());
    }

    #[test]
    fn single_insert_changes_root() {
        let mut state = SparseMerkleTree::new();
        let batch = Batch::new(vec![Transaction {
            key: 0,
            value: Some([1u8; 32]),
        }]);
        batch.validate().unwrap();
        let result = batch.apply(&mut state);
        assert_ne!(result.pre_state_root, result.post_state_root);
        assert_eq!(result.tx_count, 1);
    }

    #[test]
    fn insert_then_delete_restores_root() {
        let mut state = SparseMerkleTree::new();
        let empty_root = state.root();

        let batch1 = Batch::new(vec![Transaction {
            key: 42,
            value: Some([0xAA; 32]),
        }]);
        batch1.apply(&mut state);
        assert_ne!(state.root(), empty_root);

        let batch2 = Batch::new(vec![Transaction {
            key: 42,
            value: None,
        }]);
        batch2.apply(&mut state);
        assert_eq!(state.root(), empty_root);
    }

    #[test]
    fn batch_hash_deterministic() {
        let batch = Batch::new(vec![
            Transaction {
                key: 1,
                value: Some([0x11; 32]),
            },
            Transaction {
                key: 2,
                value: Some([0x22; 32]),
            },
        ]);
        let h1 = batch.batch_hash();
        let h2 = batch.batch_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn batch_hash_changes_with_content() {
        let batch_a = Batch::new(vec![Transaction {
            key: 1,
            value: Some([0x11; 32]),
        }]);
        let batch_b = Batch::new(vec![Transaction {
            key: 1,
            value: Some([0x22; 32]),
        }]);
        assert_ne!(batch_a.batch_hash(), batch_b.batch_hash());
    }

    #[test]
    fn public_inputs_consistent() {
        let mut state = SparseMerkleTree::new();
        let batch = Batch::new(vec![Transaction {
            key: 0,
            value: Some([0xFF; 32]),
        }]);
        let result = batch.apply(&mut state);
        let pi = result.public_inputs(&batch);
        assert_eq!(pi.pre_state_root, *result.pre_state_root.as_bytes());
        assert_eq!(pi.post_state_root, *result.post_state_root.as_bytes());
        assert_eq!(pi.tx_count, 1);
    }

    #[test]
    fn multi_tx_batch() {
        let mut state = SparseMerkleTree::new();
        let batch = Batch::new(vec![
            Transaction {
                key: 0,
                value: Some([1; 32]),
            },
            Transaction {
                key: 1,
                value: Some([2; 32]),
            },
            Transaction {
                key: 2,
                value: Some([3; 32]),
            },
        ]);
        let result = batch.apply(&mut state);
        assert_eq!(result.tx_count, 3);
        assert_eq!(state.len(), 3);

        // All values should be readable.
        assert_eq!(state.get(0), Some(&[1; 32]));
        assert_eq!(state.get(1), Some(&[2; 32]));
        assert_eq!(state.get(2), Some(&[3; 32]));
    }
}
