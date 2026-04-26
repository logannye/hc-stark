//! Rollup state transition proof framework for hc-stark.
//!
//! This crate provides the building blocks for ZK-rollup state transitions:
//!
//! - [`state::SparseMerkleTree`]: Sparse Merkle tree for rollup state
//! - [`batch::Batch`]: Transaction batching and state transitions
//!
//! ## Usage
//!
//! ```rust,ignore
//! use hc_rollup::{state::SparseMerkleTree, batch::{Batch, Transaction}};
//!
//! let mut state = SparseMerkleTree::new();
//!
//! // Create a batch of transactions.
//! let batch = Batch::new(vec![
//!     Transaction { key: 0, value: Some([1u8; 32]) },
//!     Transaction { key: 1, value: Some([2u8; 32]) },
//! ]);
//!
//! // Apply the batch and get the state transition result.
//! let result = batch.apply(&mut state);
//!
//! // The result contains pre/post state roots for proof generation.
//! println!("pre:  {:?}", result.pre_state_root);
//! println!("post: {:?}", result.post_state_root);
//! ```

pub mod batch;
pub mod state;
