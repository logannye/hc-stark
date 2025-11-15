//! Polynomial utilities (dense, sparse, and evaluation helpers).

pub mod dense;
pub mod eval;
pub mod sparse;

pub use dense::DensePolynomial;
pub use eval::{evaluate_batch, horner, interpolate, lde_block};
pub use sparse::{SparsePolynomial, SparseTerm};
