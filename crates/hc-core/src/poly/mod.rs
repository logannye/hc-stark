//! Polynomial utilities (dense, sparse, and evaluation helpers).

pub mod dense;
pub mod eval;
pub mod sparse;

pub use dense::DensePolynomial;
pub use sparse::{SparsePolynomial, SparseTerm};
