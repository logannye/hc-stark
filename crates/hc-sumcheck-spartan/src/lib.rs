#![forbid(unsafe_code)]

//! `hc-sumcheck-spartan` — Spartan-style R1CS reduction over the
//! height-compressed sumcheck.
//!
//! ## What this crate ships
//!
//! Given an R1CS instance `(A, B, C, w)` with constraint
//!
//! ```text
//!     (A·w) ⊙ (B·w) - C·w = 0
//! ```
//!
//! (Hadamard product, must be the zero vector), this crate produces a
//! sumcheck proof that the relation holds, with `O(√M + √N)` prover memory
//! through the [`hc_sumcheck`] backend.
//!
//! The reduction follows the standard Spartan recipe:
//!
//! 1. Compute the three vectors `Aw, Bw, Cw ∈ F^M`.
//! 2. View them as multilinear extensions on `{0,1}^{log M}`.
//! 3. Sample a random point `τ ∈ F^{log M}` and form the equality polynomial
//!    `eq_τ`. By the Schwartz–Zippel lemma the original Hadamard relation
//!    holds iff
//!
//!    ```text
//!       Σ_{x ∈ {0,1}^{log M}} eq_τ(x) · (Aw(x)·Bw(x) - Cw(x)) = 0
//!    ```
//!
//!    with overwhelming probability over τ.
//! 4. Run a single [`hc_sumcheck::LinearProductPoly`] sumcheck on the LHS:
//!    two terms (`eq_τ·Aw·Bw` minus `eq_τ·Cw`), max degree 3.
//!
//! Verification is the standard sumcheck verifier (general degree, via
//! Lagrange interpolation) plus a final-point evaluation of all four
//! polynomials at the sampled challenge.
//!
//! ## Status
//!
//! End-to-end working for power-of-two `M, N`. The R1CS struct is dense for
//! now (sparse matrices land in a follow-on); the sumcheck backend already
//! streams the hypercube, so the dominant memory is the witness/matrix
//! storage, not the prover working set.
//!
//! ## Surface stability
//!
//! `R1cs`, `prove_r1cs`, `verify_r1cs`, and the `R1csProof` envelope are the
//! long-term contract. Sparse-matrix variants will plug in via a trait the
//! current dense `R1cs` already satisfies.

pub mod eq;
pub mod prove;
pub mod r1cs;
pub mod sparse;

pub use eq::{eq_poly, eq_evaluations};
pub use prove::{prove_r1cs, verify_r1cs, HcSpartanConfig, R1csProof, R1csVerifyOutcome};
pub use r1cs::R1cs;
pub use sparse::{prove_sparse_r1cs, verify_sparse_r1cs, SparseMatrix, SparseR1cs};
