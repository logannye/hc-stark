//! Multilinear extension trait + a dummy implementation for tests.
//!
//! Downstream systems (Spartan, HyperPlonk, etc.) will provide their own
//! polynomial implementations — typically a small algebraic combination of
//! a handful of multilinear extensions of witness columns. The streaming
//! prover only ever touches the polynomial through this trait, so it never
//! needs to know how the values were produced.

use hc_core::HcResult;

/// A `n`-variate polynomial used as the body of a sumcheck claim.
///
/// The trait is intentionally minimal so different downstream systems can
/// plug in arbitrary algebraic combinations of multilinear extensions, low-
/// degree monomial polynomials, or AIR composition polynomials.
pub trait SumcheckPolynomial {
    /// Number of variables `n`. The polynomial is summed over `{0, 1}^n`.
    fn num_variables(&self) -> usize;

    /// Maximum total degree per variable in the round-univariate polynomials.
    /// Used by the verifier to size the round message.
    fn degree(&self) -> usize;

    /// Evaluate the polynomial at a tile of hypercube points.
    ///
    /// `prefix` is the variable assignment fixed by previous rounds; `tile`
    /// is the set of points on the current hypercube slice. The
    /// implementation should fill `out` with the polynomial value at each
    /// point.
    fn evaluate_on_slice(&self, prefix: &[u64], tile: &[Vec<u64>], out: &mut [u64])
        -> HcResult<()>;
}

/// A multilinear extension of a vector of evaluations on `{0,1}^n`.
///
/// Stored sparsely so that an `n=20` polynomial doesn't immediately consume
/// 8 MB of RAM in the test suite — only entries explicitly inserted are
/// kept. (Real implementations will replace this with a streaming variant.)
#[derive(Clone, Debug, Default)]
pub struct MultilinearExtension {
    pub num_vars: usize,
    /// Sparse map `index → value` over `{0,1}^n`.
    pub evaluations: std::collections::BTreeMap<u64, u64>,
}

impl MultilinearExtension {
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            evaluations: Default::default(),
        }
    }

    pub fn set(&mut self, index: u64, value: u64) {
        self.evaluations.insert(index, value);
    }
}

/// Dummy polynomial used by tests: returns 0 everywhere. Real implementations
/// (Spartan, HyperPlonk, etc.) live in their own crates.
#[derive(Clone, Debug)]
pub struct DummyPolynomial {
    pub num_vars: usize,
    pub deg: usize,
}

impl DummyPolynomial {
    pub fn new(num_vars: usize, deg: usize) -> Self {
        Self { num_vars, deg }
    }
}

impl SumcheckPolynomial for DummyPolynomial {
    fn num_variables(&self) -> usize {
        self.num_vars
    }

    fn degree(&self) -> usize {
        self.deg
    }

    fn evaluate_on_slice(
        &self,
        _prefix: &[u64],
        tile: &[Vec<u64>],
        out: &mut [u64],
    ) -> HcResult<()> {
        for (i, _) in tile.iter().enumerate() {
            if i < out.len() {
                out[i] = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_polynomial_metadata() {
        let p = DummyPolynomial::new(10, 3);
        assert_eq!(p.num_variables(), 10);
        assert_eq!(p.degree(), 3);
    }

    #[test]
    fn dummy_polynomial_evaluates_to_zero() {
        let p = DummyPolynomial::new(2, 1);
        let tile = vec![vec![0, 0], vec![0, 1]];
        let mut out = vec![1u64; 2];
        p.evaluate_on_slice(&[], &tile, &mut out).unwrap();
        assert_eq!(out, vec![0, 0]);
    }
}
