//! R1CS instance: dense matrices `A, B, C ∈ F^{M×N}` and witness `w ∈ F^N`.
//!
//! Both `M` (number of constraints) and `N` (witness length) must be powers
//! of two so the multilinear-extension hypercubes are clean. Padding to
//! the next power of two is the caller's responsibility — pad `A, B, C`
//! with zero rows/columns and `w` with zeros.

use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_sumcheck::MultilinearPoly;

/// A dense R1CS instance.
#[derive(Clone, Debug)]
pub struct R1cs {
    /// Number of constraints (rows of A, B, C). Must be a power of two.
    pub m: usize,
    /// Witness length / columns of A, B, C. Must be a power of two.
    pub n: usize,
    /// Row-major dense matrices, each of length `m * n`.
    pub a: Vec<F>,
    pub b: Vec<F>,
    pub c: Vec<F>,
    /// Witness vector of length `n`.
    pub w: Vec<F>,
}

impl R1cs {
    pub fn new(m: usize, n: usize, a: Vec<F>, b: Vec<F>, c: Vec<F>, w: Vec<F>) -> HcResult<Self> {
        if !m.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "R1cs: m must be a power of two, got {m}"
            )));
        }
        if !n.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "R1cs: n must be a power of two, got {n}"
            )));
        }
        let expect = m * n;
        if a.len() != expect || b.len() != expect || c.len() != expect {
            return Err(HcError::invalid_argument(format!(
                "R1cs: matrix lengths must equal m*n = {expect}; got A={}, B={}, C={}",
                a.len(),
                b.len(),
                c.len()
            )));
        }
        if w.len() != n {
            return Err(HcError::invalid_argument(format!(
                "R1cs: witness length must equal n = {n}, got {}",
                w.len()
            )));
        }
        Ok(Self { m, n, a, b, c, w })
    }

    /// `log_2(m)` — number of variables in the constraint-side hypercube.
    pub fn log_m(&self) -> usize {
        self.m.trailing_zeros() as usize
    }

    /// Compute the M-vector `A·w`.
    pub fn a_times_w(&self) -> Vec<F> {
        matvec(&self.a, &self.w, self.m, self.n)
    }

    /// Compute the M-vector `B·w`.
    pub fn b_times_w(&self) -> Vec<F> {
        matvec(&self.b, &self.w, self.m, self.n)
    }

    /// Compute the M-vector `C·w`.
    pub fn c_times_w(&self) -> Vec<F> {
        matvec(&self.c, &self.w, self.m, self.n)
    }

    /// Return `true` iff every constraint `(A·w)_i · (B·w)_i = (C·w)_i`
    /// holds. Useful for tests.
    pub fn is_satisfied(&self) -> bool {
        let aw = self.a_times_w();
        let bw = self.b_times_w();
        let cw = self.c_times_w();
        for i in 0..self.m {
            if aw[i].mul(bw[i]) != cw[i] {
                return false;
            }
        }
        true
    }

    /// Convert `Aw` to a multilinear polynomial over `{0,1}^{log m}`.
    pub fn aw_polynomial(&self) -> HcResult<MultilinearPoly> {
        MultilinearPoly::new(self.log_m(), self.a_times_w())
    }

    pub fn bw_polynomial(&self) -> HcResult<MultilinearPoly> {
        MultilinearPoly::new(self.log_m(), self.b_times_w())
    }

    pub fn cw_polynomial(&self) -> HcResult<MultilinearPoly> {
        MultilinearPoly::new(self.log_m(), self.c_times_w())
    }
}

fn matvec(matrix: &[F], vec: &[F], rows: usize, cols: usize) -> Vec<F> {
    let mut out = vec![F::ZERO; rows];
    for i in 0..rows {
        let row_base = i * cols;
        let mut acc = F::ZERO;
        for j in 0..cols {
            acc = acc.add(matrix[row_base + j].mul(vec[j]));
        }
        out[i] = acc;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a satisfied R1CS: constraint x · y = z, witness (x, y, z).
    /// m = 1 constraint, n = 4 witness elements (x, y, z, padding).
    /// Matrices encode the constraint a_0 = x, b_0 = y, c_0 = z.
    fn xyz_instance(x: u64, y: u64) -> R1cs {
        let z = x * y;
        let m = 1usize;
        let n = 4usize;
        // A row: [0, 1, 0, 0]  → A·w = w[1] = x
        // B row: [0, 0, 1, 0]  → B·w = w[2] = y
        // C row: [0, 0, 0, 1]  → C·w = w[3] = z
        let mut a = vec![F::ZERO; m * n];
        let mut b = vec![F::ZERO; m * n];
        let mut c = vec![F::ZERO; m * n];
        a[1] = F::ONE; // pick up x at column 1
        b[2] = F::ONE; // pick up y at column 2
        c[3] = F::ONE; // pick up z at column 3
        let w = vec![F::ONE, F::new(x), F::new(y), F::new(z)];
        R1cs::new(m, n, a, b, c, w).unwrap()
    }

    #[test]
    fn rejects_non_pot_dimensions() {
        let r = R1cs::new(
            3,
            4,
            vec![F::ZERO; 12],
            vec![F::ZERO; 12],
            vec![F::ZERO; 12],
            vec![F::ZERO; 4],
        );
        assert!(r.is_err());
    }

    #[test]
    fn xyz_instance_satisfies() {
        let r = xyz_instance(7, 11);
        assert!(r.is_satisfied());
    }

    #[test]
    fn xyz_instance_unsatisfies_when_z_wrong() {
        let mut r = xyz_instance(7, 11);
        // Corrupt z.
        r.w[3] = F::new(99);
        assert!(!r.is_satisfied());
    }

    #[test]
    fn aw_bw_cw_recover_constraint_values() {
        let r = xyz_instance(3, 4);
        let aw = r.a_times_w();
        let bw = r.b_times_w();
        let cw = r.c_times_w();
        assert_eq!(aw[0], F::new(3));
        assert_eq!(bw[0], F::new(4));
        assert_eq!(cw[0], F::new(12));
    }

    #[test]
    fn aw_polynomial_has_correct_arity() {
        let r = xyz_instance(2, 5);
        let p = r.aw_polynomial().unwrap();
        assert_eq!(p.num_vars, 0); // log m = log 1 = 0
        assert_eq!(p.evaluations.len(), 1);
        assert_eq!(p.evaluations[0], F::new(2));
    }
}
