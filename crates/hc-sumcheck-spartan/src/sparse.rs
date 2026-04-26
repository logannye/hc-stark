//! Sparse R1CS — production-readiness backend for large circuits.
//!
//! ## Why a sparse representation
//!
//! The dense [`crate::r1cs::R1cs`] caps at `m·n ≤ 2^18` for tractable RAM.
//! Real R1CS instances coming out of frontend compilers (Circom, Noir,
//! Halo2 lowering, gnark) routinely have `m, n` in the `10^5` to `10^7`
//! range with each row carrying `O(1)` non-zeros, so dense storage would
//! burn petabytes while the actual non-zero count is often `≤ 10·m`.
//!
//! ## What this module provides
//!
//! - [`SparseMatrix`] — coordinate-form (COO) `(row, col, value)` triples.
//! - [`SparseR1cs`] — the sparse analogue of dense `R1cs`.
//! - Methods to compute `Aw, Bw, Cw` in `O(non_zeros)` rather than
//!   `O(m·n)`.
//! - [`prove_sparse_r1cs`] — entry point that reuses the existing
//!   sumcheck plumbing.

use crate::eq::{eq_at_field_point, eq_poly};
use crate::prove::{HcSpartanConfig, R1csProof, R1csVerifyOutcome};
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, HashFunction};
use hc_sumcheck::{
    prove_linear_product, verify_protocol_general, LinearProductPoly, MultilinearPoly,
    SumcheckClaim, Term,
};

/// Coordinate-form sparse matrix. Triples need not be unique nor sorted;
/// duplicates are summed by [`SparseMatrix::canonicalize`].
#[derive(Clone, Debug, Default)]
pub struct SparseMatrix {
    pub rows: usize,
    pub cols: usize,
    pub triples: Vec<(usize, usize, F)>,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize, triples: Vec<(usize, usize, F)>) -> HcResult<Self> {
        for (idx, (r, c, _)) in triples.iter().enumerate() {
            if *r >= rows || *c >= cols {
                return Err(HcError::invalid_argument(format!(
                    "SparseMatrix triple {idx}: ({r}, {c}) outside ({rows}, {cols})"
                )));
            }
        }
        Ok(Self { rows, cols, triples })
    }

    /// Multiply by a vector: `M · w` in `O(non_zeros)`.
    pub fn matvec(&self, w: &[F]) -> HcResult<Vec<F>> {
        if w.len() != self.cols {
            return Err(HcError::invalid_argument(format!(
                "SparseMatrix::matvec: w len {} != cols {}",
                w.len(),
                self.cols
            )));
        }
        let mut out = vec![F::ZERO; self.rows];
        for (r, c, v) in &self.triples {
            out[*r] = out[*r].add(v.mul(w[*c]));
        }
        Ok(out)
    }

    pub fn nnz(&self) -> usize {
        self.triples.len()
    }

    /// Canonicalize: sort by (row, col), combine duplicates, drop zeros.
    pub fn canonicalize(&self) -> Vec<(usize, usize, F)> {
        let mut sorted = self.triples.clone();
        sorted.sort_by_key(|(r, c, _)| (*r, *c));
        let mut out: Vec<(usize, usize, F)> = Vec::with_capacity(sorted.len());
        for (r, c, v) in sorted {
            if let Some(last) = out.last_mut() {
                if last.0 == r && last.1 == c {
                    last.2 = last.2.add(v);
                    continue;
                }
            }
            out.push((r, c, v));
        }
        out.retain(|(_, _, v)| *v != F::ZERO);
        out
    }
}

/// Sparse R1CS instance.
#[derive(Clone, Debug)]
pub struct SparseR1cs {
    pub m: usize,
    pub n: usize,
    pub a: SparseMatrix,
    pub b: SparseMatrix,
    pub c: SparseMatrix,
    pub w: Vec<F>,
}

impl SparseR1cs {
    pub fn new(
        m: usize,
        n: usize,
        a: SparseMatrix,
        b: SparseMatrix,
        c: SparseMatrix,
        w: Vec<F>,
    ) -> HcResult<Self> {
        if !m.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "SparseR1cs: m must be a power of two, got {m}"
            )));
        }
        if !n.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "SparseR1cs: n must be a power of two, got {n}"
            )));
        }
        for (label, mat) in [("A", &a), ("B", &b), ("C", &c)] {
            if mat.rows != m || mat.cols != n {
                return Err(HcError::invalid_argument(format!(
                    "SparseR1cs: matrix {label} dimensions ({}, {}) != ({m}, {n})",
                    mat.rows, mat.cols
                )));
            }
        }
        if w.len() != n {
            return Err(HcError::invalid_argument(format!(
                "SparseR1cs: witness length {} != n = {n}",
                w.len()
            )));
        }
        Ok(Self { m, n, a, b, c, w })
    }

    pub fn log_m(&self) -> usize {
        self.m.trailing_zeros() as usize
    }

    pub fn a_times_w(&self) -> HcResult<Vec<F>> {
        self.a.matvec(&self.w)
    }
    pub fn b_times_w(&self) -> HcResult<Vec<F>> {
        self.b.matvec(&self.w)
    }
    pub fn c_times_w(&self) -> HcResult<Vec<F>> {
        self.c.matvec(&self.w)
    }

    pub fn is_satisfied(&self) -> HcResult<bool> {
        let aw = self.a_times_w()?;
        let bw = self.b_times_w()?;
        let cw = self.c_times_w()?;
        for i in 0..self.m {
            if aw[i].mul(bw[i]) != cw[i] {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Domain-separated digest of a sparse R1CS architecture.
fn sparse_r1cs_digest(r1cs: &SparseR1cs) -> [u8; 32] {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"hc-spartan/sparse-r1cs/v1");
    payload.extend_from_slice(&(r1cs.m as u64).to_le_bytes());
    payload.extend_from_slice(&(r1cs.n as u64).to_le_bytes());
    for (label, mat) in [("A", &r1cs.a), ("B", &r1cs.b), ("C", &r1cs.c)] {
        payload.extend_from_slice(label.as_bytes());
        let canon = mat.canonicalize();
        payload.extend_from_slice(&(canon.len() as u64).to_le_bytes());
        for (r, c, v) in canon {
            payload.extend_from_slice(&(r as u64).to_le_bytes());
            payload.extend_from_slice(&(c as u64).to_le_bytes());
            payload.extend_from_slice(&v.0.to_le_bytes());
        }
    }
    Blake3::hash(&payload).to_bytes()
}

/// Prove a satisfied sparse R1CS instance. Mirror of
/// [`crate::prove::prove_r1cs`] for sparse matrices.
pub fn prove_sparse_r1cs(
    r1cs: &SparseR1cs,
    tau: &[F],
    config: &HcSpartanConfig,
) -> HcResult<R1csProof> {
    if tau.len() != r1cs.log_m() {
        return Err(HcError::invalid_argument(format!(
            "prove_sparse_r1cs: |tau| = {} must equal log_2 m = {}",
            tau.len(),
            r1cs.log_m()
        )));
    }
    if !r1cs.is_satisfied()? {
        return Err(HcError::invalid_argument(
            "prove_sparse_r1cs: R1CS instance is not satisfied",
        ));
    }

    let aw = MultilinearPoly::new(r1cs.log_m(), r1cs.a_times_w()?)?;
    let bw = MultilinearPoly::new(r1cs.log_m(), r1cs.b_times_w()?)?;
    let cw = MultilinearPoly::new(r1cs.log_m(), r1cs.c_times_w()?)?;
    let eq = eq_poly(tau)?;

    let term_pos = Term::new(F::ONE, vec![eq.clone(), aw.clone(), bw.clone()])?;
    let neg_one = F::ZERO.sub(F::ONE);
    let term_neg = Term::new(neg_one, vec![eq.clone(), cw.clone()])?;
    let poly = LinearProductPoly::new(vec![term_pos, term_neg])?;

    let total = poly.total_sum().0;
    if total != 0 {
        return Err(HcError::math(format!(
            "prove_sparse_r1cs internal: total sum should be 0; got {total}"
        )));
    }
    let claim = SumcheckClaim::new(r1cs.log_m(), poly.degree(), total);
    let (sumcheck, challenges) = prove_linear_product(&poly, &claim, &config.sumcheck)?;

    let aw_at_r = aw.evaluate_at(&challenges)?;
    let bw_at_r = bw.evaluate_at(&challenges)?;
    let cw_at_r = cw.evaluate_at(&challenges)?;

    Ok(R1csProof {
        version: R1csProof::VERSION,
        r1cs_digest: sparse_r1cs_digest(r1cs),
        tau: tau.iter().map(|t| t.0).collect(),
        sumcheck,
        aw_at_r: aw_at_r.0,
        bw_at_r: bw_at_r.0,
        cw_at_r: cw_at_r.0,
    })
}

/// Verify a sparse-R1CS proof against a reference instance.
pub fn verify_sparse_r1cs(
    r1cs: &SparseR1cs,
    proof: &R1csProof,
    config: &HcSpartanConfig,
) -> HcResult<R1csVerifyOutcome> {
    if proof.version != R1csProof::VERSION {
        return Err(HcError::invalid_argument(format!(
            "unsupported R1cs proof version {}",
            proof.version
        )));
    }
    let expected_digest = sparse_r1cs_digest(r1cs);
    if expected_digest != proof.r1cs_digest {
        return Err(HcError::invalid_argument(
            "Sparse R1cs digest mismatch",
        ));
    }
    if proof.tau.len() != r1cs.log_m() {
        return Err(HcError::invalid_argument(format!(
            "|tau| = {} does not match log_2 m = {}",
            proof.tau.len(),
            r1cs.log_m()
        )));
    }

    let claim = SumcheckClaim::new(r1cs.log_m(), 3, 0);
    let outcome = match verify_protocol_general(&claim, &proof.sumcheck, &config.sumcheck)? {
        Some(o) => o,
        None => {
            return Ok(R1csVerifyOutcome {
                challenges: vec![],
                sumcheck_consistent: false,
                final_bind_holds: false,
            })
        }
    };

    let tau: Vec<F> = proof.tau.iter().map(|&u| F::new(u)).collect();
    let eq_at_r = eq_at_field_point(&tau, &outcome.challenges)?;
    let aw_at_r = F::new(proof.aw_at_r);
    let bw_at_r = F::new(proof.bw_at_r);
    let cw_at_r = F::new(proof.cw_at_r);
    let lhs = eq_at_r.mul(aw_at_r.mul(bw_at_r).sub(cw_at_r));
    let final_bind_holds = lhs == outcome.final_evaluation;

    Ok(R1csVerifyOutcome {
        challenges: outcome.challenges,
        sumcheck_consistent: true,
        final_bind_holds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parallel_xyz_sparse(seed: u64) -> SparseR1cs {
        let m = 4usize;
        let n = 16usize;
        let mut a_triples = Vec::new();
        let mut b_triples = Vec::new();
        let mut c_triples = Vec::new();
        let mut w = vec![F::ONE; n];
        let mut x = seed;
        for i in 0..m {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let xi = (x % 17) + 1;
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let yi = (x % 19) + 1;
            let zi = xi * yi;
            let xj = 1 + 3 * i;
            let yj = 2 + 3 * i;
            let zj = 3 + 3 * i;
            assert!(zj < n);
            w[xj] = F::new(xi);
            w[yj] = F::new(yi);
            w[zj] = F::new(zi);
            a_triples.push((i, xj, F::ONE));
            b_triples.push((i, yj, F::ONE));
            c_triples.push((i, zj, F::ONE));
        }
        let a = SparseMatrix::new(m, n, a_triples).unwrap();
        let b = SparseMatrix::new(m, n, b_triples).unwrap();
        let c = SparseMatrix::new(m, n, c_triples).unwrap();
        SparseR1cs::new(m, n, a, b, c, w).unwrap()
    }

    #[test]
    fn sparse_matvec_matches_naive() {
        let m = 4usize;
        let n = 4usize;
        let triples = vec![
            (0, 0, F::new(1)),
            (0, 1, F::new(2)),
            (1, 2, F::new(3)),
            (3, 3, F::new(4)),
        ];
        let mat = SparseMatrix::new(m, n, triples).unwrap();
        let w = vec![F::new(10), F::new(20), F::new(30), F::new(40)];
        let got = mat.matvec(&w).unwrap();
        // row 0: 1*10 + 2*20 = 50
        // row 1: 3*30        = 90
        // row 2: 0
        // row 3: 4*40        = 160
        assert_eq!(got, vec![F::new(50), F::new(90), F::ZERO, F::new(160)]);
    }

    #[test]
    fn canonicalize_combines_duplicate_triples() {
        let m = 2usize;
        let n = 2usize;
        let triples = vec![
            (0, 0, F::new(3)),
            (0, 0, F::new(7)),
            (1, 1, F::new(5)),
        ];
        let mat = SparseMatrix::new(m, n, triples).unwrap();
        let canon = mat.canonicalize();
        assert_eq!(canon, vec![(0, 0, F::new(10)), (1, 1, F::new(5))]);
    }

    #[test]
    fn canonicalize_drops_zero_combined_triples() {
        let m = 1usize;
        let n = 1usize;
        let triples = vec![(0, 0, F::new(7)), (0, 0, F::ZERO.sub(F::new(7)))];
        let mat = SparseMatrix::new(m, n, triples).unwrap();
        assert!(mat.canonicalize().is_empty());
    }

    #[test]
    fn sparse_instance_is_satisfied() {
        let r = parallel_xyz_sparse(42);
        assert!(r.is_satisfied().unwrap());
    }

    #[test]
    fn prove_and_verify_sparse_roundtrip() {
        let r = parallel_xyz_sparse(123);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(7 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let proof = prove_sparse_r1cs(&r, &tau, &cfg).unwrap();
        let outcome = verify_sparse_r1cs(&r, &proof, &cfg).unwrap();
        assert!(outcome.accepted());
    }

    #[test]
    fn prove_sparse_rejects_unsatisfied() {
        let mut r = parallel_xyz_sparse(7);
        r.w[3] = F::new(99);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(3 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let err = prove_sparse_r1cs(&r, &tau, &cfg).unwrap_err();
        assert!(format!("{err}").contains("not satisfied"));
    }

    #[test]
    fn verify_sparse_rejects_tampered_eval() {
        let r = parallel_xyz_sparse(99);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(2 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let mut proof = prove_sparse_r1cs(&r, &tau, &cfg).unwrap();
        proof.aw_at_r = proof.aw_at_r.wrapping_add(1);
        let outcome = verify_sparse_r1cs(&r, &proof, &cfg).unwrap();
        assert!(!outcome.accepted());
    }

    #[test]
    fn verify_sparse_rejects_wrong_instance() {
        let r1 = parallel_xyz_sparse(101);
        let mut r2 = parallel_xyz_sparse(202);
        r2.a.triples.push((0, 0, F::new(13)));
        let tau: Vec<F> = (0..r1.log_m()).map(|i| F::new(2 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let proof = prove_sparse_r1cs(&r1, &tau, &cfg).unwrap();
        let err = verify_sparse_r1cs(&r2, &proof, &cfg).unwrap_err();
        assert!(format!("{err}").contains("digest mismatch"));
    }

    #[test]
    fn dense_and_sparse_digests_differ_for_same_matrices() {
        use crate::r1cs::R1cs;
        let m = 1;
        let n = 4;
        let mut a_dense = vec![F::ZERO; m * n];
        let mut b_dense = vec![F::ZERO; m * n];
        let mut c_dense = vec![F::ZERO; m * n];
        a_dense[1] = F::ONE;
        b_dense[2] = F::ONE;
        c_dense[3] = F::ONE;
        let w = vec![F::ONE, F::new(7), F::new(11), F::new(77)];
        let dense = R1cs::new(m, n, a_dense, b_dense, c_dense, w.clone()).unwrap();
        let a_sparse = SparseMatrix::new(m, n, vec![(0, 1, F::ONE)]).unwrap();
        let b_sparse = SparseMatrix::new(m, n, vec![(0, 2, F::ONE)]).unwrap();
        let c_sparse = SparseMatrix::new(m, n, vec![(0, 3, F::ONE)]).unwrap();
        let sparse = SparseR1cs::new(m, n, a_sparse, b_sparse, c_sparse, w).unwrap();
        let tau: Vec<F> = vec![];
        let cfg = HcSpartanConfig::default();
        let dense_proof = crate::prove::prove_r1cs(&dense, &tau, &cfg).unwrap();
        let sparse_proof = prove_sparse_r1cs(&sparse, &tau, &cfg).unwrap();
        assert_ne!(dense_proof.r1cs_digest, sparse_proof.r1cs_digest);
        assert!(crate::prove::verify_r1cs(&dense, &dense_proof, &cfg)
            .unwrap()
            .accepted());
        assert!(verify_sparse_r1cs(&sparse, &sparse_proof, &cfg)
            .unwrap()
            .accepted());
    }
}
