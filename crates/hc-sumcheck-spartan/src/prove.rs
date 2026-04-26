//! Spartan-style R1CS prover and verifier — see crate-level docs.

use crate::eq::{eq_at_field_point, eq_poly};
use crate::r1cs::R1cs;
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_hash::{Blake3, HashFunction};
use hc_sumcheck::{
    prove_linear_product, verify_protocol_general, LinearProductPoly, SumcheckClaim, SumcheckProof,
    Term,
};
use serde::{Deserialize, Serialize};

/// R1CS proof envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R1csProof {
    pub version: u8,
    pub r1cs_digest: [u8; 32],
    pub tau: Vec<u64>,
    pub sumcheck: SumcheckProof,
    pub aw_at_r: u64,
    pub bw_at_r: u64,
    pub cw_at_r: u64,
}

impl R1csProof {
    pub const VERSION: u8 = 1;
}

/// Verifier outcome.
#[derive(Clone, Debug)]
pub struct R1csVerifyOutcome {
    pub challenges: Vec<F>,
    pub sumcheck_consistent: bool,
    pub final_bind_holds: bool,
}

impl R1csVerifyOutcome {
    pub fn accepted(&self) -> bool {
        self.sumcheck_consistent && self.final_bind_holds
    }
}

/// Tunables.
#[derive(Clone, Debug, Default)]
pub struct HcSpartanConfig {
    pub sumcheck: hc_sumcheck::HcSumcheckConfig,
}

/// Prove a satisfied R1CS instance.
pub fn prove_r1cs(r1cs: &R1cs, tau: &[F], config: &HcSpartanConfig) -> HcResult<R1csProof> {
    if tau.len() != r1cs.log_m() {
        return Err(HcError::invalid_argument(format!(
            "prove_r1cs: |tau| = {} must equal log_2 m = {}",
            tau.len(),
            r1cs.log_m()
        )));
    }
    if !r1cs.is_satisfied() {
        return Err(HcError::invalid_argument(
            "prove_r1cs: R1CS instance is not satisfied",
        ));
    }

    let aw = r1cs.aw_polynomial()?;
    let bw = r1cs.bw_polynomial()?;
    let cw = r1cs.cw_polynomial()?;
    let eq = eq_poly(tau)?;

    let term_pos = Term::new(F::ONE, vec![eq.clone(), aw.clone(), bw.clone()])?;
    let neg_one = F::ZERO.sub(F::ONE);
    let term_neg = Term::new(neg_one, vec![eq.clone(), cw.clone()])?;
    let poly = LinearProductPoly::new(vec![term_pos, term_neg])?;

    let total = poly.total_sum().0;
    if total != 0 {
        return Err(HcError::math(format!(
            "prove_r1cs internal: total sum should be 0 for a satisfied instance; got {total}"
        )));
    }
    let claim = SumcheckClaim::new(r1cs.log_m(), poly.degree(), total);

    let (sumcheck, challenges) = prove_linear_product(&poly, &claim, &config.sumcheck)?;

    let aw_at_r = aw.evaluate_at(&challenges)?;
    let bw_at_r = bw.evaluate_at(&challenges)?;
    let cw_at_r = cw.evaluate_at(&challenges)?;

    Ok(R1csProof {
        version: R1csProof::VERSION,
        r1cs_digest: r1cs_digest(r1cs),
        tau: tau.iter().map(|t| t.0).collect(),
        sumcheck,
        aw_at_r: aw_at_r.0,
        bw_at_r: bw_at_r.0,
        cw_at_r: cw_at_r.0,
    })
}

/// Verify an R1CS proof.
pub fn verify_r1cs(
    r1cs: &R1cs,
    proof: &R1csProof,
    config: &HcSpartanConfig,
) -> HcResult<R1csVerifyOutcome> {
    if proof.version != R1csProof::VERSION {
        return Err(HcError::invalid_argument(format!(
            "unsupported R1cs proof version {}",
            proof.version
        )));
    }
    let expected_digest = r1cs_digest(r1cs);
    if expected_digest != proof.r1cs_digest {
        return Err(HcError::invalid_argument("R1cs digest mismatch"));
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

fn r1cs_digest(r1cs: &R1cs) -> [u8; 32] {
    let mut payload: Vec<u8> = Vec::with_capacity(1 + 16 + 24 * r1cs.m * r1cs.n);
    payload.extend_from_slice(b"hc-spartan/r1cs/v1");
    payload.extend_from_slice(&(r1cs.m as u64).to_le_bytes());
    payload.extend_from_slice(&(r1cs.n as u64).to_le_bytes());
    for v in r1cs.a.iter().chain(r1cs.b.iter()).chain(r1cs.c.iter()) {
        payload.extend_from_slice(&v.0.to_le_bytes());
    }
    Blake3::hash(&payload).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_sumcheck::HcSumcheckConfig;

    fn parallel_xyz_instance(seed: u64) -> R1cs {
        let m = 4usize;
        let n = 16usize;
        let mut a = vec![F::ZERO; m * n];
        let mut b = vec![F::ZERO; m * n];
        let mut c = vec![F::ZERO; m * n];
        let mut w = vec![F::ONE; n];
        let mut x = seed;
        for i in 0..m {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let xi = (x % 17) + 1;
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let yi = (x % 19) + 1;
            let zi = xi * yi;
            let xj = 1 + 3 * i;
            let yj = 2 + 3 * i;
            let zj = 3 + 3 * i;
            assert!(zj < n);
            w[xj] = F::new(xi);
            w[yj] = F::new(yi);
            w[zj] = F::new(zi);
            a[i * n + xj] = F::ONE;
            b[i * n + yj] = F::ONE;
            c[i * n + zj] = F::ONE;
        }
        R1cs::new(m, n, a, b, c, w).unwrap()
    }

    #[test]
    fn parallel_instance_is_satisfied() {
        let r = parallel_xyz_instance(42);
        assert!(r.is_satisfied());
    }

    #[test]
    fn prove_and_verify_roundtrip_satisfied_instance() {
        let r = parallel_xyz_instance(123);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(7 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let proof = prove_r1cs(&r, &tau, &cfg).unwrap();
        let outcome = verify_r1cs(&r, &proof, &cfg).unwrap();
        assert!(outcome.accepted());
    }

    #[test]
    fn prover_rejects_unsatisfied_instance() {
        let mut r = parallel_xyz_instance(7);
        r.w[3] = F::new(99);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(3 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let err = prove_r1cs(&r, &tau, &cfg).unwrap_err();
        assert!(format!("{err}").contains("not satisfied"));
    }

    #[test]
    fn verify_rejects_tampered_aw_value() {
        let r = parallel_xyz_instance(99);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(2 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let mut proof = prove_r1cs(&r, &tau, &cfg).unwrap();
        proof.aw_at_r = proof.aw_at_r.wrapping_add(1);
        let outcome = verify_r1cs(&r, &proof, &cfg).unwrap();
        assert!(!outcome.accepted());
        assert!(!outcome.final_bind_holds);
    }

    #[test]
    fn verify_rejects_tampered_sumcheck_round() {
        let r = parallel_xyz_instance(55);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(5 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let mut proof = prove_r1cs(&r, &tau, &cfg).unwrap();
        proof.sumcheck.rounds[0].coefficients[1] =
            proof.sumcheck.rounds[0].coefficients[1].wrapping_add(1);
        let outcome = verify_r1cs(&r, &proof, &cfg).unwrap();
        assert!(!outcome.sumcheck_consistent);
    }

    #[test]
    fn verify_rejects_wrong_r1cs_instance() {
        // Two instances with *different matrices* must have different digests.
        // (The witness alone does not enter the digest; that's the job of a
        //  polynomial-commitment binding, which lands in a follow-on PR.)
        let r1 = parallel_xyz_instance(101);
        let mut r2 = parallel_xyz_instance(202);
        // Mutate one matrix entry so r2 has a different architecture digest.
        r2.a[0] = r2.a[0].add(F::ONE);
        let tau: Vec<F> = (0..r1.log_m()).map(|i| F::new(2 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let proof = prove_r1cs(&r1, &tau, &cfg).unwrap();
        let err = verify_r1cs(&r2, &proof, &cfg).unwrap_err();
        assert!(format!("{err}").contains("digest mismatch"));
    }

    #[test]
    fn determinism_same_inputs_same_proof() {
        let r = parallel_xyz_instance(77);
        let tau: Vec<F> = (0..r.log_m()).map(|i| F::new(9 + i as u64)).collect();
        let cfg = HcSpartanConfig::default();
        let p1 = prove_r1cs(&r, &tau, &cfg).unwrap();
        let p2 = prove_r1cs(&r, &tau, &cfg).unwrap();
        assert_eq!(p1.aw_at_r, p2.aw_at_r);
        assert_eq!(p1.bw_at_r, p2.bw_at_r);
        assert_eq!(p1.cw_at_r, p2.cw_at_r);
        assert_eq!(p1.sumcheck.final_evaluation, p2.sumcheck.final_evaluation);
    }

    #[test]
    fn handles_single_constraint_instance() {
        let m = 1usize;
        let n = 4usize;
        let mut a = vec![F::ZERO; m * n];
        let mut b = vec![F::ZERO; m * n];
        let mut c = vec![F::ZERO; m * n];
        a[1] = F::ONE;
        b[2] = F::ONE;
        c[3] = F::ONE;
        let w = vec![F::ONE, F::new(7), F::new(11), F::new(77)];
        let r = R1cs::new(m, n, a, b, c, w).unwrap();
        let tau: Vec<F> = vec![];
        let cfg = HcSpartanConfig {
            sumcheck: HcSumcheckConfig::default(),
        };
        let proof = prove_r1cs(&r, &tau, &cfg).unwrap();
        assert_eq!(proof.sumcheck.rounds.len(), 0);
        let outcome = verify_r1cs(&r, &proof, &cfg).unwrap();
        assert!(outcome.accepted());
    }
}
