//! The equality polynomial `eq_τ(x)` and its dense multilinear extension.
//!
//! For a parameter point `τ ∈ F^n`, the equality polynomial is
//!
//! ```text
//!     eq_τ(x) = ∏_{i=0..n-1} (τ_i · x_i + (1 - τ_i)(1 - x_i))
//! ```
//!
//! It is the multilinear polynomial that interpolates the indicator
//! function of "x equals τ" on the boolean hypercube. For any boolean
//! point `b ∈ {0,1}^n`,
//!
//! ```text
//!     eq_τ(b) = ∏ τ_i^{b_i} · (1 - τ_i)^{1 - b_i}
//! ```
//!
//! In Spartan it serves as the "where on the hypercube does the verifier
//! probe?" coupon — by Schwartz–Zippel, if the prover's claim
//! `Σ_x eq_τ(x) · h(x) = 0` holds for random τ then `h ≡ 0` on `{0,1}^n`
//! with overwhelming probability.

use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use hc_sumcheck::MultilinearPoly;

/// Evaluate `eq_τ` at every boolean point of `{0,1}^n`. Variable order is
/// little-endian: bit `b` of the index corresponds to variable `b`.
///
/// Output length is `2^n`. Computation is `O(n · 2^n)` field ops; memory is
/// the output vector.
pub fn eq_evaluations(tau: &[F]) -> HcResult<Vec<F>> {
    let n = tau.len();
    if n == 0 {
        return Ok(vec![F::ONE]);
    }
    let len = 1usize << n;
    let mut out = vec![F::ONE; len];
    // Build incrementally: after processing variable i, every entry holds
    // ∏_{j<=i} (τ_j if bit_j else (1 - τ_j)).
    for (i, &t) in tau.iter().enumerate() {
        let one_minus_t = F::ONE.sub(t);
        let stride = 1usize << i;
        // Iterate output in pairs (low, low + stride): low gets multiplied by
        // (1 - τ_i), high gets multiplied by τ_i.
        let mut base = 0;
        while base < len {
            for j in 0..stride {
                let lo_idx = base + j;
                let hi_idx = lo_idx + stride;
                let lo_val = out[lo_idx];
                let hi_val = out[hi_idx];
                out[lo_idx] = lo_val.mul(one_minus_t);
                out[hi_idx] = hi_val.mul(t);
            }
            base += 2 * stride;
        }
    }
    Ok(out)
}

/// Build the [`MultilinearPoly`] representation of `eq_τ`.
pub fn eq_poly(tau: &[F]) -> HcResult<MultilinearPoly> {
    let evals = eq_evaluations(tau)?;
    MultilinearPoly::new(tau.len(), evals)
}

/// Evaluate `eq_τ` at an arbitrary field point — closed-form, no table
/// materialization. Equivalent to `eq_poly(τ).evaluate_at(point)` but
/// `O(n)` instead of `O(2^n)`.
pub fn eq_at_field_point(tau: &[F], point: &[F]) -> HcResult<F> {
    if tau.len() != point.len() {
        return Err(HcError::invalid_argument(format!(
            "eq_at_field_point: dim mismatch τ={}, point={}",
            tau.len(),
            point.len()
        )));
    }
    let mut acc = F::ONE;
    for (&t, &x) in tau.iter().zip(point.iter()) {
        // eq_i = t·x + (1-t)·(1-x)
        let term = t.mul(x).add(F::ONE.sub(t).mul(F::ONE.sub(x)));
        acc = acc.mul(term);
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_zero_vars_is_one() {
        let v = eq_evaluations(&[]).unwrap();
        assert_eq!(v, vec![F::ONE]);
    }

    #[test]
    fn eq_one_var_at_boolean_recovers_indicator() {
        // For τ = [1], eq([0]) = 0, eq([1]) = 1.
        let v = eq_evaluations(&[F::ONE]).unwrap();
        assert_eq!(v, vec![F::ZERO, F::ONE]);
        // For τ = [0], eq([0]) = 1, eq([1]) = 0.
        let v = eq_evaluations(&[F::ZERO]).unwrap();
        assert_eq!(v, vec![F::ONE, F::ZERO]);
    }

    #[test]
    fn eq_two_vars_at_arbitrary_tau_sums_to_one() {
        // For any τ over the hypercube, Σ_x eq_τ(x) = 1.
        let tau = vec![F::new(7), F::new(11)];
        let v = eq_evaluations(&tau).unwrap();
        let mut s = F::ZERO;
        for &e in &v {
            s = s.add(e);
        }
        assert_eq!(s, F::ONE);
    }

    #[test]
    fn eq_at_field_point_matches_polynomial() {
        // eq_poly(τ).evaluate_at(point) == eq_at_field_point(τ, point).
        let tau = vec![F::new(3), F::new(5), F::new(7)];
        let point = vec![F::new(11), F::new(13), F::new(17)];
        let p = eq_poly(&tau).unwrap();
        let via_poly = p.evaluate_at(&point).unwrap();
        let direct = eq_at_field_point(&tau, &point).unwrap();
        assert_eq!(via_poly, direct);
    }

    #[test]
    fn eq_at_boolean_index_matches_table() {
        let tau = vec![F::new(3), F::new(5), F::new(7)];
        let table = eq_evaluations(&tau).unwrap();
        for idx in 0..(1u64 << 3) {
            let pt: Vec<F> = (0..3).map(|b| F::new((idx >> b) & 1)).collect();
            let direct = eq_at_field_point(&tau, &pt).unwrap();
            assert_eq!(direct, table[idx as usize]);
        }
    }
}
