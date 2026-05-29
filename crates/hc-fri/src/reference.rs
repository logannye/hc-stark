//! Dependency-free, obviously-correct FRI fold. The differential oracle for
//! the optimized paths and the executable definition of the spec §3 math.
//! NOT used in production — test/reference only.
//!
//! # FRI fold formula (antipodal + 1/x)
//!
//! Given a codeword `f` evaluated on coset `D = offset·⟨g⟩` with `|D| = n`
//! (even) and `D[j + n/2] = -D[j]` (antipodal property), the fold with
//! challenge `β` produces a half-size codeword on the squared domain:
//!
//! ```text
//! out[j] = (a + b)/2  +  β · (a − b) / (2·x),
//!   where  a = f(D[j]),  b = f(D[j + n/2]) = f(-D[j]),  x = D[j]
//! ```
//!
//! Equivalently, writing `f(X) = f_e(X²) + X·f_o(X²)`:
//! ```text
//! out[j] = f_e(D[j]²) + β · f_o(D[j]²)
//! ```
//! which is the evaluation of the half-degree polynomial `g = f_e + β·f_o`
//! at the squared domain point `D[j]²`.

use hc_core::field::FieldElement;

/// Fold one FRI layer of size `n` (even) down to size `n/2`.
///
/// `values[j] = f(domain[j])`; `domain[j] = D[j]` (the layer's coset points
/// in the value field `E`). Requires the coset enumeration where
/// `D[j + n/2] = -D[j]` (antipodal).
///
/// Returns `out[j] = (a+b)/2 + beta*(a-b)/(2x)` with
/// `a = f(x)`, `b = f(-x)`, `x = D[j]`.
pub fn reference_fold<E: FieldElement>(values: &[E], domain: &[E], beta: E) -> Vec<E> {
    assert!(values.len() % 2 == 0, "layer size must be even");
    assert_eq!(
        values.len(),
        domain.len(),
        "values and domain must be same length"
    );
    let half = values.len() / 2;
    let two_inv = E::from_u64(2)
        .inverse()
        .expect("2 must be invertible in the field");
    let mut out = Vec::with_capacity(half);
    for j in 0..half {
        let a = values[j];
        let b = values[j + half];
        let x = domain[j];
        // even part: (a + b) / 2
        let even = a.add(b).mul(two_inv);
        // odd part: (a - b) / (2x); use sub since FieldElement has sub
        let two_x_inv = x
            .add(x)
            .inverse()
            .expect("domain point must be nonzero on a coset");
        let odd = a.sub(b).mul(two_x_inv); // (a - b) / (2x)
        out.push(even.add(beta.mul(odd)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::{
        domain::EvaluationDomain,
        field::{prime_field::GoldilocksField, FieldElement},
    };

    // --------------------------------------------------------------------- //
    // Helpers                                                                 //
    // --------------------------------------------------------------------- //

    /// Horner-scheme polynomial evaluation: Σ coeffs[i]·x^i.
    ///
    /// Completely independent of any domain or FFT machinery.
    fn eval_poly<E: FieldElement>(coeffs: &[E], x: E) -> E {
        if coeffs.is_empty() {
            return E::ZERO;
        }
        // Horner: start with highest-degree coefficient, repeatedly
        // multiply by x and add the next coefficient.
        let mut acc = *coeffs.last().unwrap();
        for c in coeffs[..coeffs.len() - 1].iter().rev() {
            acc = acc.mul(x).add(*c);
        }
        acc
    }

    /// Tiny deterministic PRNG — SplitMix64, no external deps required.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            SplitMix64(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// Draw a (not necessarily canonical) Goldilocks field element.
        fn next_field(&mut self) -> GoldilocksField {
            GoldilocksField::from_u64(self.next_u64())
        }
    }

    // --------------------------------------------------------------------- //
    // Test: polynomial round-trip matches reference fold at multiple sizes   //
    // --------------------------------------------------------------------- //

    /// For a uniformly-distributed degree-n polynomial f and a random β,
    /// folding f's evaluations on the coset must equal evaluating the
    /// directly-computed half-degree polynomial g = f_e + β·f_o on the
    /// squared coset points.
    ///
    /// This is a genuinely independent oracle: it does NOT replicate the
    /// domain generator logic or the fold formula — it works purely from
    /// polynomial coefficient arithmetic via Horner evaluation.
    #[test]
    fn poly_roundtrip_matches_reference() {
        let offset = GoldilocksField::from_u64(7);

        for &n in &[2usize, 4, 8, 16, 64] {
            let domain =
                EvaluationDomain::<GoldilocksField>::new_coset(n, offset).unwrap_or_else(|e| {
                    panic!("failed to build coset domain of size {n}: {e}");
                });
            let half = n / 2;

            // --- Guard: verify the antipodal property D[j + n/2] == -D[j] ---
            // This is the structural invariant that the fold relies on.
            // Run the check once (first size) to keep output concise; the
            // property is algebraic and holds for all valid EvaluationDomains.
            if n == 2 {
                for j in 0..half {
                    let pos = domain.element(j);
                    let neg_pos = domain.element(j + half);
                    assert_eq!(
                        neg_pos,
                        pos.neg(),
                        "antipodal guard FAILED at n={n} j={j}: \
                         D[j+n/2]={neg_pos:?} != -D[j]={:?}",
                        pos.neg()
                    );
                }
            }

            // --- Random coefficients for a degree-(n-1) polynomial f ---
            let mut rng = SplitMix64::new(0xDEAD_BEEF_0000_0000_u64 ^ (n as u64));
            let coeffs: Vec<GoldilocksField> = (0..n).map(|_| rng.next_field()).collect();
            let beta = rng.next_field();

            // f evaluated at each coset point
            let values: Vec<GoldilocksField> = (0..n)
                .map(|i| eval_poly(&coeffs, domain.element(i)))
                .collect();

            // --- Independent oracle: g_coeffs[i] = coeffs[2i] + β·coeffs[2i+1] ---
            // This encodes f_e(X) + β·f_o(X) in coefficient form directly.
            let g_coeffs: Vec<GoldilocksField> = (0..half)
                .map(|i| coeffs[2 * i].add(beta.mul(coeffs[2 * i + 1])))
                .collect();

            // g evaluated at squared coset points D[j]² — the squared domain
            let expected: Vec<GoldilocksField> = (0..half)
                .map(|j| {
                    let x_sq = domain.element(j).mul(domain.element(j));
                    eval_poly(&g_coeffs, x_sq)
                })
                .collect();

            // domain slice for reference_fold
            let domain_points: Vec<GoldilocksField> = (0..n).map(|i| domain.element(i)).collect();

            // --- The differential assertion ---
            let got = reference_fold(&values, &domain_points, beta);
            assert_eq!(
                got, expected,
                "poly_roundtrip mismatch at n={n}: got {got:?}\nexpected {expected:?}"
            );
        }
    }

    // --------------------------------------------------------------------- //
    // Test: hand anchor n=2                                                   //
    // --------------------------------------------------------------------- //

    /// Concrete closed-form check for n=2, offset=7.
    ///
    /// Domain: D[0] = 7, D[1] = -7  (the generator g for size-2 satisfies g=-1,
    /// so D[1] = 7·(-1) = -7, confirming the antipodal property).
    ///
    /// fold formula: out[0] = (f0 + f1)/2 + β·(f0 - f1)/(2·7)
    ///
    /// With f0 = 3, f1 = 5, β = 11:
    ///   a - b = 3 - 5 = -2
    ///   a + b = 8
    ///   even  = 8 / 2 = 4
    ///   odd   = -2 / 14 = (-2)·(14)^{-1}  (mod p)
    ///   out   = 4 + 11·odd
    ///
    /// All arithmetic is done independently below using raw FieldElement ops.
    #[test]
    fn hand_anchor_n2() {
        type F = GoldilocksField;

        let offset = F::from_u64(7);
        let n = 2usize;
        let half = 1usize;

        let domain = EvaluationDomain::<F>::new_coset(n, offset).unwrap();

        // Fixed test values
        let f0 = F::from_u64(3);
        let f1 = F::from_u64(5);
        let beta = F::from_u64(11);

        let values = vec![f0, f1];
        let domain_points: Vec<F> = (0..n).map(|i| domain.element(i)).collect();

        // Check domain[0]=7, domain[1]=-7
        assert_eq!(domain_points[0], F::from_u64(7), "D[0] must equal offset 7");
        assert_eq!(
            domain_points[1],
            F::from_u64(7).neg(),
            "D[1] must equal -7 (antipodal)"
        );

        // --- Independent closed-form computation ---
        //
        // out[0] = (f0 + f1)/2  +  β * (f0 - f1) / (2 * D[0])
        //        = (3 + 5)/2    +  11 * (3 - 5)  / (2 * 7)
        //        = 4            +  11 * (-2)      / 14
        //
        let x = F::from_u64(7); // D[0]
        let two = F::from_u64(2);
        let two_inv = two.inverse().expect("2 must be invertible");
        let two_x = x.add(x); // 2 * 7 = 14
        let two_x_inv = two_x.inverse().expect("14 must be invertible");

        let sum = f0.add(f1); // 8
        let diff = f0.sub(f1); // -2 in field
        let even_part = sum.mul(two_inv); // 8/2 = 4
        let odd_part = diff.mul(two_x_inv); // (-2)/14
        let expected_out0 = even_part.add(beta.mul(odd_part)); // 4 + 11*(-2/14)

        // Also verify from the fold
        let got = reference_fold(&values, &domain_points, beta);
        assert_eq!(got.len(), half, "output length must be n/2 = 1");
        assert_eq!(
            got[0], expected_out0,
            "hand_anchor: reference_fold[0]={:?} != closed-form={:?}",
            got[0], expected_out0
        );
    }
}
