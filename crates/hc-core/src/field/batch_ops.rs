//! Batch field operations for high-throughput polynomial arithmetic.
//!
//! These routines operate on slices of field elements, enabling better
//! instruction-level parallelism and cache utilization compared to
//! element-at-a-time operations.
//!
//! # Parallelism
//!
//! Element-wise routines (`add_slices`, `mul_slices`, `add_assign_slices`,
//! ..., `linear_combination`, `butterfly_slice`) are **rayon-parallelized
//! above a length threshold** controlled by `PAR_THRESHOLD`. Below the
//! threshold the scalar path stays — rayon's worker-pool dispatch is
//! ~few-µs latency, which dominates a 256-element multiply.
//!
//! The reductions (`dot_product`, `batch_inverse`) keep their sequential
//! shape: `dot_product` is order-dependent under non-associative semantics
//! we don't want to assume the user accepts (Goldilocks `mul` is associative,
//! so this is conservative — tracked as a follow-up), and `batch_inverse`
//! has carry-style state across iterations that doesn't trivially
//! parallelize.

use super::FieldElement;
use rayon::prelude::*;

/// Below this slice length, the scalar path runs serially. Above it, rayon
/// dispatches across worker threads. The threshold is empirical: rayon's
/// fork/join cost is roughly equivalent to a few thousand u64 multiplies on
/// modern cores, so a 1024-element slice is the rough crossover where
/// parallelism stops being a slowdown.
const PAR_THRESHOLD: usize = 1024;

/// Montgomery's trick: compute the inverse of every element in `values` using
/// a single field inversion plus `3(n-1)` multiplications.
///
/// Returns `None` for any position whose element is zero; all other positions
/// receive the correct inverse.
pub fn batch_inverse<F: FieldElement>(values: &[F]) -> Vec<Option<F>> {
    let n = values.len();
    if n == 0 {
        return Vec::new();
    }

    // Phase 1: compute running products (prefix products, skipping zeros).
    let mut prefix = Vec::with_capacity(n);
    let mut acc = F::ONE;
    for &v in values {
        if v.is_zero() {
            prefix.push(F::ZERO);
        } else {
            acc = acc.mul(v);
            prefix.push(acc);
        }
    }

    // Single inversion of the accumulated product.
    let mut inv_acc = match acc.inverse() {
        Some(inv) => inv,
        None => return vec![None; n],
    };

    // Phase 2: propagate inverse backwards.
    let mut result = vec![None; n];
    for i in (0..n).rev() {
        if values[i].is_zero() {
            continue;
        }
        if i == 0 {
            result[i] = Some(inv_acc);
        } else {
            // The prefix up to i-1 (skipping zeros) gives us the product of
            // all non-zero elements before index i.
            let mut prev_prefix = prefix[i - 1];
            // If prefix[i-1] is zero, we need to find the last non-zero prefix.
            if prev_prefix.is_zero() {
                // Walk back to find the last non-zero prefix.
                let mut j = i - 1;
                while j > 0 && prefix[j].is_zero() {
                    j -= 1;
                }
                prev_prefix = if j == 0 && prefix[0].is_zero() {
                    F::ONE
                } else {
                    prefix[j]
                };
            }
            result[i] = Some(inv_acc.mul(prev_prefix));
        }
        inv_acc = inv_acc.mul(values[i]);
    }

    result
}

/// Batch inverse for a slice known to contain no zeros. Panics if any element
/// is zero.
pub fn batch_inverse_nonzero<F: FieldElement>(values: &[F]) -> Vec<F> {
    batch_inverse(values)
        .into_iter()
        .map(|opt| opt.expect("batch_inverse_nonzero: unexpected zero element"))
        .collect()
}

/// Element-wise addition: `out[i] = a[i] + b[i]`.
///
/// # Panics
/// Panics if `a` and `b` have different lengths.
#[inline]
pub fn add_slices<F: FieldElement>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len(), "add_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(&x, &y)| x.add(y))
            .collect()
    } else {
        a.iter().zip(b.iter()).map(|(&x, &y)| x.add(y)).collect()
    }
}

/// Element-wise subtraction: `out[i] = a[i] - b[i]`.
#[inline]
pub fn sub_slices<F: FieldElement>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len(), "sub_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(&x, &y)| x.sub(y))
            .collect()
    } else {
        a.iter().zip(b.iter()).map(|(&x, &y)| x.sub(y)).collect()
    }
}

/// Element-wise multiplication: `out[i] = a[i] * b[i]`.
#[inline]
pub fn mul_slices<F: FieldElement>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len(), "mul_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(&x, &y)| x.mul(y))
            .collect()
    } else {
        a.iter().zip(b.iter()).map(|(&x, &y)| x.mul(y)).collect()
    }
}

/// In-place element-wise addition: `a[i] += b[i]`.
#[inline]
pub fn add_assign_slices<F: FieldElement>(a: &mut [F], b: &[F]) {
    debug_assert_eq!(a.len(), b.len(), "add_assign_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter_mut().zip(b.par_iter()).for_each(|(x, &y)| {
            *x = x.add(y);
        });
    } else {
        for (x, &y) in a.iter_mut().zip(b.iter()) {
            *x = x.add(y);
        }
    }
}

/// In-place element-wise subtraction: `a[i] -= b[i]`.
#[inline]
pub fn sub_assign_slices<F: FieldElement>(a: &mut [F], b: &[F]) {
    debug_assert_eq!(a.len(), b.len(), "sub_assign_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter_mut().zip(b.par_iter()).for_each(|(x, &y)| {
            *x = x.sub(y);
        });
    } else {
        for (x, &y) in a.iter_mut().zip(b.iter()) {
            *x = x.sub(y);
        }
    }
}

/// In-place element-wise multiplication: `a[i] *= b[i]`.
#[inline]
pub fn mul_assign_slices<F: FieldElement>(a: &mut [F], b: &[F]) {
    debug_assert_eq!(a.len(), b.len(), "mul_assign_slices: length mismatch");
    if a.len() >= PAR_THRESHOLD {
        a.par_iter_mut().zip(b.par_iter()).for_each(|(x, &y)| {
            *x = x.mul(y);
        });
    } else {
        for (x, &y) in a.iter_mut().zip(b.iter()) {
            *x = x.mul(y);
        }
    }
}

/// Scale every element by a constant: `a[i] *= scalar`.
#[inline]
pub fn scale_slice<F: FieldElement>(a: &mut [F], scalar: F) {
    if a.len() >= PAR_THRESHOLD {
        a.par_iter_mut().for_each(|x| {
            *x = x.mul(scalar);
        });
    } else {
        for x in a.iter_mut() {
            *x = x.mul(scalar);
        }
    }
}

/// Dot product: `sum(a[i] * b[i])`.
#[inline]
pub fn dot_product<F: FieldElement>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len(), "dot_product: length mismatch");
    a.iter()
        .zip(b.iter())
        .fold(F::ZERO, |acc, (&x, &y)| acc.add(x.mul(y)))
}

/// Compute a linear combination: `result[i] = sum_j(coeffs[j] * columns[j][i])`.
///
/// All columns must have the same length. Returns a vector of that length.
///
/// Parallelism strategy: rather than parallelizing across columns (which
/// would require an atomic-style accumulator on `result`), we parallelize
/// across rows. For each row index, we sum across columns sequentially.
/// This gives O(n_rows / num_threads) wall time when n_rows is large
/// without changing the order of summation per cell — bit-for-bit
/// equivalent to the scalar implementation.
pub fn linear_combination<F: FieldElement>(coeffs: &[F], columns: &[&[F]]) -> Vec<F> {
    debug_assert_eq!(coeffs.len(), columns.len());
    if columns.is_empty() {
        return Vec::new();
    }
    let n = columns[0].len();
    if n >= PAR_THRESHOLD {
        (0..n)
            .into_par_iter()
            .map(|i| {
                let mut acc = F::ZERO;
                for (&coeff, col) in coeffs.iter().zip(columns.iter()) {
                    debug_assert_eq!(col.len(), n);
                    acc = acc.add(coeff.mul(col[i]));
                }
                acc
            })
            .collect()
    } else {
        let mut result = vec![F::ZERO; n];
        for (&coeff, col) in coeffs.iter().zip(columns.iter()) {
            debug_assert_eq!(col.len(), n);
            for (r, &v) in result.iter_mut().zip(col.iter()) {
                *r = r.add(coeff.mul(v));
            }
        }
        result
    }
}

/// FFT butterfly operation on a pair: `(a + tw*b, a - tw*b)`.
#[inline]
pub fn butterfly<F: FieldElement>(a: F, b: F, twiddle: F) -> (F, F) {
    let t = twiddle.mul(b);
    (a.add(t), a.sub(t))
}

/// Apply butterfly operations across two aligned slices with precomputed twiddle
/// factors. After this call, `a[i] = a[i] + tw[i]*b[i]` and `b[i] = a[i] - tw[i]*b[i]`
/// (using the original `a[i]`).
pub fn butterfly_slice<F: FieldElement>(a: &mut [F], b: &mut [F], twiddles: &[F]) {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    debug_assert_eq!(n, twiddles.len());
    if n >= PAR_THRESHOLD {
        a.par_iter_mut()
            .zip(b.par_iter_mut())
            .zip(twiddles.par_iter())
            .for_each(|((ai, bi), tw)| {
                let t = tw.mul(*bi);
                let u = *ai;
                *ai = u.add(t);
                *bi = u.sub(t);
            });
    } else {
        for i in 0..n {
            let t = twiddles[i].mul(b[i]);
            let u = a[i];
            a[i] = u.add(t);
            b[i] = u.sub(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;
    type F = GoldilocksField;

    #[test]
    fn batch_inverse_correctness() {
        let values: Vec<F> = (1..=10).map(|i| F::from_u64(i)).collect();
        let inverses = batch_inverse_nonzero(&values);
        for (v, inv) in values.iter().zip(inverses.iter()) {
            assert_eq!(v.mul(*inv), F::ONE, "inverse of {:?} failed", v);
        }
    }

    #[test]
    fn batch_inverse_with_zeros() {
        let values = vec![F::from_u64(3), F::ZERO, F::from_u64(7)];
        let inverses = batch_inverse(&values);
        assert!(inverses[0].is_some());
        assert!(inverses[1].is_none());
        assert!(inverses[2].is_some());
        assert_eq!(values[0].mul(inverses[0].unwrap()), F::ONE);
        assert_eq!(values[2].mul(inverses[2].unwrap()), F::ONE);
    }

    #[test]
    fn add_sub_slices_roundtrip() {
        let a: Vec<F> = (1..=5).map(|i| F::from_u64(i * 100)).collect();
        let b: Vec<F> = (1..=5).map(|i| F::from_u64(i * 7)).collect();
        let sum = add_slices(&a, &b);
        let back = sub_slices(&sum, &b);
        assert_eq!(a, back);
    }

    #[test]
    fn dot_product_matches_manual() {
        let a = vec![F::from_u64(2), F::from_u64(3)];
        let b = vec![F::from_u64(5), F::from_u64(7)];
        // 2*5 + 3*7 = 31
        assert_eq!(dot_product(&a, &b), F::from_u64(31));
    }

    #[test]
    fn linear_combination_correctness() {
        let c0 = vec![F::from_u64(1), F::from_u64(2)];
        let c1 = vec![F::from_u64(10), F::from_u64(20)];
        let coeffs = vec![F::from_u64(3), F::from_u64(4)];
        let result = linear_combination(&coeffs, &[&c0, &c1]);
        // result[0] = 3*1 + 4*10 = 43
        // result[1] = 3*2 + 4*20 = 86
        assert_eq!(result[0], F::from_u64(43));
        assert_eq!(result[1], F::from_u64(86));
    }

    #[test]
    fn butterfly_roundtrip() {
        let a = F::from_u64(100);
        let b = F::from_u64(42);
        let tw = F::from_u64(7);
        let (u, v) = butterfly(a, b, tw);
        // u = a + tw*b, v = a - tw*b
        // u + v = 2a, u - v = 2*tw*b
        let two = F::from_u64(2);
        assert_eq!(u.add(v), a.mul(two));
    }

    /// Pseudo-random Goldilocks field elements from a fixed seed for
    /// parity-test inputs. Deterministic so test failures are reproducible.
    fn deterministic_field_vec(seed: u64, n: usize) -> Vec<F> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x14_05_7B_7E_F7_67_81_4F);
                F::from_u64(x)
            })
            .collect()
    }

    /// Force the parallel path by exceeding PAR_THRESHOLD; force the
    /// serial path with a small input. Results must be bit-equivalent.
    /// This is the parity gate that catches a parallelization bug.
    #[test]
    fn par_vs_serial_parity_add() {
        let n = PAR_THRESHOLD * 4;
        let a = deterministic_field_vec(1, n);
        let b = deterministic_field_vec(2, n);
        let par = add_slices(&a, &b);
        // Manual scalar reference, never touches the par path.
        let serial: Vec<F> = a.iter().zip(b.iter()).map(|(&x, &y)| x.add(y)).collect();
        assert_eq!(par, serial);
    }

    #[test]
    fn par_vs_serial_parity_mul() {
        let n = PAR_THRESHOLD * 4;
        let a = deterministic_field_vec(3, n);
        let b = deterministic_field_vec(4, n);
        let par = mul_slices(&a, &b);
        let serial: Vec<F> = a.iter().zip(b.iter()).map(|(&x, &y)| x.mul(y)).collect();
        assert_eq!(par, serial);
    }

    #[test]
    fn par_vs_serial_parity_assign_mul() {
        let n = PAR_THRESHOLD * 4;
        let mut a_par = deterministic_field_vec(5, n);
        let mut a_ser = a_par.clone();
        let b = deterministic_field_vec(6, n);

        mul_assign_slices(&mut a_par, &b);
        for (x, &y) in a_ser.iter_mut().zip(b.iter()) {
            *x = x.mul(y);
        }
        assert_eq!(a_par, a_ser);
    }

    #[test]
    fn par_vs_serial_parity_butterfly() {
        let n = PAR_THRESHOLD * 4;
        let mut a_par = deterministic_field_vec(7, n);
        let mut b_par = deterministic_field_vec(8, n);
        let mut a_ser = a_par.clone();
        let mut b_ser = b_par.clone();
        let tw = deterministic_field_vec(9, n);

        butterfly_slice(&mut a_par, &mut b_par, &tw);
        for i in 0..n {
            let t = tw[i].mul(b_ser[i]);
            let u = a_ser[i];
            a_ser[i] = u.add(t);
            b_ser[i] = u.sub(t);
        }
        assert_eq!(a_par, a_ser);
        assert_eq!(b_par, b_ser);
    }

    #[test]
    fn par_vs_serial_parity_linear_combination() {
        let n = PAR_THRESHOLD * 4;
        let coeffs = deterministic_field_vec(10, 5);
        let cols: Vec<Vec<F>> = (0..5).map(|i| deterministic_field_vec(11 + i, n)).collect();
        let col_refs: Vec<&[F]> = cols.iter().map(|c| c.as_slice()).collect();

        let par = linear_combination(&coeffs, &col_refs);
        // Scalar reference.
        let mut serial = vec![F::ZERO; n];
        for (&coeff, col) in coeffs.iter().zip(cols.iter()) {
            for (r, &v) in serial.iter_mut().zip(col.iter()) {
                *r = r.add(coeff.mul(v));
            }
        }
        assert_eq!(par, serial);
    }

    /// Microbench the parallelization gain on mul_slices. Run with:
    ///     cargo test -p hc-core --release --lib \
    ///       field::batch_ops::tests::bench_mul_slices -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_mul_slices() {
        use std::time::Instant;
        const N: usize = 4_000_000;
        let a = deterministic_field_vec(123, N);
        let b = deterministic_field_vec(456, N);

        // Warmup.
        let _ = mul_slices(&a, &b);

        let t0 = Instant::now();
        let par = mul_slices(&a, &b);
        let dt_par = t0.elapsed();

        // Compare against an explicit serial reference (bypass the par path).
        let t0 = Instant::now();
        let serial: Vec<F> = a.iter().zip(b.iter()).map(|(&x, &y)| x.mul(y)).collect();
        let dt_ser = t0.elapsed();

        assert_eq!(par, serial);
        let mps_par = N as f64 / dt_par.as_secs_f64() / 1e6;
        let mps_ser = N as f64 / dt_ser.as_secs_f64() / 1e6;
        println!(
            "mul_slices x{N}: par={:.2}ms ({:.1} M/s), ser={:.2}ms ({:.1} M/s), speedup={:.2}x",
            dt_par.as_secs_f64() * 1000.0,
            mps_par,
            dt_ser.as_secs_f64() * 1000.0,
            mps_ser,
            mps_par / mps_ser,
        );
    }

    #[test]
    fn par_path_handles_below_threshold_inputs() {
        // A length below the threshold should still produce correct
        // results — confirms we didn't break the small-input scalar path
        // when adding the par branch.
        let small_n = 16;
        let a = deterministic_field_vec(99, small_n);
        let b = deterministic_field_vec(100, small_n);
        let got = add_slices(&a, &b);
        let want: Vec<F> = a.iter().zip(b.iter()).map(|(&x, &y)| x.add(y)).collect();
        assert_eq!(got, want);
    }
}
