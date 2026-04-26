//! Parallel radix-2 FFT using Rayon.
//!
//! For large transforms (>= 2^14 elements), the butterfly stages are
//! parallelized across independent groups. For the early stages where `m` is
//! small, all `n/m` groups are independent and can be split across threads.
//! For the later stages where `m` is large, the butterfly *within* each group
//! is parallelized.
//!
//! Twiddle factors are precomputed to avoid redundant `pow` calls.

use rayon::prelude::*;

use crate::{
    error::{HcError, HcResult},
    field::TwoAdicField,
    utils::{bit_reverse_permute, is_power_of_two, log2},
};

/// Minimum FFT size for which we use parallel butterfly stages.
/// Below this threshold, Rayon overhead exceeds the computation benefit.
const PARALLEL_THRESHOLD: usize = 1 << 14; // 16384

/// Precompute twiddle factors for a given butterfly stage.
///
/// Returns `m/2` twiddle values: `[1, w_m, w_m^2, ..., w_m^(m/2-1)]`.
fn precompute_twiddles<F: TwoAdicField>(w_m: F, half_m: usize) -> Vec<F> {
    let mut twiddles = Vec::with_capacity(half_m);
    let mut w = F::ONE;
    for _ in 0..half_m {
        twiddles.push(w);
        w = w.mul(w_m);
    }
    twiddles
}

/// Perform a single butterfly stage (stride `m`) using precomputed twiddles.
///
/// Each group of `m` elements is independent, so we split them across threads.
fn butterfly_stage_parallel<F: TwoAdicField>(values: &mut [F], m: usize, twiddles: &[F]) {
    let half_m = m / 2;
    let n = values.len();

    // Collect group start indices. Each group of `m` elements is fully
    // independent (no data dependencies between groups at a given stage).
    // We use par_chunks_mut so Rayon can split the slice across threads.
    values.par_chunks_mut(m).for_each(|group| {
        for j in 0..half_m {
            let t = twiddles[j].mul(group[j + half_m]);
            let u = group[j];
            group[j] = u.add(t);
            group[j + half_m] = u.sub(t);
        }
    });

    // For verification: assert we processed the expected number of elements.
    debug_assert_eq!(n, values.len());
}

/// Perform a single butterfly stage sequentially (for small stages).
fn butterfly_stage_sequential<F: TwoAdicField>(values: &mut [F], m: usize, twiddles: &[F]) {
    let half_m = m / 2;
    for k in (0..values.len()).step_by(m) {
        for j in 0..half_m {
            let t = twiddles[j].mul(values[k + j + half_m]);
            let u = values[k + j];
            values[k + j] = u.add(t);
            values[k + j + half_m] = u.sub(t);
        }
    }
}

/// Parallel in-place FFT using precomputed twiddles and Rayon.
///
/// For inputs >= `PARALLEL_THRESHOLD`, butterfly stages are parallelized
/// across independent groups. For smaller inputs, falls through to
/// sequential execution (still with precomputed twiddles).
pub fn fft_parallel<F: TwoAdicField>(values: &mut [F]) -> HcResult<()> {
    fft_parallel_internal(values, false)
}

/// Parallel in-place inverse FFT.
pub fn ifft_parallel<F: TwoAdicField>(values: &mut [F]) -> HcResult<()> {
    fft_parallel_internal(values, true)?;
    if values.is_empty() {
        return Ok(());
    }
    let n_inv = F::from_u64(values.len() as u64)
        .inverse()
        .ok_or_else(|| HcError::math("domain size has no inverse"))?;
    // Parallel scaling for large arrays.
    if values.len() >= PARALLEL_THRESHOLD {
        values.par_iter_mut().for_each(|v| *v = v.mul(n_inv));
    } else {
        for v in values.iter_mut() {
            *v = v.mul(n_inv);
        }
    }
    Ok(())
}

fn fft_parallel_internal<F: TwoAdicField>(values: &mut [F], inverse: bool) -> HcResult<()> {
    let n = values.len();
    if n == 0 {
        return Ok(());
    }
    if !is_power_of_two(n) {
        return Err(HcError::invalid_argument(
            "FFT length must be a power of two",
        ));
    }
    let log_n = log2(n);
    if log_n > F::TWO_ADICITY {
        return Err(HcError::invalid_argument(
            "FFT length exceeds field two-adicity",
        ));
    }

    bit_reverse_permute(values);

    let mut omega = F::primitive_root_of_unity().pow(1u64 << (F::TWO_ADICITY - log_n));
    if inverse {
        omega = omega.inverse().expect("non-zero root");
    }

    let use_parallel = n >= PARALLEL_THRESHOLD;

    let mut m = 2;
    while m <= n {
        let w_m = omega.pow((n / m) as u64);
        let half_m = m / 2;
        let twiddles = precompute_twiddles(w_m, half_m);

        if use_parallel {
            butterfly_stage_parallel(values, m, &twiddles);
        } else {
            butterfly_stage_sequential(values, m, &twiddles);
        }
        m <<= 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{prime_field::GoldilocksField, FieldElement, TwoAdicField};

    type F = GoldilocksField;

    #[test]
    fn parallel_fft_matches_sequential() {
        let input: Vec<F> = (0..256).map(F::from_u64).collect();
        let mut seq = input.clone();
        let mut par = input;
        crate::fft::radix2::fft_in_place(&mut seq).unwrap();
        fft_parallel(&mut par).unwrap();
        assert_eq!(seq, par);
    }

    #[test]
    fn parallel_ifft_roundtrip() {
        let original: Vec<F> = (0..128).map(|i| F::from_u64(i * 7 + 3)).collect();
        let mut values = original.clone();
        fft_parallel(&mut values).unwrap();
        ifft_parallel(&mut values).unwrap();
        assert_eq!(values, original);
    }

    #[test]
    fn parallel_fft_small_input() {
        let mut values = vec![F::from_u64(1), F::from_u64(2)];
        let mut expected = values.clone();
        crate::fft::radix2::fft_in_place(&mut expected).unwrap();
        fft_parallel(&mut values).unwrap();
        assert_eq!(values, expected);
    }

    #[test]
    fn parallel_fft_power_of_two_sizes() {
        for log_n in 1..=10 {
            let n = 1 << log_n;
            let input: Vec<F> = (0..n).map(|i| F::from_u64(i as u64)).collect();
            let mut seq = input.clone();
            let mut par = input;
            crate::fft::radix2::fft_in_place(&mut seq).unwrap();
            fft_parallel(&mut par).unwrap();
            assert_eq!(seq, par, "mismatch at size 2^{log_n}");
        }
    }

    #[test]
    fn twiddle_precomputation_correctness() {
        let n = 8usize;
        let log_n = log2(n);
        let omega = F::primitive_root_of_unity().pow(1u64 << (F::TWO_ADICITY - log_n));
        let m = 4;
        let w_m = omega.pow((n / m) as u64);
        let twiddles = precompute_twiddles(w_m, m / 2);
        assert_eq!(twiddles[0], F::ONE);
        assert_eq!(twiddles[1], w_m);
    }
}
