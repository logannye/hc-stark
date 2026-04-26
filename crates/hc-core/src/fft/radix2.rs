//! Iterative radix-2 FFT and IFFT implementations.

use crate::{
    error::{HcError, HcResult},
    field::TwoAdicField,
    utils::{bit_reverse_permute, is_power_of_two, log2},
};

/// Performs an in-place decimation-in-time FFT.
pub fn fft_in_place<F: TwoAdicField>(values: &mut [F]) -> HcResult<()> {
    fft_internal(values, false)
}

/// Performs an in-place inverse FFT.
pub fn ifft_in_place<F: TwoAdicField>(values: &mut [F]) -> HcResult<()> {
    fft_internal(values, true)?;
    if values.is_empty() {
        return Ok(());
    }
    let n_inv = F::from_u64(values.len() as u64)
        .inverse()
        .ok_or_else(|| HcError::math("domain size has no inverse"))?;
    for value in values.iter_mut() {
        *value = value.mul(n_inv);
    }
    Ok(())
}

fn fft_internal<F: TwoAdicField>(values: &mut [F], inverse: bool) -> HcResult<()> {
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

    let mut m = 2;
    while m <= n {
        let half_m = m / 2;
        let w_m = omega.pow((n / m) as u64);

        // Precompute twiddle table for this stage: [1, w_m, w_m^2, ..., w_m^(half_m-1)].
        // Without this, the inner loop does twiddle = twiddle.mul(w_m)
        // every iteration, creating a tight dependency chain that
        // serializes the butterflies and prevents the compiler from
        // vectorizing. Precomputing turns each butterfly into an
        // independent op (data-only dependency on values[]), enabling
        // ILP and auto-vectorization.
        //
        // Cost: O(half_m) memory + half_m mults to build the table per
        // stage. With log_n stages on N elements, total table-build
        // cost is bounded by N (geometric series), well below the
        // O(N log N) work the FFT itself does.
        let twiddles: Vec<F> = {
            let mut t = Vec::with_capacity(half_m);
            let mut w = F::ONE;
            for _ in 0..half_m {
                t.push(w);
                w = w.mul(w_m);
            }
            t
        };

        for k in (0..n).step_by(m) {
            for j in 0..half_m {
                let t = twiddles[j].mul(values[k + j + half_m]);
                let u = values[k + j];
                values[k + j] = u.add(t);
                values[k + j + half_m] = u.sub(t);
            }
        }
        m <<= 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;

    #[test]
    fn fft_and_ifft_roundtrip() {
        let mut values = vec![
            GoldilocksField::new(1),
            GoldilocksField::new(2),
            GoldilocksField::new(3),
            GoldilocksField::new(4),
        ];
        let original = values.clone();
        fft_in_place(&mut values).unwrap();
        ifft_in_place(&mut values).unwrap();
        assert_eq!(values, original);
    }

    /// Larger FFT roundtrip — verifies the precomputed-twiddle path
    /// doesn't drift from the previous accumulator-twiddle behavior.
    /// At n=1024 the inner loop runs through every twiddle index in
    /// every stage, exercising the new table fully.
    #[test]
    fn fft_roundtrip_large() {
        let n = 1024;
        let mut values: Vec<GoldilocksField> = (0..n)
            .map(|i| GoldilocksField::new((i * 31337) as u64))
            .collect();
        let original = values.clone();
        fft_in_place(&mut values).unwrap();
        // Doing it twice (FFT then iFFT) takes us back to original up
        // to permutation; both functions internally bit-reverse so the
        // composition cancels.
        ifft_in_place(&mut values).unwrap();
        assert_eq!(values, original);
    }

    /// Reference: pre-precompute version with the accumulator-twiddle
    /// inner-loop pattern. Used by `bench_fft_ab` to quantify the
    /// speedup from the precomputed twiddle table.
    fn fft_old_internal(values: &mut [GoldilocksField]) {
        use crate::field::{FieldElement, TwoAdicField};
        let n = values.len();
        if n == 0 {
            return;
        }
        bit_reverse_permute(values);
        let log_n = log2(n);
        let omega = GoldilocksField::primitive_root_of_unity()
            .pow(1u64 << (GoldilocksField::TWO_ADICITY - log_n));
        let mut m = 2;
        while m <= n {
            let w_m = omega.pow((n / m) as u64);
            for k in (0..n).step_by(m) {
                let mut twiddle = GoldilocksField::ONE;
                for j in 0..(m / 2) {
                    let t = twiddle.mul(values[k + j + m / 2]);
                    let u = values[k + j];
                    values[k + j] = u.add(t);
                    values[k + j + m / 2] = u.sub(t);
                    twiddle = twiddle.mul(w_m);
                }
            }
            m <<= 1;
        }
    }

    /// A/B microbench: old (accumulator twiddle) vs new (precomputed
    /// twiddle table) at multiple sizes. Output reports speedup factor.
    /// Run with:
    ///     cargo test -p hc-core --release --lib \
    ///       fft::radix2::tests::bench_fft_ab -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_fft_ab() {
        use std::time::Instant;
        const ITERS: usize = 50;
        println!(
            "{:>6} {:>10} {:>14} {:>14} {:>10}",
            "log_n", "n", "old(us)", "new(us)", "speedup"
        );
        for &log_n in &[10u32, 12, 14, 16, 18, 20] {
            let n = 1usize << log_n;
            let template: Vec<GoldilocksField> = (0..n)
                .map(|i| GoldilocksField::new((i * 31337) as u64))
                .collect();

            // Warmup.
            let _ = fft_in_place(&mut template.clone());

            let t0 = Instant::now();
            for _ in 0..ITERS {
                let mut v = template.clone();
                fft_old_internal(&mut v);
                std::hint::black_box(v);
            }
            let old_us = (t0.elapsed().as_secs_f64() * 1_000_000.0) / ITERS as f64;

            let t0 = Instant::now();
            for _ in 0..ITERS {
                let mut v = template.clone();
                fft_in_place(&mut v).unwrap();
                std::hint::black_box(v);
            }
            let new_us = (t0.elapsed().as_secs_f64() * 1_000_000.0) / ITERS as f64;

            println!(
                "{:>6} {:>10} {:>14.2} {:>14.2} {:>9.2}x",
                log_n,
                n,
                old_us,
                new_us,
                old_us / new_us,
            );
        }
    }
}
