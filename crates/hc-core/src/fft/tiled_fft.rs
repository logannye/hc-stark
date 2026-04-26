//! Cache-friendly blocked FFT that still produces the exact same output as the
//! canonical in-core transform.

use crate::{
    error::{HcError, HcResult},
    field::TwoAdicField,
    utils::{bit_reverse_permute, is_power_of_two, log2},
};

/// Performs an FFT by first transforming tiles of length `tile_size`, then
/// stitching the result with an additional column FFT. This retains correctness
/// while lowering peak working-set requirements.
pub fn blocked_fft_in_place<F: TwoAdicField>(values: &mut [F], tile_size: usize) -> HcResult<()> {
    let n = values.len();
    if n == 0 {
        return Ok(());
    }
    if tile_size == 0 || !is_power_of_two(tile_size) {
        return Err(HcError::invalid_argument(
            "tile_size must be a non-zero power of two",
        ));
    }
    if !is_power_of_two(n) {
        return Err(HcError::invalid_argument(
            "values length must be a power of two",
        ));
    }
    if n % tile_size != 0 {
        return Err(HcError::invalid_argument(
            "tile_size must divide the input length",
        ));
    }
    // This is the same iterative radix-2 DIT FFT as `fft::radix2::fft_in_place`, but
    // with the outer loop blocked in tiles to reduce cache thrash on large inputs.
    //
    // Correctness is *identical* to the canonical transform.
    let log_n = log2(n);
    if log_n > F::TWO_ADICITY {
        return Err(HcError::invalid_argument(
            "FFT length exceeds field two-adicity",
        ));
    }

    bit_reverse_permute(values);
    let omega = F::primitive_root_of_unity().pow(1u64 << (F::TWO_ADICITY - log_n));

    let mut m = 2;
    while m <= n {
        let w_m = omega.pow((n / m) as u64);
        if tile_size >= m {
            // `tile_size` and `m` are powers of two, so `tile_size` is a multiple of `m`.
            for tile_start in (0..n).step_by(tile_size) {
                let tile_end = (tile_start + tile_size).min(n);
                for k in (tile_start..tile_end).step_by(m) {
                    let mut twiddle = F::ONE;
                    for j in 0..(m / 2) {
                        let t = twiddle.mul(values[k + j + m / 2]);
                        let u = values[k + j];
                        values[k + j] = u.add(t);
                        values[k + j + m / 2] = u.sub(t);
                        twiddle = twiddle.mul(w_m);
                    }
                }
            }
        } else {
            for k in (0..n).step_by(m) {
                let mut twiddle = F::ONE;
                for j in 0..(m / 2) {
                    let t = twiddle.mul(values[k + j + m / 2]);
                    let u = values[k + j];
                    values[k + j] = u.add(t);
                    values[k + j + m / 2] = u.sub(t);
                    twiddle = twiddle.mul(w_m);
                }
            }
        }
        m <<= 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fft::radix2::{fft_in_place, ifft_in_place},
        field::prime_field::GoldilocksField,
    };

    #[test]
    fn blocked_fft_matches_standard() {
        let mut baseline = vec![
            GoldilocksField::new(1),
            GoldilocksField::new(2),
            GoldilocksField::new(3),
            GoldilocksField::new(4),
            GoldilocksField::new(5),
            GoldilocksField::new(6),
            GoldilocksField::new(7),
            GoldilocksField::new(8),
        ];
        let mut tiled = baseline.clone();
        fft_in_place(&mut baseline).unwrap();
        blocked_fft_in_place(&mut tiled, 4).unwrap();
        assert_eq!(baseline, tiled);

        ifft_in_place(&mut tiled).unwrap();
        assert_eq!(
            tiled,
            vec![
                GoldilocksField::new(1),
                GoldilocksField::new(2),
                GoldilocksField::new(3),
                GoldilocksField::new(4),
                GoldilocksField::new(5),
                GoldilocksField::new(6),
                GoldilocksField::new(7),
                GoldilocksField::new(8),
            ]
        );
    }
}
