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
        let w_m = omega.pow((n / m) as u64);
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
}
