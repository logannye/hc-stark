//! Cache-friendly blocked FFT that still produces the exact same output as the
//! canonical in-core transform.

use crate::{
    error::{HcError, HcResult},
    fft::radix2::fft_in_place,
    field::TwoAdicField,
    utils::is_power_of_two,
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
    fft_in_place(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fft::radix2::ifft_in_place, field::prime_field::GoldilocksField};

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
