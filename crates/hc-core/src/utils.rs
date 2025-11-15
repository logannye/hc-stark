//! Generic helpers that do not belong to a specific module.

/// Returns `true` if `value` is a power of two.
#[inline]
pub fn is_power_of_two(value: usize) -> bool {
    value != 0 && (value & (value - 1)) == 0
}

/// Computes `log2(value)` assuming `value` is a power of two.
#[inline]
pub fn log2(value: usize) -> u32 {
    debug_assert!(is_power_of_two(value));
    value.trailing_zeros()
}

/// Returns the bit-reversal of `value` given the number of bits used.
#[inline]
pub fn bit_reverse(value: usize, bits: u32) -> usize {
    value.reverse_bits() >> (usize::BITS - bits)
}

/// Bit-reversal permutation applied in-place.
pub fn bit_reverse_permute<T: Copy>(values: &mut [T]) {
    let n = values.len();
    if n <= 1 {
        return;
    }
    let bits = log2(n);
    for i in 0..n {
        let j = bit_reverse(i, bits);
        if j > i {
            values.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reverse_roundtrip() {
        assert_eq!(bit_reverse(0b0011, 4), 0b1100);
        assert_eq!(bit_reverse(0b0101, 4), 0b1010);
    }

    #[test]
    fn permutation_swaps_expected_entries() {
        let mut values = [0, 1, 2, 3];
        bit_reverse_permute(&mut values);
        assert_eq!(values, [0, 2, 1, 3]);
    }
}
