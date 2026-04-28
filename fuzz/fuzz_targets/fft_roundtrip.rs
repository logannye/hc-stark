#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 8 bytes per element, and the length must be a power of 2.
    if data.len() < 16 {
        return;
    }
    let n_elements = data.len() / 8;
    // Round down to nearest power of 2.
    let n = n_elements.next_power_of_two() >> 1;
    if n < 2 {
        return;
    }
    // Cap at reasonable size to avoid slow tests.
    if n > 256 {
        return;
    }

    use hc_core::field::prime_field::GoldilocksField;

    let original: Vec<GoldilocksField> = (0..n)
        .map(|i| {
            let start = i * 8;
            let raw = u64::from_le_bytes(data[start..start + 8].try_into().unwrap());
            GoldilocksField::new(raw)
        })
        .collect();

    // Forward FFT then inverse should recover the original.
    let mut coeffs = original.clone();
    let _ = hc_core::fft::fft_in_place(&mut coeffs);
    let _ = hc_core::fft::ifft_in_place(&mut coeffs);

    for (i, (orig, roundtripped)) in original.iter().zip(coeffs.iter()).enumerate() {
        assert_eq!(
            orig, roundtripped,
            "FFT roundtrip mismatch at index {i}: original={:?}, got={:?}",
            orig, roundtripped
        );
    }
});
