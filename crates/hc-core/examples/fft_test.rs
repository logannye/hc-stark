use hc_core::{
    error::HcResult,
    fft::{fft_in_place, ifft_in_place},
    field::{prime_field::GoldilocksField, FieldElement},
};

fn main() -> HcResult<()> {
    let mut values = vec![
        GoldilocksField::new(1),
        GoldilocksField::new(2),
        GoldilocksField::new(3),
        GoldilocksField::new(4),
    ];
    let original = values.clone();

    fft_in_place(&mut values)?;
    println!(
        "FFT output: {:?}",
        values.iter().map(|v| v.to_u64()).collect::<Vec<_>>()
    );

    ifft_in_place(&mut values)?;
    assert_eq!(values, original);
    println!(
        "Round-trip successful: {:?}",
        values.iter().map(|v| v.to_u64()).collect::<Vec<_>>()
    );
    Ok(())
}
