#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    // Extract three u64 values from the fuzz input.
    let a_raw = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let b_raw = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let c_raw = u64::from_le_bytes(data[16..24].try_into().unwrap());

    use hc_core::field::prime_field::{GoldilocksField, GOLDILOCKS_MODULUS};
    use hc_core::field::FieldElement;

    let a = GoldilocksField::new(a_raw);
    let b = GoldilocksField::new(b_raw);
    let c = GoldilocksField::new(c_raw);

    // Commutativity: a + b == b + a, a * b == b * a
    assert_eq!(a.add(b), b.add(a));
    assert_eq!(a.mul(b), b.mul(a));

    // Associativity: (a + b) + c == a + (b + c)
    assert_eq!(a.add(b).add(c), a.add(b.add(c)));
    // Associativity: (a * b) * c == a * (b * c)
    assert_eq!(a.mul(b).mul(c), a.mul(b.mul(c)));

    // Distributivity: a * (b + c) == a*b + a*c
    assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));

    // Identity: a + 0 == a, a * 1 == a
    assert_eq!(a.add(GoldilocksField::ZERO), a);
    assert_eq!(a.mul(GoldilocksField::ONE), a);

    // Negation: a + (-a) == 0
    assert_eq!(a.add(a.neg()), GoldilocksField::ZERO);

    // Subtraction: a - b == a + (-b)
    assert_eq!(a.sub(b), a.add(b.neg()));

    // Inverse: a * a^{-1} == 1 (when a != 0)
    if !a.is_zero() {
        let inv = a.inverse().unwrap();
        assert_eq!(a.mul(inv), GoldilocksField::ONE);
    }

    // Square: a^2 == a * a
    assert_eq!(a.square(), a.mul(a));

    // Canonical representation: element value must be < MODULUS
    assert!(a.to_u64() < GOLDILOCKS_MODULUS);
    assert!(b.to_u64() < GOLDILOCKS_MODULUS);
    assert!(a.add(b).to_u64() < GOLDILOCKS_MODULUS);
    assert!(a.mul(b).to_u64() < GOLDILOCKS_MODULUS);

    // pow_ct matches pow
    let small_exp = (data[0] as u64) | ((data[1] as u64) << 8);
    assert_eq!(a.pow(small_exp), a.pow_ct(small_exp));
});
