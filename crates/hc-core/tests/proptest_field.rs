//! Property-based tests for Goldilocks field arithmetic.

use hc_core::field::prime_field::{GoldilocksField, GOLDILOCKS_MODULUS};
use hc_core::field::FieldElement;
use proptest::prelude::*;

/// Proptest strategy for generating valid Goldilocks field elements.
fn arb_field_element() -> impl Strategy<Value = GoldilocksField> {
    (0u64..GOLDILOCKS_MODULUS).prop_map(GoldilocksField)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    // ---- Algebraic properties ----

    #[test]
    fn add_commutative(a in arb_field_element(), b in arb_field_element()) {
        prop_assert_eq!(a.add(b), b.add(a));
    }

    #[test]
    fn mul_commutative(a in arb_field_element(), b in arb_field_element()) {
        prop_assert_eq!(a.mul(b), b.mul(a));
    }

    #[test]
    fn add_associative(
        a in arb_field_element(),
        b in arb_field_element(),
        c in arb_field_element()
    ) {
        prop_assert_eq!(a.add(b).add(c), a.add(b.add(c)));
    }

    #[test]
    fn mul_associative(
        a in arb_field_element(),
        b in arb_field_element(),
        c in arb_field_element()
    ) {
        prop_assert_eq!(a.mul(b).mul(c), a.mul(b.mul(c)));
    }

    #[test]
    fn distributive(
        a in arb_field_element(),
        b in arb_field_element(),
        c in arb_field_element()
    ) {
        prop_assert_eq!(a.mul(b.add(c)), a.mul(b).add(a.mul(c)));
    }

    // ---- Identity elements ----

    #[test]
    fn add_identity(a in arb_field_element()) {
        prop_assert_eq!(a.add(GoldilocksField::ZERO), a);
    }

    #[test]
    fn mul_identity(a in arb_field_element()) {
        prop_assert_eq!(a.mul(GoldilocksField::ONE), a);
    }

    #[test]
    fn mul_zero(a in arb_field_element()) {
        prop_assert_eq!(a.mul(GoldilocksField::ZERO), GoldilocksField::ZERO);
    }

    // ---- Inverse elements ----

    #[test]
    fn additive_inverse(a in arb_field_element()) {
        prop_assert_eq!(a.add(a.neg()), GoldilocksField::ZERO);
    }

    #[test]
    fn multiplicative_inverse(a in arb_field_element()) {
        if !a.is_zero() {
            let inv = a.inverse().unwrap();
            prop_assert_eq!(a.mul(inv), GoldilocksField::ONE);
        }
    }

    // ---- Subtraction ----

    #[test]
    fn sub_is_add_neg(a in arb_field_element(), b in arb_field_element()) {
        prop_assert_eq!(a.sub(b), a.add(b.neg()));
    }

    #[test]
    fn sub_self_is_zero(a in arb_field_element()) {
        prop_assert_eq!(a.sub(a), GoldilocksField::ZERO);
    }

    // ---- Square and pow ----

    #[test]
    fn square_is_self_mul(a in arb_field_element()) {
        prop_assert_eq!(a.square(), a.mul(a));
    }

    #[test]
    fn pow_ct_matches_pow(a in arb_field_element(), exp in 0u64..1024) {
        prop_assert_eq!(a.pow(exp), a.pow_ct(exp));
    }

    // ---- Canonical representation ----

    #[test]
    fn canonical_range(a in arb_field_element(), b in arb_field_element()) {
        prop_assert!(a.add(b).to_u64() < GOLDILOCKS_MODULUS);
        prop_assert!(a.mul(b).to_u64() < GOLDILOCKS_MODULUS);
        prop_assert!(a.neg().to_u64() < GOLDILOCKS_MODULUS);
        prop_assert!(a.sub(b).to_u64() < GOLDILOCKS_MODULUS);
    }

    // ---- Double negation ----

    #[test]
    fn double_neg(a in arb_field_element()) {
        prop_assert_eq!(a.neg().neg(), a);
    }

    // ---- From/to roundtrip ----

    #[test]
    fn from_to_roundtrip(v in 0u64..GOLDILOCKS_MODULUS) {
        let elem = GoldilocksField::from_u64(v);
        prop_assert_eq!(elem.to_u64(), v);
    }
}
