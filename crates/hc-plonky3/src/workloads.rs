use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks, GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};

const FIBONACCI_COLUMNS: usize = 2;
const POSEIDON2_WIDTH: usize = 8;
const POSEIDON2_SBOX_DEGREE: u64 = p3_goldilocks::poseidon1::GOLDILOCKS_S_BOX_DEGREE;
const POSEIDON2_SBOX_REGISTERS: usize = 1;

/// Upstream-style Fibonacci AIR with the start pair and final value public.
pub struct FibonacciAir;

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        FIBONACCI_COLUMNS
    }

    fn num_public_values(&self) -> usize {
        3
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let public = builder.public_values();
        let initial_a = public[0];
        let initial_b = public[1];
        let final_value = public[2];

        let mut first = builder.when_first_row();
        first.assert_eq(local[0], initial_a);
        first.assert_eq(local[1], initial_b);

        let mut transition = builder.when_transition();
        transition.assert_eq(local[1], next[0]);
        transition.assert_eq(local[0] + local[1], next[1]);

        builder.when_last_row().assert_eq(local[1], final_value);
    }
}

pub fn fibonacci_trace<F: PrimeField64>(a: u64, b: u64, rows: usize) -> RowMajorMatrix<F> {
    assert!(rows.is_power_of_two() && rows > 0);
    let mut values = F::zero_vec(rows * FIBONACCI_COLUMNS);
    values[0] = F::from_u64(a);
    values[1] = F::from_u64(b);
    for row in 1..rows {
        let prior = (row - 1) * FIBONACCI_COLUMNS;
        let current = row * FIBONACCI_COLUMNS;
        values[current] = values[prior + 1];
        values[current + 1] = values[prior] + values[prior + 1];
    }
    RowMajorMatrix::new(values, FIBONACCI_COLUMNS)
}

pub fn fibonacci_public_values(a: u64, b: u64, rows: usize) -> Vec<Goldilocks> {
    let trace = fibonacci_trace::<Goldilocks>(a, b, rows);
    let final_value = trace.values[trace.values.len() - 1];
    vec![
        Goldilocks::from_u64(a),
        Goldilocks::from_u64(b),
        final_value,
    ]
}

pub type Poseidon2GoldilocksAir = Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
>;

pub const fn poseidon2_goldilocks_air() -> Poseidon2GoldilocksAir {
    Poseidon2Air::new(RoundConstants::new(
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    ))
}

pub fn poseidon2_trace(rows: usize, extra_capacity_bits: usize) -> RowMajorMatrix<Goldilocks> {
    poseidon2_goldilocks_air().generate_trace_rows(rows, extra_capacity_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;
    use p3_matrix::Matrix;

    #[test]
    fn fibonacci_public_value_matches_trace_endpoint() {
        let public = fibonacci_public_values(0, 1, 8);
        assert_eq!(public[2].as_canonical_u64(), 21);
    }

    #[test]
    fn poseidon2_trace_has_requested_rows() {
        let trace = poseidon2_trace(8, 0);
        assert_eq!(trace.height(), 8);
        assert!(trace.width() > 8);
    }
}
