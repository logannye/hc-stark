use crate::dft::GoldilocksWord;
use crate::profile::{DurableFieldProfile, GoldilocksProfile};
use hc_stream::{ArtifactDigest, BlockMatrix, CanonicalElement, MatrixStore};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks, GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};
use rand::rngs::Xoshiro256PlusPlus;
use rand::{RngExt, SeedableRng};

const FIBONACCI_COLUMNS: usize = 2;
const POSEIDON2_WIDTH: usize = 8;
const POSEIDON2_SBOX_DEGREE: u64 = p3_goldilocks::poseidon1::GOLDILOCKS_S_BOX_DEGREE;
const POSEIDON2_SBOX_REGISTERS: usize = 1;

#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    #[error("invalid resource-bounded workload shape")]
    InvalidShape,
    #[error(transparent)]
    Stream(#[from] hc_stream::StreamError),
}

pub type WorkloadResult<T> = std::result::Result<T, WorkloadError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadIdentityV1 {
    pub id: &'static str,
    pub version: u32,
}

/// The base field defaults to Goldilocks so partner crates that already name
/// `GeneratedTraceV1` keep compiling unchanged; the durable prover always
/// spells the parameter explicitly as `P::Val`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedTraceV1<F = Goldilocks> {
    pub identity: WorkloadIdentityV1,
    pub rows: u64,
    pub columns: usize,
    pub public_values: Vec<F>,
    pub input_digest: [u8; 32],
    pub trace_digest: ArtifactDigest,
}

/// A statically linked Plonky3 workload whose trace can be emitted without an
/// owned full-trace allocation. Partner AIRs implement this trait in their own
/// integration crate; the production CLI registers only the built-in types.
///
/// The three profile parameters default to Goldilocks' `<8, 4,
/// GoldilocksProfile>`, so an existing `impl ResourceBoundedWorkload for
/// MyWorkload` — including the one in `examples/partner-adapter` — still means
/// exactly what it meant before this trait became profile-generic. A workload
/// whose trace generation is field-agnostic (`FibonacciWorkload`) implements it
/// once for every profile instead.
pub trait ResourceBoundedWorkload<
    const PERM_WIDTH: usize = 8,
    const DIGEST_ELEMS: usize = 4,
    P: DurableFieldProfile<PERM_WIDTH, DIGEST_ELEMS> = GoldilocksProfile,
>: Sync where
    [P::Val; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Air;

    fn identity(&self) -> WorkloadIdentityV1;
    fn rows(&self) -> u64;
    fn air(&self) -> Self::Air;
    fn public_values(&self) -> Vec<P::Val>;
    fn input_digest(&self) -> [u8; 32];
    fn write_trace<S: MatrixStore<P::Word>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> WorkloadResult<GeneratedTraceV1<P::Val>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FibonacciWorkload {
    pub initial_a: u64,
    pub initial_b: u64,
    pub logical_rows: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Poseidon2Workload {
    pub logical_rows: u64,
}

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

pub fn fibonacci_public_values<F: PrimeField64>(a: u64, b: u64, rows: usize) -> Vec<F> {
    assert!(rows.is_power_of_two() && rows > 0);
    let (coefficient_a, coefficient_b) = fibonacci_pair::<F>((rows - 1) as u64);
    let final_value = coefficient_a * F::from_u64(a) + coefficient_b * F::from_u64(b);
    vec![F::from_u64(a), F::from_u64(b), final_value]
}

fn fibonacci_pair<F: PrimeField64>(index: u64) -> (F, F) {
    if index == 0 {
        return (F::ZERO, F::ONE);
    }
    let (left, right) = fibonacci_pair::<F>(index / 2);
    let doubled = left * (F::from_u64(2) * right - left);
    let adjacent = left * left + right * right;
    if index.is_multiple_of(2) {
        (doubled, adjacent)
    } else {
        (adjacent, doubled + adjacent)
    }
}

/// Implemented once for every profile: the Fibonacci recurrence, its public
/// values, and its AIR are all field-agnostic. The seed-canonicality check
/// that used to compare against the `GOLDILOCKS_MODULUS_U64` literal now goes
/// through `P::modulus_u64()`, which is the only field-specific thing here.
impl<const PERM_WIDTH: usize, const DIGEST_ELEMS: usize, P>
    ResourceBoundedWorkload<PERM_WIDTH, DIGEST_ELEMS, P> for FibonacciWorkload
where
    P: DurableFieldProfile<PERM_WIDTH, DIGEST_ELEMS>,
    [P::Val; DIGEST_ELEMS]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Air = FibonacciAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: "fibonacci",
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.logical_rows
    }

    fn air(&self) -> Self::Air {
        FibonacciAir
    }

    fn public_values(&self) -> Vec<P::Val> {
        let rows = usize::try_from(self.logical_rows).expect("validated workload row count");
        fibonacci_public_values::<P::Val>(self.initial_a, self.initial_b, rows)
    }

    fn input_digest(&self) -> [u8; 32] {
        // `self.identity()` is ambiguous here: `FibonacciWorkload` implements
        // the trait for every profile, so the receiver cannot pick one. The
        // value is profile-independent, so any instantiation would do; naming
        // this one keeps the digest's provenance obvious.
        workload_input_digest(
            ResourceBoundedWorkload::<PERM_WIDTH, DIGEST_ELEMS, P>::identity(self),
            self.logical_rows,
            &[self.initial_a, self.initial_b],
        )
    }

    fn write_trace<S: MatrixStore<P::Word>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> WorkloadResult<GeneratedTraceV1<P::Val>> {
        if self.initial_a >= P::modulus_u64() || self.initial_b >= P::modulus_u64() {
            return Err(WorkloadError::InvalidShape);
        }
        validate_trace_target(store, self.logical_rows, FIBONACCI_COLUMNS, block_rows)?;
        let rows = usize::try_from(self.logical_rows).map_err(|_| WorkloadError::InvalidShape)?;
        let block_rows = block_rows.min(rows);
        let mut block = vec![P::Word::default(); block_rows * FIBONACCI_COLUMNS];
        let mut left = P::Val::from_u64(self.initial_a);
        let mut right = P::Val::from_u64(self.initial_b);
        for block_start in (0..rows).step_by(block_rows) {
            let row_count = (rows - block_start).min(block_rows);
            for row in 0..row_count {
                let offset = row * FIBONACCI_COLUMNS;
                block[offset] = P::Word::from(left);
                block[offset + 1] = P::Word::from(right);
                if block_start + row + 1 < rows {
                    (left, right) = (right, left + right);
                }
            }
            store.write_rows(
                block_start as u64,
                row_count,
                &block[..row_count * FIBONACCI_COLUMNS],
            )?;
        }
        let trace_digest = store.finalize()?;
        Ok(GeneratedTraceV1 {
            identity: ResourceBoundedWorkload::<PERM_WIDTH, DIGEST_ELEMS, P>::identity(self),
            rows: self.logical_rows,
            columns: FIBONACCI_COLUMNS,
            public_values: ResourceBoundedWorkload::<PERM_WIDTH, DIGEST_ELEMS, P>::public_values(
                self,
            ),
            input_digest: ResourceBoundedWorkload::<PERM_WIDTH, DIGEST_ELEMS, P>::input_digest(
                self,
            ),
            trace_digest,
        })
    }
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
    Poseidon2Air::new(poseidon2_round_constants())
}

const fn poseidon2_round_constants() -> RoundConstants<
    Goldilocks,
    POSEIDON2_WIDTH,
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
    GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
> {
    RoundConstants::new(
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL,
        GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    )
}

pub fn poseidon2_trace(rows: usize, extra_capacity_bits: usize) -> RowMajorMatrix<Goldilocks> {
    poseidon2_goldilocks_air().generate_trace_rows(rows, extra_capacity_bits)
}

/// Goldilocks-only: `Poseidon2GoldilocksAir` is built from Goldilocks' own
/// round constants and MDS layers, so unlike `FibonacciWorkload` this workload
/// has no meaning at another profile.
impl ResourceBoundedWorkload<8, 4, GoldilocksProfile> for Poseidon2Workload {
    type Air = Poseidon2GoldilocksAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: "poseidon2_goldilocks",
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.logical_rows
    }

    fn air(&self) -> Self::Air {
        poseidon2_goldilocks_air()
    }

    fn public_values(&self) -> Vec<Goldilocks> {
        vec![]
    }

    fn input_digest(&self) -> [u8; 32] {
        workload_input_digest(self.identity(), self.logical_rows, &[0])
    }

    fn write_trace<S: MatrixStore<GoldilocksWord>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> WorkloadResult<GeneratedTraceV1> {
        let columns = self.air().width();
        validate_trace_target(store, self.logical_rows, columns, block_rows)?;
        let rows = usize::try_from(self.logical_rows).map_err(|_| WorkloadError::InvalidShape)?;
        let block_rows = block_rows.min(rows);
        let constants = poseidon2_round_constants();
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        for block_start in (0..rows).step_by(block_rows) {
            let row_count = (rows - block_start).min(block_rows);
            let inputs: Vec<[Goldilocks; POSEIDON2_WIDTH]> =
                (0..row_count).map(|_| rng.random()).collect();
            let trace = p3_poseidon2_air::generate_trace_rows::<
                Goldilocks,
                GenericPoseidon2LinearLayersGoldilocks,
                POSEIDON2_WIDTH,
                POSEIDON2_SBOX_DEGREE,
                POSEIDON2_SBOX_REGISTERS,
                GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS,
                GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
            >(inputs, &constants, 0);
            let words: Vec<_> = trace.values.into_iter().map(GoldilocksWord).collect();
            store.write_rows(block_start as u64, row_count, &words)?;
        }
        let trace_digest = store.finalize()?;
        Ok(GeneratedTraceV1 {
            identity: self.identity(),
            rows: self.logical_rows,
            columns,
            public_values: self.public_values(),
            input_digest: self.input_digest(),
            trace_digest,
        })
    }
}

fn validate_trace_target<Word: CanonicalElement, S: BlockMatrix<Word>>(
    store: &S,
    rows: u64,
    columns: usize,
    block_rows: usize,
) -> WorkloadResult<()> {
    if rows == 0
        || !rows.is_power_of_two()
        || store.rows() != rows
        || store.columns() != columns
        || block_rows == 0
        || !block_rows.is_power_of_two()
    {
        return Err(WorkloadError::InvalidShape);
    }
    Ok(())
}

fn workload_input_digest(identity: WorkloadIdentityV1, rows: u64, inputs: &[u64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tinyzkp/plonky3/workload-input/v1\0");
    hasher.update(&(identity.id.len() as u64).to_le_bytes());
    hasher.update(identity.id.as_bytes());
    hasher.update(&identity.version.to_le_bytes());
    hasher.update(&rows.to_le_bytes());
    hasher.update(&(inputs.len() as u64).to_le_bytes());
    for value in inputs {
        hasher.update(&value.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_stream::{BlockMatrix, MemoryMatrix};
    use p3_matrix::Matrix;

    #[test]
    fn fibonacci_public_value_matches_trace_endpoint() {
        for rows in [1, 2, 8, 32, 1024] {
            for (left, right) in [(0, 1), (u64::MAX, 0), (17, u64::MAX)] {
                let public = fibonacci_public_values::<Goldilocks>(left, right, rows);
                let trace = fibonacci_trace::<Goldilocks>(left, right, rows);
                assert_eq!(public[2], *trace.values.last().unwrap());
            }
        }
    }

    #[test]
    fn poseidon2_trace_has_requested_rows() {
        let trace = poseidon2_trace(8, 0);
        assert_eq!(trace.height(), 8);
        assert!(trace.width() > 8);
    }

    #[test]
    fn streamed_fibonacci_matches_owned_reference_across_blocks() {
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 32,
        };
        let mut store =
            MemoryMatrix::<GoldilocksWord>::preallocated(32, FIBONACCI_COLUMNS).unwrap();
        let generated = ResourceBoundedWorkload::<8, 4, GoldilocksProfile>::write_trace(
            &workload, &mut store, 8,
        )
        .unwrap();
        let reference = fibonacci_trace::<Goldilocks>(0, 1, 32);
        let mut words = vec![GoldilocksWord::default(); reference.values.len()];
        store.read_rows(0, 32, &mut words).unwrap();
        assert_eq!(
            words.into_iter().map(|word| word.0).collect::<Vec<_>>(),
            reference.values
        );
        assert_eq!(
            generated.public_values[2],
            *reference.values.last().unwrap()
        );
    }

    #[test]
    fn streamed_poseidon2_matches_owned_reference_across_blocks() {
        let workload = Poseidon2Workload { logical_rows: 16 };
        let columns = workload.air().width();
        let mut store = MemoryMatrix::<GoldilocksWord>::preallocated(16, columns).unwrap();
        workload.write_trace(&mut store, 4).unwrap();
        let reference = poseidon2_trace(16, 0);
        let mut words = vec![GoldilocksWord::default(); reference.values.len()];
        store.read_rows(0, 16, &mut words).unwrap();
        assert_eq!(
            words.into_iter().map(|word| word.0).collect::<Vec<_>>(),
            reference.values
        );
    }
}
