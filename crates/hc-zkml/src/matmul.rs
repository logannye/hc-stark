//! Tiled matrix-multiplication AIR primitives.
//!
//! This module is the load-bearing kernel of the zkML prover. Every dense
//! layer, attention block, and (after `im2col`) every convolution lowers to
//! a matrix multiplication, which in turn lowers to the streaming evaluator
//! and constraint relation defined here.
//!
//! ## The AIR in one paragraph
//!
//! For an output entry `C[i, j] = Σ_{k=0}^{K-1} A[i, k] * B[k, j]`, the
//! prover emits a trace of `K` rows. Each row carries a running accumulator
//! `acc[t]`. The transition constraint is
//!
//! ```text
//!     acc[t+1] = acc[t] + A[i, k(t)] * B[k(t), j]
//! ```
//!
//! with boundary `acc[0] = 0` and final `acc[K] = C[i, j]`. Each output
//! entry has its own independent accumulator chain — they are *embarrassingly
//! parallel* across (i, j), and the height-compression discipline applies
//! per-chain.
//!
//! ## Tiling for `O(√K)` working memory
//!
//! We split each chain into `B = ceil(K / tile_dim)` tiles of length
//! `tile_dim ≈ √K`. The prover keeps live, per output entry:
//!
//! - One `tile_dim`-sized slice of `A[i, _]` and `B[_, j]` (replayable from
//!   the input commitment).
//! - One running partial sum (`F`-sized — the inter-tile checkpoint).
//!
//! Once a tile is consumed, it is dropped and the next tile is replayed
//! from the providers. Only `O(tile_dim) = O(√K)` field elements per output
//! chain are alive at any time.
//!
//! ## Field choice
//!
//! All arithmetic is in [`GoldilocksField`] (`p = 2^64 - 2^32 + 1`). Int8
//! quantized inputs lifted into the field stay well below the modulus even
//! for very large `K`: a single product is `≤ 2^16`, and `K = 2^40` partial
//! sums still fit in `2^56 ≪ p`.

use crate::tensor::Tensor;
use hc_core::field::{FieldElement, GoldilocksField as F};
use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

// ── Spec / providers ────────────────────────────────────────────────────────

/// Static description of a matmul: shapes and tile size. The actual matrix
/// data is supplied via the provider traits below so the prover never owns
/// `O(M·K + K·N)` worth of buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatMulSpec {
    pub m: usize,
    pub n: usize,
    pub k: usize,
    pub tile_dim: usize,
}

impl MatMulSpec {
    pub fn new(m: usize, n: usize, k: usize, tile_dim: usize) -> HcResult<Self> {
        if m == 0 || n == 0 || k == 0 {
            return Err(HcError::invalid_argument(format!(
                "matmul shape ({m}, {n}, {k}) has zero dimension"
            )));
        }
        if !tile_dim.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "tile_dim must be a power of two, got {tile_dim}"
            )));
        }
        if tile_dim < 1 {
            return Err(HcError::invalid_argument("tile_dim must be at least 1"));
        }
        Ok(Self { m, n, k, tile_dim })
    }

    /// Number of inner-dim tiles per output chain (last tile may be partial).
    pub fn tiles_per_chain(&self) -> usize {
        self.k.div_ceil(self.tile_dim)
    }

    /// Total number of output entries (`M·N`).
    pub fn output_entries(&self) -> usize {
        self.m * self.n
    }

    /// Total trace length across all chains: `M·N·K`.
    pub fn trace_length(&self) -> usize {
        self.m * self.n * self.k
    }
}

/// Replayable source for the left matrix `A ∈ F^{M×K}`.
///
/// Returns the value at `(row, k)` on demand. Implementations are expected to
/// pull from a witness commitment, on-disk parquet, or — in tests — a flat
/// `Vec<F>`. Importantly, they must not require holding the entire matrix in
/// RAM; the prover only ever asks for one tile-sized window per output entry.
pub trait MatrixA {
    fn rows(&self) -> usize;
    fn cols_inner(&self) -> usize;
    fn read_tile(&self, row: usize, k_start: usize, out: &mut [F]) -> HcResult<()>;
}

/// Replayable source for the right matrix `B ∈ F^{K×N}`.
pub trait MatrixB {
    fn rows_inner(&self) -> usize;
    fn cols(&self) -> usize;
    fn read_tile(&self, k_start: usize, col: usize, out: &mut [F]) -> HcResult<()>;
}

// ── Transition relation ─────────────────────────────────────────────────────

/// One step of the per-chain accumulator recurrence:
///
/// ```text
///     next_acc = prev_acc + a * b
/// ```
#[inline]
pub fn step_transition(prev_acc: F, a: F, b: F) -> F {
    prev_acc.add(a.mul(b))
}

/// The transition *constraint* polynomial, evaluated at a single trace row.
///
/// Returns zero iff the row is consistent — i.e., `next == prev + a * b`.
/// This is the exact polynomial the AIR composer would lower into a STARK
/// transition constraint:
///
/// ```text
///     C(prev, next, a, b) = next - prev - a * b
/// ```
#[inline]
pub fn transition_residual(prev_acc: F, next_acc: F, a: F, b: F) -> F {
    // next - (prev + a*b)
    next_acc.sub(step_transition(prev_acc, a, b))
}

/// Check whether a trace row satisfies the transition constraint.
#[inline]
pub fn check_transition(prev_acc: F, next_acc: F, a: F, b: F) -> bool {
    transition_residual(prev_acc, next_acc, a, b) == F::ZERO
}

// ── Tile-streaming evaluator ────────────────────────────────────────────────

/// One inner-dim tile of an accumulator chain — the unit of replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTile {
    /// Output row.
    pub i: usize,
    /// Output column.
    pub j: usize,
    /// Inclusive start of this tile's `k` range.
    pub k_start: usize,
    /// Length of this tile (≤ `tile_dim`; smaller for the final tile).
    pub len: usize,
    /// Running partial sum *entering* this tile (`acc` at row `k_start`).
    pub entry_partial: F,
    /// Running partial sum *leaving* this tile (`acc` at row `k_start+len`).
    pub exit_partial: F,
}

impl ChainTile {
    /// Whether this is the final tile of its chain (i.e., `exit_partial`
    /// equals the output entry `C[i, j]`).
    pub fn is_final(&self, spec: &MatMulSpec) -> bool {
        self.k_start + self.len == spec.k
    }
}

/// Evaluate one inner-dim tile of the chain `(i, j)` starting at `k_start`,
/// using a tile-sized scratch buffer for `A` and `B`. Returns the resulting
/// tile descriptor including the entry/exit partial sums.
///
/// Working memory for this call is exactly `2 * tile_dim` field elements
/// regardless of `K`.
pub fn evaluate_tile<A: MatrixA, B: MatrixB>(
    spec: &MatMulSpec,
    a: &A,
    b: &B,
    i: usize,
    j: usize,
    k_start: usize,
    entry_partial: F,
    scratch_a: &mut [F],
    scratch_b: &mut [F],
) -> HcResult<ChainTile> {
    if i >= spec.m || j >= spec.n {
        return Err(HcError::invalid_argument(format!(
            "output index ({i}, {j}) out of bounds for ({}, {})",
            spec.m, spec.n
        )));
    }
    if k_start >= spec.k {
        return Err(HcError::invalid_argument(format!(
            "k_start {k_start} exceeds K = {}",
            spec.k
        )));
    }
    let len = spec.tile_dim.min(spec.k - k_start);
    if scratch_a.len() < len || scratch_b.len() < len {
        return Err(HcError::invalid_argument(format!(
            "scratch buffers too small: need {len}, got A={}, B={}",
            scratch_a.len(),
            scratch_b.len()
        )));
    }
    a.read_tile(i, k_start, &mut scratch_a[..len])?;
    b.read_tile(k_start, j, &mut scratch_b[..len])?;
    let mut acc = entry_partial;
    for t in 0..len {
        acc = step_transition(acc, scratch_a[t], scratch_b[t]);
    }
    Ok(ChainTile {
        i,
        j,
        k_start,
        len,
        entry_partial,
        exit_partial: acc,
    })
}

/// Evaluate a complete output entry `C[i, j]` by running every tile of its
/// chain in sequence. Working memory: `O(tile_dim)` field elements.
///
/// This is the per-entry kernel of the streaming prover. Real proving will
/// emit constraint witnesses (one per trace row) as it goes, but the
/// arithmetic is identical.
pub fn evaluate_entry<A: MatrixA, B: MatrixB>(
    spec: &MatMulSpec,
    a: &A,
    b: &B,
    i: usize,
    j: usize,
) -> HcResult<F> {
    let mut sa = vec![F::ZERO; spec.tile_dim];
    let mut sb = vec![F::ZERO; spec.tile_dim];
    let mut k_start = 0usize;
    let mut partial = F::ZERO;
    while k_start < spec.k {
        let tile = evaluate_tile(spec, a, b, i, j, k_start, partial, &mut sa, &mut sb)?;
        partial = tile.exit_partial;
        k_start += tile.len;
    }
    Ok(partial)
}

/// Evaluate the full output matrix in row-major order, streaming one entry
/// at a time. Peak working memory: `O(tile_dim)` field elements regardless
/// of `M`, `N`, or `K`.
pub fn evaluate_streaming<A: MatrixA, B: MatrixB>(
    spec: &MatMulSpec,
    a: &A,
    b: &B,
) -> HcResult<Vec<F>> {
    let mut out = Vec::with_capacity(spec.output_entries());
    for i in 0..spec.m {
        for j in 0..spec.n {
            out.push(evaluate_entry(spec, a, b, i, j)?);
        }
    }
    Ok(out)
}

// ── Reference (naive) evaluator ─────────────────────────────────────────────

/// Reference implementation that materializes nothing intelligently — pure
/// triple-loop over field elements. Used in tests to cross-check the
/// streaming evaluator.
pub fn evaluate_naive<A: MatrixA, B: MatrixB>(
    spec: &MatMulSpec,
    a: &A,
    b: &B,
) -> HcResult<Vec<F>> {
    let mut sa = vec![F::ZERO; spec.tile_dim];
    let mut sb = vec![F::ZERO; spec.tile_dim];
    let mut out = Vec::with_capacity(spec.output_entries());
    for i in 0..spec.m {
        for j in 0..spec.n {
            // Read a row of A and a column of B in tile-sized chunks (not for
            // memory reasons here — just to reuse the trait API), and sum.
            let mut acc = F::ZERO;
            let mut k_start = 0usize;
            while k_start < spec.k {
                let len = spec.tile_dim.min(spec.k - k_start);
                a.read_tile(i, k_start, &mut sa[..len])?;
                b.read_tile(k_start, j, &mut sb[..len])?;
                for t in 0..len {
                    acc = acc.add(sa[t].mul(sb[t]));
                }
                k_start += len;
            }
            out.push(acc);
        }
    }
    Ok(out)
}

// ── Tensor-backed providers (suitable for test fixtures and small models) ──

/// A simple `Vec<F>`-backed `MatrixA` implementation.
pub struct DenseMatrixA {
    pub rows: usize,
    pub inner: usize,
    /// Row-major: element `(i, k)` is at `data[i*inner + k]`.
    pub data: Vec<F>,
}

impl DenseMatrixA {
    pub fn from_i32(rows: usize, inner: usize, src: &[i32]) -> HcResult<Self> {
        if src.len() != rows * inner {
            return Err(HcError::invalid_argument(format!(
                "DenseMatrixA: expected {} elements, got {}",
                rows * inner,
                src.len()
            )));
        }
        Ok(Self {
            rows,
            inner,
            data: src.iter().map(|&v| i32_to_field(v)).collect(),
        })
    }
}

impl MatrixA for DenseMatrixA {
    fn rows(&self) -> usize {
        self.rows
    }
    fn cols_inner(&self) -> usize {
        self.inner
    }
    fn read_tile(&self, row: usize, k_start: usize, out: &mut [F]) -> HcResult<()> {
        if row >= self.rows || k_start + out.len() > self.inner {
            return Err(HcError::invalid_argument(format!(
                "DenseMatrixA tile ({row}, {k_start}, len={}) out of bounds",
                out.len()
            )));
        }
        let base = row * self.inner + k_start;
        out.copy_from_slice(&self.data[base..base + out.len()]);
        Ok(())
    }
}

/// A simple `Vec<F>`-backed `MatrixB` implementation.
pub struct DenseMatrixB {
    pub inner: usize,
    pub cols: usize,
    /// Row-major: element `(k, j)` is at `data[k*cols + j]`.
    pub data: Vec<F>,
}

impl DenseMatrixB {
    pub fn from_i32(inner: usize, cols: usize, src: &[i32]) -> HcResult<Self> {
        if src.len() != inner * cols {
            return Err(HcError::invalid_argument(format!(
                "DenseMatrixB: expected {} elements, got {}",
                inner * cols,
                src.len()
            )));
        }
        Ok(Self {
            inner,
            cols,
            data: src.iter().map(|&v| i32_to_field(v)).collect(),
        })
    }
}

impl MatrixB for DenseMatrixB {
    fn rows_inner(&self) -> usize {
        self.inner
    }
    fn cols(&self) -> usize {
        self.cols
    }
    fn read_tile(&self, k_start: usize, col: usize, out: &mut [F]) -> HcResult<()> {
        if col >= self.cols || k_start + out.len() > self.inner {
            return Err(HcError::invalid_argument(format!(
                "DenseMatrixB tile ({k_start}, {col}, len={}) out of bounds",
                out.len()
            )));
        }
        for (t, slot) in out.iter_mut().enumerate() {
            *slot = self.data[(k_start + t) * self.cols + col];
        }
        Ok(())
    }
}

// ── Quantized-input lifting ────────────────────────────────────────────────

/// Lift a signed int8/int16/int32 into the field. Negative values map to
/// their additive inverse (`p - |v|`), so multiplication/addition stays in
/// the standard `Z/pZ` semantics.
#[inline]
pub fn i32_to_field(v: i32) -> F {
    if v >= 0 {
        F::new(v as u64)
    } else {
        // -|v| mod p
        F::ZERO.sub(F::new((-(v as i64)) as u64))
    }
}

/// Lift a [`Tensor`] backed by signed quantized integers into a flat field
/// vector in the tensor's stored row-major order.
pub fn tensor_to_field_vec(t: &Tensor) -> Vec<F> {
    t.data.iter().map(|&v| i32_to_field(v)).collect()
}

/// Build a `DenseMatrixA` from a 2-D [`Tensor`].
pub fn dense_matrix_a_from_tensor(t: &Tensor) -> HcResult<DenseMatrixA> {
    if t.shape.rank() != 2 {
        return Err(HcError::invalid_argument(format!(
            "expected rank-2 tensor for matrix A, got rank {}",
            t.shape.rank()
        )));
    }
    let rows = t.shape.0[0];
    let inner = t.shape.0[1];
    Ok(DenseMatrixA {
        rows,
        inner,
        data: tensor_to_field_vec(t),
    })
}

/// Build a `DenseMatrixB` from a 2-D [`Tensor`].
pub fn dense_matrix_b_from_tensor(t: &Tensor) -> HcResult<DenseMatrixB> {
    if t.shape.rank() != 2 {
        return Err(HcError::invalid_argument(format!(
            "expected rank-2 tensor for matrix B, got rank {}",
            t.shape.rank()
        )));
    }
    let inner = t.shape.0[0];
    let cols = t.shape.0[1];
    Ok(DenseMatrixB {
        inner,
        cols,
        data: tensor_to_field_vec(t),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn small_random_field_vec(seed: u64, n: usize, range_log2: u32) -> Vec<F> {
        // Tiny LCG so we don't pull in the rand crate just for tests.
        let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mask: u64 = (1u64 << range_log2) - 1;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                F::new(x & mask)
            })
            .collect()
    }

    fn dense_pair(m: usize, n: usize, k: usize, seed: u64) -> (DenseMatrixA, DenseMatrixB) {
        let a = DenseMatrixA {
            rows: m,
            inner: k,
            data: small_random_field_vec(seed, m * k, 8),
        };
        let b = DenseMatrixB {
            inner: k,
            cols: n,
            data: small_random_field_vec(seed ^ 0xdeadbeef, k * n, 8),
        };
        (a, b)
    }

    #[test]
    fn spec_validates() {
        assert!(MatMulSpec::new(0, 1, 1, 4).is_err());
        assert!(MatMulSpec::new(1, 1, 1, 3).is_err()); // not POT
        let s = MatMulSpec::new(4, 5, 8, 4).unwrap();
        assert_eq!(s.tiles_per_chain(), 2);
        assert_eq!(s.output_entries(), 20);
        assert_eq!(s.trace_length(), 4 * 5 * 8);
    }

    #[test]
    fn transition_residual_is_zero_on_consistent_row() {
        let prev = F::new(7);
        let a = F::new(3);
        let b = F::new(5);
        let next = step_transition(prev, a, b);
        assert!(check_transition(prev, next, a, b));
        assert_eq!(transition_residual(prev, next, a, b), F::ZERO);
    }

    #[test]
    fn transition_residual_is_nonzero_on_corruption() {
        let prev = F::new(7);
        let a = F::new(3);
        let b = F::new(5);
        let bogus = F::new(99);
        assert!(!check_transition(prev, bogus, a, b));
    }

    #[test]
    fn streaming_matches_naive_small() {
        let (a, b) = dense_pair(3, 4, 8, 1);
        let spec = MatMulSpec::new(3, 4, 8, 4).unwrap();
        let s = evaluate_streaming(&spec, &a, &b).unwrap();
        let n = evaluate_naive(&spec, &a, &b).unwrap();
        assert_eq!(s, n);
    }

    #[test]
    fn streaming_matches_naive_partial_tail_tile() {
        // K = 10 with tile_dim = 4 → tiles of (4, 4, 2).
        let (a, b) = dense_pair(2, 3, 10, 7);
        let spec = MatMulSpec::new(2, 3, 10, 4).unwrap();
        let s = evaluate_streaming(&spec, &a, &b).unwrap();
        let n = evaluate_naive(&spec, &a, &b).unwrap();
        assert_eq!(s, n);
    }

    #[test]
    fn streaming_matches_naive_tile_size_one() {
        // tile_dim = 1 reduces to per-element streaming — should still match.
        let (a, b) = dense_pair(2, 2, 5, 11);
        let spec = MatMulSpec::new(2, 2, 5, 1).unwrap();
        let s = evaluate_streaming(&spec, &a, &b).unwrap();
        let n = evaluate_naive(&spec, &a, &b).unwrap();
        assert_eq!(s, n);
    }

    #[test]
    fn streaming_matches_naive_larger_with_pot_tile() {
        // K = 64, tile_dim = 8 → 8 full tiles per chain.
        let (a, b) = dense_pair(4, 5, 64, 42);
        let spec = MatMulSpec::new(4, 5, 64, 8).unwrap();
        let s = evaluate_streaming(&spec, &a, &b).unwrap();
        let n = evaluate_naive(&spec, &a, &b).unwrap();
        assert_eq!(s, n);
    }

    #[test]
    fn evaluate_entry_satisfies_transition_constraints_per_row() {
        // Walk one chain (i=1, j=2) row-by-row and assert the transition
        // constraint holds at every step.
        let (a, b) = dense_pair(2, 3, 16, 99);
        let spec = MatMulSpec::new(2, 3, 16, 4).unwrap();
        let i = 1;
        let j = 2;
        let mut sa = vec![F::ZERO; spec.tile_dim];
        let mut sb = vec![F::ZERO; spec.tile_dim];
        let mut prev = F::ZERO;
        let mut k_start = 0;
        while k_start < spec.k {
            let len = spec.tile_dim.min(spec.k - k_start);
            a.read_tile(i, k_start, &mut sa[..len]).unwrap();
            b.read_tile(k_start, j, &mut sb[..len]).unwrap();
            for t in 0..len {
                let next = step_transition(prev, sa[t], sb[t]);
                assert!(
                    check_transition(prev, next, sa[t], sb[t]),
                    "row {k_start}+{t}: transition residual nonzero"
                );
                prev = next;
            }
            k_start += len;
        }
        // Final accumulator must equal the streaming evaluator's output.
        let want = evaluate_entry(&spec, &a, &b, i, j).unwrap();
        assert_eq!(prev, want);
    }

    #[test]
    fn i32_to_field_handles_negatives() {
        let neg_one = i32_to_field(-1);
        let one = F::new(1);
        // -1 + 1 == 0 in the field
        assert_eq!(neg_one.add(one), F::ZERO);
    }

    #[test]
    fn tensor_to_field_lifts_quantized_int8() {
        use crate::tensor::{Quantization, Shape, Tensor};
        let t = Tensor::new(
            Shape::matrix(2, 3),
            Quantization::int8(1.0),
            vec![1, -1, 0, 5, -5, 7],
        )
        .unwrap();
        let v = tensor_to_field_vec(&t);
        assert_eq!(v.len(), 6);
        assert_eq!(v[0], F::new(1));
        assert_eq!(v[1].add(F::new(1)), F::ZERO);
        assert_eq!(v[2], F::ZERO);
    }
}
