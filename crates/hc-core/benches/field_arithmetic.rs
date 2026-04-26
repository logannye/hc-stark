//! Criterion regression benches for the Goldilocks field hot loops.
//!
//! These exist to lock in the perf wins from:
//! - The Goldilocks fast reduction (replaced `value % MODULUS_U128`)
//! - The rayon-parallelized batch ops (PAR_THRESHOLD=1024)
//!
//! Run locally:
//!     cargo bench -p hc-core --bench field_arithmetic
//!
//! Compare against a baseline (typical CI gate workflow):
//!     # On main:
//!     cargo bench -p hc-core --bench field_arithmetic -- --save-baseline main
//!     # On a PR:
//!     cargo bench -p hc-core --bench field_arithmetic -- --baseline main
//!
//! Inputs are seeded so a noisy host reproduces the same numbers across
//! runs.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hc_core::field::batch_ops::{add_assign_slices, mul_assign_slices, mul_slices};
use hc_core::field::prime_field::{GoldilocksField, GOLDILOCKS_MODULUS};
use hc_core::field::FieldElement;

/// Simple LCG-style seeded source so bench inputs are deterministic
/// across runs and machines. Matches the pattern used in the unit-test
/// `deterministic_field_vec`.
fn seeded_field_vec(seed: u64, n: usize) -> Vec<GoldilocksField> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x14_05_7B_7E_F7_67_81_4F);
            GoldilocksField(x % GOLDILOCKS_MODULUS)
        })
        .collect()
}

/// Single-element field multiplication. Tracks the Goldilocks fast
/// reduction primitive directly. A regression here is the most expensive
/// possible — every prover phase that touches field arithmetic slows
/// proportionally.
fn bench_single_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_mul_scalar");
    let a = GoldilocksField::from_u64(0x1234_5678_9ABC_DEF0);
    let b = GoldilocksField::from_u64(0x0FED_CBA9_8765_4321);
    group.throughput(Throughput::Elements(1));
    group.bench_function("single", |bencher| {
        bencher.iter(|| {
            let r = black_box(a).mul(black_box(b));
            black_box(r)
        });
    });
    group.finish();
}

/// Slice-wise multiplication across the parallelization threshold.
/// Sweeps 4 sizes that span the scalar→parallel transition so a
/// regression at any size shows up. Throughput labels make
/// `criterion --baseline` comparisons meaningful (M elements/sec, not
/// total wall time).
fn bench_mul_slices_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("mul_slices");
    for &n in &[256_usize, 1024, 16_384, 1_048_576] {
        let a = seeded_field_vec(1, n);
        let b = seeded_field_vec(2, n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bencher, _| {
            bencher.iter(|| {
                let r = mul_slices(black_box(&a), black_box(&b));
                black_box(r);
            });
        });
    }
    group.finish();
}

/// In-place mul_assign_slices — covers the par_iter_mut path. Same
/// rationale as the read-only sweep above.
fn bench_mul_assign_slices_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("mul_assign_slices");
    for &n in &[256_usize, 1024, 16_384, 1_048_576] {
        let b = seeded_field_vec(3, n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bencher, _| {
            bencher.iter_batched(
                || seeded_field_vec(4, n),
                |mut a| {
                    mul_assign_slices(&mut a, black_box(&b));
                    black_box(a);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// add_assign_slices — same shape as mul_assign but exercises the add
/// reduction (cheaper per-op than mul). Lets a future regression on
/// just one of {add, mul} surface independently.
fn bench_add_assign_slices_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_assign_slices");
    for &n in &[256_usize, 1024, 16_384, 1_048_576] {
        let b = seeded_field_vec(5, n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bencher, _| {
            bencher.iter_batched(
                || seeded_field_vec(6, n),
                |mut a| {
                    add_assign_slices(&mut a, black_box(&b));
                    black_box(a);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_single_mul,
    bench_mul_slices_sweep,
    bench_mul_assign_slices_sweep,
    bench_add_assign_slices_sweep,
);
criterion_main!(benches);
