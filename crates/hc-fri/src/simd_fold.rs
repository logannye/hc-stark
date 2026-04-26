//! SIMD specialization for the FRI fold hot path on Goldilocks.
//!
//! The fold operation is `next[i] = pair[0] + beta * pair[1]` over each
//! consecutive pair of values. This is the canonical hot loop in any
//! STARK FRI prover — called log₂(N) times per proof, halving the
//! polynomial each time.
//!
//! `try_fold_goldilocks` accepts a generic `&[F]` slice and a `beta`,
//! checks at runtime whether `F == GoldilocksField`, and if so invokes
//! the packed-field fast path that processes WIDTH lanes at a time.
//! Returns `None` for non-Goldilocks types so the caller falls back to
//! the scalar generic fold.
//!
//! The runtime type check via `TypeId` is the standard pattern for
//! specialization without nightly. Rust's stable trait system can't
//! express "specialize this generic function on a particular type
//! parameter" — `TypeId::of::<F>() == TypeId::of::<GoldilocksField>()`
//! is the workaround. The transmute below is then safe by construction:
//! we only reach it after type-equality is established.

#![allow(unsafe_code)] // localised: only the transmute below uses unsafe.

use std::any::TypeId;

use hc_core::field::prime_field::GoldilocksField;
use hc_core::field::FieldElement;
use hc_simd::PackedGoldilocks;

// We only have a non-trivial SIMD impl behind one of the feature flags.
// Without them, PackedGoldilocks is the scalar4 fallback — still
// correct, but the compiler likely already auto-vectorizes the scalar
// path so we don't claim a perf win.

/// Try to apply the Goldilocks SIMD fold. Returns `None` if `F` is not
/// `GoldilocksField`; in that case the caller should fall back to the
/// generic scalar implementation.
///
/// Output layout: `out[i] = values[2*i] + beta * values[2*i + 1]`.
/// Length contract: `values.len()` must be even and equal `2 * out.len()`.
pub fn try_fold_goldilocks<F: FieldElement>(values: &[F], beta: F) -> Option<Vec<F>> {
    if TypeId::of::<F>() != TypeId::of::<GoldilocksField>() {
        return None;
    }
    // SAFETY: just verified `F` and `GoldilocksField` have the same
    // TypeId. They are therefore the same concrete type and this
    // transmute is a no-op at runtime — it only convinces the
    // type-checker. We never observe `F` through a non-Goldilocks lens
    // inside this branch.
    let values_g: &[GoldilocksField] =
        unsafe { std::mem::transmute::<&[F], &[GoldilocksField]>(values) };
    let beta_g: GoldilocksField = unsafe { std::mem::transmute_copy::<F, GoldilocksField>(&beta) };
    let out_g = fold_goldilocks_simd(values_g, beta_g);
    // SAFETY: same type-equality argument in reverse.
    let out_f: Vec<F> = unsafe { std::mem::transmute::<Vec<GoldilocksField>, Vec<F>>(out_g) };
    Some(out_f)
}

/// Concrete Goldilocks fold using the packed field abstraction. WIDTH
/// pairs are processed per iteration; each iteration packs the even
/// lanes (pair[0]) and odd lanes (pair[1]) into separate packed
/// registers, computes `evens + beta_broadcast * odds`, and stores.
///
/// Tail handling: when the chunk count isn't a multiple of WIDTH, the
/// remainder runs through the scalar path with the same arithmetic.
/// This is what makes the function bit-equivalent to the scalar
/// reference: same op order, same intermediate types.
fn fold_goldilocks_simd(values: &[GoldilocksField], beta: GoldilocksField) -> Vec<GoldilocksField> {
    use hc_core::field::PackedField;

    debug_assert!(values.len() % 2 == 0, "fold_layer: length must be even");
    let pair_count = values.len() / 2;
    let mut out: Vec<GoldilocksField> = Vec::with_capacity(pair_count);

    let width = <PackedGoldilocks as PackedField>::WIDTH;
    let beta_p = PackedGoldilocks::broadcast(beta);

    // Process WIDTH pairs at a time. We materialise even-/odd-lane
    // staging buffers because the values slice interleaves them; a
    // gather-style load (one packed register from strided memory)
    // isn't part of the PackedField API. WIDTH-element staging arrays
    // are stack-allocated and cheap.
    let mut full_chunks = pair_count / width;
    let mut idx = 0usize;
    let mut evens = vec![GoldilocksField::ZERO; width];
    let mut odds = vec![GoldilocksField::ZERO; width];
    let mut out_buf = vec![GoldilocksField::ZERO; width];
    while full_chunks > 0 {
        for lane in 0..width {
            evens[lane] = values[idx + 2 * lane];
            odds[lane] = values[idx + 2 * lane + 1];
        }
        let evens_p = PackedGoldilocks::from_slice(&evens);
        let odds_p = PackedGoldilocks::from_slice(&odds);
        let result_p = PackedField::add(evens_p, PackedField::mul(beta_p, odds_p));
        result_p.to_slice(&mut out_buf);
        out.extend_from_slice(&out_buf);

        idx += 2 * width;
        full_chunks -= 1;
    }

    // Scalar tail.
    while idx < values.len() {
        let lo = values[idx];
        let hi = values[idx + 1];
        out.push(lo.add(beta.mul(hi)));
        idx += 2;
    }

    debug_assert_eq!(out.len(), pair_count);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::FieldElement as _;

    fn det_vec(seed: u64, n: usize) -> Vec<GoldilocksField> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x14_05_7B_7E_F7_67_81_4F);
                GoldilocksField::from_u64(x)
            })
            .collect()
    }

    /// Reference scalar implementation, identical to fold_layer in
    /// crate::layer.
    fn scalar_ref(values: &[GoldilocksField], beta: GoldilocksField) -> Vec<GoldilocksField> {
        let mut out = Vec::with_capacity(values.len() / 2);
        for pair in values.chunks(2) {
            out.push(pair[0].add(beta.mul(pair[1])));
        }
        out
    }

    /// Bit-exact parity: SIMD output must match scalar reference at
    /// every size, including the tail-handling boundary cases.
    #[test]
    fn simd_matches_scalar_at_assorted_sizes() {
        let beta = GoldilocksField::from_u64(0xDEAD_BEEF_CAFE_F00D);
        for &n_pairs in &[1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 64, 128, 1024, 4096] {
            let values = det_vec(n_pairs as u64 + 1, n_pairs * 2);
            let want = scalar_ref(&values, beta);
            let got = fold_goldilocks_simd(&values, beta);
            assert_eq!(got, want, "simd vs scalar mismatch at n_pairs={n_pairs}",);
        }
    }

    #[test]
    fn try_fold_returns_some_for_goldilocks() {
        let values = det_vec(1, 16);
        let beta = GoldilocksField::from_u64(7);
        let got = try_fold_goldilocks::<GoldilocksField>(&values, beta);
        assert!(got.is_some());
        assert_eq!(got.unwrap(), scalar_ref(&values, beta));
    }

    /// Microbench: scalar fold vs SIMD fold at production-sized inputs.
    /// Run with:
    ///     cargo test -p hc-fri --release --features neon \
    ///       simd_fold::tests::bench_fold -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_fold() {
        use std::time::Instant;
        let beta = GoldilocksField::from_u64(0xDEAD_BEEF_CAFE_F00D);
        const ITERS: usize = 50;
        let sizes: &[usize] = &[1024, 4096, 16_384, 65_536, 262_144, 1_048_576];
        println!(
            "{:>10} {:>14} {:>14} {:>10}",
            "n_pairs", "scalar(us)", "simd(us)", "speedup"
        );
        for &n_pairs in sizes {
            let n = n_pairs * 2;
            let values = det_vec(7, n);

            // Scalar warmup + measurement.
            let _ = scalar_ref(&values, beta);
            let t0 = Instant::now();
            for _ in 0..ITERS {
                let r = scalar_ref(&values, beta);
                std::hint::black_box(r);
            }
            let scalar_us = (t0.elapsed().as_secs_f64() * 1_000_000.0) / ITERS as f64;

            // SIMD warmup + measurement.
            let _ = fold_goldilocks_simd(&values, beta);
            let t0 = Instant::now();
            for _ in 0..ITERS {
                let r = fold_goldilocks_simd(&values, beta);
                std::hint::black_box(r);
            }
            let simd_us = (t0.elapsed().as_secs_f64() * 1_000_000.0) / ITERS as f64;

            println!(
                "{:>10} {:>14.2} {:>14.2} {:>9.2}x",
                n_pairs,
                scalar_us,
                simd_us,
                scalar_us / simd_us,
            );
        }
    }

    #[test]
    fn try_fold_returns_none_for_non_goldilocks() {
        // QuadExtension<GoldilocksField> is a real FieldElement that's
        // not the Goldilocks base type — perfect for verifying the
        // TypeId guard rejects non-Goldilocks types without needing a
        // hand-rolled mock.
        use hc_core::field::QuadExtension;

        let values: Vec<QuadExtension<GoldilocksField>> =
            (0..16u64).map(|i| QuadExtension::from_u64(i)).collect();
        let beta = QuadExtension::from_u64(7);
        let got = try_fold_goldilocks::<QuadExtension<GoldilocksField>>(&values, beta);
        assert!(got.is_none(), "non-Goldilocks F must take scalar path");
    }
}
