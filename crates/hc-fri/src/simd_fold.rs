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

use hc_core::error::{HcError, HcResult};
use hc_core::field::prime_field::GoldilocksField;
use hc_core::field::FieldElement;
use hc_simd::PackedGoldilocks;

use crate::layer::{batch_invert, LayerDomain};

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

// ------------------------------------------------------------------------- //
// v5: correct antipodal, 1/x fold (spec §3).                                  //
// ------------------------------------------------------------------------- //

/// Try the Goldilocks SIMD fast-path for the v5 (antipodal, 1/x) fold.
///
/// Returns `None` if `F` is not `GoldilocksField`; the caller should then fall
/// back to the generic scalar [`crate::layer::fold_layer_v5`]. (The SIMD
/// fast-path applies only for the Goldilocks base field — falling back to
/// scalar for other fields is acceptable and bit-identical.)
///
/// Output: `out[j] = (a+b)/2 + beta*(a-b)/(2*D[j])` with `a = values[j]`,
/// `b = values[j + n/2]`, matching [`crate::reference::reference_fold`].
pub fn try_fold_goldilocks_v5<F: FieldElement>(
    values: &[F],
    domain: &LayerDomain<F>,
    beta: F,
) -> Option<HcResult<Vec<F>>> {
    if TypeId::of::<F>() != TypeId::of::<GoldilocksField>() {
        return None;
    }
    // SAFETY: TypeId equality established above; `F` and `GoldilocksField` are
    // the same concrete type, so these transmutes are no-ops at runtime and
    // only convince the type-checker.
    let values_g: &[GoldilocksField] =
        unsafe { std::mem::transmute::<&[F], &[GoldilocksField]>(values) };
    let beta_g: GoldilocksField = unsafe { std::mem::transmute_copy::<F, GoldilocksField>(&beta) };
    let domain_g: &LayerDomain<GoldilocksField> =
        unsafe { std::mem::transmute::<&LayerDomain<F>, &LayerDomain<GoldilocksField>>(domain) };
    let out_g = match fold_goldilocks_simd_v5(values_g, domain_g, beta_g) {
        Ok(v) => v,
        Err(e) => return Some(Err(e)),
    };
    // SAFETY: same type-equality argument in reverse.
    let out_f: Vec<F> = unsafe { std::mem::transmute::<Vec<GoldilocksField>, Vec<F>>(out_g) };
    Some(Ok(out_f))
}

/// Concrete Goldilocks v5 fold. Precomputes the per-output `1/(2*D[j])` via a
/// single batch inversion, broadcasts `1/2`, and computes the packed
/// `even + beta*odd` where `even = (a+b)/2` and `odd = (a-b)/(2*D[j])`.
///
/// Unlike the legacy fold, `a = values[j]` and `b = values[j + half]` are each
/// drawn from a *contiguous* half of `values`, so the packed loads are direct
/// (no even/odd staging). A scalar tail handles the non-WIDTH-aligned suffix.
fn fold_goldilocks_simd_v5(
    values: &[GoldilocksField],
    domain: &LayerDomain<GoldilocksField>,
    beta: GoldilocksField,
) -> HcResult<Vec<GoldilocksField>> {
    use hc_core::field::PackedField;

    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument("FRI layer size must be even"));
    }
    let half = values.len() / 2;
    let half_inv = GoldilocksField::from_u64(2)
        .inverse()
        .ok_or_else(|| HcError::math("2 not invertible"))?;

    // inv_two_x[j] = 1 / (2 * D[j]).
    let mut inv_two_x: Vec<GoldilocksField> = (0..half)
        .map(|j| {
            let x = domain.point(j);
            x.add(x)
        })
        .collect();
    batch_invert(&mut inv_two_x)?;

    let mut out: Vec<GoldilocksField> = Vec::with_capacity(half);

    let width = <PackedGoldilocks as PackedField>::WIDTH;
    let beta_p = PackedGoldilocks::broadcast(beta);
    let half_inv_p = PackedGoldilocks::broadcast(half_inv);

    let (lo_vals, hi_vals) = values.split_at(half);

    let full_chunks = half / width;
    let mut j = 0usize;
    let mut out_buf = vec![GoldilocksField::ZERO; width];
    for _ in 0..full_chunks {
        let a_p = PackedGoldilocks::from_slice(&lo_vals[j..j + width]);
        let b_p = PackedGoldilocks::from_slice(&hi_vals[j..j + width]);
        let inv_p = PackedGoldilocks::from_slice(&inv_two_x[j..j + width]);
        // even = (a + b) * (1/2)
        let even_p = PackedField::mul(PackedField::add(a_p, b_p), half_inv_p);
        // odd = (a - b) * (1/(2x))
        let odd_p = PackedField::mul(PackedField::sub(a_p, b_p), inv_p);
        let result_p = PackedField::add(even_p, PackedField::mul(beta_p, odd_p));
        result_p.to_slice(&mut out_buf);
        out.extend_from_slice(&out_buf);
        j += width;
    }

    // Scalar tail.
    while j < half {
        let a = lo_vals[j];
        let b = hi_vals[j];
        let even = a.add(b).mul(half_inv);
        let odd = a.sub(b).mul(inv_two_x[j]);
        out.push(even.add(beta.mul(odd)));
        j += 1;
    }

    debug_assert_eq!(out.len(), half);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            (0..16u64).map(QuadExtension::from_u64).collect();
        let beta = QuadExtension::from_u64(7);
        let got = try_fold_goldilocks::<QuadExtension<GoldilocksField>>(&values, beta);
        assert!(got.is_none(), "non-Goldilocks F must take scalar path");
    }

    // --------------------------------------------------------------------- //
    // v5 parity                                                              //
    // --------------------------------------------------------------------- //

    fn layer_domain(n: usize) -> LayerDomain<GoldilocksField> {
        use hc_core::domain::EvaluationDomain;
        let dom =
            EvaluationDomain::<GoldilocksField>::new_coset(n, GoldilocksField::from_u64(7)).unwrap();
        LayerDomain {
            offset: dom.offset(),
            gen: dom.generator(),
            size: dom.size(),
        }
    }

    /// SIMD-v5 must equal the scalar `fold_layer_v5` at every size. Domain
    /// sizes must be powers of two (coset requirement); the small sizes
    /// (n=2,4,8 -> half=1,2,4) plus the larger ones exercise the WIDTH tail
    /// boundary on both the scalar-WIDTH-1 and NEON-WIDTH-4 packed paths.
    #[test]
    fn simd_v5_matches_scalar_v5() {
        use crate::layer::fold_layer_v5;
        for &n in &[2usize, 4, 8, 16, 32, 64, 128, 256, 1024, 4096] {
            let ld = layer_domain(n);
            let values = det_vec(n as u64 + 1, n);
            let beta = GoldilocksField::from_u64(0xDEAD_BEEF_CAFE_F00D);
            let want = fold_layer_v5(&values, &ld, beta).unwrap();
            let got = fold_goldilocks_simd_v5(&values, &ld, beta).unwrap();
            assert_eq!(got, want, "simd-v5 vs scalar-v5 mismatch at n={n}");
        }
    }

    /// SIMD-v5 vs scalar-v5 parity for half-counts NOT divisible by WIDTH,
    /// forcing the packed-loop-plus-scalar-tail path. The `LayerDomain` here
    /// is synthetic (arbitrary offset/gen) — parity only requires both paths
    /// see the same `domain.point(j)`, which they do; the antipodal property
    /// is irrelevant to SIMD-vs-scalar equivalence.
    #[test]
    fn simd_v5_tail_parity_arbitrary_half() {
        use crate::layer::fold_layer_v5;
        // half = 5,6,7,9,13,17 -> exercises packed chunks + a 1..3 tail at WIDTH=4.
        for &half in &[1usize, 2, 3, 5, 6, 7, 9, 13, 17] {
            let n = half * 2;
            let ld = LayerDomain {
                offset: GoldilocksField::from_u64(7),
                gen: GoldilocksField::from_u64(0x1B0F_3C2D_5E7A_9C11),
                size: n,
            };
            let values = det_vec(31 * half as u64 + 5, n);
            let beta = GoldilocksField::from_u64(0xABCD_1234);
            let want = fold_layer_v5(&values, &ld, beta).unwrap();
            let got = fold_goldilocks_simd_v5(&values, &ld, beta).unwrap();
            assert_eq!(got, want, "simd-v5 tail parity mismatch at half={half}");
        }
    }

    #[test]
    fn try_fold_v5_returns_some_for_goldilocks() {
        use crate::layer::fold_layer_v5;
        let n = 64;
        let ld = layer_domain(n);
        let values = det_vec(1, n);
        let beta = GoldilocksField::from_u64(7);
        let got = try_fold_goldilocks_v5::<GoldilocksField>(&values, &ld, beta);
        assert!(got.is_some());
        assert_eq!(
            got.unwrap().unwrap(),
            fold_layer_v5(&values, &ld, beta).unwrap()
        );
    }

    #[test]
    fn try_fold_v5_returns_none_for_non_goldilocks() {
        use hc_core::field::QuadExtension;
        type Q = QuadExtension<GoldilocksField>;
        let n = 16;
        let values: Vec<Q> = (0..n as u64).map(Q::from_u64).collect();
        let ld: LayerDomain<Q> = LayerDomain {
            offset: Q::from_u64(7),
            gen: Q::from_u64(3),
            size: n,
        };
        let beta = Q::from_u64(7);
        let got = try_fold_goldilocks_v5::<Q>(&values, &ld, beta);
        assert!(got.is_none(), "non-Goldilocks F must take scalar path");
    }
}
