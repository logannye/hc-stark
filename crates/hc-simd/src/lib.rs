//! Platform-specific SIMD implementations of `PackedField` for the Goldilocks
//! prime field (`p = 2^64 - 2^32 + 1`).
//!
//! This crate is intentionally separated from `hc-core` because SIMD intrinsics
//! require `unsafe` code, and `hc-core` uses `#![forbid(unsafe_code)]`.
//!
//! # STATUS: DORMANT — not yet wired into the prover
//!
//! As of this commit, `hc-simd` has **zero downstream consumers** in the
//! workspace. The NEON, AVX2, and scalar4 backends compile and pass their
//! own tests, but no crate calls them. The hot loops that should consume
//! a `PackedField`-style API still operate on scalar `GoldilocksField`:
//!
//! - `crates/hc-core/src/field/batch_ops.rs` (`mul_slices`,
//!   `add_assign_slices`, `linear_combination`) — sequential scalar loops.
//! - `crates/hc-core/src/fft/radix2.rs` and `tiled_fft.rs` — butterflies
//!   are scalar.
//! - `crates/hc-fri/src/prover.rs` — fold/extension layers.
//!
//! Wiring this in is a perf project of its own. Doing it responsibly
//! requires (a) a scalar-vs-packed property test gate per call site —
//! the same discipline the Goldilocks fast-reduction commit used —
//! (b) CI exercising both arches, and (c) a length threshold below
//! which the scalar path stays (packed setup overhead is real on small
//! inputs).
//!
//! Until that work lands, this crate exists as scaffolding. Do not
//! delete it casually — the NEON and AVX2 code below is non-trivial.
//! But also do not assume reading this crate's presence in `Cargo.toml`
//! means SIMD is active anywhere in the prover. **It is not.**
//!
//! # Available backends
//!
//! - **NEON** (`aarch64`, feature `neon`): 2-wide packed Goldilocks using 128-bit NEON.
//! - **AVX2** (`x86_64`, feature `avx2`): 4-wide packed Goldilocks using 256-bit AVX2.
//! - **Scalar fallback**: Always available via `hc_core::field::ScalarPacked`.
//!
//! # Usage
//!
//! ```ignore
//! use hc_simd::PackedGoldilocks;
//! use hc_core::field::{GoldilocksField, PackedField};
//!
//! let a = PackedGoldilocks::broadcast(GoldilocksField::from_u64(42));
//! let b = PackedGoldilocks::broadcast(GoldilocksField::from_u64(7));
//! let c = a.mul(b); // all lanes = 42 * 7 mod p
//! ```

#[cfg(all(target_arch = "aarch64", feature = "neon"))]
pub mod neon;

#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
pub mod avx2;

pub mod scalar4;

// Re-export the best available packed type as `PackedGoldilocks`.
#[cfg(all(target_arch = "aarch64", feature = "neon"))]
pub type PackedGoldilocks = neon::NeonPackedGoldilocks;

#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
pub type PackedGoldilocks = avx2::Avx2PackedGoldilocks;

#[cfg(not(any(
    all(target_arch = "aarch64", feature = "neon"),
    all(target_arch = "x86_64", feature = "avx2")
)))]
pub type PackedGoldilocks = scalar4::Scalar4Goldilocks;
