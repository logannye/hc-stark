//! Platform-specific SIMD implementations of `PackedField` for the Goldilocks
//! prime field (`p = 2^64 - 2^32 + 1`).
//!
//! This crate is intentionally separated from `hc-core` because SIMD intrinsics
//! require `unsafe` code, and `hc-core` uses `#![forbid(unsafe_code)]`.
//!
//! # STATUS: WIRED — first consumer is the FRI fold hot path
//!
//! `crates/hc-fri/src/simd_fold.rs` consumes `PackedGoldilocks` via a
//! TypeId-gated specialization on the `fold_layer` operation
//! (`out[i] = pair[0] + beta * pair[1]`), the canonical hottest loop
//! in any STARK FRI prover. Bench numbers on M4 Max (aarch64):
//!
//!     n_pairs    scalar(us)   simd(us)   speedup
//!     16384       24.34       17.98       1.35x
//!     65536       92.65       70.87       1.31x
//!     262144     393.31      285.52       1.38x
//!     1048576   1533.94     1118.12       1.37x
//!
//! The win compounds across log₂(N) FRI folds per proof. Notably,
//! the speedup is roughly identical with `--features neon` and
//! without — the compiler auto-vectorizes the scalar4 fallback's
//! 4-wide structure on its own. NEON intrinsics give a tiny
//! incremental gain on top.
//!
//! ## Other call sites still pending
//!
//! These hot loops are still scalar; wiring them is straightforward
//! follow-up work using the same TypeId-specialization pattern:
//!
//! - `crates/hc-core/src/field/batch_ops.rs` (`mul_slices`,
//!   `add_assign_slices`, `linear_combination`) — would need the
//!   helper to live in a separate crate to avoid the hc-core ↔
//!   hc-simd dependency cycle. Most direct path: a new `hc-batch-ops`
//!   crate.
//! - `crates/hc-core/src/fft/radix2.rs` and `tiled_fft.rs` —
//!   butterfly stages. Same crate-cycle constraint as batch_ops.
//! - DEEP-OOD composition oracle in `hc-prover` — already in a leaf
//!   crate; could pull `hc-simd` directly.
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
