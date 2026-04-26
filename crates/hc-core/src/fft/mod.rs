//! Fast Fourier Transform primitives.

pub mod backend;
pub mod parallel;
pub mod radix2;
pub mod tiled_fft;

#[cfg(feature = "gpu-fft")]
pub use backend::GpuBackend;
pub use backend::{CpuBackend, FftBackend};
pub use parallel::{fft_parallel, ifft_parallel};
pub use radix2::{fft_in_place, ifft_in_place};
pub use tiled_fft::blocked_fft_in_place;

use crate::{error::HcResult, field::TwoAdicField};

/// Dispatches to the best available FFT backend.
///
/// Priority order:
/// 1. GPU backend (if `gpu-fft` feature enabled and `prefer_gpu` is true)
/// 2. Parallel CPU FFT (Rayon-parallelized butterfly stages)
///
/// The parallel path is always used since it falls through to sequential
/// execution for small inputs where Rayon overhead isn't worthwhile.
pub fn fft_auto<F: TwoAdicField>(values: &mut [F], prefer_gpu: bool) -> HcResult<()> {
    #[cfg(not(feature = "gpu-fft"))]
    let _ = prefer_gpu;
    #[cfg(feature = "gpu-fft")]
    {
        if prefer_gpu {
            return GpuBackend::fft(values);
        }
    }
    // Use parallel FFT which automatically falls back to sequential for small inputs.
    fft_parallel(values)
}

/// Auto-dispatching inverse FFT. See [`fft_auto`] for backend selection.
pub fn ifft_auto<F: TwoAdicField>(values: &mut [F], prefer_gpu: bool) -> HcResult<()> {
    #[cfg(not(feature = "gpu-fft"))]
    let _ = prefer_gpu;
    #[cfg(feature = "gpu-fft")]
    {
        if prefer_gpu {
            // GPU IFFT would go here.
            return ifft_parallel(values);
        }
    }
    ifft_parallel(values)
}
