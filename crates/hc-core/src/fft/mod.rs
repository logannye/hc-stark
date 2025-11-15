//! Fast Fourier Transform primitives.

pub mod backend;
pub mod radix2;
pub mod tiled_fft;

#[cfg(feature = "gpu-fft")]
pub use backend::GpuBackend;
pub use backend::{CpuBackend, FftBackend};
pub use radix2::{fft_in_place, ifft_in_place};
pub use tiled_fft::blocked_fft_in_place;

use crate::{error::HcResult, field::TwoAdicField};

/// Dispatches to the CPU backend by default, but can opt-in to the GPU backend
/// (when the `gpu-fft` feature is enabled) for the heavy-weight layers.
pub fn fft_auto<F: TwoAdicField>(values: &mut [F], prefer_gpu: bool) -> HcResult<()> {
    #[cfg(not(feature = "gpu-fft"))]
    let _ = prefer_gpu;
    #[cfg(feature = "gpu-fft")]
    {
        if prefer_gpu {
            return GpuBackend::fft(values);
        }
    }
    CpuBackend::fft(values)
}
