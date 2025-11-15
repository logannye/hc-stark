use super::radix2::fft_in_place;
use crate::{error::HcResult, field::TwoAdicField};

pub trait FftBackend<F: TwoAdicField> {
    fn fft(values: &mut [F]) -> HcResult<()>;
}

pub struct CpuBackend;

impl<F: TwoAdicField> FftBackend<F> for CpuBackend {
    fn fft(values: &mut [F]) -> HcResult<()> {
        fft_in_place(values)
    }
}

#[cfg(feature = "gpu-fft")]
pub struct GpuBackend;

#[cfg(feature = "gpu-fft")]
impl<F: TwoAdicField> FftBackend<F> for GpuBackend {
    fn fft(values: &mut [F]) -> HcResult<()> {
        // Placeholder: GPU backend currently routes to the CPU path while the CUDA/OpenCL
        // kernels are being integrated.
        fft_in_place(values)
    }
}
