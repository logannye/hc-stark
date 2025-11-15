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
