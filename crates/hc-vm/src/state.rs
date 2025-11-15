use hc_core::field::FieldElement;

#[derive(Clone, Copy, Debug)]
pub struct VmRow<F: FieldElement> {
    pub accumulator: F,
    pub delta: F,
}

impl<F: FieldElement> VmRow<F> {
    pub fn new(accumulator: F, delta: F) -> Self {
        Self { accumulator, delta }
    }
}
