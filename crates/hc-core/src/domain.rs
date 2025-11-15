//! Evaluation domains built from powers-of-two roots of unity.

use crate::{
    error::{HcError, HcResult},
    field::TwoAdicField,
    utils::{is_power_of_two, log2},
};

/// Multiplicative subgroup used for FFT-style algorithms.
#[derive(Clone)]
pub struct EvaluationDomain<F: TwoAdicField> {
    size: usize,
    log_size: u32,
    generator: F,
    elements: Vec<F>,
}

impl<F: TwoAdicField> EvaluationDomain<F> {
    /// Constructs a new domain of the given size.
    pub fn new(size: usize) -> HcResult<Self> {
        if size == 0 || !is_power_of_two(size) {
            return Err(HcError::invalid_argument(
                "domain size must be a non-zero power of two",
            ));
        }
        let log_size = log2(size);
        if log_size > F::TWO_ADICITY {
            return Err(HcError::invalid_argument(
                "domain size exceeds field two-adicity",
            ));
        }
        let exponent = F::TWO_ADICITY - log_size;
        let primitive_root = F::primitive_root_of_unity();
        let generator = primitive_root.pow(1u64 << exponent);
        let mut elements = Vec::with_capacity(size);
        let mut value = F::ONE;
        for _ in 0..size {
            elements.push(value);
            value = value.mul(generator);
        }
        Ok(Self {
            size,
            log_size,
            generator,
            elements,
        })
    }

    /// Number of elements in the domain.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the generator used to enumerate the domain.
    pub fn generator(&self) -> F {
        self.generator
    }

    /// Returns domain elements.
    pub fn elements(&self) -> &[F] {
        &self.elements
    }

    /// Returns the `i`-th element in the domain.
    pub fn element(&self, index: usize) -> F {
        self.elements[index]
    }

    /// Log2(size) for this domain.
    pub fn log_size(&self) -> u32 {
        self.log_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{prime_field::GoldilocksField, FieldElement};

    #[test]
    fn generator_has_correct_order() {
        let domain = EvaluationDomain::<GoldilocksField>::new(1 << 6).unwrap();
        let w = domain.generator();
        assert_eq!(w.pow(64), GoldilocksField::ONE);
        assert_ne!(w.pow(32), GoldilocksField::ONE);
    }

    #[test]
    fn builder_rejects_invalid_sizes() {
        assert!(EvaluationDomain::<GoldilocksField>::new(0).is_err());
        assert!(EvaluationDomain::<GoldilocksField>::new(3).is_err());
    }
}
