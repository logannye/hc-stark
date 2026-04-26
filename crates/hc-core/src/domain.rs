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
    offset: F,
    elements: Vec<F>,
}

impl<F: TwoAdicField> EvaluationDomain<F> {
    /// Constructs a new domain of the given size.
    pub fn new(size: usize) -> HcResult<Self> {
        Self::new_coset(size, F::ONE)
    }

    /// Constructs a new multiplicative coset domain `offset * <omega>`.
    pub fn new_coset(size: usize, offset: F) -> HcResult<Self> {
        if size == 0 || !is_power_of_two(size) {
            return Err(HcError::invalid_argument(
                "domain size must be a non-zero power of two",
            ));
        }
        if offset.is_zero() {
            return Err(HcError::invalid_argument("domain offset must be non-zero"));
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
        let mut value = offset;
        for _ in 0..size {
            elements.push(value);
            value = value.mul(generator);
        }
        Ok(Self {
            size,
            log_size,
            generator,
            offset,
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

    /// Returns the coset offset (1 for a pure subgroup domain).
    pub fn offset(&self) -> F {
        self.offset
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

/// Generate a Low-Degree Extension domain for a trace of the given length.
/// The LDE domain is typically 2-4x larger than the trace domain for security.
pub fn generate_lde_domain<F: TwoAdicField>(
    trace_length: usize,
    blowup_factor: usize,
) -> HcResult<EvaluationDomain<F>> {
    if blowup_factor < 1 {
        return Err(HcError::invalid_argument(
            "blowup factor must be at least 1",
        ));
    }

    let lde_size = trace_length * blowup_factor;
    if !is_power_of_two(lde_size) {
        return Err(HcError::invalid_argument(
            "LDE domain size must be a power of two",
        ));
    }

    EvaluationDomain::new(lde_size)
}

/// Generate a Low-Degree Extension domain on a multiplicative coset.
///
/// This is required for quotienting by `Z_H(X) = X^N - 1` (where `N = trace_length`),
/// since `Z_H` would vanish on the trace subgroup `H` itself.
pub fn generate_lde_coset_domain<F: TwoAdicField>(
    trace_length: usize,
    blowup_factor: usize,
    offset: F,
) -> HcResult<EvaluationDomain<F>> {
    if blowup_factor < 1 {
        return Err(HcError::invalid_argument(
            "blowup factor must be at least 1",
        ));
    }
    let lde_size = trace_length * blowup_factor;
    if !is_power_of_two(lde_size) {
        return Err(HcError::invalid_argument(
            "LDE domain size must be a power of two",
        ));
    }
    EvaluationDomain::new_coset(lde_size, offset)
}

/// Generate the standard trace domain for a given trace length.
pub fn generate_trace_domain<F: TwoAdicField>(
    trace_length: usize,
) -> HcResult<EvaluationDomain<F>> {
    if !is_power_of_two(trace_length) {
        return Err(HcError::invalid_argument(
            "trace length must be a power of two",
        ));
    }

    EvaluationDomain::new(trace_length)
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
