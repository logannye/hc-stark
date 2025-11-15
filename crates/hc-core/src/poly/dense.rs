use crate::{
    domain::EvaluationDomain,
    error::{HcError, HcResult},
    fft::{fft_in_place, ifft_in_place},
    field::{FieldElement, TwoAdicField},
};

/// Dense polynomial in coefficient form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DensePolynomial<F: FieldElement> {
    coeffs: Vec<F>,
}

impl<F: FieldElement> DensePolynomial<F> {
    /// Creates a polynomial from the provided coefficients.
    pub fn new(mut coeffs: Vec<F>) -> Self {
        trim_trailing_zeros(&mut coeffs);
        Self { coeffs }
    }

    /// Zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: vec![] }
    }

    /// Degree of the polynomial (`None` for zero polynomial).
    pub fn degree(&self) -> Option<usize> {
        if self.coeffs.is_empty() {
            None
        } else {
            Some(self.coeffs.len() - 1)
        }
    }

    /// Raw coefficient slice.
    pub fn coefficients(&self) -> &[F] {
        &self.coeffs
    }

    /// Evaluates the polynomial at `point`.
    pub fn evaluate(&self, point: F) -> F {
        self.coeffs
            .iter()
            .rev()
            .fold(F::ZERO, |acc, coeff| acc.mul(point).add(*coeff))
    }

    /// Adds two polynomials.
    pub fn add(&self, rhs: &Self) -> Self {
        let max_len = self.coeffs.len().max(rhs.coeffs.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let a = *self.coeffs.get(i).unwrap_or(&F::ZERO);
            let b = *rhs.coeffs.get(i).unwrap_or(&F::ZERO);
            coeffs.push(a.add(b));
        }
        Self::new(coeffs)
    }

    /// Subtracts two polynomials.
    pub fn sub(&self, rhs: &Self) -> Self {
        let max_len = self.coeffs.len().max(rhs.coeffs.len());
        let mut coeffs = Vec::with_capacity(max_len);
        for i in 0..max_len {
            let a = *self.coeffs.get(i).unwrap_or(&F::ZERO);
            let b = *rhs.coeffs.get(i).unwrap_or(&F::ZERO);
            coeffs.push(a.sub(b));
        }
        Self::new(coeffs)
    }

    /// Scalar multiplication.
    pub fn scale(&self, factor: F) -> Self {
        if factor.is_zero() {
            return Self::zero();
        }
        Self::new(self.coeffs.iter().map(|c| c.mul(factor)).collect())
    }

    /// Naive convolution-based multiplication (sufficient for small degrees).
    pub fn mul(&self, rhs: &Self) -> Self {
        if self.coeffs.is_empty() || rhs.coeffs.is_empty() {
            return Self::zero();
        }
        let mut coeffs = vec![F::ZERO; self.coeffs.len() + rhs.coeffs.len() - 1];
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in rhs.coeffs.iter().enumerate() {
                coeffs[i + j] = coeffs[i + j].add(a.mul(*b));
            }
        }
        Self::new(coeffs)
    }
}

impl<F: TwoAdicField> DensePolynomial<F> {
    /// Constructs a polynomial from point-value form using IFFT.
    pub fn interpolate(domain: &EvaluationDomain<F>, mut values: Vec<F>) -> HcResult<Self> {
        if values.len() != domain.size() {
            return Err(HcError::invalid_argument(
                "value count must equal domain size",
            ));
        }
        ifft_in_place(&mut values)?;
        Ok(Self::new(values))
    }

    /// Evaluates the polynomial over the entire domain via FFT.
    pub fn evaluate_domain(&self, domain: &EvaluationDomain<F>) -> HcResult<Vec<F>> {
        let mut coeffs = self.coeffs.clone();
        if coeffs.len() < domain.size() {
            coeffs.resize(domain.size(), F::ZERO);
        }
        fft_in_place(&mut coeffs)?;
        Ok(coeffs)
    }
}

fn trim_trailing_zeros<F: FieldElement>(coeffs: &mut Vec<F>) {
    while coeffs.last().map_or(false, |c| c.is_zero()) {
        coeffs.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;

    fn poly(coeffs: &[u64]) -> DensePolynomial<GoldilocksField> {
        DensePolynomial::new(coeffs.iter().map(|&c| GoldilocksField::new(c)).collect())
    }

    #[test]
    fn addition_and_multiplication() {
        let a = poly(&[1, 2, 3]);
        let b = poly(&[3, 4]);
        let sum = a.add(&b);
        assert_eq!(
            sum.coefficients(),
            &[
                GoldilocksField::new(4),
                GoldilocksField::new(6),
                GoldilocksField::new(3)
            ]
        );
        let product = a.mul(&b);
        assert_eq!(product.degree(), Some(3));
        assert_eq!(
            product.coefficients(),
            &[
                GoldilocksField::new(3),
                GoldilocksField::new(10),
                GoldilocksField::new(17),
                GoldilocksField::new(12)
            ]
        );
    }

    #[test]
    fn interpolation_roundtrip() {
        let domain = EvaluationDomain::<GoldilocksField>::new(4).unwrap();
        let poly = poly(&[5, 0, 1]);
        let values = poly.evaluate_domain(&domain).unwrap();
        let recovered = DensePolynomial::interpolate(&domain, values).unwrap();
        assert_eq!(poly, recovered);
    }
}
