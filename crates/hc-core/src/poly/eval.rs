//! Helper functions for evaluating polynomials at various points.

use crate::field::FieldElement;

/// Horner evaluation for a polynomial represented by coefficients in ascending order.
pub fn horner<F: FieldElement>(coeffs: &[F], point: F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc.mul(point).add(*coeff))
}

/// Naively evaluate the polynomial at multiple points.
pub fn evaluate_batch<F: FieldElement>(coeffs: &[F], points: &[F]) -> Vec<F> {
    points.iter().map(|&p| horner(coeffs, p)).collect()
}

/// Computes the value of the `index`-th Lagrange basis polynomial at `point`.
pub fn lagrange_basis<F: FieldElement>(domain: &[F], index: usize, point: F) -> F {
    let xi = domain[index];
    let mut numerator = F::ONE;
    let mut denominator = F::ONE;
    for (j, &xj) in domain.iter().enumerate() {
        if j == index {
            continue;
        }
        numerator = numerator.mul(point.sub(xj));
        denominator = denominator.mul(xi.sub(xj));
    }
    numerator.mul(denominator.inverse().expect("non-zero denominator"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;

    #[test]
    fn horner_matches_manual_eval() {
        let coeffs = [
            GoldilocksField::new(1),
            GoldilocksField::new(2),
            GoldilocksField::new(3),
        ];
        let point = GoldilocksField::new(5);
        let expected = coeffs[0]
            .add(coeffs[1].mul(point))
            .add(coeffs[2].mul(point.square()));
        assert_eq!(horner(&coeffs, point), expected);
    }

    #[test]
    fn lagrange_basis_interpolates() {
        let domain = [
            GoldilocksField::new(0),
            GoldilocksField::new(1),
            GoldilocksField::new(2),
        ];
        let point = GoldilocksField::new(3);
        let mut acc = GoldilocksField::ZERO;
        for i in 0..domain.len() {
            acc = acc.add(lagrange_basis(&domain, i, point));
        }
        assert_eq!(acc, GoldilocksField::ONE);
    }
}
