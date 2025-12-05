//! Helper functions for evaluating polynomials at various points.

use crate::field::FieldElement;
use rayon::prelude::*;

/// Low-Degree Extension (LDE) for STARK trace values.
/// Extends trace values from a small domain to a larger domain for low-degree testing.
pub fn lde_block<F: FieldElement>(
    trace_values: &[F],
    trace_domain: &[F],
    lde_domain: &[F],
) -> Vec<F> {
    // Interpolate the trace values to get polynomial coefficients
    let coeffs = interpolate(trace_values, trace_domain);

    // Evaluate the polynomial on the larger LDE domain
    evaluate_batch(&coeffs, lde_domain)
}

/// Interpolate values on a domain to get polynomial coefficients.
/// Uses Lagrange interpolation (suitable for small domains).
pub fn interpolate<F: FieldElement>(values: &[F], domain: &[F]) -> Vec<F> {
    assert_eq!(values.len(), domain.len());

    let n = values.len();
    let mut coeffs = vec![F::ZERO; n];

    for (i, &value) in values.iter().enumerate() {
        let basis_coeffs = lagrange_coefficients(domain, i);
        for (coeff, basis) in coeffs.iter_mut().zip(basis_coeffs.iter()) {
            *coeff = coeff.add(basis.mul(value));
        }
    }

    coeffs
}

/// Get the coefficients of the i-th Lagrange basis polynomial.
fn lagrange_coefficients<F: FieldElement>(domain: &[F], index: usize) -> Vec<F> {
    let n = domain.len();
    let xi = domain[index];

    // Start with constant polynomial 1
    let mut coeffs = vec![F::ZERO; n];
    coeffs[0] = F::ONE;

    // Multiply by (x - xj) for j != i
    for (j, &xj) in domain.iter().enumerate() {
        if j == index {
            continue;
        }

        // Multiply current polynomial by (x - xj)
        let mut new_coeffs = vec![F::ZERO; n];
        for k in 0..n {
            if k > 0 {
                new_coeffs[k] = new_coeffs[k].add(coeffs[k - 1]);
            }
            new_coeffs[k] = new_coeffs[k].sub(coeffs[k].mul(xj));
        }
        coeffs = new_coeffs;
    }

    // Normalize by the denominator
    let mut denominator = F::ONE;
    for (j, &xj) in domain.iter().enumerate() {
        if j == index {
            continue;
        }
        denominator = denominator.mul(xi.sub(xj));
    }

    let denominator_inv = denominator.inverse().expect("non-zero denominator");
    for coeff in &mut coeffs {
        *coeff = coeff.mul(denominator_inv);
    }

    coeffs
}

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

/// Evaluate multiple columns (sets of coefficients) over the same domain in parallel.
pub fn evaluate_columns_parallel<F: FieldElement>(
    coeff_columns: &[&[F]],
    points: &[F],
) -> Vec<Vec<F>> {
    coeff_columns
        .par_iter()
        .map(|coeffs| evaluate_batch(coeffs, points))
        .collect()
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
