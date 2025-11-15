use crate::field::FieldElement;

/// Single sparse term `coeff * x^degree`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparseTerm<F: FieldElement> {
    pub coeff: F,
    pub degree: usize,
}

/// Sparse polynomial represented as a list of terms.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SparsePolynomial<F: FieldElement> {
    terms: Vec<SparseTerm<F>>,
}

impl<F: FieldElement> SparsePolynomial<F> {
    pub fn new(mut terms: Vec<SparseTerm<F>>) -> Self {
        terms.retain(|term| !term.coeff.is_zero());
        terms.sort_by_key(|term| term.degree);
        Self { terms }
    }

    pub fn terms(&self) -> &[SparseTerm<F>] {
        &self.terms
    }

    pub fn evaluate(&self, point: F) -> F {
        self.terms.iter().fold(F::ZERO, |acc, term| {
            acc.add(term.coeff.mul(point.pow(term.degree as u64)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::prime_field::GoldilocksField;

    #[test]
    fn sparse_eval_matches_dense() {
        let sparse = SparsePolynomial::new(vec![
            SparseTerm {
                coeff: GoldilocksField::new(5),
                degree: 0,
            },
            SparseTerm {
                coeff: GoldilocksField::new(3),
                degree: 5,
            },
        ]);
        let point = GoldilocksField::new(7);
        let expected = GoldilocksField::new(5).add(GoldilocksField::new(3).mul(point.pow(5)));
        assert_eq!(sparse.evaluate(point), expected);
    }
}
