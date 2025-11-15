use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::oracles::{FriOracle, InMemoryFriOracle};

#[derive(Clone, Debug)]
pub struct FriLayer<F: FieldElement> {
    pub beta: F,
    pub oracle: InMemoryFriOracle<F>,
}

impl<F: FieldElement> FriLayer<F> {
    pub fn len(&self) -> usize {
        self.oracle.len()
    }
}

pub fn fold_layer<F: FieldElement>(values: &[F], beta: F) -> HcResult<Vec<F>> {
    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument(
            "FRI layer size must be even for folding",
        ));
    }
    let mut next = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks(2) {
        next.push(pair[0].add(beta.mul(pair[1])));
    }
    Ok(next)
}
