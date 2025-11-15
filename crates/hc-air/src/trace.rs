use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

#[derive(Clone, Debug)]
pub struct TraceTable<F: FieldElement> {
    rows: Vec<[F; 2]>,
}

impl<F: FieldElement> TraceTable<F> {
    pub fn new(rows: Vec<[F; 2]>) -> HcResult<Self> {
        if rows.len() < 2 {
            return Err(HcError::invalid_argument(
                "trace must contain at least two rows",
            ));
        }
        Ok(Self { rows })
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn rows(&self) -> &[[F; 2]] {
        &self.rows
    }

    pub fn first(&self) -> &[F; 2] {
        &self.rows[0]
    }

    pub fn last(&self) -> &[F; 2] {
        self.rows.last().expect("trace is non-empty")
    }
}
