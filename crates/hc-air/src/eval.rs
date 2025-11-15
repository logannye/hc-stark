use hc_core::error::HcResult;

use crate::{
    constraints::{boundary::BoundaryConstraints, composition},
    trace::TraceTable,
};

#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn evaluate<F: hc_core::field::FieldElement>(
    trace: &TraceTable<F>,
    public_inputs: PublicInputs<F>,
) -> HcResult<()> {
    let boundary = BoundaryConstraints {
        initial_acc: public_inputs.initial_acc,
        final_acc: public_inputs.final_acc,
    };
    composition::enforce(trace, &boundary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    #[test]
    fn simple_trace_satisfies_constraints() {
        let rows = vec![
            [GoldilocksField::new(5), GoldilocksField::new(1)],
            [GoldilocksField::new(6), GoldilocksField::new(2)],
            [GoldilocksField::new(8), GoldilocksField::new(0)],
        ];
        let trace = TraceTable::new(rows).unwrap();
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        evaluate(&trace, public_inputs).unwrap();
    }
}
