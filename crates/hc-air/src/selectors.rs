//! Instruction selector columns for degree-2 constraint optimization.
//!
//! In a VM AIR, each instruction type has its own transition constraints.
//! Rather than using a single opcode column and comparing against each possible
//! value (which requires high-degree constraints), we use binary selector
//! columns: one per instruction, where exactly one is 1 and the rest are 0.
//!
//! This lets us write degree-2 constraints: `selector_i * constraint_i(row)`.
//!
//! Trade-off: more columns (one per instruction) but lower constraint degree
//! (degree 2 instead of degree = num_opcodes). For FRI-based STARKs, lower
//! degree means fewer blowup rounds and smaller proofs.

use hc_core::field::FieldElement;

/// Generate binary selector columns from an opcode column.
///
/// Given a column of opcode values `[0, num_opcodes)`, produces `num_opcodes`
/// binary columns where column `i` is 1 wherever the opcode equals `i`.
///
/// # Panics
///
/// Panics if any opcode value is >= `num_opcodes`.
pub fn opcode_to_selectors<F: FieldElement>(opcodes: &[F], num_opcodes: usize) -> Vec<Vec<F>> {
    let n = opcodes.len();
    let mut selectors = vec![vec![F::ZERO; n]; num_opcodes];
    for (row_idx, &opcode) in opcodes.iter().enumerate() {
        let op = opcode.to_u64() as usize;
        assert!(
            op < num_opcodes,
            "opcode {op} out of range [0, {num_opcodes})"
        );
        selectors[op][row_idx] = F::ONE;
    }
    selectors
}

/// Verify that selector columns are well-formed:
/// - Each selector is binary (0 or 1).
/// - Exactly one selector is 1 at each row.
pub fn verify_selectors<F: FieldElement>(selectors: &[Vec<F>]) -> bool {
    if selectors.is_empty() {
        return true;
    }
    let n = selectors[0].len();
    for row in 0..n {
        let mut count = F::ZERO;
        for sel in selectors {
            let val = sel[row];
            // Must be binary
            if val != F::ZERO && val != F::ONE {
                return false;
            }
            count = count.add(val);
        }
        // Exactly one must be set
        if count != F::ONE {
            return false;
        }
    }
    true
}

/// Build the "sum of selectors equals one" constraint for a row.
///
/// This returns the constraint evaluation: `sum(selectors) - 1`.
/// Should be zero for valid traces.
pub fn selector_sum_constraint<F: FieldElement>(row: &[F], selector_columns: &[usize]) -> F {
    let mut sum = F::ZERO;
    for &col_idx in selector_columns {
        sum = sum.add(row[col_idx]);
    }
    sum.sub(F::ONE)
}

/// Build binary constraints for selector columns.
///
/// Returns: `selector * (selector - 1)` for each selector column.
/// Should be zero for valid traces (constrains each selector to {0, 1}).
pub fn selector_binary_constraints<F: FieldElement>(
    row: &[F],
    selector_columns: &[usize],
) -> Vec<F> {
    selector_columns
        .iter()
        .map(|&col_idx| {
            let s = row[col_idx];
            s.mul(s.sub(F::ONE))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn opcode_to_selectors_basic() {
        let opcodes = vec![
            F::from_u64(0),
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(0),
        ];
        let sels = opcode_to_selectors(&opcodes, 3);
        assert_eq!(sels.len(), 3);
        // Selector 0: [1, 0, 0, 1]
        assert_eq!(sels[0], vec![F::ONE, F::ZERO, F::ZERO, F::ONE]);
        // Selector 1: [0, 1, 0, 0]
        assert_eq!(sels[1], vec![F::ZERO, F::ONE, F::ZERO, F::ZERO]);
        // Selector 2: [0, 0, 1, 0]
        assert_eq!(sels[2], vec![F::ZERO, F::ZERO, F::ONE, F::ZERO]);
    }

    #[test]
    fn verify_selectors_valid() {
        let opcodes = vec![F::from_u64(0), F::from_u64(1), F::from_u64(2)];
        let sels = opcode_to_selectors(&opcodes, 3);
        assert!(verify_selectors(&sels));
    }

    #[test]
    fn verify_selectors_invalid_sum() {
        // Two selectors both set at row 0
        let sels = vec![
            vec![F::ONE, F::ZERO],
            vec![F::ONE, F::ONE], // both set at row 0
        ];
        assert!(!verify_selectors(&sels));
    }

    #[test]
    fn verify_selectors_non_binary() {
        let sels = vec![
            vec![F::from_u64(2)], // not binary
        ];
        assert!(!verify_selectors(&sels));
    }

    #[test]
    fn selector_sum_constraint_satisfied() {
        // Row with one-hot selector at columns 1,2,3; column 2 is set
        let row = vec![
            F::from_u64(42), // col 0: data
            F::ZERO,         // col 1: selector 0
            F::ONE,          // col 2: selector 1
            F::ZERO,         // col 3: selector 2
        ];
        let result = selector_sum_constraint(&row, &[1, 2, 3]);
        assert_eq!(result, F::ZERO);
    }

    #[test]
    fn selector_binary_constraints_satisfied() {
        let row = vec![F::ZERO, F::ONE, F::ZERO];
        let results = selector_binary_constraints(&row, &[0, 1, 2]);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(*r, F::ZERO, "binary constraint failed at selector {i}");
        }
    }

    #[test]
    fn selector_binary_constraints_violated() {
        let row = vec![F::from_u64(2)]; // not binary
        let results = selector_binary_constraints(&row, &[0]);
        assert_ne!(results[0], F::ZERO);
    }
}
