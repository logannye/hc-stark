//! N-column trace table for general-purpose AIRs.
//!
//! Unlike the legacy `TraceTable` (fixed 2-column `[F; 2]`), this module
//! provides a variable-width trace where the column count is determined at
//! construction time. Rows are stored column-major for efficient per-column
//! polynomial operations (LDE, FFT), with row-major accessors for constraint
//! evaluation.

use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

/// A variable-width execution trace.
///
/// Internally stored column-major: `columns[col_idx][row_idx]`.
/// This layout is optimal for the prover which needs to FFT each column
/// independently, while row-level accessors are provided for constraint
/// evaluation.
#[derive(Clone, Debug)]
pub struct MultiColumnTrace<F: FieldElement> {
    /// Column-major storage: `columns[col][row]`.
    columns: Vec<Vec<F>>,
    /// Number of columns (trace width).
    width: usize,
    /// Number of rows.
    num_rows: usize,
}

impl<F: FieldElement> MultiColumnTrace<F> {
    /// Create a trace from row-major data (e.g., from VM execution).
    ///
    /// Each inner slice must have exactly `width` elements.
    pub fn from_rows(rows: &[Vec<F>], width: usize) -> HcResult<Self> {
        if width == 0 {
            return Err(HcError::invalid_argument("trace width must be positive"));
        }
        if rows.len() < 2 {
            return Err(HcError::invalid_argument(
                "trace must contain at least two rows",
            ));
        }
        for (i, row) in rows.iter().enumerate() {
            if row.len() != width {
                return Err(HcError::invalid_argument(format!(
                    "row {i} has {} columns, expected {width}",
                    row.len()
                )));
            }
        }

        let num_rows = rows.len();
        let mut columns = vec![Vec::with_capacity(num_rows); width];
        for row in rows {
            for (col_idx, &val) in row.iter().enumerate() {
                columns[col_idx].push(val);
            }
        }

        Ok(Self {
            columns,
            width,
            num_rows,
        })
    }

    /// Create a trace from fixed-size arrays (convenience for known-width traces).
    pub fn from_fixed_rows<const W: usize>(rows: &[[F; W]]) -> HcResult<Self> {
        if rows.len() < 2 {
            return Err(HcError::invalid_argument(
                "trace must contain at least two rows",
            ));
        }
        let num_rows = rows.len();
        let mut columns = vec![Vec::with_capacity(num_rows); W];
        for row in rows {
            for (col_idx, &val) in row.iter().enumerate() {
                columns[col_idx].push(val);
            }
        }
        Ok(Self {
            columns,
            width: W,
            num_rows,
        })
    }

    /// Create from column-major data directly.
    pub fn from_columns(columns: Vec<Vec<F>>) -> HcResult<Self> {
        if columns.is_empty() {
            return Err(HcError::invalid_argument("trace width must be positive"));
        }
        let num_rows = columns[0].len();
        if num_rows < 2 {
            return Err(HcError::invalid_argument(
                "trace must contain at least two rows",
            ));
        }
        for (i, col) in columns.iter().enumerate() {
            if col.len() != num_rows {
                return Err(HcError::invalid_argument(format!(
                    "column {i} has {} rows, expected {num_rows}",
                    col.len()
                )));
            }
        }
        let width = columns.len();
        Ok(Self {
            columns,
            width,
            num_rows,
        })
    }

    /// Number of columns (trace width).
    pub fn width(&self) -> usize {
        self.width
    }

    /// Number of rows.
    pub fn num_rows(&self) -> usize {
        self.num_rows
    }

    /// Get a single column as a slice (for FFT / LDE).
    pub fn column(&self, col_idx: usize) -> &[F] {
        &self.columns[col_idx]
    }

    /// Get a mutable column (for in-place FFT).
    pub fn column_mut(&mut self, col_idx: usize) -> &mut [F] {
        &mut self.columns[col_idx]
    }

    /// Get all columns (for iteration).
    pub fn columns(&self) -> &[Vec<F>] {
        &self.columns
    }

    /// Extract a single row into a caller-provided buffer.
    pub fn row_into(&self, row_idx: usize, buf: &mut [F]) {
        debug_assert!(buf.len() >= self.width);
        for (col_idx, dst) in buf.iter_mut().enumerate().take(self.width) {
            *dst = self.columns[col_idx][row_idx];
        }
    }

    /// Extract a single row as a new Vec.
    pub fn row(&self, row_idx: usize) -> Vec<F> {
        let mut buf = vec![F::ZERO; self.width];
        self.row_into(row_idx, &mut buf);
        buf
    }

    /// Get a specific cell value.
    pub fn get(&self, row_idx: usize, col_idx: usize) -> F {
        self.columns[col_idx][row_idx]
    }

    /// Pad the trace to a power of two by repeating the last row.
    pub fn pad_to_power_of_two(&mut self) {
        let target = self.num_rows.next_power_of_two();
        if target == self.num_rows {
            return;
        }
        for col in &mut self.columns {
            let last = *col.last().unwrap();
            col.resize(target, last);
        }
        self.num_rows = target;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn from_rows_basic() {
        let rows = vec![
            vec![F::from_u64(1), F::from_u64(2), F::from_u64(3)],
            vec![F::from_u64(4), F::from_u64(5), F::from_u64(6)],
        ];
        let trace = MultiColumnTrace::from_rows(&rows, 3).unwrap();
        assert_eq!(trace.width(), 3);
        assert_eq!(trace.num_rows(), 2);
        assert_eq!(trace.get(0, 0), F::from_u64(1));
        assert_eq!(trace.get(1, 2), F::from_u64(6));
    }

    #[test]
    fn from_fixed_rows() {
        let rows = [
            [F::from_u64(10), F::from_u64(20)],
            [F::from_u64(30), F::from_u64(40)],
        ];
        let trace = MultiColumnTrace::from_fixed_rows(&rows).unwrap();
        assert_eq!(trace.width(), 2);
        assert_eq!(trace.row(0), vec![F::from_u64(10), F::from_u64(20)]);
    }

    #[test]
    fn column_access() {
        let rows = vec![
            vec![F::from_u64(1), F::from_u64(2)],
            vec![F::from_u64(3), F::from_u64(4)],
            vec![F::from_u64(5), F::from_u64(6)],
        ];
        let trace = MultiColumnTrace::from_rows(&rows, 2).unwrap();
        assert_eq!(
            trace.column(0),
            &[F::from_u64(1), F::from_u64(3), F::from_u64(5)]
        );
        assert_eq!(
            trace.column(1),
            &[F::from_u64(2), F::from_u64(4), F::from_u64(6)]
        );
    }

    #[test]
    fn pad_to_power_of_two() {
        let rows = vec![
            vec![F::from_u64(1), F::from_u64(2)],
            vec![F::from_u64(3), F::from_u64(4)],
            vec![F::from_u64(5), F::from_u64(6)],
        ];
        let mut trace = MultiColumnTrace::from_rows(&rows, 2).unwrap();
        trace.pad_to_power_of_two();
        assert_eq!(trace.num_rows(), 4); // 3 → 4
                                         // Padded row should repeat the last row.
        assert_eq!(trace.get(3, 0), F::from_u64(5));
        assert_eq!(trace.get(3, 1), F::from_u64(6));
    }

    #[test]
    fn rejects_width_mismatch() {
        let rows = vec![
            vec![F::from_u64(1), F::from_u64(2)],
            vec![F::from_u64(3)], // wrong width
        ];
        assert!(MultiColumnTrace::from_rows(&rows, 2).is_err());
    }

    #[test]
    fn rejects_too_few_rows() {
        let rows = vec![vec![F::from_u64(1)]];
        assert!(MultiColumnTrace::from_rows(&rows, 1).is_err());
    }
}
