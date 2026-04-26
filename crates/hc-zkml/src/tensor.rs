//! Tensor types for the zkML prover.
//!
//! Tensors are addressed by [`Shape`] and stored as quantized integer values
//! (`Vec<i32>`) under a [`Quantization`] schedule. Real-valued models are
//! lowered to this representation by the frontend before proving.

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Multi-dimensional shape descriptor. Conceptually `[d0, d1, ..., dn]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shape(pub Vec<usize>);

impl Shape {
    /// Total element count.
    pub fn numel(&self) -> usize {
        self.0.iter().product()
    }

    /// Rank (number of dimensions).
    pub fn rank(&self) -> usize {
        self.0.len()
    }

    /// Convenience constructor: 2-D shape (rows, cols).
    pub fn matrix(rows: usize, cols: usize) -> Self {
        Self(vec![rows, cols])
    }

    /// Convenience constructor: 4-D shape (batch, channels, height, width).
    pub fn nchw(n: usize, c: usize, h: usize, w: usize) -> Self {
        Self(vec![n, c, h, w])
    }
}

/// Symmetric per-tensor quantization: `real_value ≈ scale * (q - zero_point)`.
///
/// `bit_width` is the number of bits used to encode each quantized element;
/// callers must keep `q` within `[-2^(bit_width-1), 2^(bit_width-1) - 1]` for
/// signed quantization.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quantization {
    pub scale: f32,
    pub zero_point: i32,
    pub bit_width: u8,
}

impl Quantization {
    /// 8-bit symmetric quantization with the given scale and a zero point of 0.
    pub fn int8(scale: f32) -> Self {
        Self {
            scale,
            zero_point: 0,
            bit_width: 8,
        }
    }
}

/// A quantized tensor. Element `i` (in row-major order) corresponds to logical
/// index `unravel(i, shape)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tensor {
    pub shape: Shape,
    pub quant: Quantization,
    /// Quantized values, row-major. Length must equal `shape.numel()`.
    pub data: Vec<i32>,
}

impl Tensor {
    /// Construct a tensor from raw quantized values, validating the shape.
    pub fn new(shape: Shape, quant: Quantization, data: Vec<i32>) -> HcResult<Self> {
        if data.len() != shape.numel() {
            return Err(HcError::invalid_argument(format!(
                "tensor data length {} does not match shape numel {}",
                data.len(),
                shape.numel()
            )));
        }
        let max = 1_i64 << (quant.bit_width as i64 - 1);
        let min = -max;
        for (i, &v) in data.iter().enumerate() {
            let v64 = v as i64;
            if v64 < min || v64 >= max {
                return Err(HcError::invalid_argument(format!(
                    "tensor element {i} = {v} outside symmetric int{} range",
                    quant.bit_width
                )));
            }
        }
        Ok(Self { shape, quant, data })
    }

    /// Zero tensor with the given shape and quantization.
    pub fn zeros(shape: Shape, quant: Quantization) -> Self {
        let n = shape.numel();
        Self {
            shape,
            quant,
            data: vec![0; n],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_numel() {
        assert_eq!(Shape::matrix(3, 4).numel(), 12);
        assert_eq!(Shape::nchw(2, 3, 4, 5).numel(), 120);
    }

    #[test]
    fn tensor_rejects_mismatched_data() {
        let shape = Shape::matrix(2, 2);
        let q = Quantization::int8(1.0);
        let t = Tensor::new(shape, q, vec![0, 0, 0]);
        assert!(t.is_err());
    }

    #[test]
    fn tensor_rejects_out_of_range_value() {
        let shape = Shape::matrix(1, 1);
        let q = Quantization::int8(1.0);
        // 8-bit symmetric range is [-128, 127]; 200 must be rejected.
        let t = Tensor::new(shape, q, vec![200]);
        assert!(t.is_err());
    }
}
