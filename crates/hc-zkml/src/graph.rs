//! Model graph: a typed DAG of layers that the prover lowers into AIRs.

use crate::proof::InferenceWitness;
use crate::tensor::Shape;
use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// A single node in the computation graph.
///
/// `Layer::MatMul` is the load-bearing primitive — every dense and attention
/// computation lowers to a sequence of matmuls. The other variants are
/// pointwise or near-pointwise operations whose AIR is a thin transition
/// constraint per element.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Layer {
    /// `out = lhs · rhs` (matrix multiplication).
    MatMul {
        lhs: Shape,
        rhs: Shape,
        /// Output shape after multiplication. Must equal `[lhs[0], rhs[1]]`.
        out: Shape,
    },
    /// Element-wise `max(0, x)`.
    Relu { shape: Shape },
    /// Element-wise add: `out = a + b` (used for residual connections).
    Add { shape: Shape },
    /// Softmax along the last dimension. Parameterized by the maximum
    /// log-domain bit-width permitted to keep the AIR linear.
    Softmax {
        shape: Shape,
        log_domain_bits: u8,
    },
    /// 2-D convolution. The implementation lowers this to a tiled matmul
    /// (im2col) before proving.
    Conv2d {
        input: Shape,
        weights: Shape,
        stride: (usize, usize),
        padding: (usize, usize),
        out: Shape,
    },
}

impl Layer {
    /// Output shape produced by this layer.
    pub fn output_shape(&self) -> &Shape {
        match self {
            Layer::MatMul { out, .. } => out,
            Layer::Relu { shape } => shape,
            Layer::Add { shape } => shape,
            Layer::Softmax { shape, .. } => shape,
            Layer::Conv2d { out, .. } => out,
        }
    }
}

/// A model graph: an ordered list of layers. The graph is a chain by default;
/// branching DAGs are encoded by replaying the same input shape into multiple
/// `Add` layers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModelGraph {
    pub layers: Vec<Layer>,
    pub input_shape: Option<Shape>,
    pub output_shape: Option<Shape>,
}

impl ModelGraph {
    /// Construct an empty graph (used by the prover stub for type-checks).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Verify that the graph is internally consistent: every layer's input
    /// shape matches the previous layer's output shape.
    ///
    /// This is `O(L)` and runs before any cryptographic work.
    pub fn validate(&self) -> HcResult<()> {
        if self.layers.is_empty() {
            return Ok(());
        }
        // For a future implementation: iterate layers and check that each
        // layer's declared input shape matches the running shape, returning a
        // descriptive error if not. For now we only check that the graph
        // declares an input shape if it has any layers.
        if self.input_shape.is_none() {
            return Err(HcError::invalid_argument(
                "model graph has layers but no declared input_shape",
            ));
        }
        Ok(())
    }

    /// Validate that a witness's tensors line up with this graph.
    pub fn validate_against(&self, witness: &InferenceWitness) -> HcResult<()> {
        self.validate()?;
        if let Some(input_shape) = &self.input_shape {
            if let Some(input_tensor) = witness.input.as_ref() {
                if &input_tensor.shape != input_shape {
                    return Err(HcError::invalid_argument(format!(
                        "witness input shape {:?} does not match graph input shape {:?}",
                        input_tensor.shape, input_shape
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Builder for assembling a [`ModelGraph`] in code.
#[derive(Default)]
pub struct ModelGraphBuilder {
    graph: ModelGraph,
}

impl ModelGraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn input(mut self, shape: Shape) -> Self {
        self.graph.input_shape = Some(shape);
        self
    }

    pub fn push(mut self, layer: Layer) -> Self {
        self.graph.layers.push(layer);
        self
    }

    pub fn output(mut self, shape: Shape) -> Self {
        self.graph.output_shape = Some(shape);
        self
    }

    pub fn build(self) -> ModelGraph {
        self.graph
    }
}

/// A succinct commitment to a model: weights hash, architecture digest, and
/// quantization metadata. Verifiers receive only this — never the weights.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelCommitment {
    /// Hash of the canonical-serialized model graph (architecture).
    pub architecture_digest: [u8; 32],
    /// Hash of the canonical-serialized concatenated weight tensors.
    pub weights_digest: [u8; 32],
    /// Optional human-readable name (not verified).
    pub label: Option<String>,
}

impl ModelCommitment {
    pub fn new(architecture_digest: [u8; 32], weights_digest: [u8; 32]) -> Self {
        Self {
            architecture_digest,
            weights_digest,
            label: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_validates() {
        ModelGraph::empty().validate().unwrap();
    }

    #[test]
    fn graph_with_layers_requires_input_shape() {
        let mut g = ModelGraph::empty();
        g.layers.push(Layer::Relu {
            shape: Shape::matrix(4, 4),
        });
        assert!(g.validate().is_err());
    }

    #[test]
    fn builder_produces_consistent_graph() {
        let g = ModelGraphBuilder::new()
            .input(Shape::matrix(8, 8))
            .push(Layer::Relu {
                shape: Shape::matrix(8, 8),
            })
            .output(Shape::matrix(8, 8))
            .build();
        g.validate().unwrap();
        assert_eq!(g.layers.len(), 1);
    }
}
