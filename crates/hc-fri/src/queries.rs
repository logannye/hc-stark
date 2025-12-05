use hc_core::field::FieldElement;

use crate::layer::{FriFinalLayer, FriLayer};

#[derive(Clone, Debug)]
pub struct FriProof<F: FieldElement> {
    pub layers: Vec<FriLayer<F>>,
    pub final_layer: FriFinalLayer<F>,
}

impl<F: FieldElement> FriProof<F> {
    pub fn new(layers: Vec<FriLayer<F>>, final_layer: FriFinalLayer<F>) -> Self {
        Self {
            layers,
            final_layer,
        }
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}

/// Propagate a query index from one FRI layer to the next.
/// For FRI with folding ratio 2, the next layer index is current_index / 2.
pub fn propagate_query_index(current_index: usize, folding_ratio: usize) -> usize {
    current_index / folding_ratio
}

/// Get the folding ratio used by FRI (currently fixed at 2)
pub fn get_folding_ratio() -> usize {
    2
}

/// Check if a query index is valid for a given layer size
pub fn is_valid_query_index(query_index: usize, layer_size: usize) -> bool {
    query_index < layer_size
}
