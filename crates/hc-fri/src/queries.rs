use hc_core::field::FieldElement;

use crate::layer::FriLayer;

#[derive(Clone, Debug)]
pub struct FriProof<F: FieldElement> {
    pub layers: Vec<FriLayer<F>>,
    pub final_layer: Vec<F>,
}

impl<F: FieldElement> FriProof<F> {
    pub fn new(layers: Vec<FriLayer<F>>, final_layer: Vec<F>) -> Self {
        Self {
            layers,
            final_layer,
        }
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}
