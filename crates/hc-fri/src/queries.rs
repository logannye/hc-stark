use hc_core::field::FieldElement;
use hc_hash::hash::HashDigest;

#[derive(Clone, Debug)]
pub struct FriProof<F: FieldElement> {
    /// Merkle roots of each committed FRI layer, in order.
    pub layer_roots: Vec<HashDigest>,
    /// Final layer evaluations (size <= `FriConfig::final_polynomial_size()`).
    ///
    /// We include these directly because the final layer is configured to be tiny.
    pub final_layer: Vec<F>,
    /// Merkle root of the final layer evaluations.
    pub final_root: HashDigest,
}

impl<F: FieldElement> FriProof<F> {
    pub fn new(layer_roots: Vec<HashDigest>, final_layer: Vec<F>, final_root: HashDigest) -> Self {
        Self {
            layer_roots,
            final_layer,
            final_root,
        }
    }

    pub fn layer_count(&self) -> usize {
        self.layer_roots.len()
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
