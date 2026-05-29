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
///
/// NOTE: this matches the legacy adjacent-pair fold (`out[i]` from
/// `values[2i]`/`values[2i+1]`). The correct antipodal fold uses
/// [`propagate_query_index_v5`].
pub fn propagate_query_index(current_index: usize, folding_ratio: usize) -> usize {
    current_index / folding_ratio
}

/// Propagate a query index for the correct antipodal fold (spec §3).
///
/// In the antipodal fold, indices `j` and `j + n/2` of a size-`n` layer both
/// map to output `D'[j]` of the size-`n/2` next layer. So the next index is
/// `q mod (n/2)`, i.e. `q & (n/2 - 1)` for power-of-two `n`.
pub fn propagate_query_index_v5(current_index: usize, layer_size: usize) -> usize {
    debug_assert!(layer_size.is_power_of_two() && layer_size >= 2);
    current_index & ((layer_size / 2) - 1)
}

/// Get the folding ratio used by FRI (currently fixed at 2)
pub fn get_folding_ratio() -> usize {
    2
}

/// Check if a query index is valid for a given layer size
pub fn is_valid_query_index(query_index: usize, layer_size: usize) -> bool {
    query_index < layer_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propagate_v5_hand_cases() {
        // layer_size 8 -> next layer size 4, mask = 3.
        assert_eq!(propagate_query_index_v5(5, 8), 1);
        assert_eq!(propagate_query_index_v5(2, 8), 2);
        assert_eq!(propagate_query_index_v5(7, 8), 3);
        assert_eq!(propagate_query_index_v5(0, 8), 0);
        // layer_size 16 -> next layer size 8, mask = 7.
        assert_eq!(propagate_query_index_v5(11, 16), 3);
    }

    /// Antipodal partners j and j+n/2 must land on the same next index.
    #[test]
    fn propagate_v5_antipodal_partners_collide() {
        for &n in &[2usize, 4, 8, 16, 256] {
            let half = n / 2;
            for j in 0..half {
                assert_eq!(
                    propagate_query_index_v5(j, n),
                    propagate_query_index_v5(j + half, n),
                    "antipodal partners must map to the same index (n={n}, j={j})"
                );
                assert!(propagate_query_index_v5(j, n) < half);
            }
        }
    }
}
