//! Parallel FRI operations using Rayon.
//!
//! These functions parallelize the compute-heavy parts of FRI:
//! - Leaf hashing (hash_value per element)
//! - Layer folding (a + beta * b per pair)
//! - Merkle commitment (parallel hash, sequential tree build)

use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_hash::{hash::HashDigest, Blake3};
use rayon::prelude::*;

use crate::layer::{batch_invert, hash_value, LayerDomain};

/// Compute leaf hashes in parallel using Rayon.
///
/// For large layers (thousands of elements), this provides 2-4x speedup on
/// multi-core machines. The hash computations are independent per element.
pub fn compute_leaf_hashes_parallel<F: FieldElement>(values: &[F]) -> Vec<HashDigest> {
    values.par_iter().map(hash_value::<F>).collect()
}

/// Fold a FRI layer in parallel: `out[i] = values[2i] + beta * values[2i+1]`.
///
/// Each pair fold is independent, making this trivially parallelizable.
///
/// NOTE: legacy fold (no antipodal pairing, no 1/x). Production callers still
/// depend on it; new code should use [`fold_layer_v5_parallel`].
pub fn fold_layer_parallel<F: FieldElement>(values: &[F], beta: F) -> Vec<F> {
    values
        .par_chunks(2)
        .map(|pair| pair[0].add(beta.mul(pair[1])))
        .collect()
}

/// Correct antipodal, 1/x FRI fold (spec §3), parallelized with Rayon.
///
/// `out[j] = (a+b)/2 + beta*(a-b)/(2*D[j])` with `a = values[j]`,
/// `b = values[j + n/2]`, matching [`crate::layer::fold_layer_v5`] /
/// [`crate::reference::reference_fold`]. The per-output `1/(2*D[j])` factors
/// are batch-inverted up front (one inversion), then the `even + beta*odd`
/// combination runs in parallel across `j`.
pub fn fold_layer_v5_parallel<F: FieldElement>(
    values: &[F],
    domain: &LayerDomain<F>,
    beta: F,
) -> HcResult<Vec<F>> {
    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument("FRI layer size must be even"));
    }
    let half = values.len() / 2;
    let two_inv = F::from_u64(2)
        .inverse()
        .ok_or_else(|| HcError::math("2 not invertible"))?;
    let mut inv_two_x: Vec<F> = (0..half)
        .map(|j| {
            let x = domain.point(j);
            x.add(x)
        })
        .collect();
    batch_invert(&mut inv_two_x)?;

    let (lo, hi) = values.split_at(half);
    let out = (0..half)
        .into_par_iter()
        .map(|j| {
            let a = lo[j];
            let b = hi[j];
            let even = a.add(b).mul(two_inv);
            let odd = a.sub(b).mul(inv_two_x[j]);
            even.add(beta.mul(odd))
        })
        .collect();
    Ok(out)
}

/// Build a Merkle root from pre-computed leaf hashes.
///
/// The hashes are computed in parallel (by the caller), and the tree is built
/// sequentially since `StreamingMerkle` is inherently sequential.
pub fn merkle_root_from_parallel_hashes(hashes: &[HashDigest]) -> Option<HashDigest> {
    let mut builder = hc_commit::merkle::height_dfs::StreamingMerkle::<Blake3>::new();
    for hash in hashes {
        builder.push(*hash);
    }
    builder.finalize()
}

/// Combined parallel hash-and-commit: hash leaves in parallel, then build tree.
///
/// This is the main optimization for FRI layer commitment. On a 4-core machine
/// with 100K+ elements, expect 2-3x speedup over the sequential path.
pub fn commit_layer_parallel<F: FieldElement>(values: &[F]) -> Option<HashDigest> {
    let hashes = compute_leaf_hashes_parallel(values);
    merkle_root_from_parallel_hashes(&hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{compute_leaf_hashes, fold_layer};
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn parallel_hashes_match_sequential() {
        let values: Vec<F> = (0..256).map(F::from_u64).collect();
        let seq = compute_leaf_hashes(&values);
        let par = compute_leaf_hashes_parallel(&values);
        assert_eq!(seq, par);
    }

    #[test]
    fn parallel_fold_matches_sequential() {
        let values: Vec<F> = (0..128).map(F::from_u64).collect();
        let beta = F::from_u64(42);
        let seq = fold_layer(&values, beta).unwrap();
        let par = fold_layer_parallel(&values, beta);
        assert_eq!(seq, par);
    }

    #[test]
    fn parallel_fold_v5_matches_scalar_v5() {
        use crate::layer::fold_layer_v5;
        use hc_core::domain::EvaluationDomain;
        for &n in &[2usize, 8, 64, 256, 1024, 4096] {
            let dom = EvaluationDomain::<F>::new_coset(n, F::from_u64(7)).unwrap();
            let ld = LayerDomain {
                offset: dom.offset(),
                gen: dom.generator(),
                size: dom.size(),
            };
            let values: Vec<F> = (0..n as u64)
                .map(|i| F::from_u64(i.wrapping_mul(1000003) + 7))
                .collect();
            let beta = F::from_u64(42);
            let seq = fold_layer_v5(&values, &ld, beta).unwrap();
            let par = fold_layer_v5_parallel(&values, &ld, beta).unwrap();
            assert_eq!(seq, par, "parallel-v5 vs scalar-v5 mismatch at n={n}");
        }
    }

    #[test]
    fn parallel_commit_matches_sequential() {
        let values: Vec<F> = (0..64).map(F::from_u64).collect();
        let hashes_seq = compute_leaf_hashes(&values);
        let root_seq = crate::layer::merkle_root_from_hashes(&hashes_seq).unwrap();
        let root_par = commit_layer_parallel(&values).unwrap();
        assert_eq!(root_seq, root_par);
    }
}
