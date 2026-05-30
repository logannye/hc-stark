use std::sync::Arc;

use hc_commit::merkle::{height_dfs::StreamingMerkle, reconstruct_path_from_replay, MerklePath};
use hc_core::{
    error::{HcError, HcResult},
    field::{FieldElement, GoldilocksField, QuadExtension},
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

/// Trait for extension-field values that can be deterministically serialized
/// to a fixed-size byte array suitable for Merkle leaf hashing.
///
/// This is a narrow local seam: only `hash_value_ext` depends on it.  It
/// avoids hard-coupling the leaf-hash function to a concrete type while
/// keeping the `hc-fri`→`hc-core` dependency surface unchanged (we already
/// import `QuadExtension` in this crate's tests).
pub trait ExtLeafHashable {
    /// Serialize self to a fixed-size byte array that binds ALL field
    /// coefficients.  Two values that differ in any coefficient must produce
    /// different byte strings.
    fn to_leaf_bytes(&self) -> [u8; 16];
}

impl ExtLeafHashable for QuadExtension<GoldilocksField> {
    /// 16-byte LE encoding: `[c0_u64_le (8 bytes) || c1_u64_le (8 bytes)]`.
    /// Delegates to `QuadExtension::to_le_bytes` defined in `hc-core`.
    #[inline]
    fn to_leaf_bytes(&self) -> [u8; 16] {
        self.to_le_bytes()
    }
}

/// Hash function for committing to FRI layer evaluations.
///
/// Note: this is not meant to be cryptographically “special”; it just needs to
/// bind values to Merkle leaves deterministically.
pub fn hash_value<F: FieldElement>(value: &F) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&value.to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&value.square().to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

/// Merkle-leaf hash for K-valued (extension-field) FRI layers.
///
/// Binds the FULL extension element (both coefficients) via the 16-byte
/// `to_leaf_bytes` encoding: `Blake3(c0_le ∥ c1_le)`.  Distinct extension
/// elements — whether differing in c0 OR c1 — produce distinct hashes with
/// overwhelming probability.
///
/// This function is ADDITIVE and leaves `hash_value` unchanged.  The FRI
/// base layer (layer 0) remains committed with `hash_value`; only folded
/// layers ≥ 1 that operate in K will use `hash_value_ext` (Tasks 7/8).
pub fn hash_value_ext<K: ExtLeafHashable>(value: &K) -> HashDigest {
    Blake3::hash(&value.to_leaf_bytes())
}

pub fn compute_leaf_hashes<F: FieldElement>(values: &[F]) -> Vec<HashDigest> {
    values.iter().map(hash_value::<F>).collect()
}

pub fn merkle_root_from_hashes(hashes: &[HashDigest]) -> HcResult<HashDigest> {
    if hashes.is_empty() {
        return Err(HcError::invalid_argument(
            "cannot build Merkle root from empty hash list",
        ));
    }
    let mut builder = StreamingMerkle::<Blake3>::new();
    for hash in hashes {
        builder.push(*hash);
    }
    builder
        .finalize()
        .ok_or_else(|| HcError::message("failed to finalize merkle tree"))
}

pub fn merkle_path_from_hashes(hashes: Arc<Vec<HashDigest>>, index: usize) -> HcResult<MerklePath> {
    reconstruct_path_from_replay::<Blake3, _>(index, hashes.len(), 2, &|idx| hashes[idx])
}

/// Fold a FRI layer: `out[i] = pair[0] + beta * pair[1]` for each
/// adjacent pair. When `F == GoldilocksField` (the production case),
/// dispatches to a SIMD specialization that processes WIDTH pairs per
/// iteration. Falls back to scalar for other field types.
///
/// Output is bit-identical to the scalar reference at every length —
/// the SIMD path uses identical add/mul semantics and a scalar-tail for
/// non-WIDTH-aligned suffixes. See `simd_fold::tests` for the parity
/// gate.
///
/// NOTE: this is the *legacy* (vacuous) fold and is NOT a low-degree test (no
/// antipodal pairing, no 1/x). New code MUST use [`fold_layer_v5`].
///
/// DEPRECATED (Phase 1A): part of the v3 FRI path that the sound v5 path
/// (`fold_layer_v5` + the v5 prover/verifier) supersedes. Retained, not
/// removed, to keep the v3 test corpus stable; removal is a documented
/// follow-up.
#[deprecated(
    note = "legacy vacuous fold superseded by the sound v5 path (`fold_layer_v5`); not used in \
            production; removal tracked as a follow-up"
)]
pub fn fold_layer<F: FieldElement>(values: &[F], beta: F) -> HcResult<Vec<F>> {
    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument(
            "FRI layer size must be even for folding",
        ));
    }
    #[allow(deprecated)] // legacy fold delegates to the legacy SIMD fold.
    if let Some(out) = crate::simd_fold::try_fold_goldilocks(values, beta) {
        return Ok(out);
    }
    // Generic scalar path.
    let mut next = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks(2) {
        next.push(pair[0].add(beta.mul(pair[1])));
    }
    Ok(next)
}

/// Coset of one FRI layer: `D[j] = offset * gen^j`, size `n`; `gen^(n/2) = -1`
/// so the antipodal partner of index `j` is `j + n/2`. The value field `E`
/// also carries the domain points.
///
/// This mirrors [`hc_core::domain::EvaluationDomain`] enumeration exactly:
/// `EvaluationDomain::element(j) == offset * generator^j`. Build a matching
/// `LayerDomain` from a coset domain via
/// `LayerDomain { offset: domain.offset(), gen: domain.generator(), size: domain.size() }`.
#[derive(Clone, Debug)]
pub struct LayerDomain<E: FieldElement> {
    pub offset: E,
    pub gen: E,
    pub size: usize,
}

impl<E: FieldElement> LayerDomain<E> {
    /// The `j`-th coset point `offset * gen^j`.
    pub fn point(&self, j: usize) -> E {
        self.offset.mul(self.gen.pow(j as u64))
    }

    /// Next-layer domain: `x -> x^2` (square offset and generator, halve size).
    pub fn squared(&self) -> Self {
        Self {
            offset: self.offset.mul(self.offset),
            gen: self.gen.mul(self.gen),
            size: self.size / 2,
        }
    }
}

/// In-place batch inversion via Montgomery's trick: one field inversion plus
/// `3(n-1)` multiplications. After the call, `xs[i]` holds `1 / xs[i]`.
///
/// Requires every element to be non-zero (true for coset points `2*D[j]`).
/// Returns an error if the running product is not invertible (i.e. some input
/// was zero).
pub(crate) fn batch_invert<E: FieldElement>(xs: &mut [E]) -> HcResult<()> {
    let n = xs.len();
    if n == 0 {
        return Ok(());
    }
    // Forward pass: prefix[i] = xs[0] * .. * xs[i].
    let mut prefix: Vec<E> = Vec::with_capacity(n);
    let mut acc = E::ONE;
    for &x in xs.iter() {
        acc = acc.mul(x);
        prefix.push(acc);
    }
    // Single inversion of the total product.
    let mut inv_acc = acc
        .inverse()
        .ok_or_else(|| HcError::math("batch_invert: product not invertible (zero element?)"))?;
    // Backward pass: distribute the inverse.
    for i in (0..n).rev() {
        let xi = xs[i];
        // inv(xs[i]) = inv_acc * prefix[i-1]  (prefix[-1] == 1).
        let inv_xi = if i == 0 {
            inv_acc
        } else {
            inv_acc.mul(prefix[i - 1])
        };
        xs[i] = inv_xi;
        inv_acc = inv_acc.mul(xi);
    }
    Ok(())
}

/// Correct antipodal, 1/x FRI fold (spec §3). Bit-identical to
/// [`crate::reference::reference_fold`].
///
/// For a layer of even size `n` on coset `D = offset·⟨gen⟩` (so
/// `D[j + n/2] = -D[j]`), folds to the squared domain of size `n/2`:
///
/// ```text
/// x = D[j]                       (j in 0..n/2)
/// a = values[j]        = f(x)
/// b = values[j + n/2]  = f(-x)   (antipodal partner, NOT values[2j+1])
/// out[j] = (a + b)/2 + beta * (a - b)/(2*x)
/// ```
///
/// Batch-inverts `{2*D[j]}` for speed. ADDITIVE — leaves [`fold_layer`] as is.
pub fn fold_layer_v5<E: FieldElement>(
    values: &[E],
    domain: &LayerDomain<E>,
    beta: E,
) -> HcResult<Vec<E>> {
    if values.len() % 2 != 0 {
        return Err(HcError::invalid_argument("FRI layer size must be even"));
    }
    let half = values.len() / 2;
    let two_inv = E::from_u64(2)
        .inverse()
        .ok_or_else(|| HcError::math("2 not invertible"))?;
    // two_x[j] = 2 * D[j], via running multiply (O(half), not O(half·log half)):
    // D[0] = offset, D[j+1] = D[j] * gen. Batch-invert in place -> 1/(2*D[j]).
    let mut two_x: Vec<E> = Vec::with_capacity(half);
    let mut x = domain.offset;
    for _ in 0..half {
        two_x.push(x.add(x));
        x = x.mul(domain.gen);
    }
    batch_invert(&mut two_x)?;
    let mut out = Vec::with_capacity(half);
    for j in 0..half {
        let a = values[j];
        let b = values[j + half];
        let even = a.add(b).mul(two_inv);
        let odd = a.sub(b).mul(two_x[j]);
        out.push(even.add(beta.mul(odd)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::{
        domain::EvaluationDomain,
        field::{prime_field::GoldilocksField, FieldElement, QuadExtension},
    };

    type K = QuadExtension<GoldilocksField>;

    // --- hash_value_ext ---

    /// Equal K values must hash to the same digest.
    #[test]
    fn hash_value_ext_equal_values_equal_hashes() {
        let x = K::new(GoldilocksField::from_u64(42), GoldilocksField::from_u64(7));
        assert_eq!(hash_value_ext(&x), hash_value_ext(&x));
    }

    /// Values differing ONLY in c0 must hash differently.
    #[test]
    fn hash_value_ext_distinct_c0_distinct_hashes() {
        let c1 = GoldilocksField::from_u64(999);
        let x = K::new(GoldilocksField::from_u64(1), c1);
        let y = K::new(GoldilocksField::from_u64(2), c1);
        assert_ne!(
            hash_value_ext(&x),
            hash_value_ext(&y),
            "distinct c0 must produce distinct leaf hashes"
        );
    }

    /// Values differing ONLY in c1 must hash differently.
    /// This is the critical c1-binding check: a c0-only encoding would be a
    /// commitment weakness that would let an adversary swap c1 without
    /// invalidating a Merkle proof.
    #[test]
    fn hash_value_ext_distinct_c1_distinct_hashes() {
        let c0 = GoldilocksField::from_u64(42);
        let x = K::new(c0, GoldilocksField::from_u64(0));
        let y = K::new(c0, GoldilocksField::from_u64(1));
        assert_ne!(
            hash_value_ext(&x),
            hash_value_ext(&y),
            "distinct c1 must produce distinct leaf hashes (c1 binding)"
        );
    }

    /// K::ZERO and K::ONE hash differently from each other.
    #[test]
    fn hash_value_ext_zero_ne_one() {
        assert_ne!(hash_value_ext(&K::ZERO), hash_value_ext(&K::ONE));
    }

    type F = GoldilocksField;

    /// SplitMix64 PRNG — deterministic, no external deps.
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            SplitMix64(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_field(&mut self) -> F {
            F::from_u64(self.next_u64())
        }
    }

    /// Build the `LayerDomain` that matches `EvaluationDomain::new_coset(n, 7)`.
    fn layer_domain_for(n: usize, offset: u64) -> (EvaluationDomain<F>, LayerDomain<F>) {
        let dom = EvaluationDomain::<F>::new_coset(n, F::from_u64(offset)).unwrap();
        let ld = LayerDomain {
            offset: dom.offset(),
            gen: dom.generator(),
            size: dom.size(),
        };
        (dom, ld)
    }

    /// `LayerDomain::point(j)` must equal `EvaluationDomain::element(j)` at
    /// every index — they encode the same coset enumeration.
    #[test]
    fn layer_domain_point_matches_evaluation_domain() {
        for &n in &[2usize, 8, 64, 1024] {
            let (dom, ld) = layer_domain_for(n, 7);
            for j in 0..n {
                assert_eq!(ld.point(j), dom.element(j), "point mismatch at n={n} j={j}");
            }
            // squared() must enumerate the squared domain D[j]^2.
            let sq = ld.squared();
            assert_eq!(sq.size, n / 2);
            for j in 0..n / 2 {
                assert_eq!(sq.point(j), dom.element(j).mul(dom.element(j)));
            }
        }
    }

    /// In-place Montgomery batch inversion correctness.
    #[test]
    fn batch_invert_matches_individual() {
        let mut rng = SplitMix64::new(0x1234_5678);
        for &n in &[1usize, 2, 3, 7, 16, 100] {
            // Draw non-zero elements.
            let orig: Vec<F> = (0..n)
                .map(|_| {
                    let mut x = rng.next_field();
                    while x.is_zero() {
                        x = rng.next_field();
                    }
                    x
                })
                .collect();
            let mut inv = orig.clone();
            batch_invert(&mut inv).unwrap();
            for (o, i) in orig.iter().zip(inv.iter()) {
                assert_eq!(o.mul(*i), F::ONE, "batch_invert wrong at n={n}");
            }
        }
    }

    #[test]
    fn batch_invert_zero_element_errors() {
        let mut xs = vec![F::from_u64(3), F::ZERO, F::from_u64(5)];
        assert!(batch_invert(&mut xs).is_err());
    }

    /// THE CRITICAL DIFFERENTIAL TEST: `fold_layer_v5` must be bit-identical to
    /// the dependency-free `reference::reference_fold` across many sizes, on
    /// cosets built via `EvaluationDomain::new_coset(n, 7)`, with random
    /// codewords and betas.
    #[test]
    fn fold_layer_v5_matches_reference_fold() {
        for &n in &[2usize, 4, 8, 16, 32, 64, 256, 1024, 4096] {
            let (dom, ld) = layer_domain_for(n, 7);
            let domain_points: Vec<F> = (0..n).map(|i| dom.element(i)).collect();

            let mut rng = SplitMix64::new(0xC0FF_EE00 ^ (n as u64));
            let values: Vec<F> = (0..n).map(|_| rng.next_field()).collect();
            let beta = rng.next_field();

            let got = fold_layer_v5(&values, &ld, beta).unwrap();
            let want = crate::reference::reference_fold(&values, &domain_points, beta);
            assert_eq!(got, want, "fold_layer_v5 != reference_fold at n={n}");
            assert_eq!(got.len(), n / 2);
        }
    }

    #[test]
    fn fold_layer_v5_rejects_odd_length() {
        let (_dom, ld) = layer_domain_for(8, 7);
        let values = vec![F::from_u64(1); 3];
        assert!(fold_layer_v5(&values, &ld, F::from_u64(2)).is_err());
    }
}
