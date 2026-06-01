//! v5 (soundness-hardened) STARK verification — Phase 1A.
//!
//! ADDITIVE module: implements [`verify_v5`] consuming the [`ProofV5`] produced
//! by the v5 prover (`hc_prover::prove_v5`). It does NOT touch the v3
//! `verify` / `verify_stark_v3` / `verify_fri_queries` path in [`crate::api`];
//! the trace/quotient opening checks are *reused* from there by calling into
//! the same logic, and the FRI part is the NEW cryptographically-correct
//! antipodal + 1/x low-degree verification over the extension field
//! `K = QuadExtension<GoldilocksField>`.
//!
//! This closes two audit findings:
//!
//! - **G2** — the v3 FRI "low-degree test" is vacuous (it re-checks the
//!   prover's own self-referential recurrence and so accepts ANY base
//!   codeword). The v5 verifier instead descends the antipodal fold from the
//!   composition opening, Merkle-verifies every opened layer value with the
//!   K-aware leaf hash, and — crucially — checks the shipped final layer is the
//!   evaluation of a polynomial of degree `< fri_final_poly_size / blowup`
//!   (the `final_coeffs` degree bound). A high-degree codeword's final layer is
//!   NOT such a low-degree evaluation, so it is REJECTED.
//!
//! - **G7** — the verifier had no security floor: it trusted whatever
//!   parameters a proof declared. [`VerifierSecurityFloor`] / [`enforce_floor`]
//!   reject any proof below hard minimums (version, blowup, query count,
//!   grinding bits, final-poly size) BEFORE any crypto runs.

use hc_air::{AccumulatorAir, GeneralAir, RangeAir};
use hc_core::{
    domain::{generate_lde_coset_domain, generate_trace_domain, EvaluationDomain},
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement, QuadExtension},
};
use hc_fri::layer::{hash_value_ext, LayerDomain};
use hc_fri::{is_valid_query_index, propagate_query_index_v5, FriProof};
use hc_hash::{grinding, hash::HashDigest, protocol, Blake3, HashFunction, Transcript};
use hc_prover::{
    commitment::CommitmentScheme,
    pipeline::phase3_queries::generate_queries,
    queries::{
        CompositionQuery, FriQuery, ProofV5, ProofV7, TraceQuery, TraceQueryN, TraceWitness,
    },
};

use crate::errors::VerifierError;

/// Base field of the v5 proof. The FRI commit phase lifts this to
/// `K = QuadExtension<F>`.
type F = GoldilocksField;
/// Extension field used by the v5 (uniform-K) FRI low-degree verification.
type K = QuadExtension<GoldilocksField>;

/// LDE coset offset shared by the v3 / v5 DEEP-STARK oracle builders and the
/// v5 FRI base [`LayerDomain`] (matches `prove_stark_v5` / `run_fri_v5`).
const LDE_COSET_OFFSET: u64 = 7;

// ───────────────────────────────────────────────────────────────────────────
// G7 — verifier-enforced security floor.
// ───────────────────────────────────────────────────────────────────────────

/// Hard minimum parameters a proof must declare to even be *considered* by the
/// v5 verifier. Mirrors `hc_prover::config::SecurityFloor` on the verifier side
/// so a malicious/weak prover cannot talk the verifier down to insecure
/// parameters.
///
/// [`Default`] is the production floor (≈128-bit target); [`relaxed`] disables
/// every minimum so tests can exercise the crypto with tiny parameters.
#[derive(Clone, Copy, Debug)]
pub struct VerifierSecurityFloor {
    /// Minimum LDE blowup factor.
    pub min_blowup: usize,
    /// Minimum number of FRI query repetitions.
    pub min_queries: usize,
    /// Minimum proof-of-work grinding bits.
    pub min_grinding_bits: u32,
    /// Maximum permitted FRI final-polynomial size.
    pub max_fri_final_poly_size: usize,
    /// Minimum protocol version considered sound (legacy versions are rejected).
    pub min_sound_version: u32,
}

impl Default for VerifierSecurityFloor {
    fn default() -> Self {
        Self {
            min_blowup: 8,
            min_queries: 40,
            min_grinding_bits: 20,
            max_fri_final_poly_size: 256,
            min_sound_version: 5,
        }
    }
}

impl VerifierSecurityFloor {
    /// No limits — for tests and benchmarks only.
    pub fn relaxed() -> Self {
        Self {
            min_blowup: 1,
            min_queries: 1,
            min_grinding_bits: 0,
            max_fri_final_poly_size: usize::MAX,
            min_sound_version: 1,
        }
    }
}

/// Enforce the verifier security floor against a proof's declared parameters.
///
/// Runs BEFORE any cryptographic check so a below-floor proof is rejected
/// without trusting its contents. Returns
/// [`VerifierError::UnsoundLegacyVersion`] for a too-old version and
/// [`VerifierError::BelowSecurityFloor`] for any other below-floor parameter.
pub fn enforce_floor(proof: &ProofV5<F>, floor: VerifierSecurityFloor) -> HcResult<()> {
    if proof.version < floor.min_sound_version {
        return Err(VerifierError::UnsoundLegacyVersion.into());
    }
    let params = &proof.params;
    if params.lde_blowup_factor < floor.min_blowup
        || params.query_count < floor.min_queries
        || params.grinding_bits < floor.min_grinding_bits
        || params.fri_final_poly_size > floor.max_fri_final_poly_size
    {
        return Err(VerifierError::BelowSecurityFloor.into());
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Public entry points.
// ───────────────────────────────────────────────────────────────────────────

/// Verify a v5 proof under the production security floor ([`VerifierSecurityFloor::default`]).
///
/// Enforces the security floor (G7) and then runs the soundness-hardened
/// crypto (G2). Returns `Ok(())` on accept, `Err` on any failure.
pub fn verify_v5(proof: &ProofV5<F>) -> HcResult<()> {
    enforce_floor(proof, VerifierSecurityFloor::default())?;
    verify_stark_v5_inner(proof)
}

/// Verify a v5 proof under a caller-supplied security floor.
///
/// Tests use [`VerifierSecurityFloor::relaxed`] to exercise the crypto with
/// small parameters (so that, e.g., the forge-PoC is rejected by the FRI /
/// final-degree path rather than the floor).
pub fn verify_v5_with_floor(proof: &ProofV5<F>, floor: VerifierSecurityFloor) -> HcResult<()> {
    enforce_floor(proof, floor)?;
    verify_stark_v5_inner(proof)
}

// ───────────────────────────────────────────────────────────────────────────
// v7 (general-AIR) verification — Phase 1B.
// ───────────────────────────────────────────────────────────────────────────

/// Production v7 security floor: identical to [`VerifierSecurityFloor::default`]
/// but requires protocol version ≥ 7 (the general-AIR sound proofs).
pub fn verifier_floor_v7() -> VerifierSecurityFloor {
    VerifierSecurityFloor {
        min_sound_version: 7,
        ..VerifierSecurityFloor::default()
    }
}

/// Enforce a security floor against a v7 proof's declared parameters. Mirrors
/// [`enforce_floor`] for the [`ProofV7`] shape; runs BEFORE any crypto.
fn enforce_floor_v7(proof: &ProofV7<F>, floor: VerifierSecurityFloor) -> HcResult<()> {
    if proof.version < floor.min_sound_version {
        return Err(VerifierError::UnsoundLegacyVersion.into());
    }
    let p = &proof.params;
    if p.lde_blowup_factor < floor.min_blowup
        || p.query_count < floor.min_queries
        || p.grinding_bits < floor.min_grinding_bits
        || p.fri_final_poly_size > floor.max_fri_final_poly_size
    {
        return Err(VerifierError::BelowSecurityFloor.into());
    }
    Ok(())
}

/// Verify a v7 proof under the production v7 floor ([`verifier_floor_v7`]).
pub fn verify_v7(proof: &ProofV7<F>) -> HcResult<()> {
    enforce_floor_v7(proof, verifier_floor_v7())?;
    verify_stark_v7_inner(proof)
}

/// Verify a v7 proof under a caller-supplied floor (tests use `relaxed`).
pub fn verify_v7_with_floor(proof: &ProofV7<F>, floor: VerifierSecurityFloor) -> HcResult<()> {
    enforce_floor_v7(proof, floor)?;
    verify_stark_v7_inner(proof)
}

/// Resolve the AIR a v7 proof claims, by its bound `air_id`, validating the
/// declared shape WITHOUT panicking (a malicious proof must not crash the
/// verifier). 1 = accumulator (width 2), 2 = range (width 4).
fn resolve_air(
    air_id: u32,
    trace_width: usize,
    trace_length: usize,
) -> HcResult<Box<dyn GeneralAir>> {
    match air_id {
        1 => {
            if trace_width != 2 {
                return Err(HcError::invalid_argument(
                    "accumulator AIR expects trace width 2",
                ));
            }
            Ok(Box::new(AccumulatorAir))
        }
        2 => {
            if trace_width != 4 {
                return Err(HcError::invalid_argument("range AIR expects trace width 4"));
            }
            // RangeAir::new asserts these; validate first so the verifier never panics.
            if !trace_length.is_power_of_two() || trace_length + 1 >= 64 {
                return Err(HcError::invalid_argument(
                    "range AIR trace length must be a power of two with 2^(n+1) < p",
                ));
            }
            Ok(Box::new(RangeAir::new(trace_length)))
        }
        other => Err(HcError::invalid_argument(format!("unknown AIR id {other}"))),
    }
}

/// The cryptographic core of v7 verification (assumes the floor was enforced).
fn verify_stark_v7_inner(proof: &ProofV7<F>) -> HcResult<()> {
    if proof.trace_commitment.scheme() != CommitmentScheme::Stark
        || proof.composition_commitment.scheme() != CommitmentScheme::Stark
    {
        return Err(VerifierError::TraceWitnessUnsupported.into());
    }
    if proof.params.protocol_version != proof.version {
        return Err(VerifierError::ProofParamsVersionMismatch.into());
    }

    // Resolve the AIR by its bound id; validate the declared shape.
    let air = resolve_air(proof.air_id, proof.trace_width, proof.trace_length)?;
    if proof.public_inputs.len() != air.public_input_len() || proof.trace_width != air.width() {
        return Err(VerifierError::InvalidPublicInputs.into());
    }

    let trace_root = proof
        .trace_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for trace commitment"))?;
    let quotient_root = proof
        .composition_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for quotient commitment"))?;

    let padded_len = proof.trace_length.next_power_of_two();
    if padded_len == 0 {
        return Err(HcError::invalid_argument("trace length must be non-zero"));
    }
    let blowup = proof.params.lde_blowup_factor;
    let lde_len = padded_len
        .checked_mul(blowup)
        .ok_or_else(|| HcError::invalid_argument("lde domain size overflow"))?;
    if lde_len == 0 {
        return Err(HcError::invalid_argument(
            "lde domain size must be non-zero",
        ));
    }

    // --- Rebuild the v7 MAIN transcript EXACTLY as `prove_v7`. ---
    let mut transcript = Transcript::<Blake3>::new(protocol::DOMAIN_MAIN_V7);
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_INPUT_COUNT,
        proof.public_inputs.len() as u64,
    );
    for pi in &proof.public_inputs {
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PUB_INPUT_ELEM,
            pi.to_u64(),
        );
    }
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_GRINDING_BITS,
        proof.params.grinding_bits as u64,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_ENABLED,
        u64::from(proof.params.zk_enabled),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_MASK_DEGREE,
        proof.params.zk_mask_degree as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_TRACE_WIDTH,
        proof.trace_width as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::AIR_ID,
        proof.air_id as u64,
    );
    transcript.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        trace_root.as_bytes(),
    );

    // Single composition challenge α ∈ K (mirrors prove_v7).
    let alpha = transcript.challenge_field::<K>(protocol::label::COMPOSITION_ALPHA);
    transcript.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        quotient_root.as_bytes(),
    );
    for root in &proof.fri_proof.layer_roots {
        transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
    }
    transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    // Grinding PoW check over the transcript the prover ground (before the nonce).
    if !grinding::check_grinding::<Blake3>(
        &transcript,
        protocol::label::FRI_GRINDING_NONCE,
        proof.grinding_nonce,
        proof.params.grinding_bits,
    ) {
        return Err(VerifierError::GrindingCheckFailed.into());
    }
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::FRI_GRINDING_NONCE,
        proof.grinding_nonce,
    );
    let base_queries = generate_queries::<F>(&mut transcript, lde_len, proof.params.query_count)?;

    let betas = recompute_fri_betas_v7(proof, trace_root, quotient_root)?;

    verify_v7_trace_and_quotient(
        air.as_ref(),
        &proof.public_inputs,
        trace_root,
        quotient_root,
        &base_queries,
        padded_len,
        lde_len,
        blowup,
        alpha,
        &proof.query_response.trace_queries,
        &proof.query_response.composition_queries,
        /* check_query_indices = */ true,
    )?;

    // OOD-style extra opening (mirrors prove_v7).
    transcript.append_message(protocol::label::CHAL_OOD_POINT, [0u8]);
    let ood_fe = transcript.challenge_field::<F>(protocol::label::CHAL_OOD_INDEX);
    let ood_index = (ood_fe.to_u64() as usize) % lde_len;
    if let Some(ood) = &proof.query_response.ood {
        if ood.index != ood_index {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
        verify_v7_trace_and_quotient(
            air.as_ref(),
            &proof.public_inputs,
            trace_root,
            quotient_root,
            &[ood.index],
            padded_len,
            lde_len,
            blowup,
            alpha,
            std::slice::from_ref(&ood.trace),
            std::slice::from_ref(&ood.quotient),
            /* check_query_indices = */ true,
        )?;
    }

    verify_fri_low_degree_v5(
        &proof.fri_proof,
        &proof.query_response.fri_queries,
        proof.params.lde_blowup_factor,
        proof.params.fri_final_poly_size,
        &base_queries,
        &betas,
        lde_len,
        &proof.query_response.composition_queries,
    )?;

    Ok(())
}

/// Recompute the K FRI betas for a v7 proof by replaying `run_fri_v5`'s seed
/// transcript (`DOMAIN_FRI_V5`). v7 binds public inputs via the MAIN transcript,
/// so the FRI seed's `initial_acc`/`final_acc` slots are 0 (as `prove_v7` set).
fn recompute_fri_betas_v7(
    proof: &ProofV7<F>,
    trace_root: HashDigest,
    quotient_root: HashDigest,
) -> HcResult<Vec<K>> {
    let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
    protocol::append_u64::<Blake3>(&mut t, protocol::label::PUB_INITIAL_ACC, 0);
    protocol::append_u64::<Blake3>(&mut t, protocol::label::PUB_FINAL_ACC, 0);
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_GRINDING_BITS,
        proof.params.grinding_bits as u64,
    );
    t.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_ZK_ENABLED,
        u64::from(proof.params.zk_enabled),
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_ZK_MASK_DEGREE,
        proof.params.zk_mask_degree as u64,
    );
    t.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        trace_root.as_bytes(),
    );
    t.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        quotient_root.as_bytes(),
    );
    let mut betas = Vec::with_capacity(proof.fri_proof.layer_roots.len());
    for root in &proof.fri_proof.layer_roots {
        t.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
        betas.push(t.challenge_field::<K>(protocol::label::CHAL_FRI_BETA));
    }
    Ok(betas)
}

/// Verify width-N trace + K quotient openings and the quotient relation at each
/// queried point, using the AIR's single-α `compose_at`. The v7 analog of
/// [`verify_v5_trace_and_quotient`].
#[allow(clippy::too_many_arguments)]
fn verify_v7_trace_and_quotient(
    air: &dyn GeneralAir,
    public_inputs: &[F],
    trace_root: HashDigest,
    quotient_root: HashDigest,
    base_queries: &[usize],
    padded_len: usize,
    lde_len: usize,
    blowup: usize,
    alpha: K,
    trace_queries: &[TraceQueryN<F>],
    composition_queries: &[CompositionQuery<K>],
    check_query_indices: bool,
) -> HcResult<()> {
    if check_query_indices {
        let mut expected = base_queries.to_vec();
        expected.sort_unstable();
        let mut tidx: Vec<usize> = trace_queries.iter().map(|q| q.index).collect();
        tidx.sort_unstable();
        if tidx != expected {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
        let mut qidx: Vec<usize> = composition_queries.iter().map(|q| q.index).collect();
        qidx.sort_unstable();
        if qidx != expected {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
    }

    let shift = blowup % lde_len;
    let coset_offset = F::from_u64(LDE_COSET_OFFSET);
    let lde_domain = generate_lde_coset_domain::<F>(padded_len, blowup, coset_offset)?;
    let omega_last = generate_trace_domain::<F>(padded_len)?
        .generator()
        .inverse()
        .ok_or_else(|| HcError::math("trace domain generator has no inverse"))?;
    let n_inv = F::from_u64(padded_len as u64)
        .inverse()
        .ok_or_else(|| HcError::math("padded_len has no inverse"))?;

    let mut trace_by_index: std::collections::HashMap<usize, &TraceQueryN<F>> =
        std::collections::HashMap::new();
    for tq in trace_queries {
        trace_by_index.insert(tq.index, tq);
    }

    for cq in composition_queries {
        let leaf_hash = hash_value_ext(&cq.value);
        if !cq.witness.verify::<Blake3>(quotient_root, leaf_hash) {
            return Err(VerifierError::CompositionQueryMerkleMismatch.into());
        }

        let tq = trace_by_index
            .get(&cq.index)
            .copied()
            .ok_or(VerifierError::QueryIndexMismatch)?;
        if tq.evaluation.len() != air.width() {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }
        let leaf_hash = hash_trace_row_n(&tq.evaluation);
        match &tq.witness {
            TraceWitness::Merkle(path) => {
                if !path.verify::<Blake3>(trace_root, leaf_hash) {
                    return Err(VerifierError::TraceQueryMerkleMismatch.into());
                }
            }
            TraceWitness::Kzg(_) => return Err(VerifierError::TraceWitnessUnsupported.into()),
        }

        let next = tq.next.as_ref().ok_or(VerifierError::TraceNextRowMissing)?;
        let expected_next = (tq.index + shift) % lde_len;
        if next.index != expected_next {
            return Err(VerifierError::TraceNextRowMissing.into());
        }
        if next.evaluation.len() != air.width() {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }
        let next_leaf_hash = hash_trace_row_n(&next.evaluation);
        if !next.witness.verify::<Blake3>(trace_root, next_leaf_hash) {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }

        // Quotient relation at x: q(x)·Z_H(x) == C(x) = Σ αⁱ·cᵢ (in K).
        let x = lde_domain.element(tq.index);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        let l0 = z_h.mul(n_inv).mul(
            x.sub(F::ONE)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L0 on coset"))?,
        );
        let l_last = z_h.mul(omega_last).mul(n_inv).mul(
            x.sub(omega_last)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L_last on coset"))?,
        );
        let selector_last = F::ONE.sub(l_last);

        let c = air.compose_at(
            &tq.evaluation,
            &next.evaluation,
            l0,
            l_last,
            selector_last,
            public_inputs,
            alpha,
        )?;
        let lhs = cq.value.mul(K::from_base(z_h));
        if lhs != c {
            return Err(VerifierError::CompositionQueryValueMismatch.into());
        }
    }

    Ok(())
}

/// Width-N trace leaf hash — must match the prover's
/// `hc_prover::pipeline::phase1_commit::hash_trace_row_n` byte-for-byte.
fn hash_trace_row_n(row: &[F]) -> HashDigest {
    let mut bytes = Vec::with_capacity(row.len() * 8);
    for v in row {
        bytes.extend_from_slice(&v.to_u64().to_le_bytes());
    }
    Blake3::hash(&bytes)
}

// ───────────────────────────────────────────────────────────────────────────
// Crypto.
// ───────────────────────────────────────────────────────────────────────────

/// The cryptographic core of v5 verification (assumes the floor has been
/// enforced by the caller).
fn verify_stark_v5_inner(proof: &ProofV5<F>) -> HcResult<()> {
    // The v5 prove path is Stark-only; the proof must carry Merkle roots.
    if proof.trace_commitment.scheme() != CommitmentScheme::Stark
        || proof.composition_commitment.scheme() != CommitmentScheme::Stark
    {
        return Err(VerifierError::TraceWitnessUnsupported.into());
    }
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }
    if proof.params.protocol_version != proof.version {
        return Err(VerifierError::ProofParamsVersionMismatch.into());
    }

    let trace_root = proof
        .trace_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for Stark commitment"))?;
    let quotient_root = proof
        .composition_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for quotient commitment"))?;

    // Domain sizes.
    let padded_len = proof.trace_length.next_power_of_two();
    if padded_len == 0 {
        return Err(HcError::invalid_argument("trace length must be non-zero"));
    }
    let blowup = proof.params.lde_blowup_factor;
    let lde_len = padded_len
        .checked_mul(blowup)
        .ok_or_else(|| HcError::invalid_argument("lde domain size overflow"))?;
    if lde_len == 0 {
        return Err(HcError::invalid_argument(
            "lde domain size must be non-zero",
        ));
    }

    // --- (a) Rebuild the v5 MAIN transcript EXACTLY as `prove_stark_v5`. ---
    // (Byte-for-byte mirror of `prove_stark_v5` / the prover's
    // `rebuild_v5_main_transcript_up_to_nonce` test helper.)
    let mut transcript = Transcript::<Blake3>::new(protocol::DOMAIN_MAIN_V5);
    transcript.append_message(
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64().to_le_bytes(),
    );
    transcript.append_message(
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64().to_le_bytes(),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_GRINDING_BITS,
        proof.params.grinding_bits as u64,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_ENABLED,
        u64::from(proof.params.zk_enabled),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_MASK_DEGREE,
        proof.params.zk_mask_degree as u64,
    );
    transcript.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        trace_root.as_bytes(),
    );
    // Draw the two composition α challenges in `K` (Phase 1A.2): the quotient /
    // composition relation is K-valued (~128-bit). The transcript state is
    // identical to squeezing F (one squeeze either way); only α gains entropy.
    let alpha_boundary =
        transcript.challenge_field::<K>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
    let alpha_transition =
        transcript.challenge_field::<K>(protocol::label::COMPOSITION_ALPHA_TRANSITION);
    transcript.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        quotient_root.as_bytes(),
    );
    for root in &proof.fri_proof.layer_roots {
        transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
    }
    transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    // --- Recompute & enforce the grinding PoW over the transcript state the
    //     prover ground over (after FRI final root, before the nonce). ---
    if !grinding::check_grinding::<Blake3>(
        &transcript,
        protocol::label::FRI_GRINDING_NONCE,
        proof.grinding_nonce,
        proof.params.grinding_bits,
    ) {
        return Err(VerifierError::GrindingCheckFailed.into());
    }
    // Bind the nonce, then sample base query indices downstream of the grind.
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::FRI_GRINDING_NONCE,
        proof.grinding_nonce,
    );
    let base_queries = generate_queries::<F>(&mut transcript, lde_len, proof.params.query_count)?;

    // --- (b) Recompute the FRI betas in K (mirror `run_fri_v5`). ---
    let betas = recompute_fri_betas_v5(proof, trace_root, quotient_root)?;

    // --- (c) Verify trace + quotient (composition) openings at base_queries (F). ---
    verify_v5_trace_and_quotient(
        proof,
        trace_root,
        quotient_root,
        &base_queries,
        padded_len,
        lde_len,
        alpha_boundary,
        alpha_transition,
        &proof.query_response.trace_queries,
        &proof.query_response.composition_queries,
        /* check_query_indices = */ true,
    )?;

    // OOD-style extra opening (mirrors the prover): sampled AFTER the openings.
    // Replicate the prover's sampling so we both consume the transcript
    // identically and validate the extra trace/quotient opening at that index.
    transcript.append_message(protocol::label::CHAL_OOD_POINT, [0u8]);
    let ood_fe = transcript.challenge_field::<F>(protocol::label::CHAL_OOD_INDEX);
    let ood_index = (ood_fe.to_u64() as usize) % lde_len;
    if let Some(ood) = &proof.query_response.ood {
        if ood.index != ood_index {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
        verify_v5_trace_and_quotient(
            proof,
            trace_root,
            quotient_root,
            &[ood.index],
            padded_len,
            lde_len,
            alpha_boundary,
            alpha_transition,
            std::slice::from_ref(&ood.trace),
            std::slice::from_ref(&ood.quotient),
            /* check_query_indices = */ true,
        )?;
    }

    // --- (d)+(e) FRI low-degree verification: antipodal + 1/x fold in K,
    //     bound to the composition openings, + final-degree check. ---
    verify_fri_low_degree_v5(
        &proof.fri_proof,
        &proof.query_response.fri_queries,
        proof.params.lde_blowup_factor,
        proof.params.fri_final_poly_size,
        &base_queries,
        &betas,
        lde_len,
        &proof.query_response.composition_queries,
    )?;

    Ok(())
}

/// Recompute the K-valued FRI betas by replaying the v5 FRI transcript
/// (`DOMAIN_FRI_V5`) exactly as `run_fri_v5` builds it.
fn recompute_fri_betas_v5(
    proof: &ProofV5<F>,
    trace_root: HashDigest,
    quotient_root: HashDigest,
) -> HcResult<Vec<K>> {
    let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    // v5 param-block addition: bind the grinding difficulty.
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_GRINDING_BITS,
        proof.params.grinding_bits as u64,
    );
    t.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    // v5 extends v4: always bind the ZK fields.
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_ZK_ENABLED,
        u64::from(proof.params.zk_enabled),
    );
    protocol::append_u64::<Blake3>(
        &mut t,
        protocol::label::PARAM_ZK_MASK_DEGREE,
        proof.params.zk_mask_degree as u64,
    );
    // v5 extends v3: LDE-trace + quotient commitment labels.
    t.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        trace_root.as_bytes(),
    );
    t.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        quotient_root.as_bytes(),
    );

    // Squeeze a K beta after appending each layer root (mirrors the commit phase).
    let mut betas = Vec::with_capacity(proof.fri_proof.layer_roots.len());
    for root in &proof.fri_proof.layer_roots {
        t.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
        betas.push(t.challenge_field::<K>(protocol::label::CHAL_FRI_BETA));
    }
    Ok(betas)
}

/// Verify trace + quotient (composition) openings at the given query indices,
/// plus the quotient relation at each queried point. Phase 1A.2: the trace
/// openings stay in `F`, but the composition (quotient) openings and the
/// α-combination / quotient relation are **`K`-valued** (~128-bit). Re-implemented
/// over the v5 query types (`QueryResponseV5`) without touching v3.
#[allow(clippy::too_many_arguments)]
fn verify_v5_trace_and_quotient(
    proof: &ProofV5<F>,
    trace_root: HashDigest,
    quotient_root: HashDigest,
    base_queries: &[usize],
    padded_len: usize,
    lde_len: usize,
    alpha_boundary: K,
    alpha_transition: K,
    trace_queries: &[TraceQuery<F>],
    composition_queries: &[CompositionQuery<K>],
    check_query_indices: bool,
) -> HcResult<()> {
    use hc_air::{DeepStarkAir, ToyAir};

    if check_query_indices {
        let mut expected = base_queries.to_vec();
        expected.sort_unstable();
        let mut trace_idx: Vec<usize> = trace_queries.iter().map(|q| q.index).collect();
        trace_idx.sort_unstable();
        if trace_idx != expected {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
        let mut quot_idx: Vec<usize> = composition_queries.iter().map(|q| q.index).collect();
        quot_idx.sort_unstable();
        if quot_idx != expected {
            return Err(VerifierError::QueryIndexMismatch.into());
        }
    }

    let shift = proof.params.lde_blowup_factor % lde_len;
    let coset_offset = F::from_u64(LDE_COSET_OFFSET);
    let lde_domain =
        generate_lde_coset_domain::<F>(padded_len, proof.params.lde_blowup_factor, coset_offset)?;
    let omega_last = generate_trace_domain::<F>(padded_len)?
        .generator()
        .inverse()
        .ok_or_else(|| HcError::math("trace domain generator has no inverse"))?;
    let n_inv = F::from_u64(padded_len as u64)
        .inverse()
        .ok_or_else(|| HcError::math("padded_len has no inverse"))?;

    let mut trace_by_index: std::collections::HashMap<usize, &TraceQuery<F>> =
        std::collections::HashMap::new();
    for tq in trace_queries {
        trace_by_index.insert(tq.index, tq);
    }

    for cq in composition_queries {
        // Verify quotient Merkle opening (K leaf, same `hash_value_ext` as the prover).
        let leaf_hash = hash_value_ext(&cq.value);
        if !cq.witness.verify::<Blake3>(quotient_root, leaf_hash) {
            return Err(VerifierError::CompositionQueryMerkleMismatch.into());
        }

        // Fetch the matching trace opening.
        let tq = trace_by_index
            .get(&cq.index)
            .copied()
            .ok_or(VerifierError::QueryIndexMismatch)?;

        // Verify the trace Merkle opening.
        let leaf_hash = hash_trace_row(&tq.evaluation);
        match &tq.witness {
            TraceWitness::Merkle(path) => {
                if !path.verify::<Blake3>(trace_root, leaf_hash) {
                    return Err(VerifierError::TraceQueryMerkleMismatch.into());
                }
            }
            TraceWitness::Kzg(_) => return Err(VerifierError::TraceWitnessUnsupported.into()),
        }

        let next = tq.next.as_ref().ok_or(VerifierError::TraceNextRowMissing)?;
        let expected_next = (tq.index + shift) % lde_len;
        if next.index != expected_next {
            return Err(VerifierError::TraceNextRowMissing.into());
        }
        let next_leaf_hash = hash_trace_row(&next.evaluation);
        if !next.witness.verify::<Blake3>(trace_root, next_leaf_hash) {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }

        // Quotient relation at x = domain[idx], checked in K (Phase 1A.2):
        // q(x) * (x^N - 1) == C(x), where C(x) = α_b·boundary + α_t·transition
        // and α_b, α_t ∈ K. The selectors/Z_H and the two base-field constraint
        // values come from the F trace opening; the combination + the equality
        // are evaluated in K.
        let x = lde_domain.element(tq.index);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        let l0 = z_h.mul(n_inv).mul(
            x.sub(F::ONE)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L0 on coset"))?,
        );
        let l_last = z_h.mul(omega_last).mul(n_inv).mul(
            x.sub(omega_last)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L_last on coset"))?,
        );
        let selector_last = F::ONE.sub(l_last);

        let acc = tq.evaluation[0];
        let delta = tq.evaluation[1];
        let acc_next = next.evaluation[0];
        let delta_next = next.evaluation[1];
        let air = ToyAir;
        let (b, t) = air.constraint_values(
            &[acc, delta],
            &[acc_next, delta_next],
            l0,
            l_last,
            selector_last,
            proof.initial_acc,
            proof.final_acc,
        )?;
        let c = K::from_base(b)
            .mul(alpha_boundary)
            .add(K::from_base(t).mul(alpha_transition));

        let lhs = cq.value.mul(K::from_base(z_h));
        if lhs != c {
            return Err(VerifierError::CompositionQueryValueMismatch.into());
        }
    }

    Ok(())
}

/// The cryptographically-correct FRI low-degree verification (spec §3): for
/// each base query, descend the antipodal + 1/x fold in K starting from the
/// composition opening, Merkle-verify every opened layer value against the
/// committed roots, then enforce the final-degree bound and tie the descended
/// value into the final layer.
#[allow(clippy::too_many_arguments)]
fn verify_fri_low_degree_v5(
    fri: &FriProof<K>,
    fri_queries: &[FriQuery<K>],
    blowup: usize,
    fri_final_poly_size: usize,
    base_queries: &[usize],
    betas: &[K],
    lde_len: usize,
    composition_queries: &[CompositionQuery<K>],
) -> HcResult<()> {
    let num_layers = fri.layer_roots.len();
    if betas.len() != num_layers {
        return Err(VerifierError::FriFailure.into());
    }

    // Composition value by index (the FRI base binding) — now K-valued.
    let composition_by_index: std::collections::HashMap<usize, K> = composition_queries
        .iter()
        .map(|q| (q.index, q.value))
        .collect();

    // --- (e)(i) Final-layer degree bound: REJECT a too-long `final_coeffs`. ---
    let final_size = fri.final_layer.len();
    let blowup = blowup.max(1);
    let expected_final_coeffs = fri_final_poly_size / blowup;
    if fri.final_coeffs.len() != expected_final_coeffs {
        return Err(VerifierError::FriFinalDegreeMismatch.into());
    }

    // Layer-0 coset = LDE coset (offset 7) of size lde_len, embedded into K
    // — identical to how `run_fri_v5` / `answer_fri_queries_v5` build it.
    let base_domain = base_layer_domain_k(lde_len)?;

    // The final coset is the base coset squared down to `final_size`. Rebuild it
    // by squaring `final_size` must be reached by halving lde_len `num_layers`
    // times: lde_len >> num_layers == final_size.
    let mut final_domain = base_domain.clone();
    {
        let mut n = lde_len;
        while n > final_size {
            final_domain = final_domain.squared();
            n /= 2;
        }
        if n != final_size {
            // The committed layer count is inconsistent with the configured
            // final size and the LDE length.
            return Err(VerifierError::FriFailure.into());
        }
    }

    // --- (e)(ii) The shipped final layer must be the low-degree polynomial
    //     `final_coeffs` evaluated on the final coset. THIS is what makes a
    //     high-degree codeword fail: its final layer is not such an evaluation. ---
    let final_points: Vec<K> = (0..final_size).map(|j| final_domain.point(j)).collect();
    let reeval = hc_core::poly::evaluate_batch(&fri.final_coeffs, &final_points);
    if reeval != fri.final_layer {
        return Err(VerifierError::FriFinalDegreeMismatch.into());
    }

    // Per-base-query antipodal descent. Each base query contributes a chain of
    // `min(num_layers, descent depth)` openings, recorded in order.
    let mut fri_iter = fri_queries.iter();

    for &base_query in base_queries {
        let mut current = base_query;
        let mut domain = base_domain.clone();
        let mut n = lde_len;
        // Seed the expected value from the composition opening (FRI base binding).
        // The quotient codeword is natively K, so this is the opened K value
        // directly (no F→K embedding).
        let mut expected: Option<K> = Some(
            *composition_by_index
                .get(&base_query)
                .ok_or(VerifierError::QueryIndexMismatch)?,
        );

        for (layer_idx, beta) in betas.iter().enumerate() {
            if !is_valid_query_index(current, n) {
                break;
            }
            if n < 2 {
                return Err(VerifierError::FriFailure.into());
            }
            let half = n / 2;
            let low = current & (half - 1);

            let recorded = fri_iter
                .next()
                .ok_or(VerifierError::FriQueryCountMismatch)?;
            if recorded.layer_index != layer_idx || recorded.query_index != low {
                return Err(VerifierError::FriQueryIndexMismatch.into());
            }

            // Merkle-verify both opened antipodal values (low, low+half) against
            // this layer's root, using the K-aware leaf hash.
            let root = fri.layer_roots[layer_idx];
            let leaf_low = hash_value_ext(&recorded.values[0]);
            if !recorded.merkle_paths[0].verify::<Blake3>(root, leaf_low) {
                return Err(VerifierError::FriQueryMerkleMismatch.into());
            }
            let leaf_high = hash_value_ext(&recorded.values[1]);
            if !recorded.merkle_paths[1].verify::<Blake3>(root, leaf_high) {
                return Err(VerifierError::FriQueryMerkleMismatch.into());
            }

            // Bind: the expected value at the absolute index `current` must equal
            // the opened value in the slot it lands in (slot 0 if current==low,
            // i.e. current<half; else slot 1 = the antipodal partner).
            if let Some(exp) = expected {
                let slot = if current == low { 0 } else { 1 };
                if recorded.values[slot] != exp {
                    return Err(VerifierError::FriQueryEvaluationMismatch.into());
                }
            }

            // Antipodal + 1/x fold to the next layer.
            let a = recorded.values[0];
            let b = recorded.values[1];
            let x = domain.point(low);
            let folded = fold_pair_k(a, b, *beta, x)?;

            expected = Some(folded);
            current = propagate_query_index_v5(current, n);
            domain = domain.squared();
            n = half;
        }

        // --- (e)(iii) The descended value must equal final_layer[current]. ---
        if let Some(exp) = expected {
            let final_idx = current;
            if !is_valid_query_index(final_idx, fri.final_layer.len()) {
                return Err(VerifierError::FriQueryEvaluationMismatch.into());
            }
            if fri.final_layer[final_idx] != exp {
                return Err(VerifierError::FriQueryEvaluationMismatch.into());
            }
        }
    }

    // No leftover openings.
    if fri_iter.next().is_some() {
        return Err(VerifierError::FriQueryCountMismatch.into());
    }

    Ok(())
}

/// Antipodal + 1/x fold of one opened pair at domain point `x`:
/// `(a + b)/2 + beta*(a - b)/(2*x)`. Mirrors `fold_layer_v5` per element.
#[inline]
fn fold_pair_k(a: K, b: K, beta: K, x: K) -> HcResult<K> {
    let two_inv = K::from_u64(2)
        .inverse()
        .ok_or_else(|| HcError::math("2 not invertible"))?;
    let inv_two_x = x
        .add(x)
        .inverse()
        .ok_or_else(|| HcError::math("2*x not invertible (zero coset point?)"))?;
    let even = a.add(b).mul(two_inv);
    let odd = a.sub(b).mul(inv_two_x);
    Ok(even.add(beta.mul(odd)))
}

/// Build the layer-0 `LayerDomain<K>`: the LDE coset (offset 7) of size `n` in
/// F, embedded into K — identical to `run_fri_v5` / `answer_fri_queries_v5`.
fn base_layer_domain_k(n: usize) -> HcResult<LayerDomain<K>> {
    let dom_f = EvaluationDomain::<F>::new_coset(n, F::from_u64(LDE_COSET_OFFSET))?;
    Ok(LayerDomain {
        offset: K::from_base(dom_f.offset()),
        gen: K::from_base(dom_f.generator()),
        size: dom_f.size(),
    })
}

fn hash_trace_row(row: &[F; 2]) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&row[0].to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&row[1].to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_prover::config::{ProverConfig, SecurityFloor};
    use hc_prover::prove_v5;
    use hc_prover::prove_v7;
    use hc_prover::PublicInputs;

    // ── v7 (general-AIR) verification tests (Phase 1B T7) ───────────────────

    /// Small relaxed v7 config (tiny params, no grinding) — verified under
    /// `VerifierSecurityFloor::relaxed`.
    fn v7_cfg() -> ProverConfig {
        let mut c = ProverConfig::with_security_floor(2, 2, 4, 2, SecurityFloor::relaxed())
            .unwrap()
            .with_protocol_version(7);
        c.grinding_bits = 0;
        c
    }

    /// Width-2 accumulator trace, height 4: acc 5→6→8→8, deltas 1,2,0,0.
    fn v7_acc_trace() -> hc_air::MultiColumnTrace<F> {
        let acc = vec![F::new(5), F::new(6), F::new(8), F::new(8)];
        let delta = vec![F::new(1), F::new(2), F::new(0), F::new(0)];
        hc_air::MultiColumnTrace::from_columns(vec![acc, delta]).unwrap()
    }

    #[test]
    fn v7_accumulator_roundtrip_verifies() {
        let proof = prove_v7(
            &AccumulatorAir,
            &v7_acc_trace(),
            &[F::new(5), F::new(8)],
            &v7_cfg(),
        )
        .unwrap();
        verify_v7_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect("honest accumulator v7 proof must verify");
    }

    #[test]
    fn v7_range_roundtrip_verifies() {
        // THE Phase 1B milestone: an end-to-end sound range proof verifies.
        let air = RangeAir::new(hc_air::RANGE_DEFAULT_N);
        let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
        let proof = prove_v7(&air, &trace, &[F::new(18), F::new(120)], &v7_cfg()).unwrap();
        verify_v7_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect("honest range v7 proof must verify");
    }

    #[test]
    fn v7_range_tampered_composition_value_rejected() {
        let air = RangeAir::new(hc_air::RANGE_DEFAULT_N);
        let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
        let mut proof = prove_v7(&air, &trace, &[F::new(18), F::new(120)], &v7_cfg()).unwrap();
        proof.query_response.composition_queries[0].value =
            proof.query_response.composition_queries[0]
                .value
                .add(K::ONE);
        assert!(verify_v7_with_floor(&proof, VerifierSecurityFloor::relaxed()).is_err());
    }

    #[test]
    fn v7_range_tampered_trace_value_rejected() {
        let air = RangeAir::new(hc_air::RANGE_DEFAULT_N);
        let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
        let mut proof = prove_v7(&air, &trace, &[F::new(18), F::new(120)], &v7_cfg()).unwrap();
        proof.query_response.trace_queries[0].evaluation[0] =
            proof.query_response.trace_queries[0].evaluation[0].add(F::new(1));
        assert!(verify_v7_with_floor(&proof, VerifierSecurityFloor::relaxed()).is_err());
    }

    #[test]
    fn v7_production_floor_rejects_relaxed_proof() {
        // Relaxed params (blowup 2, grinding 0) are below the production v7 floor.
        let proof = prove_v7(
            &AccumulatorAir,
            &v7_acc_trace(),
            &[F::new(5), F::new(8)],
            &v7_cfg(),
        )
        .unwrap();
        assert!(verify_v7(&proof).is_err());
    }

    #[test]
    fn v7_tampered_version_rejected() {
        let mut proof = prove_v7(
            &AccumulatorAir,
            &v7_acc_trace(),
            &[F::new(5), F::new(8)],
            &v7_cfg(),
        )
        .unwrap();
        proof.version = 5; // altered version must be rejected
        assert!(verify_v7_with_floor(&proof, VerifierSecurityFloor::relaxed()).is_err());
    }
    use hc_vm::{Instruction, Program};

    /// Small honest v5 config (relaxed floor so tiny params are allowed; small
    /// grinding so the PoW search is fast). Mirrors the prover's own test config.
    fn honest_config(grinding_bits: u32) -> ProverConfig {
        let mut config = ProverConfig::with_security_floor(
            2, // block_size
            2, // fri_final_poly_size
            4, // query_count
            2, // lde_blowup_factor
            SecurityFloor::relaxed(),
        )
        .unwrap()
        .with_protocol_version(5);
        config.grinding_bits = grinding_bits;
        config
    }

    fn honest_program() -> Program {
        Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
            Instruction::AddImmediate(3),
            Instruction::AddImmediate(4),
        ])
    }

    fn honest_inputs() -> PublicInputs<F> {
        // acc: 5 → 6 → 8 → 11 → 15.
        PublicInputs {
            initial_acc: F::new(5),
            final_acc: F::new(15),
        }
    }

    fn honest_proof(grinding_bits: u32) -> ProofV5<F> {
        prove_v5(
            honest_config(grinding_bits),
            honest_program(),
            honest_inputs(),
        )
        .unwrap()
    }

    // ── G2: honest v5 round-trip ACCEPTS ───────────────────────────────────

    #[test]
    fn v5_round_trip_accepts() {
        let proof = honest_proof(8);
        verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect("honest v5 proof must verify under a relaxed floor");
    }

    #[test]
    fn v5_round_trip_accepts_zero_grinding() {
        let proof = honest_proof(0);
        verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect("honest v5 proof (bits=0) must verify under a relaxed floor");
    }

    // ── G2: tamper tests REJECT ─────────────────────────────────────────────

    #[test]
    fn v5_tampered_fri_value_rejected() {
        let mut proof = honest_proof(8);
        let q = proof
            .query_response
            .fri_queries
            .first_mut()
            .expect("at least one fri opening");
        q.values[0] = q.values[0].add(K::ONE);
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered FRI value must be rejected");
        eprintln!("v5_tampered_fri_value_rejected: {err}");
    }

    #[test]
    fn v5_tampered_fri_merkle_path_rejected() {
        let mut proof = honest_proof(8);
        let q = proof
            .query_response
            .fri_queries
            .first_mut()
            .expect("at least one fri opening");
        q.merkle_paths[0] = Default::default();
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered FRI Merkle path must be rejected");
        eprintln!("v5_tampered_fri_merkle_path_rejected: {err}");
    }

    #[test]
    fn v5_swapped_fri_query_ordering_rejected() {
        let mut proof = honest_proof(8);
        if proof.query_response.fri_queries.len() >= 2 {
            proof.query_response.fri_queries.swap(0, 1);
        }
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("swapped FRI query ordering must be rejected");
        eprintln!("v5_swapped_fri_query_ordering_rejected: {err}");
    }

    #[test]
    fn v5_tampered_trace_opening_rejected() {
        let mut proof = honest_proof(8);
        let last = proof
            .query_response
            .trace_queries
            .last_mut()
            .expect("trace query");
        last.evaluation[0] = last.evaluation[0].add(F::ONE);
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered trace opening must be rejected");
        eprintln!("v5_tampered_trace_opening_rejected: {err}");
    }

    #[test]
    fn v5_tampered_composition_value_rejected() {
        let mut proof = honest_proof(8);
        let first = proof
            .query_response
            .composition_queries
            .first_mut()
            .expect("composition query");
        first.value = first.value.add(K::ONE);
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered composition value must be rejected");
        eprintln!("v5_tampered_composition_value_rejected: {err}");
    }

    /// Soundness — K quotient-opening tampering is rejected.
    ///
    /// The K-valued composition/quotient oracle is protected by TWO checks
    /// (Phase 1A.2):
    ///   1. **Merkle commitment**: the leaf hash `hash_value_ext(value)` binds
    ///      both c0 and c1; any change to the K value produces a different leaf
    ///      hash, which the Merkle path no longer verifies against the committed
    ///      quotient root → `CompositionQueryMerkleMismatch`.
    ///   2. **Quotient-relation check**: `q(x)·Z_H(x) == C(x)` in K; a wrong K
    ///      value that somehow passed the Merkle check would be caught here →
    ///      `CompositionQueryValueMismatch`.
    ///
    /// This test confirms that BOTH tamper surfaces (c0-only and c1-only changes)
    /// are caught by the first applicable check, and that the K quotient oracle
    /// relation is independently verified algebraically.
    #[test]
    fn v5_k_quotient_opening_tamper_rejected() {
        // --- Tamper 1: add K::ONE (changes c0); Merkle check fires first. ---
        let mut proof1 = honest_proof(8);
        {
            let first = proof1
                .query_response
                .composition_queries
                .first_mut()
                .expect("at least one composition query");
            first.value = first.value.add(K::ONE);
        }
        let err1 = verify_v5_with_floor(&proof1, VerifierSecurityFloor::relaxed())
            .expect_err("c0-tampered K quotient value must be rejected");
        let msg1 = err1.to_string();
        // The Merkle leaf hash binds both c0 and c1, so a c0 change triggers
        // CompositionQueryMerkleMismatch (error text: "does not verify") before the
        // relation check is reached.
        assert!(
            !msg1.is_empty(),
            "c0-tamper must produce a non-empty error; got empty string"
        );
        eprintln!("v5_k_quotient_opening_tamper c0 rejected: {msg1}");

        // --- Tamper 2: add a pure-K element (c0=0, c1=1); c1 change is also
        //     caught by the Merkle check (hash_value_ext binds both limbs). ---
        let mut proof2 = honest_proof(8);
        {
            let first = proof2
                .query_response
                .composition_queries
                .first_mut()
                .expect("at least one composition query");
            first.value = first.value.add(K::new(F::ZERO, F::ONE));
        }
        let err2 = verify_v5_with_floor(&proof2, VerifierSecurityFloor::relaxed())
            .expect_err("c1-only tampered K quotient value must be rejected");
        let msg2 = err2.to_string();
        assert!(
            !msg2.is_empty(),
            "c1-only tamper must produce a non-empty error; got empty string"
        );
        eprintln!("v5_k_quotient_opening_tamper c1 rejected: {msg2}");

        // --- Algebraic spot-check of the K quotient relation in isolation ---
        // Build an honest proof and directly verify the relation
        //   q(x) * Z_H(x) == C(x)  in K
        // for the first composition query, then confirm a tampered value fails it.
        let honest = honest_proof(8);
        let padded_len = honest.trace_length.next_power_of_two();
        let blowup = honest.params.lde_blowup_factor;
        let lde_len = padded_len * blowup;
        let coset_offset = F::from_u64(LDE_COSET_OFFSET);
        let lde_domain = generate_lde_coset_domain::<F>(padded_len, blowup, coset_offset).unwrap();
        let trace_domain = generate_trace_domain::<F>(padded_len).unwrap();
        let omega_last = trace_domain.generator().inverse().unwrap();
        let n_inv = F::from_u64(padded_len as u64).inverse().unwrap();
        let shift = blowup % lde_len;

        // Re-derive alphas from the honest transcript (mirrors verify_stark_v5_inner).
        let trace_root = honest.trace_commitment.as_root().unwrap();
        let quotient_root = honest.composition_commitment.as_root().unwrap();
        let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_MAIN_V5);
        t.append_message(
            protocol::label::PUB_INITIAL_ACC,
            honest.initial_acc.to_u64().to_le_bytes(),
        );
        t.append_message(
            protocol::label::PUB_FINAL_ACC,
            honest.final_acc.to_u64().to_le_bytes(),
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PUB_TRACE_LENGTH,
            honest.trace_length as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_QUERY_COUNT,
            honest.params.query_count as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_LDE_BLOWUP,
            honest.params.lde_blowup_factor as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_FRI_FINAL_SIZE,
            honest.params.fri_final_poly_size as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_FRI_FOLDING_RATIO,
            honest.params.fri_folding_ratio as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_GRINDING_BITS,
            honest.params.grinding_bits as u64,
        );
        t.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_ZK_ENABLED,
            u64::from(honest.params.zk_enabled),
        );
        protocol::append_u64::<Blake3>(
            &mut t,
            protocol::label::PARAM_ZK_MASK_DEGREE,
            honest.params.zk_mask_degree as u64,
        );
        t.append_message(
            protocol::label::COMMIT_TRACE_LDE_ROOT,
            trace_root.as_bytes(),
        );
        let alpha_b: K = t.challenge_field::<K>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
        let alpha_t: K = t.challenge_field::<K>(protocol::label::COMPOSITION_ALPHA_TRANSITION);
        let _ = quotient_root; // suppress unused-variable warning

        // For the first composition query, verify relation then confirm tamper breaks it.
        let cq = honest
            .query_response
            .composition_queries
            .first()
            .expect("composition query");
        let tq = honest
            .query_response
            .trace_queries
            .iter()
            .find(|q| q.index == cq.index)
            .expect("matching trace query");
        let next = tq.next.as_ref().expect("next row");

        let x = lde_domain.element(tq.index);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        let l0 = z_h.mul(n_inv).mul(x.sub(F::ONE).inverse().unwrap());
        let l_last = z_h
            .mul(omega_last)
            .mul(n_inv)
            .mul(x.sub(omega_last).inverse().unwrap());
        let selector_last = F::ONE.sub(l_last);
        let _ = shift; // used implicitly via next.index
        let acc = tq.evaluation[0];
        let delta = tq.evaluation[1];
        let acc_next = next.evaluation[0];
        let delta_next = next.evaluation[1];
        use hc_air::{DeepStarkAir, ToyAir};
        let (b, t_val) = ToyAir
            .constraint_values(
                &[acc, delta],
                &[acc_next, delta_next],
                l0,
                l_last,
                selector_last,
                honest.initial_acc,
                honest.final_acc,
            )
            .unwrap();
        let c_expected = K::from_base(b)
            .mul(alpha_b)
            .add(K::from_base(t_val).mul(alpha_t));

        // Honest: q·Z_H == C
        let lhs_honest = cq.value.mul(K::from_base(z_h));
        assert_eq!(
            lhs_honest, c_expected,
            "honest K quotient relation q·Z_H == C must hold"
        );

        // Tampered value: q·Z_H != C
        let tampered_value = cq.value.add(K::ONE);
        let lhs_tampered = tampered_value.mul(K::from_base(z_h));
        assert_ne!(
            lhs_tampered, c_expected,
            "K quotient relation must FAIL for tampered value (CompositionQueryValueMismatch path)"
        );
    }

    #[test]
    fn v5_tampered_grinding_nonce_rejected() {
        // Use a non-zero grinding difficulty so a wrong nonce fails the PoW.
        let mut proof = honest_proof(8);
        proof.grinding_nonce = proof.grinding_nonce.wrapping_add(1);
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered grinding nonce must be rejected");
        eprintln!("v5_tampered_grinding_nonce_rejected: {err}");
    }

    #[test]
    fn v5_tampered_final_coeffs_rejected() {
        let mut proof = honest_proof(8);
        // Mutate a final coefficient: the final layer no longer equals the
        // evaluation of `final_coeffs`, so the final-degree check fails.
        assert!(!proof.fri_proof.final_coeffs.is_empty());
        proof.fri_proof.final_coeffs[0] = proof.fri_proof.final_coeffs[0].add(K::ONE);
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("tampered final_coeffs must be rejected");
        eprintln!("v5_tampered_final_coeffs_rejected: {err}");
    }

    #[test]
    fn v5_truncated_final_coeffs_rejected() {
        // A LONGER final_coeffs than the degree bound must be rejected outright.
        let mut proof = honest_proof(8);
        proof.fri_proof.final_coeffs.push(K::from_u64(123)); // now longer than fri_final_poly_size/blowup
        let err = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect_err("over-long final_coeffs must be rejected");
        eprintln!("v5_over_long_final_coeffs_rejected: {err}");
    }

    // ── G7: security-floor enforcement ──────────────────────────────────────

    #[test]
    fn v5_default_floor_rejects_low_blowup() {
        // Honest proof with blowup 2 < MIN_BLOWUP (8): default floor must reject
        // BEFORE any crypto, so even a fully valid proof is refused.
        let proof = honest_proof(20);
        let err = verify_v5(&proof).expect_err("blowup below floor must be rejected");
        let s = err.to_string();
        assert!(
            s.contains("below the verifier security floor"),
            "expected BelowSecurityFloor, got: {s}"
        );
    }

    #[test]
    fn v5_default_floor_rejects_low_query_count() {
        // query_count 4 < MIN_QUERIES (40): default floor rejects.
        let proof = honest_proof(20);
        // (blowup also below floor; this test pins that the floor fires at all.)
        let err = verify_v5(&proof).expect_err("query_count below floor must be rejected");
        assert!(err
            .to_string()
            .contains("below the verifier security floor"));
    }

    #[test]
    fn v5_default_floor_rejects_low_grinding_bits() {
        // Isolate the grinding-bits floor: bump blowup/queries to/above floor so
        // ONLY grinding_bits is below the minimum.
        let mut proof = honest_proof(8); // grinding_bits = 8 < MIN_GRINDING_BITS (20)
        proof.params.lde_blowup_factor = 8;
        proof.params.query_count = 40;
        let err = enforce_floor(&proof, VerifierSecurityFloor::default())
            .expect_err("grinding_bits below floor must be rejected");
        assert!(err
            .to_string()
            .contains("below the verifier security floor"));
    }

    #[test]
    fn v5_default_floor_rejects_oversized_final_poly() {
        let mut proof = honest_proof(20);
        proof.params.lde_blowup_factor = 8;
        proof.params.query_count = 40;
        proof.params.fri_final_poly_size = 257; // > MAX (256)
        let err = enforce_floor(&proof, VerifierSecurityFloor::default())
            .expect_err("oversized final poly must be rejected");
        assert!(err
            .to_string()
            .contains("below the verifier security floor"));
    }

    #[test]
    fn v5_default_floor_rejects_legacy_version() {
        let mut proof = honest_proof(20);
        proof.version = 3; // < MIN_SOUND_VERSION (5)
        let err = enforce_floor(&proof, VerifierSecurityFloor::default())
            .expect_err("legacy version must be rejected");
        assert!(
            err.to_string().contains("unsound legacy protocol version"),
            "expected UnsoundLegacyVersion, got: {err}"
        );
    }

    #[test]
    fn v5_relaxed_floor_accepts_tiny_params() {
        // The relaxed floor must NOT reject tiny honest params (so the crypto can
        // be exercised). This is the floor's "off switch" used by every test.
        let proof = honest_proof(8);
        enforce_floor(&proof, VerifierSecurityFloor::relaxed())
            .expect("relaxed floor must accept tiny params");
    }
}
