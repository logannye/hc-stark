use std::{borrow::Cow, sync::Arc};

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::scalar_mul::variable_base::VariableBaseMSM;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_poly::{polynomial::univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_poly_commit::kzg10::{
    Commitment, Powers, Proof, Randomness, UniversalParams, VerifierKey, KZG10,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use once_cell::sync::OnceCell;

use hc_core::{
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};

const MAX_KZG_DEGREE: usize = 1 << 20; // Supports padded traces up to 1M rows.
const KZG_SEED: u64 = 0x5a51_d34d_c0de;

pub type KzgCurve = Bn254;
pub type KzgPoly = DensePolynomial<Fr>;

pub struct TraceKzgState {
    pub polynomials: Vec<KzgPoly>,
    pub randomness: Vec<Randomness<Fr, KzgPoly>>,
    pub commitments: Vec<Commitment<KzgCurve>>,
    pub domain_points: Arc<Vec<Fr>>,
}

pub struct KzgService {
    pub params: Arc<UniversalParams<KzgCurve>>,
    pub vk: Arc<VerifierKey<KzgCurve>>,
}

static KZG_SERVICE: OnceCell<KzgService> = OnceCell::new();

pub fn kzg_service() -> &'static KzgService {
    KZG_SERVICE.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(KZG_SEED);
        let params = KZG10::<KzgCurve, KzgPoly>::setup(MAX_KZG_DEGREE, false, &mut rng)
            .expect("kzg setup should succeed");
        let vk = VerifierKey {
            g: params.powers_of_g[0],
            gamma_g: params.powers_of_gamma_g[&0],
            h: params.h,
            beta_h: params.beta_h,
            prepared_h: params.prepared_h.clone(),
            prepared_beta_h: params.prepared_beta_h.clone(),
        };
        KzgService {
            params: Arc::new(params),
            vk: Arc::new(vk),
        }
    })
}

pub fn ensure_degree(limit: usize) -> HcResult<()> {
    if limit > MAX_KZG_DEGREE {
        Err(HcError::invalid_argument(format!(
            "KZG degree {limit} exceeds max supported {MAX_KZG_DEGREE}"
        )))
    } else {
        Ok(())
    }
}

pub fn goldilocks_to_fr(value: GoldilocksField) -> Fr {
    Fr::from(value.to_u64())
}

pub fn convert_coeffs<F: FieldElement>(values: &[F]) -> KzgPoly {
    let coeffs: Vec<Fr> = values.iter().map(|v| Fr::from(v.to_u64())).collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

pub fn convert_domain<F: FieldElement>(domain: &[F]) -> Arc<Vec<Fr>> {
    Arc::new(domain.iter().map(|v| Fr::from(v.to_u64())).collect())
}

pub fn serialize_commitment(comm: &Commitment<KzgCurve>) -> HcResult<G1Projective> {
    Ok(G1Projective::from(comm.0))
}

pub fn serialize_proof(proof: &Proof<KzgCurve>) -> HcResult<Vec<u8>> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|err| HcError::message(format!("failed to serialize KZG proof: {err}")))?;
    Ok(bytes)
}

pub fn deserialize_proof(bytes: &[u8]) -> HcResult<Proof<KzgCurve>> {
    Proof::<KzgCurve>::deserialize_compressed(bytes)
        .map_err(|err| HcError::message(format!("failed to parse KZG proof: {err}")))
}

pub fn serialize_fr(value: &Fr) -> HcResult<Vec<u8>> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|err| HcError::message(format!("failed to serialize field element: {err}")))?;
    Ok(bytes)
}

pub fn deserialize_fr(bytes: &[u8]) -> HcResult<Fr> {
    Fr::deserialize_compressed(bytes)
        .map_err(|err| HcError::message(format!("failed to parse field element: {err}")))
}

pub fn commitment_from_projective(point: &G1Projective) -> Commitment<KzgCurve> {
    Commitment(G1Affine::from(*point))
}

pub fn commit_polynomial(
    poly: &KzgPoly,
) -> HcResult<(Commitment<KzgCurve>, Randomness<Fr, KzgPoly>)> {
    let degree = poly.degree().max(1);
    let powers = trim_powers(degree)?;
    KZG10::<KzgCurve, KzgPoly>::commit(&powers, poly, None, None)
        .map_err(|err| HcError::message(format!("failed to commit polynomial: {err}")))
}

pub fn open_polynomial(
    poly: &KzgPoly,
    point: Fr,
    randomness: &Randomness<Fr, KzgPoly>,
) -> HcResult<Proof<KzgCurve>> {
    if randomness.is_hiding() {
        return Err(HcError::message(
            "streaming KZG openings do not support hiding randomness",
        ));
    }

    let degree = poly.degree().max(1);
    let powers = trim_powers(degree)?;
    let (witness_poly, _) = KZG10::<KzgCurve, KzgPoly>::compute_witness_polynomial(
        poly, point, randomness,
    )
    .map_err(|err| HcError::message(format!("failed to build witness polynomial: {err}")))?;

    let (num_leading_zeros, coeffs) = leading_zeros_and_bigints(&witness_poly);
    let msm = <G1Projective as VariableBaseMSM>::msm_bigint(
        &powers.powers_of_g[num_leading_zeros..],
        coeffs.as_slice(),
    );

    Ok(Proof {
        w: msm.into_affine(),
        random_v: None,
    })
}

pub fn verify_proof(
    commitment: &Commitment<KzgCurve>,
    point: Fr,
    value: Fr,
    proof: &Proof<KzgCurve>,
) -> HcResult<bool> {
    KZG10::<KzgCurve, KzgPoly>::check(&kzg_service().vk, commitment, point, value, proof)
        .map_err(|err| HcError::message(format!("failed to verify KZG proof: {err}")))
}

fn trim_powers(degree: usize) -> HcResult<Powers<'static, KzgCurve>> {
    let supported = degree.max(1);
    ensure_degree(supported)?;
    let params = kzg_service().params.clone();
    if params.powers_of_g.len() <= supported {
        return Err(HcError::message(format!(
            "kzg params lack enough powers for degree {supported}"
        )));
    }
    let g_powers = params.powers_of_g[..=supported].to_vec();
    let mut gamma_powers = Vec::with_capacity(supported + 1);
    for i in 0..=supported {
        let value = params
            .powers_of_gamma_g
            .get(&i)
            .ok_or_else(|| HcError::message(format!("missing gamma power {i}")))?;
        gamma_powers.push(*value);
    }
    Ok(Powers {
        powers_of_g: Cow::Owned(g_powers),
        powers_of_gamma_g: Cow::Owned(gamma_powers),
    })
}

fn leading_zeros_and_bigints(poly: &KzgPoly) -> (usize, Vec<<Fr as ark_ff::PrimeField>::BigInt>) {
    let coeffs = poly.coeffs();
    let mut first_non_zero = 0usize;
    while first_non_zero < coeffs.len() && coeffs[first_non_zero].is_zero() {
        first_non_zero += 1;
    }
    let bigints = coeffs[first_non_zero..]
        .iter()
        .map(|value| value.into_bigint())
        .collect();
    (first_non_zero, bigints)
}
