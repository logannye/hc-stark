use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, Selector, SingleVerifier,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::bn256::{Fr, G1Affine};
use rand::rngs::OsRng;

use hc_core::{
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};

use super::encode_summary;
use super::poseidon as poseidon_native;
use crate::aggregator::ProofSummary;

const HALO2_MIN_K: u32 = 9;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Halo2RecursiveProof {
    pub k: u32,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PoseidonWitnessCircuit {
    inputs: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    state0: Column<Advice>,
    state1: Column<Advice>,
    state2: Column<Advice>,
    in0: Column<Advice>,
    in1: Column<Advice>,
    ark0: Column<Fixed>,
    ark1: Column<Fixed>,
    ark2: Column<Fixed>,
    q_absorb: Selector,
    q_full: Selector,
    q_partial: Selector,
    instance: Column<Instance>,
    mds: [[Fr; 3]; 3],
}

fn pow5_expr(x: halo2_proofs::plonk::Expression<Fr>) -> halo2_proofs::plonk::Expression<Fr> {
    // x^5 = x * x^2 * x^2
    let x2 = x.clone() * x.clone();
    x.clone() * x2.clone() * x2
}

impl Circuit<Fr> for PoseidonWitnessCircuit {
    type Config = PoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: vec![Fr::ZERO; self.inputs.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let state0 = meta.advice_column();
        let state1 = meta.advice_column();
        let state2 = meta.advice_column();
        let in0 = meta.advice_column();
        let in1 = meta.advice_column();
        let ark0 = meta.fixed_column();
        let ark1 = meta.fixed_column();
        let ark2 = meta.fixed_column();
        let q_absorb = meta.selector();
        let q_full = meta.selector();
        let q_partial = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(state0);
        meta.enable_equality(state1);
        meta.enable_equality(state2);
        meta.enable_equality(instance);

        let params = poseidon_native::params();
        let mds = params.mds;

        // Absorb: (s0',s1',s2') = (s0+in0, s1+in1, s2)
        meta.create_gate("poseidon_absorb", |meta| {
            let q = meta.query_selector(q_absorb);
            let s0 = meta.query_advice(state0, Rotation::cur());
            let s1 = meta.query_advice(state1, Rotation::cur());
            let s2 = meta.query_advice(state2, Rotation::cur());
            let n0 = meta.query_advice(state0, Rotation::next());
            let n1 = meta.query_advice(state1, Rotation::next());
            let n2 = meta.query_advice(state2, Rotation::next());
            let i0 = meta.query_advice(in0, Rotation::cur());
            let i1 = meta.query_advice(in1, Rotation::cur());
            vec![
                q.clone() * (n0 - (s0 + i0)),
                q.clone() * (n1 - (s1 + i1)),
                q * (n2 - s2),
            ]
        });

        let round_gate = |is_full: bool| {
            move |meta: &mut halo2_proofs::plonk::VirtualCells<'_, Fr>| {
                let q = if is_full {
                    meta.query_selector(q_full)
                } else {
                    meta.query_selector(q_partial)
                };

                let s0 = meta.query_advice(state0, Rotation::cur());
                let s1 = meta.query_advice(state1, Rotation::cur());
                let s2 = meta.query_advice(state2, Rotation::cur());
                let n0 = meta.query_advice(state0, Rotation::next());
                let n1 = meta.query_advice(state1, Rotation::next());
                let n2 = meta.query_advice(state2, Rotation::next());

                let k0 = meta.query_fixed(ark0);
                let k1 = meta.query_fixed(ark1);
                let k2 = meta.query_fixed(ark2);

                let x0 = s0 + k0;
                let x1 = s1 + k1;
                let x2 = s2 + k2;

                let y0 = pow5_expr(x0);
                let (y1, y2) = if is_full {
                    (pow5_expr(x1), pow5_expr(x2))
                } else {
                    (x1, x2)
                };

                let z0 = halo2_proofs::plonk::Expression::Constant(mds[0][0]) * y0.clone()
                    + halo2_proofs::plonk::Expression::Constant(mds[0][1]) * y1.clone()
                    + halo2_proofs::plonk::Expression::Constant(mds[0][2]) * y2.clone();
                let z1 = halo2_proofs::plonk::Expression::Constant(mds[1][0]) * y0.clone()
                    + halo2_proofs::plonk::Expression::Constant(mds[1][1]) * y1.clone()
                    + halo2_proofs::plonk::Expression::Constant(mds[1][2]) * y2.clone();
                let z2 = halo2_proofs::plonk::Expression::Constant(mds[2][0]) * y0
                    + halo2_proofs::plonk::Expression::Constant(mds[2][1]) * y1
                    + halo2_proofs::plonk::Expression::Constant(mds[2][2]) * y2;

                vec![q.clone() * (n0 - z0), q.clone() * (n1 - z1), q * (n2 - z2)]
            }
        };

        meta.create_gate("poseidon_round_full", round_gate(true));
        meta.create_gate("poseidon_round_partial", round_gate(false));

        PoseidonConfig {
            state0,
            state1,
            state2,
            in0,
            in1,
            ark0,
            ark1,
            ark2,
            q_absorb,
            q_full,
            q_partial,
            instance,
            mds,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let params = poseidon_native::params();
        let rounds = params.ark.len();
        let full_half = poseidon_native::FULL_ROUNDS / 2;
        let partial_rounds = poseidon_native::PARTIAL_ROUNDS;
        let full_start_2 = full_half + partial_rounds;

        // Chunk inputs into rate-2 absorbs (pad with 1 if needed).
        let mut chunks = Vec::new();
        let mut i = 0usize;
        while i < self.inputs.len() {
            let a = self.inputs[i];
            let b = if i + 1 < self.inputs.len() {
                self.inputs[i + 1]
            } else {
                Fr::ONE
            };
            chunks.push((a, b));
            i += 2;
        }
        if chunks.is_empty() {
            chunks.push((Fr::ONE, Fr::ZERO));
        }

        let mut final_cell = None;

        layouter.assign_region(
            || "poseidon_witness_commitment",
            |mut region| {
                let mut offset = 0usize;

                // Initialize state to zero.
                region.assign_advice(|| "s0", config.state0, offset, || Value::known(Fr::ZERO))?;
                region.assign_advice(|| "s1", config.state1, offset, || Value::known(Fr::ZERO))?;
                region.assign_advice(|| "s2", config.state2, offset, || Value::known(Fr::ZERO))?;
                region.assign_advice(|| "in0", config.in0, offset, || Value::known(Fr::ZERO))?;
                region.assign_advice(|| "in1", config.in1, offset, || Value::known(Fr::ZERO))?;
                offset += 1;

                // Domain separation permutation: start from state = [domain_tag, 0, 0] and permute.
                let mut state = [poseidon_native::domain_tag(), Fr::ZERO, Fr::ZERO];
                region.assign_advice(
                    || "s0_domain",
                    config.state0,
                    offset,
                    || Value::known(state[0]),
                )?;
                region.assign_advice(
                    || "s1_domain",
                    config.state1,
                    offset,
                    || Value::known(state[1]),
                )?;
                region.assign_advice(
                    || "s2_domain",
                    config.state2,
                    offset,
                    || Value::known(state[2]),
                )?;
                region.assign_advice(
                    || "in0_domain",
                    config.in0,
                    offset,
                    || Value::known(Fr::ZERO),
                )?;
                region.assign_advice(
                    || "in1_domain",
                    config.in1,
                    offset,
                    || Value::known(Fr::ZERO),
                )?;

                // Run permutation rounds (no absorb).
                for r in 0..rounds {
                    let is_full = r < full_half || r >= full_start_2;
                    if is_full {
                        config.q_full.enable(&mut region, offset)?;
                    } else {
                        config.q_partial.enable(&mut region, offset)?;
                    }
                    region.assign_fixed(
                        || "ark0",
                        config.ark0,
                        offset,
                        || Value::known(params.ark[r][0]),
                    )?;
                    region.assign_fixed(
                        || "ark1",
                        config.ark1,
                        offset,
                        || Value::known(params.ark[r][1]),
                    )?;
                    region.assign_fixed(
                        || "ark2",
                        config.ark2,
                        offset,
                        || Value::known(params.ark[r][2]),
                    )?;
                    region.assign_advice(
                        || "s0",
                        config.state0,
                        offset,
                        || Value::known(state[0]),
                    )?;
                    region.assign_advice(
                        || "s1",
                        config.state1,
                        offset,
                        || Value::known(state[1]),
                    )?;
                    region.assign_advice(
                        || "s2",
                        config.state2,
                        offset,
                        || Value::known(state[2]),
                    )?;
                    region.assign_advice(
                        || "in0",
                        config.in0,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1",
                        config.in1,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;

                    let mut x0 = state[0] + params.ark[r][0];
                    let mut x1 = state[1] + params.ark[r][1];
                    let mut x2 = state[2] + params.ark[r][2];
                    x0 = x0.pow_vartime([5, 0, 0, 0]);
                    if is_full {
                        x1 = x1.pow_vartime([5, 0, 0, 0]);
                        x2 = x2.pow_vartime([5, 0, 0, 0]);
                    }
                    let n0 = config.mds[0][0] * x0 + config.mds[0][1] * x1 + config.mds[0][2] * x2;
                    let n1 = config.mds[1][0] * x0 + config.mds[1][1] * x1 + config.mds[1][2] * x2;
                    let n2 = config.mds[2][0] * x0 + config.mds[2][1] * x1 + config.mds[2][2] * x2;
                    state = [n0, n1, n2];
                    region.assign_advice(
                        || "s0_next",
                        config.state0,
                        offset + 1,
                        || Value::known(state[0]),
                    )?;
                    region.assign_advice(
                        || "s1_next",
                        config.state1,
                        offset + 1,
                        || Value::known(state[1]),
                    )?;
                    region.assign_advice(
                        || "s2_next",
                        config.state2,
                        offset + 1,
                        || Value::known(state[2]),
                    )?;
                    region.assign_advice(
                        || "in0_next",
                        config.in0,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1_next",
                        config.in1,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    offset += 1;
                }

                // Absorb + permute per chunk (starting from the domain-separated state).
                for (chunk_idx, (a, b)) in chunks.iter().copied().enumerate() {
                    // Absorb row.
                    config.q_absorb.enable(&mut region, offset)?;
                    region.assign_advice(|| "in0", config.in0, offset, || Value::known(a))?;
                    region.assign_advice(|| "in1", config.in1, offset, || Value::known(b))?;

                    // Set current state.
                    region.assign_advice(
                        || "s0",
                        config.state0,
                        offset,
                        || Value::known(state[0]),
                    )?;
                    region.assign_advice(
                        || "s1",
                        config.state1,
                        offset,
                        || Value::known(state[1]),
                    )?;
                    region.assign_advice(
                        || "s2",
                        config.state2,
                        offset,
                        || Value::known(state[2]),
                    )?;

                    // Next state after absorb.
                    state[0] += a;
                    state[1] += b;
                    region.assign_advice(
                        || "s0'",
                        config.state0,
                        offset + 1,
                        || Value::known(state[0]),
                    )?;
                    region.assign_advice(
                        || "s1'",
                        config.state1,
                        offset + 1,
                        || Value::known(state[1]),
                    )?;
                    region.assign_advice(
                        || "s2'",
                        config.state2,
                        offset + 1,
                        || Value::known(state[2]),
                    )?;
                    region.assign_advice(
                        || "in0'",
                        config.in0,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1'",
                        config.in1,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;

                    offset += 1;

                    // Permutation rounds: each round consumes one row (cur) and writes next row.
                    for r in 0..rounds {
                        let is_full = r < full_half || r >= full_start_2;
                        if is_full {
                            config.q_full.enable(&mut region, offset)?;
                        } else {
                            config.q_partial.enable(&mut region, offset)?;
                        }

                        // Fixed ARK for this round at this row.
                        region.assign_fixed(
                            || "ark0",
                            config.ark0,
                            offset,
                            || Value::known(params.ark[r][0]),
                        )?;
                        region.assign_fixed(
                            || "ark1",
                            config.ark1,
                            offset,
                            || Value::known(params.ark[r][1]),
                        )?;
                        region.assign_fixed(
                            || "ark2",
                            config.ark2,
                            offset,
                            || Value::known(params.ark[r][2]),
                        )?;

                        // Assign current state (already assigned on the first round's row via absorb next),
                        // but for subsequent rounds we need to ensure it's present.
                        region.assign_advice(
                            || "s0",
                            config.state0,
                            offset,
                            || Value::known(state[0]),
                        )?;
                        region.assign_advice(
                            || "s1",
                            config.state1,
                            offset,
                            || Value::known(state[1]),
                        )?;
                        region.assign_advice(
                            || "s2",
                            config.state2,
                            offset,
                            || Value::known(state[2]),
                        )?;
                        region.assign_advice(
                            || "in0",
                            config.in0,
                            offset,
                            || Value::known(Fr::ZERO),
                        )?;
                        region.assign_advice(
                            || "in1",
                            config.in1,
                            offset,
                            || Value::known(Fr::ZERO),
                        )?;

                        // Compute next state n = MDS * SBOX(state + ark)
                        let mut x0 = state[0] + params.ark[r][0];
                        let mut x1 = state[1] + params.ark[r][1];
                        let mut x2 = state[2] + params.ark[r][2];
                        x0 = x0.pow_vartime([5, 0, 0, 0]);
                        if is_full {
                            x1 = x1.pow_vartime([5, 0, 0, 0]);
                            x2 = x2.pow_vartime([5, 0, 0, 0]);
                        }
                        let n0 =
                            config.mds[0][0] * x0 + config.mds[0][1] * x1 + config.mds[0][2] * x2;
                        let n1 =
                            config.mds[1][0] * x0 + config.mds[1][1] * x1 + config.mds[1][2] * x2;
                        let n2 =
                            config.mds[2][0] * x0 + config.mds[2][1] * x1 + config.mds[2][2] * x2;
                        state = [n0, n1, n2];

                        // Assign next row state.
                        region.assign_advice(
                            || "s0_next",
                            config.state0,
                            offset + 1,
                            || Value::known(state[0]),
                        )?;
                        region.assign_advice(
                            || "s1_next",
                            config.state1,
                            offset + 1,
                            || Value::known(state[1]),
                        )?;
                        region.assign_advice(
                            || "s2_next",
                            config.state2,
                            offset + 1,
                            || Value::known(state[2]),
                        )?;
                        region.assign_advice(
                            || "in0_next",
                            config.in0,
                            offset + 1,
                            || Value::known(Fr::ZERO),
                        )?;
                        region.assign_advice(
                            || "in1_next",
                            config.in1,
                            offset + 1,
                            || Value::known(Fr::ZERO),
                        )?;

                        offset += 1;
                    }

                    // After last chunk's permutation, remember state0 as output.
                    if chunk_idx + 1 == chunks.len() {
                        final_cell = Some(region.assign_advice(
                            || "digest",
                            config.state0,
                            offset,
                            || Value::known(state[0]),
                        )?);
                    }
                }
                Ok(())
            },
        )?;

        // Constrain digest to instance[0].
        let cell = final_cell.ok_or(Error::Synthesis)?;
        layouter.constrain_instance(cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

pub fn prove_summaries(
    summaries: &[ProofSummary<GoldilocksField>],
) -> HcResult<Halo2RecursiveProof> {
    if summaries.is_empty() {
        return Err(HcError::invalid_argument(
            "cannot build recursion circuit without summaries",
        ));
    }

    let mut inputs = Vec::new();
    for summary in summaries {
        inputs.extend(
            encode_summary(summary)
                .as_fields()
                .into_iter()
                .map(|value| Fr::from(value.to_u64())),
        );
    }
    let digest = poseidon_native::hash(inputs.as_slice());
    let circuit = PoseidonWitnessCircuit {
        inputs: inputs.clone(),
    };

    let k = halo2_k_for_rows(
        1 + (1 + poseidon_native::params().ark.len()) * ((inputs.len() + 1).div_ceil(2)),
    );
    let params = halo2_params(k);

    let vk = keygen_vk(&params, &circuit)
        .map_err(|err| HcError::message(format!("failed to build recursion vk: {err}")))?;
    let pk = keygen_pk(&params, vk, &circuit)
        .map_err(|err| HcError::message(format!("failed to build recursion pk: {err}")))?;

    let public_inputs = vec![digest];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<G1Affine>>::init(Vec::new());
    let instance_columns = vec![public_inputs.as_slice()];
    let instance_views = vec![instance_columns.as_slice()];
    create_proof::<G1Affine, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &instance_views,
        OsRng,
        &mut transcript,
    )
    .map_err(|err| HcError::message(format!("failed to create recursion proof: {err}")))?;
    let proof = transcript.finalize();

    Ok(Halo2RecursiveProof { k, proof })
}

pub fn verify_summaries(
    halo2_proof: &Halo2RecursiveProof,
    summaries: &[ProofSummary<GoldilocksField>],
) -> HcResult<()> {
    let mut inputs = Vec::new();
    for summary in summaries {
        inputs.extend(
            encode_summary(summary)
                .as_fields()
                .into_iter()
                .map(|value| Fr::from(value.to_u64())),
        );
    }
    let digest = poseidon_native::hash(inputs.as_slice());
    let circuit = PoseidonWitnessCircuit {
        inputs: inputs.clone(),
    };

    let params = halo2_params(halo2_proof.k);
    let vk = keygen_vk(&params, &circuit)
        .map_err(|err| HcError::message(format!("failed to rebuild recursion vk: {err}")))?;

    let strategy = SingleVerifier::new(&params);
    let public_inputs = vec![digest];
    let instance_columns = vec![public_inputs.as_slice()];
    let instance_views = vec![instance_columns.as_slice()];
    let mut transcript =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(halo2_proof.proof.as_slice());
    verify_proof::<G1Affine, _, _, _>(&params, &vk, strategy, &instance_views, &mut transcript)
        .map_err(|err| HcError::message(format!("halo2 recursion proof invalid: {err}")))
}

fn halo2_k_for_rows(rows: usize) -> u32 {
    let size = rows.max(1);
    let mut k = HALO2_MIN_K;
    while (1usize << k) <= size {
        k += 1;
    }
    k
}

fn halo2_params(k: u32) -> Params<G1Affine> {
    Params::<G1Affine>::new(k)
}
