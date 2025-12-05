use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Instance, Selector, SingleVerifier,
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
use crate::aggregator::ProofSummary;

const HALO2_MIN_K: u32 = 9;
const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Halo2RecursiveProof {
    pub k: u32,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SummaryCircuit {
    encoding_fields: Vec<Vec<Fr>>,
    encoding_words: Vec<Vec<u64>>,
    digests: Vec<Fr>,
    total_rows: usize,
}

impl SummaryCircuit {
    fn new(encoding_fields: Vec<Vec<Fr>>, encoding_words: Vec<Vec<u64>>, digests: Vec<Fr>) -> Self {
        let total_rows = encoding_fields.iter().map(|e| e.len()).sum();
        Self {
            encoding_fields,
            encoding_words,
            digests,
            total_rows,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SummaryConfig {
    value: Column<Advice>,
    acc: Column<Advice>,
    carry: Column<Advice>,
    q_first: Selector,
    q_acc: Selector,
    instance: Column<Instance>,
}

impl Circuit<Fr> for SummaryCircuit {
    type Config = SummaryConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let encoding_fields = self
            .encoding_fields
            .iter()
            .map(|encoding| vec![Fr::ZERO; encoding.len()])
            .collect();
        let encoding_words = self
            .encoding_words
            .iter()
            .map(|encoding| vec![0u64; encoding.len()])
            .collect();
        let digests = vec![Fr::ZERO; self.digests.len()];
        SummaryCircuit::new(encoding_fields, encoding_words, digests)
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let value = meta.advice_column();
        let acc = meta.advice_column();
        let carry = meta.advice_column();
        let q_first = meta.selector();
        let q_acc = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(value);
        meta.enable_equality(acc);
        meta.enable_equality(carry);
        meta.enable_equality(instance);

        let goldilocks_mod = Fr::from(GOLDILOCKS_MODULUS);

        meta.create_gate("first row", |meta| {
            let q = meta.query_selector(q_first);
            let v = meta.query_advice(value, Rotation::cur());
            let a = meta.query_advice(acc, Rotation::cur());
            let c = meta.query_advice(carry, Rotation::cur());
            vec![q.clone() * (a - v), q * c]
        });

        meta.create_gate("accumulate", |meta| {
            let q = meta.query_selector(q_acc);
            let v = meta.query_advice(value, Rotation::cur());
            let a = meta.query_advice(acc, Rotation::cur());
            let a_prev = meta.query_advice(acc, Rotation::prev());
            let c = meta.query_advice(carry, Rotation::cur());
            let bool_check = c.clone() * (c.clone() - Expression::Constant(Fr::ONE));
            let relation = a_prev + v - a - c * Expression::Constant(goldilocks_mod);
            vec![q.clone() * relation, q * bool_check]
        });

        SummaryConfig {
            value,
            acc,
            carry,
            q_first,
            q_acc,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut final_cells = Vec::with_capacity(self.digests.len());

        layouter.assign_region(
            || "summary accumulation",
            |mut region| {
                let mut offset = 0;
                let mut summary_idx = 0usize;
                final_cells.clear();
                for (encoding_fields, encoding_words) in
                    self.encoding_fields.iter().zip(self.encoding_words.iter())
                {
                    let mut acc_u64 = 0u64;
                    for (index, (value, word)) in
                        encoding_fields.iter().zip(encoding_words).enumerate()
                    {
                        let (new_acc, carry) = add_goldilocks(acc_u64, *word);
                        acc_u64 = new_acc;
                        let carry_fr = Fr::from(carry);
                        let acc_fr = Fr::from(new_acc);
                        region.assign_advice(
                            || "value",
                            config.value,
                            offset,
                            || Value::known(*value),
                        )?;
                        let cell = region.assign_advice(
                            || "acc",
                            config.acc,
                            offset,
                            || Value::known(acc_fr),
                        )?;
                        region.assign_advice(
                            || "carry",
                            config.carry,
                            offset,
                            || Value::known(carry_fr),
                        )?;
                        if index == 0 {
                            config.q_first.enable(&mut region, offset)?;
                        } else {
                            config.q_acc.enable(&mut region, offset)?;
                        }
                        offset += 1;
                        if index + 1 == encoding_fields.len() {
                            #[cfg(debug_assertions)]
                            debug_assert_eq!(
                                acc_fr,
                                self.digests[summary_idx],
                                "accumulator mismatch for summary {summary_idx}"
                            );
                            final_cells.push(cell);
                            summary_idx += 1;
                        }
                    }
                }
                Ok(())
            },
        )?;

        for (idx, cell) in final_cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, idx)?;
        }

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
    let encoding_fields = summaries.iter().map(encoding_to_fr).collect::<Vec<_>>();
    let encoding_words = summaries.iter().map(encoding_words).collect::<Vec<_>>();
    #[cfg(debug_assertions)]
    for (summary, words) in summaries.iter().zip(encoding_words.iter()) {
        let mut acc = 0u64;
        for word in words {
            acc = add_goldilocks(acc, *word).0;
        }
        debug_assert_eq!(
            acc,
            summary.circuit_digest.to_u64(),
            "summary digest mismatch"
        );
    }
    let public_inputs = summaries
        .iter()
        .map(|summary| Fr::from(summary.circuit_digest.to_u64()))
        .collect::<Vec<_>>();
    let circuit = SummaryCircuit::new(encoding_fields, encoding_words, public_inputs.clone());
    let k = halo2_k_for_rows(circuit.total_rows);
    let params = halo2_params(k);

    let vk = keygen_vk(&params, &circuit)
        .map_err(|err| HcError::message(format!("failed to build recursion vk: {err}")))?;
    let pk = keygen_pk(&params, vk, &circuit)
        .map_err(|err| HcError::message(format!("failed to build recursion pk: {err}")))?;

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
    let encoding_fields = summaries.iter().map(encoding_to_fr).collect::<Vec<_>>();
    let encoding_words = summaries.iter().map(encoding_words).collect::<Vec<_>>();
    let public_inputs = summaries
        .iter()
        .map(|summary| Fr::from(summary.circuit_digest.to_u64()))
        .collect::<Vec<_>>();
    let circuit = SummaryCircuit::new(encoding_fields, encoding_words, public_inputs.clone());
    let params = halo2_params(halo2_proof.k);
    let vk = keygen_vk(&params, &circuit)
        .map_err(|err| HcError::message(format!("failed to rebuild recursion vk: {err}")))?;

    let strategy = SingleVerifier::new(&params);
    let instance_columns = vec![public_inputs.as_slice()];
    let instance_views = vec![instance_columns.as_slice()];
    let mut transcript =
        Blake2bRead::<_, G1Affine, Challenge255<G1Affine>>::init(halo2_proof.proof.as_slice());
    verify_proof::<G1Affine, _, _, _>(&params, &vk, strategy, &instance_views, &mut transcript)
        .map_err(|err| HcError::message(format!("halo2 recursion proof invalid: {err}")))
}

fn encoding_to_fr(summary: &ProofSummary<GoldilocksField>) -> Vec<Fr> {
    encode_summary(summary)
        .as_fields()
        .into_iter()
        .map(|value| Fr::from(value.to_u64()))
        .collect()
}

fn encoding_words(summary: &ProofSummary<GoldilocksField>) -> Vec<u64> {
    encode_summary(summary)
        .as_fields()
        .into_iter()
        .map(|value| value.to_u64())
        .collect()
}

fn add_goldilocks(acc: u64, value: u64) -> (u64, u64) {
    let sum = acc as u128 + value as u128;
    if sum >= GOLDILOCKS_MODULUS as u128 {
        ((sum - GOLDILOCKS_MODULUS as u128) as u64, 1)
    } else {
        (sum as u64, 0)
    }
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
