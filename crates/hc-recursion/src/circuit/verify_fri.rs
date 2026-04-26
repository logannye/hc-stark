//! FRI folding verification gadget (in-circuit) + Poseidon transcript-derived challenge.
//!
//! This module is intentionally minimal for Phase 3B: it enforces the folding relation
//! \(v_{next} = v_0 + \beta \cdot v_1\) at a queried point, where \(\beta\) is derived
//! from a Poseidon transcript over committed roots.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use super::{poseidon, poseidon_chip::PoseidonChip};

#[derive(Clone, Debug)]
struct FriFoldCircuit {
    root0: Fr,
    root1: Fr,
    v0: Fr,
    v1: Fr,
    v_next: Fr,
}

#[derive(Clone, Debug)]
struct FriFoldConfig {
    chip: crate::circuit::poseidon_chip::PoseidonChipConfig,
    instance: Column<Instance>,
    a: Column<Advice>,
    b: Column<Advice>,
    next: Column<Advice>,
    q_fold: Selector,
}

impl Circuit<Fr> for FriFoldCircuit {
    type Config = FriFoldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            root0: Fr::ZERO,
            root1: Fr::ZERO,
            v0: Fr::ZERO,
            v1: Fr::ZERO,
            v_next: Fr::ZERO,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let chip = PoseidonChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let a = meta.advice_column();
        let b = meta.advice_column();
        let next = meta.advice_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(next);

        let q_fold = meta.selector();
        meta.create_gate("fri_fold", |meta| {
            let q = meta.query_selector(q_fold);
            let v0 = meta.query_advice(a, Rotation::cur());
            let v1 = meta.query_advice(b, Rotation::cur());
            let vnext = meta.query_advice(next, Rotation::cur());
            let beta = meta.query_instance(instance, Rotation::cur());
            vec![q * (vnext - (v0 + beta * v1))]
        });

        FriFoldConfig {
            chip,
            instance,
            a,
            b,
            next,
            q_fold,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::new(config.chip);

        // Derive beta = Poseidon(domain_tag, root0, root1) in-circuit.
        let root0_cell = layouter.assign_region(
            || "root0",
            |mut region| {
                region.assign_advice(
                    || "root0",
                    chip.cfg().state0,
                    0,
                    || Value::known(self.root0),
                )
            },
        )?;
        let root1_cell = layouter.assign_region(
            || "root1",
            |mut region| {
                region.assign_advice(
                    || "root1",
                    chip.cfg().state1,
                    0,
                    || Value::known(self.root1),
                )
            },
        )?;
        let beta_cell = chip.hash2_cells(
            layouter.namespace(|| "beta"),
            poseidon::domain_tag(),
            &root0_cell,
            &root1_cell,
        )?;

        // Constrain beta_cell == instance[0].
        layouter.constrain_instance(beta_cell.cell(), config.instance, 0)?;

        // Enforce folding relation using beta from instance.
        layouter.assign_region(
            || "fold",
            |mut region| {
                config.q_fold.enable(&mut region, 0)?;
                region.assign_advice(|| "v0", config.a, 0, || Value::known(self.v0))?;
                region.assign_advice(|| "v1", config.b, 0, || Value::known(self.v1))?;
                region.assign_advice(|| "vnext", config.next, 0, || Value::known(self.v_next))?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use hc_core::field::{prime_field::GoldilocksField, FieldElement};
    use hc_prover::{config::ProverConfig, prove, PublicInputs};
    use hc_verifier::Proof;
    use hc_vm::{Instruction, Program};

    #[test]
    fn fri_fold_constraint_holds() {
        let root0 = Fr::from(7u64);
        let root1 = Fr::from(9u64);

        let beta = poseidon::hash(&[root0, root1]);

        let v0 = Fr::from(3u64);
        let v1 = Fr::from(11u64);
        let v_next = v0 + beta * v1;

        let circuit = FriFoldCircuit {
            root0,
            root1,
            v0,
            v1,
            v_next,
        };

        let k = 18;
        let prover = MockProver::run(k, &circuit, vec![vec![beta]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn fri_fold_accepts_real_proof_opening_shape() {
        // Generate a real proof so we consume "real" STARK-style openings.
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let prover_out = prove(config, program, inputs.clone()).unwrap();
        let proof = Proof {
            version: prover_out.version,
            trace_commitment: prover_out.trace_commitment,
            composition_commitment: prover_out.composition_commitment,
            fri_proof: prover_out.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover_out.query_response,
            trace_length: prover_out.trace_length,
            params: prover_out.params,
        };

        let response = proof.query_response.as_ref().expect("query response");
        let fq0 = response.fri_queries.first().expect("fri query");
        // "Roots" are Blake3 digests; for gadget wiring we map them into Fr via u64 limbs.
        let root0 = Fr::from(u64::from_le_bytes(
            proof.fri_proof.layer_roots[0].as_bytes()[0..8]
                .try_into()
                .unwrap(),
        ));
        let root1 = if proof.fri_proof.layer_roots.len() > 1 {
            Fr::from(u64::from_le_bytes(
                proof.fri_proof.layer_roots[1].as_bytes()[0..8]
                    .try_into()
                    .unwrap(),
            ))
        } else {
            Fr::from(0u64)
        };

        let beta = poseidon::hash(&[root0, root1]);
        let v0 = Fr::from(fq0.values[0].to_u64());
        let v1 = Fr::from(fq0.values[1].to_u64());
        let v_next = v0 + beta * v1;

        let circuit = FriFoldCircuit {
            root0,
            root1,
            v0,
            v1,
            v_next,
        };
        let k = 18;
        let prover = MockProver::run(k, &circuit, vec![vec![beta]]).unwrap();
        prover.assert_satisfied();
    }
}
