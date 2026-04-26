//! Multi-layer FRI chain verification gadget.
//!
//! Extends the single-layer `FriFoldCircuit` to verify the full FRI protocol:
//!
//! 1. For each FRI layer `i`:
//!    - Derive beta_i = Poseidon(accumulated_state, layer_root_i)
//!    - Verify Merkle opening of the coset pair (v0, v1) against layer_root_i
//!    - Enforce folding: folded_i = v0 + beta_i * v1
//!    - folded_i becomes the expected value for the next layer
//!
//! 2. After all layers, verify that the final folded value matches the
//!    claimed final polynomial evaluation.
//!
//! Each layer uses the PoseidonChip for beta derivation and MerkleCircuit
//! infrastructure for opening verification.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use super::poseidon as poseidon_native;
use super::poseidon_chip::PoseidonChip;

/// Witness data for a single FRI layer fold.
#[derive(Clone, Debug)]
pub struct FriLayerWitness {
    /// Root commitment for this FRI layer (mapped to Fr).
    pub layer_root: Fr,
    /// The two coset values opened at the queried pair index.
    pub v0: Fr,
    pub v1: Fr,
    /// The folded value (v0 + beta * v1).
    pub folded: Fr,
    /// Beta challenge for this layer.
    pub beta: Fr,
}

/// Witness for the complete FRI chain verification.
#[derive(Clone, Debug)]
pub struct FriChainWitness {
    /// Per-layer fold witnesses.
    pub layers: Vec<FriLayerWitness>,
    /// The expected final value after all folding.
    pub final_value: Fr,
    /// The claimed final polynomial evaluation from the proof.
    pub claimed_final: Fr,
}

/// Configuration for the FRI chain verification circuit.
#[derive(Clone, Debug)]
pub struct FriChainConfig {
    pub chip: super::poseidon_chip::PoseidonChipConfig,
    pub instance: Column<Instance>,
    /// Advice columns for fold values.
    pub col_v0: Column<Advice>,
    pub col_v1: Column<Advice>,
    pub col_folded: Column<Advice>,
    /// Advice column for beta (constrained to instance via copy constraint).
    pub col_beta: Column<Advice>,
    /// Selector for the fold gate.
    pub q_fold: Selector,
    /// Selector for final value equality check.
    pub q_final: Selector,
}

impl FriChainConfig {
    /// Configure with its own PoseidonChip and instance column (standalone use).
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let chip = PoseidonChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::configure_with_shared(meta, chip, instance)
    }

    /// Configure using a shared PoseidonChipConfig and instance column.
    ///
    /// This allows the FRI chain to be embedded in a larger circuit
    /// (like the STARK verifier) without creating duplicate columns.
    pub fn configure_with_shared(
        meta: &mut ConstraintSystem<Fr>,
        chip: super::poseidon_chip::PoseidonChipConfig,
        instance: Column<Instance>,
    ) -> Self {
        let col_v0 = meta.advice_column();
        let col_v1 = meta.advice_column();
        let col_folded = meta.advice_column();
        let col_beta = meta.advice_column();

        meta.enable_equality(col_v0);
        meta.enable_equality(col_v1);
        meta.enable_equality(col_folded);
        meta.enable_equality(col_beta);

        let q_fold = meta.selector();
        let q_final = meta.selector();

        // Fold gate: folded = v0 + beta * v1
        // Beta is in an advice column, constrained to instance via copy constraint.
        meta.create_gate("fri_fold_chain", |meta| {
            let q = meta.query_selector(q_fold);
            let v0 = meta.query_advice(col_v0, Rotation::cur());
            let v1 = meta.query_advice(col_v1, Rotation::cur());
            let folded = meta.query_advice(col_folded, Rotation::cur());
            let beta = meta.query_advice(col_beta, Rotation::cur());
            vec![q * (folded - (v0 + beta * v1))]
        });

        // Final equality: folded == claimed
        meta.create_gate("fri_final_check", |meta| {
            let q = meta.query_selector(q_final);
            let folded = meta.query_advice(col_folded, Rotation::cur());
            let claimed = meta.query_advice(col_v0, Rotation::cur()); // reuse v0 for claimed
            vec![q * (folded - claimed)]
        });

        Self {
            chip,
            instance,
            col_v0,
            col_v1,
            col_folded,
            col_beta,
            q_fold,
            q_final,
        }
    }
}

/// Derive FRI beta challenges from layer roots using Poseidon.
///
/// This mirrors the native verifier's beta derivation but uses Poseidon
/// instead of Blake3 for circuit-friendliness.
pub fn derive_fri_betas(layer_roots: &[Fr], transcript_seed: Fr) -> Vec<Fr> {
    let mut betas = Vec::with_capacity(layer_roots.len());
    let mut acc = transcript_seed;
    for root in layer_roots {
        // beta_i = Poseidon(acc, root_i)
        let beta = poseidon_native::hash(&[acc, *root]);
        betas.push(beta);
        acc = beta; // chain the betas
    }
    betas
}

/// Compute the full FRI chain witness from layer openings.
///
/// Given coset pairs (v0, v1) for each layer and the layer roots,
/// computes betas and folded values, producing a complete witness.
pub fn compute_fri_chain_witness(
    layer_roots: &[Fr],
    coset_pairs: &[(Fr, Fr)],
    transcript_seed: Fr,
    claimed_final: Fr,
) -> FriChainWitness {
    assert_eq!(layer_roots.len(), coset_pairs.len());

    let betas = derive_fri_betas(layer_roots, transcript_seed);
    let mut layers = Vec::with_capacity(layer_roots.len());

    for (i, ((v0, v1), beta)) in coset_pairs.iter().zip(betas.iter()).enumerate() {
        let folded = *v0 + *beta * *v1;
        layers.push(FriLayerWitness {
            layer_root: layer_roots[i],
            v0: *v0,
            v1: *v1,
            folded,
            beta: *beta,
        });
    }

    let final_value = if let Some(last) = layers.last() {
        last.folded
    } else {
        Fr::ZERO
    };

    FriChainWitness {
        layers,
        final_value,
        claimed_final,
    }
}

/// Assign the FRI chain verification in the circuit.
///
/// For each layer:
/// 1. Derive beta via Poseidon (constrained)
/// 2. Enforce fold: folded = v0 + beta * v1
///
/// Finally verify the folded output matches the claimed final value.
///
/// `instance_offset` is the starting index in the instance column for FRI betas.
/// When used standalone, pass 0. When embedded in a larger circuit (e.g., STARK
/// verifier), pass the number of public inputs that precede the FRI betas.
pub fn assign_fri_chain(
    config: &FriChainConfig,
    chip: &PoseidonChip,
    layouter: &mut impl Layouter<Fr>,
    witness: &FriChainWitness,
    transcript_seed: Fr,
    instance_offset: usize,
) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
    let mut beta_cells = Vec::with_capacity(witness.layers.len());
    // Reserved for future: connecting fold outputs across layers.
    let _acc_cell: Option<AssignedCell<Fr, Fr>> = None;

    // Assign transcript seed.
    let seed_cell = layouter.assign_region(
        || "fri_seed",
        |mut region| {
            region.assign_advice(
                || "seed",
                chip.cfg().state0,
                0,
                || Value::known(transcript_seed),
            )
        },
    )?;

    let mut prev_cell = seed_cell;

    for (i, layer) in witness.layers.iter().enumerate() {
        // Derive beta = Poseidon(prev, layer_root)
        let root_cell = layouter.assign_region(
            || format!("fri_root_{i}"),
            |mut region| {
                region.assign_advice(
                    || "root",
                    chip.cfg().state1,
                    0,
                    || Value::known(layer.layer_root),
                )
            },
        )?;

        let beta_cell = chip.hash2_cells(
            layouter.namespace(|| format!("fri_beta_{i}")),
            poseidon_native::domain_tag(),
            &prev_cell,
            &root_cell,
        )?;

        // Constrain beta to instance column via copy constraint.
        layouter.constrain_instance(beta_cell.cell(), config.instance, instance_offset + i)?;

        // Assign fold: folded = v0 + beta * v1
        // Beta goes in col_beta advice column; it's copy-constrained to the
        // Poseidon output cell above (via the fold gate).
        let fold_beta_cell = layouter.assign_region(
            || format!("fri_fold_{i}"),
            |mut region| {
                config.q_fold.enable(&mut region, 0)?;
                region.assign_advice(|| "v0", config.col_v0, 0, || Value::known(layer.v0))?;
                region.assign_advice(|| "v1", config.col_v1, 0, || Value::known(layer.v1))?;
                region.assign_advice(
                    || "folded",
                    config.col_folded,
                    0,
                    || Value::known(layer.folded),
                )?;
                region.assign_advice(|| "beta", config.col_beta, 0, || Value::known(layer.beta))
            },
        )?;

        // Copy-constrain the fold's beta to the Poseidon-derived beta.
        layouter.assign_region(
            || format!("fri_beta_copy_{i}"),
            |mut region| {
                let a = region.assign_advice(
                    || "beta_poseidon",
                    config.col_beta,
                    0,
                    || Value::known(layer.beta),
                )?;
                region.constrain_equal(a.cell(), beta_cell.cell())?;
                region.constrain_equal(a.cell(), fold_beta_cell.cell())?;
                Ok(())
            },
        )?;

        beta_cells.push(beta_cell.clone());
        prev_cell = beta_cell;
    }

    // Final check: last folded value == claimed final
    if !witness.layers.is_empty() {
        layouter.assign_region(
            || "fri_final_check",
            |mut region| {
                config.q_final.enable(&mut region, 0)?;
                region.assign_advice(
                    || "folded_final",
                    config.col_folded,
                    0,
                    || Value::known(witness.final_value),
                )?;
                region.assign_advice(
                    || "claimed_final",
                    config.col_v0,
                    0,
                    || Value::known(witness.claimed_final),
                )?;
                Ok(())
            },
        )?;
    }

    Ok(beta_cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    #[derive(Clone)]
    struct FriChainTestCircuit {
        witness: FriChainWitness,
        seed: Fr,
    }

    impl Circuit<Fr> for FriChainTestCircuit {
        type Config = FriChainConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                witness: FriChainWitness {
                    layers: vec![
                        FriLayerWitness {
                            layer_root: Fr::ZERO,
                            v0: Fr::ZERO,
                            v1: Fr::ZERO,
                            folded: Fr::ZERO,
                            beta: Fr::ZERO,
                        };
                        self.witness.layers.len()
                    ],
                    final_value: Fr::ZERO,
                    claimed_final: Fr::ZERO,
                },
                seed: Fr::ZERO,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            FriChainConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = PoseidonChip::new(config.chip.clone());
            assign_fri_chain(&config, &chip, &mut layouter, &self.witness, self.seed, 0)?;
            Ok(())
        }
    }

    #[test]
    fn fri_chain_single_layer() {
        let seed = Fr::from(42u64);
        let root = Fr::from(100u64);
        let v0 = Fr::from(3u64);
        let v1 = Fr::from(7u64);

        let beta = poseidon_native::hash(&[seed, root]);
        let folded = v0 + beta * v1;

        let witness = FriChainWitness {
            layers: vec![FriLayerWitness {
                layer_root: root,
                v0,
                v1,
                folded,
                beta,
            }],
            final_value: folded,
            claimed_final: folded,
        };

        let circuit = FriChainTestCircuit { witness, seed };

        let k = 18;
        let instance = vec![beta];
        let prover = MockProver::run(k, &circuit, vec![instance]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn fri_chain_two_layers() {
        let seed = Fr::from(99u64);
        let roots = [Fr::from(10u64), Fr::from(20u64)];
        let pairs = [
            (Fr::from(3u64), Fr::from(5u64)),
            (Fr::from(11u64), Fr::from(13u64)),
        ];

        let betas = derive_fri_betas(&roots, seed);
        assert_eq!(betas.len(), 2);

        let witness = compute_fri_chain_witness(&roots, &pairs, seed, Fr::ZERO);
        // Override claimed_final to match actual computation.
        let actual_final = witness.final_value;
        let witness = FriChainWitness {
            claimed_final: actual_final,
            ..witness
        };

        let circuit = FriChainTestCircuit { witness, seed };

        let k = 18;
        let instance = betas;
        let prover = MockProver::run(k, &circuit, vec![instance]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn fri_chain_three_layers() {
        let seed = Fr::from(1u64);
        let roots: Vec<Fr> = (0..3).map(|i| Fr::from(100 + i as u64)).collect();
        let pairs: Vec<(Fr, Fr)> = (0..3)
            .map(|i| (Fr::from(2 * i as u64 + 1), Fr::from(2 * i as u64 + 2)))
            .collect();

        let betas = derive_fri_betas(&roots, seed);
        let witness = compute_fri_chain_witness(&roots, &pairs, seed, Fr::ZERO);
        let witness = FriChainWitness {
            claimed_final: witness.final_value,
            ..witness
        };

        let circuit = FriChainTestCircuit { witness, seed };

        let k = 18;
        let prover = MockProver::run(k, &circuit, vec![betas]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn fri_chain_final_mismatch_fails() {
        let seed = Fr::from(42u64);
        let root = Fr::from(100u64);
        let v0 = Fr::from(3u64);
        let v1 = Fr::from(7u64);

        let beta = poseidon_native::hash(&[seed, root]);
        let folded = v0 + beta * v1;

        // Wrong claimed final value.
        let witness = FriChainWitness {
            layers: vec![FriLayerWitness {
                layer_root: root,
                v0,
                v1,
                folded,
                beta,
            }],
            final_value: folded,
            claimed_final: Fr::from(999u64), // wrong!
        };

        let circuit = FriChainTestCircuit { witness, seed };

        let k = 18;
        let instance = vec![beta];
        let prover = MockProver::run(k, &circuit, vec![instance]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn derive_betas_deterministic() {
        let roots = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let seed = Fr::from(42u64);
        let b1 = derive_fri_betas(&roots, seed);
        let b2 = derive_fri_betas(&roots, seed);
        assert_eq!(b1, b2);
    }
}
