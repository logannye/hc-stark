//! Poseidon Merkle path verification gadget and tests.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
};
use halo2curves::bn256::Fr;

use super::{poseidon, poseidon_chip::PoseidonChip};

/// A Merkle path element. `sibling_is_left = true` means sibling is the left child, so
/// parent = H(sibling, current); else parent = H(current, sibling).
#[derive(Clone, Copy, Debug)]
pub struct MerklePathElem {
    pub sibling: Fr,
    pub sibling_is_left: bool,
}

/// Native Poseidon Merkle hashing (for witness generation).
pub fn poseidon_parent(left: Fr, right: Fr) -> Fr {
    poseidon::hash(&[left, right])
}

pub fn compute_root(leaf: Fr, path: &[MerklePathElem]) -> Fr {
    let mut acc = leaf;
    for node in path {
        acc = if node.sibling_is_left {
            poseidon_parent(node.sibling, acc)
        } else {
            poseidon_parent(acc, node.sibling)
        };
    }
    acc
}

#[derive(Clone, Debug)]
struct MerkleCircuit {
    leaf: Fr,
    path: Vec<MerklePathElem>,
}

#[derive(Clone, Debug)]
struct MerkleConfig {
    chip: crate::circuit::poseidon_chip::PoseidonChipConfig,
    instance: Column<Instance>,
    b: Column<Advice>,
    q_bool: Selector,
}

impl Circuit<Fr> for MerkleCircuit {
    type Config = MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Fr::ZERO,
            path: vec![
                MerklePathElem {
                    sibling: Fr::ZERO,
                    sibling_is_left: false,
                };
                self.path.len()
            ],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let chip = PoseidonChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let b = meta.advice_column();
        meta.enable_equality(b);
        let q_bool = meta.selector();
        meta.create_gate("bool", |meta| {
            let q = meta.query_selector(q_bool);
            let v = meta.query_advice(b, halo2_proofs::poly::Rotation::cur());
            vec![q * v.clone() * (v - Expression::Constant(Fr::ONE))]
        });

        MerkleConfig {
            chip,
            instance,
            b,
            q_bool,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = PoseidonChip::new(config.chip);

        // Constrain boolean bits and compute root natively but with Poseidon round constraints.
        let mut current = layouter.assign_region(
            || "leaf",
            |mut region| {
                let cell = region.assign_advice(
                    || "leaf",
                    chip.cfg().state0,
                    0,
                    || Value::known(self.leaf),
                )?;
                Ok(cell)
            },
        )?;
        for (idx, node) in self.path.iter().enumerate() {
            layouter.assign_region(
                || format!("bool_{idx}"),
                |mut region| {
                    config.q_bool.enable(&mut region, 0)?;
                    let bit = if node.sibling_is_left {
                        Fr::ONE
                    } else {
                        Fr::ZERO
                    };
                    region.assign_advice(|| "b", config.b, 0, || Value::known(bit))?;
                    Ok(())
                },
            )?;

            let sibling = layouter.assign_region(
                || format!("sibling_{idx}"),
                |mut region| {
                    let cell = region.assign_advice(
                        || "sib",
                        chip.cfg().state1,
                        0,
                        || Value::known(node.sibling),
                    )?;
                    Ok(cell)
                },
            )?;
            let out_cell = if node.sibling_is_left {
                chip.hash2_cells(
                    layouter.namespace(|| format!("hash_{idx}")),
                    poseidon::domain_tag(),
                    &sibling,
                    &current,
                )?
            } else {
                chip.hash2_cells(
                    layouter.namespace(|| format!("hash_{idx}")),
                    poseidon::domain_tag(),
                    &current,
                    &sibling,
                )?
            };
            current = out_cell;
        }

        // Constrain output root to instance[0].
        layouter.constrain_instance(current.cell(), config.instance, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_core::field::FieldElement;
    use hc_prover::{config::ProverConfig, prove, PublicInputs};
    use hc_verifier::Proof;
    use hc_vm::{Instruction, Program};

    #[test]
    fn poseidon_merkle_path_verifies() {
        // Build a tiny tree of 8 leaves, use Poseidon hash2 for parents.
        let leaves: Vec<Fr> = (0u64..8).map(Fr::from).collect();
        let mut level = leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                next.push(poseidon_parent(pair[0], pair[1]));
            }
            level = next;
        }
        let root = level[0];

        // Path for leaf index 3.
        let idx = 3usize;
        let mut path = Vec::new();
        path.push(MerklePathElem {
            sibling: leaves[2],
            sibling_is_left: true,
        });
        let p0 = poseidon_parent(leaves[0], leaves[1]);
        path.push(MerklePathElem {
            sibling: p0,
            sibling_is_left: true,
        });
        let p2 = poseidon_parent(
            poseidon_parent(leaves[4], leaves[5]),
            poseidon_parent(leaves[6], leaves[7]),
        );
        path.push(MerklePathElem {
            sibling: p2,
            sibling_is_left: false,
        });

        assert_eq!(compute_root(leaves[idx], &path), root);

        let circuit = MerkleCircuit {
            leaf: leaves[idx],
            path,
        };

        let k = 18;
        let public_inputs = vec![root];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn poseidon_merkle_accepts_real_path_shape() {
        // Generate a real proof so we use a real Merkle path length/shape.
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
        let tq = response.trace_queries.first().expect("trace query");
        let path = match &tq.witness {
            hc_prover::queries::TraceWitness::Merkle(path) => path,
            _ => panic!("expected merkle witness"),
        };

        // Map Blake3 sibling digests into Fr to use as Poseidon-tree siblings.
        let mut poseidon_path = Vec::new();
        for node in path.nodes() {
            let limb = u64::from_le_bytes(node.sibling.as_bytes()[0..8].try_into().unwrap());
            poseidon_path.push(MerklePathElem {
                sibling: Fr::from(limb),
                sibling_is_left: node.sibling_is_left,
            });
        }

        // Leaf is the opened trace row (as Frs) hashed under Poseidon.
        let leaf = poseidon::hash(&[
            Fr::from(tq.evaluation[0].to_u64()),
            Fr::from(tq.evaluation[1].to_u64()),
        ]);
        let root = compute_root(leaf, &poseidon_path);

        let circuit = MerkleCircuit {
            leaf,
            path: poseidon_path,
        };
        let k = 18;
        let prover = MockProver::run(k, &circuit, vec![vec![root]]).unwrap();
        prover.assert_satisfied();
    }
}
