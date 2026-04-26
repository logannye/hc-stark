//! Reusable Halo2 Poseidon gadget (BN254 `Fr`).
//!
//! This chip is intentionally minimal: it supports absorbing 2 field elements (rate=2),
//! running a full Poseidon permutation, and returning `state[0]` as the output.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

use super::poseidon as poseidon_native;

#[derive(Clone, Debug)]
pub struct PoseidonChipConfig {
    pub state0: Column<Advice>,
    pub state1: Column<Advice>,
    pub state2: Column<Advice>,
    pub in0: Column<Advice>,
    pub in1: Column<Advice>,
    pub ark0: Column<Fixed>,
    pub ark1: Column<Fixed>,
    pub ark2: Column<Fixed>,
    pub q_absorb: Selector,
    pub q_full: Selector,
    pub q_partial: Selector,
    pub mds: [[Fr; 3]; 3],
}

#[derive(Clone, Debug)]
pub struct PoseidonChip {
    cfg: PoseidonChipConfig,
}

fn pow5_expr(x: Expression<Fr>) -> Expression<Fr> {
    let x2 = x.clone() * x.clone();
    x * x2.clone() * x2
}

impl PoseidonChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PoseidonChipConfig {
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

        meta.enable_equality(state0);
        meta.enable_equality(state1);
        meta.enable_equality(state2);
        meta.enable_equality(in0);
        meta.enable_equality(in1);

        let params = poseidon_native::params();
        let mds = params.mds;

        meta.create_gate("poseidon_absorb_rate2", |meta| {
            let q = meta.query_selector(q_absorb);
            let s0 = meta.query_advice(state0, Rotation::cur());
            let s1 = meta.query_advice(state1, Rotation::cur());
            let s2 = meta.query_advice(state2, Rotation::cur());
            let n0 = meta.query_advice(state0, Rotation::next());
            let n1 = meta.query_advice(state1, Rotation::next());
            let n2 = meta.query_advice(state2, Rotation::next());
            let a = meta.query_advice(in0, Rotation::cur());
            let b = meta.query_advice(in1, Rotation::cur());
            vec![
                q.clone() * (n0 - (s0 + a)),
                q.clone() * (n1 - (s1 + b)),
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

                let z0 = Expression::Constant(mds[0][0]) * y0.clone()
                    + Expression::Constant(mds[0][1]) * y1.clone()
                    + Expression::Constant(mds[0][2]) * y2.clone();
                let z1 = Expression::Constant(mds[1][0]) * y0.clone()
                    + Expression::Constant(mds[1][1]) * y1.clone()
                    + Expression::Constant(mds[1][2]) * y2.clone();
                let z2 = Expression::Constant(mds[2][0]) * y0
                    + Expression::Constant(mds[2][1]) * y1
                    + Expression::Constant(mds[2][2]) * y2;

                vec![q.clone() * (n0 - z0), q.clone() * (n1 - z1), q * (n2 - z2)]
            }
        };

        meta.create_gate("poseidon_round_full", round_gate(true));
        meta.create_gate("poseidon_round_partial", round_gate(false));

        PoseidonChipConfig {
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
            mds,
        }
    }

    pub fn new(cfg: PoseidonChipConfig) -> Self {
        Self { cfg }
    }

    pub fn cfg(&self) -> &PoseidonChipConfig {
        &self.cfg
    }

    pub fn hash2_cells(
        &self,
        mut layouter: impl Layouter<Fr>,
        domain_tag: Fr,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let params = poseidon_native::params();
        let rounds = params.ark.len();
        let full_half = poseidon_native::FULL_ROUNDS / 2;
        let partial = poseidon_native::PARTIAL_ROUNDS;
        let full_start_2 = full_half + partial;

        layouter.assign_region(
            || "poseidon_hash2",
            |mut region| {
                let mut offset = 0usize;
                let mut s0 = Value::known(domain_tag);
                let mut s1 = Value::known(Fr::ZERO);
                let mut s2 = Value::known(Fr::ZERO);

                // Apply one full permutation on the domain-separated state.
                for r in 0..rounds {
                    let is_full = r < full_half || r >= full_start_2;
                    if is_full {
                        self.cfg.q_full.enable(&mut region, offset)?;
                    } else {
                        self.cfg.q_partial.enable(&mut region, offset)?;
                    }
                    region.assign_fixed(
                        || "ark0",
                        self.cfg.ark0,
                        offset,
                        || Value::known(params.ark[r][0]),
                    )?;
                    region.assign_fixed(
                        || "ark1",
                        self.cfg.ark1,
                        offset,
                        || Value::known(params.ark[r][1]),
                    )?;
                    region.assign_fixed(
                        || "ark2",
                        self.cfg.ark2,
                        offset,
                        || Value::known(params.ark[r][2]),
                    )?;
                    region.assign_advice(|| "s0", self.cfg.state0, offset, || s0)?;
                    region.assign_advice(|| "s1", self.cfg.state1, offset, || s1)?;
                    region.assign_advice(|| "s2", self.cfg.state2, offset, || s2)?;
                    region.assign_advice(
                        || "in0",
                        self.cfg.in0,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1",
                        self.cfg.in1,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;

                    // Compute next state (witness) in Value-space.
                    let ark0 = params.ark[r][0];
                    let ark1 = params.ark[r][1];
                    let ark2 = params.ark[r][2];
                    let x0 = s0.map(|v| v + ark0);
                    let x1 = s1.map(|v| v + ark1);
                    let x2 = s2.map(|v| v + ark2);
                    let y0 = x0.map(|v| v.pow_vartime([5, 0, 0, 0]));
                    let (y1, y2) = if is_full {
                        (
                            x1.map(|v| v.pow_vartime([5, 0, 0, 0])),
                            x2.map(|v| v.pow_vartime([5, 0, 0, 0])),
                        )
                    } else {
                        (x1, x2)
                    };
                    let n0 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[0][0] * a + self.cfg.mds[0][1] * b + self.cfg.mds[0][2] * c
                    });
                    let n1 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[1][0] * a + self.cfg.mds[1][1] * b + self.cfg.mds[1][2] * c
                    });
                    let n2 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[2][0] * a + self.cfg.mds[2][1] * b + self.cfg.mds[2][2] * c
                    });
                    s0 = n0;
                    s1 = n1;
                    s2 = n2;

                    region.assign_advice(|| "s0_next", self.cfg.state0, offset + 1, || s0)?;
                    region.assign_advice(|| "s1_next", self.cfg.state1, offset + 1, || s1)?;
                    region.assign_advice(|| "s2_next", self.cfg.state2, offset + 1, || s2)?;
                    region.assign_advice(
                        || "in0_next",
                        self.cfg.in0,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1_next",
                        self.cfg.in1,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    offset += 1;
                }

                // Absorb a,b (rate=2) then permute again.
                self.cfg.q_absorb.enable(&mut region, offset)?;
                region.assign_advice(|| "s0_abs", self.cfg.state0, offset, || s0)?;
                region.assign_advice(|| "s1_abs", self.cfg.state1, offset, || s1)?;
                region.assign_advice(|| "s2_abs", self.cfg.state2, offset, || s2)?;
                a.copy_advice(|| "a", &mut region, self.cfg.in0, offset)?;
                b.copy_advice(|| "b", &mut region, self.cfg.in1, offset)?;
                s0 = s0.zip(a.value().copied()).map(|(x, y)| x + y);
                s1 = s1.zip(b.value().copied()).map(|(x, y)| x + y);

                region.assign_advice(|| "s0_abs_next", self.cfg.state0, offset + 1, || s0)?;
                region.assign_advice(|| "s1_abs_next", self.cfg.state1, offset + 1, || s1)?;
                region.assign_advice(|| "s2_abs_next", self.cfg.state2, offset + 1, || s2)?;
                region.assign_advice(
                    || "in0_abs_next",
                    self.cfg.in0,
                    offset + 1,
                    || Value::known(Fr::ZERO),
                )?;
                region.assign_advice(
                    || "in1_abs_next",
                    self.cfg.in1,
                    offset + 1,
                    || Value::known(Fr::ZERO),
                )?;
                offset += 1;

                for r in 0..rounds {
                    let is_full = r < full_half || r >= full_start_2;
                    if is_full {
                        self.cfg.q_full.enable(&mut region, offset)?;
                    } else {
                        self.cfg.q_partial.enable(&mut region, offset)?;
                    }
                    region.assign_fixed(
                        || "ark0",
                        self.cfg.ark0,
                        offset,
                        || Value::known(params.ark[r][0]),
                    )?;
                    region.assign_fixed(
                        || "ark1",
                        self.cfg.ark1,
                        offset,
                        || Value::known(params.ark[r][1]),
                    )?;
                    region.assign_fixed(
                        || "ark2",
                        self.cfg.ark2,
                        offset,
                        || Value::known(params.ark[r][2]),
                    )?;
                    region.assign_advice(|| "s0", self.cfg.state0, offset, || s0)?;
                    region.assign_advice(|| "s1", self.cfg.state1, offset, || s1)?;
                    region.assign_advice(|| "s2", self.cfg.state2, offset, || s2)?;
                    region.assign_advice(
                        || "in0",
                        self.cfg.in0,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1",
                        self.cfg.in1,
                        offset,
                        || Value::known(Fr::ZERO),
                    )?;

                    let ark0 = params.ark[r][0];
                    let ark1 = params.ark[r][1];
                    let ark2 = params.ark[r][2];
                    let x0 = s0.map(|v| v + ark0);
                    let x1 = s1.map(|v| v + ark1);
                    let x2 = s2.map(|v| v + ark2);
                    let y0 = x0.map(|v| v.pow_vartime([5, 0, 0, 0]));
                    let (y1, y2) = if is_full {
                        (
                            x1.map(|v| v.pow_vartime([5, 0, 0, 0])),
                            x2.map(|v| v.pow_vartime([5, 0, 0, 0])),
                        )
                    } else {
                        (x1, x2)
                    };
                    let n0 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[0][0] * a + self.cfg.mds[0][1] * b + self.cfg.mds[0][2] * c
                    });
                    let n1 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[1][0] * a + self.cfg.mds[1][1] * b + self.cfg.mds[1][2] * c
                    });
                    let n2 = y0.zip(y1).zip(y2).map(|((a, b), c)| {
                        self.cfg.mds[2][0] * a + self.cfg.mds[2][1] * b + self.cfg.mds[2][2] * c
                    });
                    s0 = n0;
                    s1 = n1;
                    s2 = n2;

                    region.assign_advice(|| "s0_next", self.cfg.state0, offset + 1, || s0)?;
                    region.assign_advice(|| "s1_next", self.cfg.state1, offset + 1, || s1)?;
                    region.assign_advice(|| "s2_next", self.cfg.state2, offset + 1, || s2)?;
                    region.assign_advice(
                        || "in0_next",
                        self.cfg.in0,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    region.assign_advice(
                        || "in1_next",
                        self.cfg.in1,
                        offset + 1,
                        || Value::known(Fr::ZERO),
                    )?;
                    offset += 1;
                }

                // Output is state[0].
                let out = region.assign_advice(|| "out", self.cfg.state0, offset, || s0)?;
                Ok(out)
            },
        )
    }
}
