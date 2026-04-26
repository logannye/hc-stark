//! In-circuit AIR quotient relation verification gadget.
//!
//! This gadget enforces the STARK quotient relation inside the Halo2 circuit:
//!
//!   q(x) * Z_H(x) = alpha_transition * (1 - L_last(x)) * transition(x)
//!                  + alpha_boundary * (boundary_constraint(x))
//!
//! For ToyAir (2-column AIR: accumulator + delta):
//!   transition(x) = acc_next - (acc + delta)
//!   boundary(x)   = L0(x) * (acc - initial) + L_last(x) * (acc - final)
//!
//! All arithmetic is over BN254 Fr (the Halo2 scalar field). Goldilocks field
//! values from the STARK proof are embedded as Fr elements.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// Configuration for the quotient check gate.
#[derive(Clone, Debug)]
pub struct QuotientCheckConfig {
    /// Advice columns for the quotient check inputs.
    pub col_q: Column<Advice>, // quotient value q(x)
    pub col_zh: Column<Advice>, // vanishing polynomial Z_H(x)
    pub col_c: Column<Advice>,  // composition numerator C(x)
    pub q_check: Selector,
}

impl QuotientCheckConfig {
    /// Configure the quotient check gate.
    ///
    /// Constrains: q * z_h - c = 0  (i.e., q(x) * Z_H(x) = C(x))
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let col_q = meta.advice_column();
        let col_zh = meta.advice_column();
        let col_c = meta.advice_column();
        let q_check = meta.selector();

        meta.enable_equality(col_q);
        meta.enable_equality(col_zh);
        meta.enable_equality(col_c);

        meta.create_gate("quotient_check", |meta| {
            let q = meta.query_selector(q_check);
            let qv = meta.query_advice(col_q, Rotation::cur());
            let zh = meta.query_advice(col_zh, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            // q(x) * Z_H(x) = C(x)
            vec![q * (qv * zh - c)]
        });

        Self {
            col_q,
            col_zh,
            col_c,
            q_check,
        }
    }
}

/// Native computation of the ToyAir quotient numerator.
///
/// This mirrors the native verifier's quotient check but over BN254 Fr.
/// Used for witness generation.
pub fn toy_air_quotient_numerator(
    acc: Fr,
    delta: Fr,
    acc_next: Fr,
    _delta_next: Fr,
    l0: Fr,
    l_last: Fr,
    alpha_boundary: Fr,
    alpha_transition: Fr,
    initial_acc: Fr,
    final_acc: Fr,
) -> Fr {
    let selector_last = Fr::ONE - l_last;

    // Transition: acc_next - (acc + delta), masked by (1 - L_last)
    let transition = acc_next - (acc + delta);
    let transition_term = alpha_transition * selector_last * transition;

    // Boundary: L0 * (acc - initial) + L_last * (acc - final)
    let boundary_first = l0 * (acc - initial_acc);
    let boundary_last = l_last * (acc - final_acc);
    let boundary_term = alpha_boundary * (boundary_first + boundary_last);

    transition_term + boundary_term
}

/// Assign and constrain a single quotient check in the circuit.
///
/// Inputs (all as Fr):
///   - `quotient_value`: q(x) from the proof
///   - `z_h`: Z_H(x) = x^N - 1 evaluated at the query point
///   - `composition_numerator`: C(x) recomputed from trace openings
///
/// The gate enforces: q(x) * Z_H(x) = C(x)
pub fn assign_quotient_check(
    config: &QuotientCheckConfig,
    layouter: &mut impl Layouter<Fr>,
    quotient_value: Fr,
    z_h: Fr,
    composition_numerator: Fr,
    query_idx: usize,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    layouter.assign_region(
        || format!("quotient_check_{query_idx}"),
        |mut region| {
            config.q_check.enable(&mut region, 0)?;

            region.assign_advice(|| "q", config.col_q, 0, || Value::known(quotient_value))?;
            region.assign_advice(|| "zh", config.col_zh, 0, || Value::known(z_h))?;
            let c_cell = region.assign_advice(
                || "c",
                config.col_c,
                0,
                || Value::known(composition_numerator),
            )?;

            Ok(c_cell)
        },
    )
}

/// Extended quotient check config that also constrains the composition
/// numerator recomputation from trace openings.
#[derive(Clone, Debug)]
pub struct FullQuotientCheckConfig {
    pub basic: QuotientCheckConfig,
    /// Columns for trace values used in recomputation.
    pub col_acc: Column<Advice>,
    pub col_delta: Column<Advice>,
    pub col_acc_next: Column<Advice>,
    pub col_l0: Column<Advice>,
    pub col_l_last: Column<Advice>,
    pub col_alpha_b: Column<Advice>,
    pub col_alpha_t: Column<Advice>,
    pub col_init: Column<Advice>,
    pub col_final_v: Column<Advice>,
    pub q_recompute: Selector,
}

impl FullQuotientCheckConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let basic = QuotientCheckConfig::configure(meta);

        let col_acc = meta.advice_column();
        let col_delta = meta.advice_column();
        let col_acc_next = meta.advice_column();
        let col_l0 = meta.advice_column();
        let col_l_last = meta.advice_column();
        let col_alpha_b = meta.advice_column();
        let col_alpha_t = meta.advice_column();
        let col_init = meta.advice_column();
        let col_final_v = meta.advice_column();
        let q_recompute = meta.selector();

        meta.enable_equality(col_acc);
        meta.enable_equality(col_delta);
        meta.enable_equality(col_acc_next);
        meta.enable_equality(col_l0);
        meta.enable_equality(col_l_last);
        meta.enable_equality(col_alpha_b);
        meta.enable_equality(col_alpha_t);
        meta.enable_equality(col_init);
        meta.enable_equality(col_final_v);

        // Gate: C = alpha_t * (1 - l_last) * (acc_next - acc - delta)
        //       + alpha_b * (l0 * (acc - init) + l_last * (acc - final))
        //
        // We split this into two sub-expressions to keep degree manageable.
        // Degree analysis:
        //   - (1 - l_last) * (acc_next - acc - delta) = degree 2 (product of two linear)
        //   - alpha_t * that = degree 3
        //   - l0 * (acc - init) = degree 2
        //   - l_last * (acc - final) = degree 2
        //   - alpha_b * sum = degree 3
        //   - Total: max degree 3, within Halo2 constraints
        meta.create_gate("composition_recompute", |meta| {
            let q = meta.query_selector(q_recompute);
            let acc = meta.query_advice(col_acc, Rotation::cur());
            let delta = meta.query_advice(col_delta, Rotation::cur());
            let acc_next = meta.query_advice(col_acc_next, Rotation::cur());
            let l0 = meta.query_advice(col_l0, Rotation::cur());
            let l_last = meta.query_advice(col_l_last, Rotation::cur());
            let alpha_b = meta.query_advice(col_alpha_b, Rotation::cur());
            let alpha_t = meta.query_advice(col_alpha_t, Rotation::cur());
            let init = meta.query_advice(col_init, Rotation::cur());
            let final_v = meta.query_advice(col_final_v, Rotation::cur());
            let c = meta.query_advice(basic.col_c, Rotation::cur());

            let one = Expression::Constant(Fr::ONE);
            let selector_last = one - l_last.clone();
            let transition = acc_next - acc.clone() - delta;
            let transition_term = alpha_t * selector_last * transition;

            let boundary_first = l0 * (acc.clone() - init);
            let boundary_last = l_last * (acc - final_v);
            let boundary_term = alpha_b * (boundary_first + boundary_last);

            vec![q * (c - transition_term - boundary_term)]
        });

        Self {
            basic,
            col_acc,
            col_delta,
            col_acc_next,
            col_l0,
            col_l_last,
            col_alpha_b,
            col_alpha_t,
            col_init,
            col_final_v,
            q_recompute,
        }
    }

    /// Assign a full quotient check: recompute C from trace openings,
    /// then verify q * Z_H = C.
    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        quotient_value: Fr,
        z_h: Fr,
        acc: Fr,
        delta: Fr,
        acc_next: Fr,
        l0: Fr,
        l_last: Fr,
        alpha_boundary: Fr,
        alpha_transition: Fr,
        initial_acc: Fr,
        final_acc: Fr,
        query_idx: usize,
    ) -> Result<(), Error> {
        let c = toy_air_quotient_numerator(
            acc,
            delta,
            acc_next,
            Fr::ZERO, // delta_next not used in ToyAir
            l0,
            l_last,
            alpha_boundary,
            alpha_transition,
            initial_acc,
            final_acc,
        );

        layouter.assign_region(
            || format!("full_quotient_check_{query_idx}"),
            |mut region| {
                self.basic.q_check.enable(&mut region, 0)?;
                self.q_recompute.enable(&mut region, 0)?;

                region.assign_advice(
                    || "q",
                    self.basic.col_q,
                    0,
                    || Value::known(quotient_value),
                )?;
                region.assign_advice(|| "zh", self.basic.col_zh, 0, || Value::known(z_h))?;
                region.assign_advice(|| "c", self.basic.col_c, 0, || Value::known(c))?;
                region.assign_advice(|| "acc", self.col_acc, 0, || Value::known(acc))?;
                region.assign_advice(|| "delta", self.col_delta, 0, || Value::known(delta))?;
                region.assign_advice(
                    || "acc_next",
                    self.col_acc_next,
                    0,
                    || Value::known(acc_next),
                )?;
                region.assign_advice(|| "l0", self.col_l0, 0, || Value::known(l0))?;
                region.assign_advice(|| "l_last", self.col_l_last, 0, || Value::known(l_last))?;
                region.assign_advice(
                    || "alpha_b",
                    self.col_alpha_b,
                    0,
                    || Value::known(alpha_boundary),
                )?;
                region.assign_advice(
                    || "alpha_t",
                    self.col_alpha_t,
                    0,
                    || Value::known(alpha_transition),
                )?;
                region.assign_advice(|| "init", self.col_init, 0, || Value::known(initial_acc))?;
                region.assign_advice(
                    || "final_v",
                    self.col_final_v,
                    0,
                    || Value::known(final_acc),
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    /// Minimal circuit to test the basic quotient check gate.
    #[derive(Clone)]
    struct BasicQuotientTestCircuit {
        q_val: Fr,
        zh_val: Fr,
        c_val: Fr,
    }

    impl Circuit<Fr> for BasicQuotientTestCircuit {
        type Config = QuotientCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                q_val: Fr::ZERO,
                zh_val: Fr::ZERO,
                c_val: Fr::ZERO,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            QuotientCheckConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            assign_quotient_check(
                &config,
                &mut layouter,
                self.q_val,
                self.zh_val,
                self.c_val,
                0,
            )?;
            Ok(())
        }
    }

    #[test]
    fn basic_quotient_check_satisfied() {
        // q * z_h = c
        let q = Fr::from(7u64);
        let zh = Fr::from(11u64);
        let c = q * zh;

        let circuit = BasicQuotientTestCircuit {
            q_val: q,
            zh_val: zh,
            c_val: c,
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn basic_quotient_check_fails_on_mismatch() {
        let q = Fr::from(7u64);
        let zh = Fr::from(11u64);
        let c = Fr::from(999u64); // wrong

        let circuit = BasicQuotientTestCircuit {
            q_val: q,
            zh_val: zh,
            c_val: c,
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    /// Test circuit for the full quotient check (recomputation + quotient relation).
    #[derive(Clone)]
    struct FullQuotientTestCircuit {
        quotient_value: Fr,
        z_h: Fr,
        acc: Fr,
        delta: Fr,
        acc_next: Fr,
        l0: Fr,
        l_last: Fr,
        alpha_b: Fr,
        alpha_t: Fr,
        init: Fr,
        final_v: Fr,
    }

    impl Circuit<Fr> for FullQuotientTestCircuit {
        type Config = FullQuotientCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                quotient_value: Fr::ZERO,
                z_h: Fr::ZERO,
                acc: Fr::ZERO,
                delta: Fr::ZERO,
                acc_next: Fr::ZERO,
                l0: Fr::ZERO,
                l_last: Fr::ZERO,
                alpha_b: Fr::ZERO,
                alpha_t: Fr::ZERO,
                init: Fr::ZERO,
                final_v: Fr::ZERO,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            FullQuotientCheckConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            config.assign(
                &mut layouter,
                self.quotient_value,
                self.z_h,
                self.acc,
                self.delta,
                self.acc_next,
                self.l0,
                self.l_last,
                self.alpha_b,
                self.alpha_t,
                self.init,
                self.final_v,
                0,
            )
        }
    }

    #[test]
    fn full_quotient_check_interior_row() {
        // Interior row: L0 = 0, L_last = 0 (no boundary), selector_last = 1
        // transition: acc_next - (acc + delta) = 10 - (3 + 7) = 0
        // C = alpha_t * 1 * 0 + alpha_b * 0 = 0
        // So q * z_h = 0, meaning q = 0 (for non-zero z_h).
        let acc = Fr::from(3u64);
        let delta = Fr::from(7u64);
        let acc_next = Fr::from(10u64);
        let alpha_t = Fr::from(5u64);
        let alpha_b = Fr::from(3u64);
        let z_h = Fr::from(100u64);
        let init = Fr::from(3u64);
        let final_v = Fr::from(99u64);

        let c = toy_air_quotient_numerator(
            acc,
            delta,
            acc_next,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            alpha_b,
            alpha_t,
            init,
            final_v,
        );
        assert_eq!(c, Fr::ZERO);

        let circuit = FullQuotientTestCircuit {
            quotient_value: Fr::ZERO,
            z_h,
            acc,
            delta,
            acc_next,
            l0: Fr::ZERO,
            l_last: Fr::ZERO,
            alpha_b,
            alpha_t,
            init,
            final_v,
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn full_quotient_check_with_boundary() {
        // First row: L0 = 1, L_last = 0
        // acc = 5 (initial), delta = 3, acc_next = 8
        // transition: 8 - (5 + 3) = 0, masked by (1 - 0) = 1 → 0
        // boundary: L0*(acc-init) = 1*(5-5) = 0
        // C = 0
        let acc = Fr::from(5u64);
        let delta = Fr::from(3u64);
        let acc_next = Fr::from(8u64);
        let alpha_t = Fr::from(7u64);
        let alpha_b = Fr::from(11u64);
        let z_h = Fr::from(50u64);
        let init = Fr::from(5u64);
        let final_v = Fr::from(100u64);
        let l0 = Fr::ONE;
        let l_last = Fr::ZERO;

        let c = toy_air_quotient_numerator(
            acc,
            delta,
            acc_next,
            Fr::ZERO,
            l0,
            l_last,
            alpha_b,
            alpha_t,
            init,
            final_v,
        );
        assert_eq!(c, Fr::ZERO);

        let circuit = FullQuotientTestCircuit {
            quotient_value: Fr::ZERO,
            z_h,
            acc,
            delta,
            acc_next,
            l0,
            l_last,
            alpha_b,
            alpha_t,
            init,
            final_v,
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn full_quotient_check_nonzero_numerator() {
        // Row with a violated transition: acc_next != acc + delta
        // acc = 3, delta = 7, acc_next = 11 (should be 10)
        // L0 = 0, L_last = 0 → no boundary
        // transition: 11 - (3+7) = 1
        // C = alpha_t * 1 * 1 = alpha_t = 5
        // q = C / z_h = 5 / 100 (in Fr arithmetic)
        let acc = Fr::from(3u64);
        let delta = Fr::from(7u64);
        let acc_next = Fr::from(11u64);
        let alpha_t = Fr::from(5u64);
        let alpha_b = Fr::from(3u64);
        let z_h = Fr::from(100u64);
        let init = Fr::from(0u64);
        let final_v = Fr::from(0u64);

        let c = toy_air_quotient_numerator(
            acc,
            delta,
            acc_next,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            alpha_b,
            alpha_t,
            init,
            final_v,
        );
        assert_eq!(c, alpha_t);

        let q = c * z_h.invert().unwrap();

        let circuit = FullQuotientTestCircuit {
            quotient_value: q,
            z_h,
            acc,
            delta,
            acc_next,
            l0: Fr::ZERO,
            l_last: Fr::ZERO,
            alpha_b,
            alpha_t,
            init,
            final_v,
        };
        let prover = MockProver::run(8, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
