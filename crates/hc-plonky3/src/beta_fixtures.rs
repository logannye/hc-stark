//! Release-bound declarative AIR fixtures used by Sandbox and hosted quickstart.

use crate::{
    contracts::{
        AirConstraintKindV1, AirConstraintV1, AirExpressionV1, AirPackageV1, PublicInputSlotV1,
    },
    COMPATIBILITY_PROFILE, GOLDILOCKS_MODULUS_U64,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BetaFixture {
    Fibonacci,
    Poseidon2,
    CustomerCubic8,
}

impl BetaFixture {
    pub const ALL: [Self; 3] = [Self::Fibonacci, Self::Poseidon2, Self::CustomerCubic8];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Fibonacci => "fibonacci",
            Self::Poseidon2 => "poseidon2",
            Self::CustomerCubic8 => "customer_cubic8",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|fixture| fixture.name() == value)
    }

    pub fn air(self) -> AirPackageV1 {
        match self {
            Self::Fibonacci => fibonacci_air(),
            Self::Poseidon2 => poseidon2_air(),
            Self::CustomerCubic8 => customer_cubic8_air(),
        }
    }

    pub fn air_digest_hex(self) -> String {
        self.air()
            .digest()
            .expect("release fixture AIR must validate")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn trace_row_and_next(self, state: &[u64]) -> (Vec<u64>, Vec<u64>) {
        match self {
            Self::Fibonacci => {
                let (a, b) = (state[0], state[1]);
                (vec![a, b], vec![b, add(a, b)])
            }
            Self::Poseidon2 => {
                let x = state[0];
                let x2 = mul(x, x);
                let x3 = mul(x2, x);
                let x6 = mul(x3, x3);
                (vec![x, x2, x3, x6], vec![add(mul(x6, x), 7)])
            }
            Self::CustomerCubic8 => {
                let row = state.to_vec();
                let next = (0..8)
                    .map(|column| {
                        add(
                            mul(mul(state[column], state[column]), state[column]),
                            state[(column + 1) % 8],
                        )
                    })
                    .collect();
                (row, next)
            }
        }
    }

    pub fn initial_state(self) -> Vec<u64> {
        match self {
            Self::Fibonacci => vec![1, 1],
            Self::Poseidon2 => vec![3],
            Self::CustomerCubic8 => (1..=8).collect(),
        }
    }

    pub fn public_values(self, first: &[u64], last: &[u64]) -> Vec<u64> {
        match self {
            Self::Fibonacci => vec![first[0], first[1], last[0], last[1]],
            Self::Poseidon2 => vec![first[0], last[0]],
            Self::CustomerCubic8 => first.iter().chain(last).copied().collect(),
        }
    }
}

pub fn beta_fixture_air_digests() -> Vec<(&'static str, String)> {
    BetaFixture::ALL
        .into_iter()
        .map(|fixture| (fixture.name(), fixture.air_digest_hex()))
        .collect()
}

struct Builder {
    width: u32,
    public_inputs: Vec<PublicInputSlotV1>,
    expressions: Vec<AirExpressionV1>,
    constraints: Vec<AirConstraintV1>,
}

impl Builder {
    fn new(width: u32, public_inputs: impl IntoIterator<Item = String>) -> Self {
        Self {
            width,
            public_inputs: public_inputs
                .into_iter()
                .map(|name| PublicInputSlotV1 { name })
                .collect(),
            expressions: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn expression(&mut self, expression: AirExpressionV1) -> u32 {
        let index = self.expressions.len() as u32;
        self.expressions.push(expression);
        index
    }
    fn current(&mut self, column: u32) -> u32 {
        self.expression(AirExpressionV1::Current { column })
    }
    fn next(&mut self, column: u32) -> u32 {
        self.expression(AirExpressionV1::Next { column })
    }
    fn public(&mut self, index: u32) -> u32 {
        self.expression(AirExpressionV1::Public { index })
    }
    fn constant(&mut self, value: u64) -> u32 {
        self.expression(AirExpressionV1::Constant { value })
    }
    fn add(&mut self, left: u32, right: u32) -> u32 {
        self.expression(AirExpressionV1::Add { left, right })
    }
    fn sub(&mut self, left: u32, right: u32) -> u32 {
        self.expression(AirExpressionV1::Sub { left, right })
    }
    fn mul(&mut self, left: u32, right: u32) -> u32 {
        self.expression(AirExpressionV1::Mul { left, right })
    }
    fn constrain(&mut self, kind: AirConstraintKindV1, expression: u32) {
        self.constraints.push(AirConstraintV1 { kind, expression });
    }
    fn boundary(&mut self, kind: AirConstraintKindV1, column: u32, public_index: u32) {
        let current = self.current(column);
        let public = self.public(public_index);
        let expression = self.sub(current, public);
        self.constrain(kind, expression);
    }
    fn package(self) -> AirPackageV1 {
        AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: self.width,
            public_inputs: self.public_inputs,
            expressions: self.expressions,
            constraints: self.constraints,
        }
    }
}

fn fibonacci_air() -> AirPackageV1 {
    let mut b = Builder::new(
        2,
        ["initial_a", "initial_b", "final_a", "final_b"].map(str::to_owned),
    );
    b.boundary(AirConstraintKindV1::FirstRow, 0, 0);
    b.boundary(AirConstraintKindV1::FirstRow, 1, 1);
    let next0 = b.next(0);
    let current1 = b.current(1);
    let c0 = b.sub(next0, current1);
    b.constrain(AirConstraintKindV1::Transition, c0);
    let next1 = b.next(1);
    let current0 = b.current(0);
    let current1 = b.current(1);
    let sum = b.add(current0, current1);
    let c1 = b.sub(next1, sum);
    b.constrain(AirConstraintKindV1::Transition, c1);
    b.boundary(AirConstraintKindV1::LastRow, 0, 2);
    b.boundary(AirConstraintKindV1::LastRow, 1, 3);
    b.package()
}

fn poseidon2_air() -> AirPackageV1 {
    let mut b = Builder::new(4, ["initial_x", "final_x"].map(str::to_owned));
    b.boundary(AirConstraintKindV1::FirstRow, 0, 0);
    let x = b.current(0);
    let x2 = b.current(1);
    let x3 = b.current(2);
    let x6 = b.current(3);
    let xx = b.mul(x, x);
    let c = b.sub(x2, xx);
    b.constrain(AirConstraintKindV1::Transition, c);
    let x2x = b.mul(x2, x);
    let c = b.sub(x3, x2x);
    b.constrain(AirConstraintKindV1::Transition, c);
    let x3x3 = b.mul(x3, x3);
    let c = b.sub(x6, x3x3);
    b.constrain(AirConstraintKindV1::Transition, c);
    let x7 = b.mul(x6, x);
    let seven = b.constant(7);
    let expected = b.add(x7, seven);
    let next = b.next(0);
    let c = b.sub(next, expected);
    b.constrain(AirConstraintKindV1::Transition, c);
    b.boundary(AirConstraintKindV1::LastRow, 0, 1);
    b.package()
}

fn customer_cubic8_air() -> AirPackageV1 {
    let names = (0..8)
        .map(|i| format!("initial_{i}"))
        .chain((0..8).map(|i| format!("final_{i}")));
    let mut b = Builder::new(8, names);
    for column in 0..8 {
        b.boundary(AirConstraintKindV1::FirstRow, column, column);
        let current = b.current(column);
        let square = b.mul(current, current);
        let cube = b.mul(square, current);
        let neighbor = b.current((column + 1) % 8);
        let expected = b.add(cube, neighbor);
        let next = b.next(column);
        let c = b.sub(next, expected);
        b.constrain(AirConstraintKindV1::Transition, c);
        b.boundary(AirConstraintKindV1::LastRow, column, 8 + column);
    }
    b.package()
}

fn add(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % GOLDILOCKS_MODULUS_U64 as u128) as u64
}

fn mul(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % GOLDILOCKS_MODULUS_U64 as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_valid_and_unique() {
        let digests = beta_fixture_air_digests();
        assert_eq!(digests.len(), 3);
        assert!(digests.iter().all(|(_, digest)| digest.len() == 64));
        for fixture in BetaFixture::ALL {
            fixture.air().validate().unwrap();
        }
        assert_ne!(digests[0].1, digests[1].1);
    }
}
