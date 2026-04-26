//! Minimal Poseidon sponge for BN254 `Fr`, with deterministic parameter generation.
//!
//! This is used for Phase 3A "dual-digest" binding: we compute a field-friendly Poseidon digest
//! over (Blake3-committed) proof data, and the recursion circuit recomputes the same digest.
//!
//! Note: we generate round constants and the MDS matrix deterministically from a fixed seed using
//! SHA-256 + rejection sampling into the field. This avoids hard-coding large constant tables while
//! keeping parameters stable across builds.

use halo2curves::bn256::Fr;
use halo2curves::ff::{Field, PrimeField};
use hc_hash::sha256::Sha256;
use hc_hash::HashFunction;

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const ALPHA: u64 = 5;

const PARAM_SEED: &[u8] = b"hc-stark/recursion/poseidon/v1";

#[derive(Clone)]
pub struct PoseidonParams {
    pub mds: [[Fr; WIDTH]; WIDTH],
    pub ark: Vec<[Fr; WIDTH]>,
}

pub fn params() -> PoseidonParams {
    let rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
    let ark = (0..rounds)
        .map(|round| {
            let mut out = [Fr::ZERO; WIDTH];
            for (i, slot) in out.iter_mut().enumerate().take(WIDTH) {
                *slot = sample_fr(
                    &[
                        PARAM_SEED,
                        b"/ark/",
                        &(round as u64).to_le_bytes(),
                        &(i as u64).to_le_bytes(),
                    ]
                    .concat(),
                );
            }
            out
        })
        .collect::<Vec<_>>();

    // MDS via the standard Cauchy construction: M[i][j] = 1 / (x_i + y_j)
    let mut xs = [Fr::ZERO; WIDTH];
    let mut ys = [Fr::ZERO; WIDTH];
    for (i, slot) in xs.iter_mut().enumerate().take(WIDTH) {
        *slot = sample_fr(&[PARAM_SEED, b"/x/", &(i as u64).to_le_bytes()].concat());
    }
    for (i, slot) in ys.iter_mut().enumerate().take(WIDTH) {
        *slot = sample_fr(&[PARAM_SEED, b"/y/", &(i as u64).to_le_bytes()].concat());
    }

    let mut mds = [[Fr::ZERO; WIDTH]; WIDTH];
    for (i, row) in mds.iter_mut().enumerate().take(WIDTH) {
        for (j, slot) in row.iter_mut().enumerate().take(WIDTH) {
            let denom = xs[i].add(&ys[j]);
            let inv = denom.invert().unwrap_or(Fr::ONE); // extremely unlikely; deterministic fallback
            *slot = inv;
        }
    }

    PoseidonParams { mds, ark }
}

pub fn domain_tag() -> Fr {
    sample_fr(&[PARAM_SEED, b"/domain"].concat())
}

fn sample_fr(seed: &[u8]) -> Fr {
    // Rejection sample a field element from SHA-256(seed || ctr).
    for ctr in 0u64.. {
        let mut input = Vec::with_capacity(seed.len() + 8);
        input.extend_from_slice(seed);
        input.extend_from_slice(&ctr.to_le_bytes());
        let digest = Sha256::hash(&input);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_bytes());

        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        if let Some(value) = Option::<Fr>::from(Fr::from_repr(repr)) {
            return value;
        }
    }
    unreachable!("rejection sampling should succeed");
}

fn apply_mds(mds: &[[Fr; WIDTH]; WIDTH], state: &[Fr; WIDTH]) -> [Fr; WIDTH] {
    let mut out = [Fr::ZERO; WIDTH];
    for (i, out_slot) in out.iter_mut().enumerate().take(WIDTH) {
        let mut acc = Fr::ZERO;
        for (m, s) in mds[i].iter().copied().zip(state.iter().copied()) {
            acc += m * s;
        }
        *out_slot = acc;
    }
    out
}

fn sbox(x: Fr) -> Fr {
    x.pow_vartime([ALPHA, 0, 0, 0])
}

pub fn permute(params: &PoseidonParams, mut state: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
    for r in 0..rounds {
        // ARK
        for (s, ark) in state.iter_mut().zip(params.ark[r].iter()).take(WIDTH) {
            *s += *ark;
        }

        // S-box
        let is_full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&r);
        if is_full {
            for s in state.iter_mut().take(WIDTH) {
                *s = sbox(*s);
            }
        } else {
            state[0] = sbox(state[0]);
        }

        // MDS
        state = apply_mds(&params.mds, &state);
    }
    state
}

/// Poseidon sponge hash with capacity 1 and rate 2; returns the first state element.
pub fn hash(inputs: &[Fr]) -> Fr {
    let params = params();
    let mut state = [Fr::ZERO; WIDTH];

    // Domain separation: absorb a fixed tag first.
    state[0] += domain_tag();
    state[1] += Fr::ZERO;
    state = permute(&params, state);

    let mut i = 0usize;
    while i < inputs.len() {
        state[0] += inputs[i];
        if i + 1 < inputs.len() {
            state[1] += inputs[i + 1];
        } else {
            state[1] += Fr::ONE;
        }
        state = permute(&params, state);
        i += RATE;
    }
    state[0]
}
