# Informal Soundness Argument

## Overview

hc-stark implements the FRI-based STARK protocol over the Goldilocks field (p = 2^64 - 2^32 + 1). This document provides an informal argument that the system achieves computational soundness: no polynomially-bounded adversary can produce a verifying proof for a false statement except with negligible probability.

## Protocol Structure

1. **Trace commitment**: The prover commits to an execution trace polynomial T(x) via Merkle tree over LDE evaluations.
2. **Constraint evaluation**: The verifier checks that the constraint polynomial C(x) vanishes on the trace domain, i.e., C(x) = Q(x) * Z_H(x) where Q is the quotient polynomial.
3. **FRI protocol**: The prover demonstrates that Q(x) has degree < |H| via the Fast Reed-Solomon Interactive Oracle Proof of Proximity.
4. **Query phase**: The verifier spot-checks consistency between committed evaluations and the FRI chain.

## Soundness Argument

### Step 1: Commitment Binding

The Merkle tree commitment uses Blake3, a cryptographic hash function. Under the collision-resistance assumption for Blake3, the prover cannot open a committed polynomial to two different values at the same point.

**Assumption**: Blake3 is collision-resistant (256-bit security level).

### Step 2: FRI Soundness

The FRI protocol reduces the claim "Q has degree < D" to "Q_k has degree < D/2^k" through k rounds of folding. At each round, the verifier sends a random challenge beta_i and the prover commits to the folded polynomial.

By the Schwartz-Zippel lemma, if Q does not have degree < D, then the folded polynomial disagrees with the prover's committed polynomial at a random evaluation point with probability >= 1 - D/|F|.

After `query_count` independent queries, the probability that a cheating prover survives all queries is at most:

    (D/|F|)^query_count

For D = 2^20 (a large trace) and |F| = 2^64 - 2^32 + 1 ~ 2^64:

    (2^20 / 2^64)^30 = (2^{-44})^30 = 2^{-1320}

This is negligibly small.

**Reference**: Ben-Sasson et al., "Fast Reed-Solomon Interactive Oracle Proofs of Proximity" (ICALP 2018).

### Step 3: Constraint Soundness

If the execution trace T does not satisfy the AIR constraints, then C(x) does not vanish on H, which means Q(x) = C(x)/Z_H(x) is not a polynomial (it has poles). The FRI protocol will detect this with the probability bound above.

### Step 4: Fiat-Shamir Security

The interactive protocol is made non-interactive via the Fiat-Shamir transform: the verifier's challenges are derived by hashing the transcript (all prior prover messages).

Under the random oracle model (ROM), the Fiat-Shamir transform preserves soundness. In practice, Blake3 serves as the random oracle.

**Assumption**: Blake3 behaves as a random oracle for transcript hashing.

**Reference**: Canetti, Goldreich, Halevi, "The Random Oracle Methodology, Revisited" (STOC 1998).

### Step 5: Zero-Knowledge (Protocol Version 4)

When ZK masking is enabled (`zk_mask_degree > 0`), a random polynomial R(x) of degree `zk_mask_degree` is added to the trace polynomial before commitment:

    T'(x) = T(x) + R(x) * Z_H(x)

Since R(x) * Z_H(x) vanishes on H, the masked polynomial agrees with T on the trace domain, preserving completeness. The LDE evaluations outside H are uniformly distributed (conditioned on T), hiding the trace values.

## Known Limitations

1. **Metrics are not cryptographically bound**: The proof's metrics fields (timing data, block counts) are not part of the Fiat-Shamir transcript. Modifying them does not affect verification.

2. **JSON proof format**: The current proof serialization uses JSON, which has some redundancy. A more compact binary format would reduce the attack surface for deserialization.

3. **Single hash function**: The protocol uses Blake3 exclusively. A hash function break would compromise both commitment binding and Fiat-Shamir security. Dual-hash support (Blake3 + Poseidon) is planned for recursion.

## Concrete Security Parameters

| Parameter | Default Value | Security Contribution |
|-----------|--------------|----------------------|
| Field size | 2^64 - 2^32 + 1 | Schwartz-Zippel bound |
| Query count | 30 | Amplifies soundness by repetition |
| LDE blowup | 2 | Rate of Reed-Solomon code |
| Blake3 digest | 256 bits | Collision resistance for commitments |
| FRI folding ratio | 2 | Degree halving per round |

**Estimated soundness error**: < 2^{-1320} (for trace length up to 2^20).
