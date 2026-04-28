# Threat Model

## System Boundaries

hc-stark is a ZK-STARK proof system. The security-critical boundary is:

**Prover (untrusted) -> Proof -> Verifier (trusted)**

The verifier must reject ALL invalid proofs. A valid proof must only be producible by someone who knows a valid witness (the execution trace).

## Attacker Model

### Adversary Capabilities

- **Full control over proof bytes**: The attacker can craft arbitrary proof data.
- **Knowledge of the protocol**: The STARK protocol is public. Security relies on computational hardness, not secrecy.
- **Computational bound**: The attacker is polynomially bounded (standard cryptographic assumption).

### Adversary Goals

1. **Forge a proof**: Produce a proof that verifies for a false statement (violates soundness).
2. **Crash the verifier**: Cause a panic, OOM, or infinite loop in the verifier (violates availability).
3. **Extract private information**: Learn the execution trace from the proof (violates zero-knowledge, when ZK masking is enabled).
4. **Timing side-channel**: Extract secret exponents or field elements through timing variations.

## Security Properties

### Soundness

A computationally bounded adversary cannot produce a proof that verifies for a false statement, except with negligible probability.

**Soundness error bound**: `1/|F|^query_count` where `|F| = 2^64 - 2^32 + 1` (Goldilocks) and default `query_count = 30`. This gives soundness error < `2^{-1920}`.

**Dependencies**:
- FRI folding correctness (each layer halves the degree)
- Merkle commitment binding (Blake3 collision resistance)
- Fiat-Shamir transcript determinism (no malleability)
- Constraint polynomial evaluation correctness

### Zero-Knowledge (when enabled)

When `zk_mask_degree > 0` (protocol version 4), the proof reveals nothing about the execution trace beyond the public inputs.

**Mechanism**: Random masking polynomial of the specified degree is added to the trace polynomial before commitment.

### Completeness

An honest prover with a valid witness always produces a proof that verifies.

### Verifier Safety

The verifier must never panic, OOM, or loop on ANY input. All error paths return `Err(VerifierError)`.

## Trust Assumptions

| Component | Trust Level | Rationale |
|-----------|------------|-----------|
| Goldilocks field arithmetic | High | Constant-time ops, proptest-verified algebraic properties |
| Blake3 hash | High | Well-audited cryptographic hash |
| Merkle tree | Medium | Custom implementation, needs audit of height_dfs.rs |
| FRI verifier | Medium | Core soundness-critical code, 0 unwrap calls |
| Fiat-Shamir transcript | Medium | Protocol labels must be unique and collision-free |
| Proof deserialization | Medium | JSON parsing, hardened against malformed input |
| WASM/Python/Node bindings | Low | Thin wrappers, security depends on underlying verifier |

## Attack Surface

### Proof Deserialization
- **Risk**: Malformed JSON could cause panics or excessive allocation
- **Mitigation**: serde_json handles bounds; all unwrap calls removed from verifier
- **Fuzz coverage**: `decode_proof_bytes`, `verify_proof_bytes`, `malformed_proof` targets

### Merkle Path Verification
- **Risk**: Adversarial paths could fool the verifier
- **Mitigation**: Path length checked against tree height; sibling hashes recomputed
- **Fuzz coverage**: `merkle_path` target

### FRI Protocol
- **Risk**: Incorrect folding or final polynomial check
- **Mitigation**: Layer roots committed before challenges drawn; final poly evaluated at all points
- **Fuzz coverage**: Indirect via `verify_proof_bytes`

### Field Arithmetic
- **Risk**: Non-canonical elements, overflow, or timing leaks
- **Mitigation**: All operations produce canonical results (< MODULUS); constant-time add/sub/neg/pow_ct
- **Fuzz coverage**: `field_ops` target; proptest algebraic properties

### HTTP Server
- **Risk**: DoS via large proofs, rate limiting bypass
- **Mitigation**: Auth + rate limiting configurable; proof size bounded by JSON parser limits
