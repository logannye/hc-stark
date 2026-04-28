# Audit Checklist

## Priority 1: Soundness-Critical Path

These files implement the core verifier logic. A bug here could allow proof forgery.

### `crates/hc-verifier/src/api.rs`
- [ ] `verify()` dispatches correctly by proof version
- [ ] `verify_stark_v3()` reconstructs Fiat-Shamir transcript identically to prover
- [ ] All query indices derived from transcript match proof data
- [ ] Trace query Merkle paths verified against committed root
- [ ] Composition query values match expected quotient evaluation
- [ ] Boundary constraints checked at first and last trace rows
- [ ] OOD (out-of-domain) evaluation verified correctly
- [ ] No early returns that skip checks

### `crates/hc-verifier/src/fri_verify.rs`
- [ ] FRI folding relation: `f(x) + f(-x) + beta * (f(x) - f(-x)) / x` computed correctly
- [ ] Layer roots verified against Merkle commitments
- [ ] Final polynomial degree check: `degree < fri_final_poly_size`
- [ ] Query count matches `params.query_count`
- [ ] No off-by-one in layer indexing

### `crates/hc-verifier/src/errors.rs`
- [ ] All error variants are reachable (no dead code)
- [ ] Error messages do not leak sensitive information

## Priority 2: Cryptographic Primitives

### `crates/hc-core/src/field/prime_field.rs`
- [ ] `add()`: constant-time, result always < MODULUS
- [ ] `sub()`: constant-time, result always < MODULUS
- [ ] `mul()`: 128-bit intermediate, reduction correct for Goldilocks
- [ ] `neg()`: constant-time, handles zero correctly
- [ ] `inverse()`: uses Fermat's little theorem (p-2 exponent)
- [ ] `pow_ct()`: Montgomery ladder, no data-dependent branching
- [ ] `from_u64()`: reduces modulo MODULUS

### `crates/hc-hash/src/blake3.rs`
- [ ] Hash function wrapper calls blake3 correctly
- [ ] Domain separation between leaf and internal nodes

### `crates/hc-hash/src/transcript.rs`
- [ ] Transcript labels are unique per protocol step
- [ ] Challenge derivation is deterministic
- [ ] No transcript state reuse between independent proofs

### `crates/hc-commit/src/merkle/`
- [ ] `height_dfs.rs`: streaming Merkle tree height calculation correct
- [ ] `path.rs`: `verify()` recomputes root from leaf + siblings
- [ ] No hash collision between leaf and internal node serialization

## Priority 3: Proof Serialization

### `crates/hc-sdk/src/proof.rs`
- [ ] `encode_proof_bytes()` / `decode_proof_bytes()` are inverse operations
- [ ] Version field checked for consistency (envelope vs payload)
- [ ] No information loss in u64 <-> field element conversion
- [ ] KZG commitment points serialize/deserialize losslessly

### `crates/hc-sdk/src/types.rs`
- [ ] `ProofBytes` version field correctly propagated
- [ ] `VerifyResult` error messages safe to expose to clients

## Priority 4: Prover Correctness (Completeness)

### `crates/hc-prover/src/prove.rs`
- [ ] Trace polynomial interpolation matches execution trace
- [ ] Constraint quotient computed correctly: `C(x) / Z_H(x)`
- [ ] FRI commitment uses same Merkle tree as verifier expects
- [ ] Query responses include correct Merkle witnesses

### `crates/hc-prover/src/pipeline/`
- [ ] `phase1_commit.rs`: LDE blowup applied correctly
- [ ] `phase2_fri.rs`: FRI folding matches verifier's expectation
- [ ] `phase3_queries.rs`: query indices match transcript

## Priority 5: Infrastructure

### `crates/hc-server/src/lib.rs`
- [ ] Auth middleware cannot be bypassed
- [ ] Rate limiting applied before expensive computation
- [ ] Job IDs are unpredictable (UUID v4)
- [ ] No path traversal in job ID handling

### WASM/Python/Node bindings
- [ ] Thin wrappers with no additional logic to audit
- [ ] Error handling doesn't leak internal state
