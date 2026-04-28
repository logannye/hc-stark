# Proof format and transcript spec (v4, ZK)

This document defines the **compatibility contract** for `hc-stark` proof artifacts and Fiat–Shamir transcripts when **zero-knowledge masking** is enabled.

This is a *protocol* specification: implementations must follow it exactly for proofs to verify.

## 1. Versions at a glance

- **v2**: legacy transcript (includes experimental KZG path). Kept for compatibility only.
- **v3**: DEEP-STARK-style native proof (Blake3/Merkle), commits to trace LDE + quotient oracle, runs FRI on quotient.
- **v4**: **v3 + ZK masking**.
Policy:

- Verifiers should accept **v4** by default.
- **v2** should be rejected unless explicitly allowed (e.g. `allow_legacy_v2`).
- v3 may remain accepted, but production deployments should prefer v4 for privacy.
## 2. Transcript domains

Domains are consensus-critical and defined in `hc_hash::protocol`:

- Main transcript domain: `hc-stark/v4`
- FRI transcript domain: `hc-stark/fri/v4`
## 3. Transcript ordering (v4)

All integers are appended as little-endian `u64`.

### 3.1 Public inputs / parameters

Append in this exact order:

1. `pub/initial_acc`
2. `pub/final_acc`
3. `pub/trace_length`
4. `param/query_count`
5. `param/lde_blowup`
6. `param/fri_final_size`
7. `param/fri_folding_ratio`
8. `param/hash_id` = `blake3`
9. `param/zk_enabled` = `1`
10. `param/zk_mask_degree` = configured mask degree
### 3.2 Commitments and challenges

1. Append `commit/trace_lde_root` (Blake3 Merkle root).
2. Sample `composition/alpha_boundary`.
3. Sample `composition/alpha_transition`.
4. Append `commit/quotient_root`.
5. Append each `commit/fri_layer_root` in order.
6. Append `commit/fri_final_root`.
7. Sample query indices (`chal/query_round`, then `chal/query_index`), exactly as in v3.
## 4. ZK masking construction (v4)

Goal: opened trace and quotient values at verifier-chosen query points reveal no information about the underlying witness beyond the public statement, up to configured leakage.

### 4.1 Masked trace oracle

Let \(N\) be the padded trace length (next power of two).
Let \(Z_H(X) = X^N - 1\).

For each trace column polynomial \(T(X)\), sample a random low-degree masking polynomial \(R(X)\) with degree ≤ `zk_mask_degree`.

Define the masked trace oracle polynomial:

\[
T'(X) = T(X) + Z_H(X) \cdot R(X).
\]
Notes:

- \(Z_H(X)\) vanishes on the trace domain \(H_N\), so \(T'(x) = T(x)\) for all \(x \in H_N\).
- \(T'(X)\) differs from \(T(X)\) on the LDE coset domain, which is where openings are provided.
- The masking randomness is **prover-private** and MUST NOT be derived from Fiat–Shamir.
### 4.2 Quotient oracle

The quotient oracle is constructed exactly as in v3, but using the **masked** trace oracle values \(T'(x)\) at LDE points.
Because the added term is divisible by \(Z_H\), the quotient relation remains consistent.
## 5. Serialization requirements

- Proof JSON must be **self-describing**:
  - include `version=4`
  - include the ZK parameters in `params` (at least `zk_mask_degree` and `zk_enabled`).
- Any change to:
  - transcript domains,
  - label bytes,
  - field ordering,

requires a version bump.
## 6. Test vectors

Every release should include:
- at least one small v4 proof fixture that verifies,
- at least one mutation/tamper fixture that fails,
- an upgrade procedure documenting changes.

