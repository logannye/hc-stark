# hc-sumcheck

Height-compressed sumcheck prover and verifier.

## What it does

Implements the sumcheck reduction in `O(√(2^n))` prover memory by streaming
the boolean hypercube in tiles. Downstream protocols (Spartan, HyperPlonk,
Jolt, Lasso, Binius) plug in their own polynomial structure via the
`SumcheckPolynomial` trait.

## Why height compression matters here

Sumcheck IS a balanced binary tree by construction — each round halves the
boolean hypercube. The dominant memory cost in standard implementations is
the initial materialization of the multilinear extension table (`O(2^n)`
field elements). Height compression keeps the table virtual and replays
evaluations on demand:

- One `O(2^(n/2))` tile is live at a time.
- Round messages are constant-size (a `degree`-bound univariate polynomial).
- Prover working memory is `O(√(table size))` instead of `O(table size)`.

## Status

Trait surface, claim/proof types, and config are stable. Cryptographic body
returns `HcError::unimplemented`. Tracked in `ROADMAP_EXTENSIONS.md` Phase 3.

## Roadmap

See [`ROADMAP_EXTENSIONS.md`](../../ROADMAP_EXTENSIONS.md) for the phased
delivery plan.
