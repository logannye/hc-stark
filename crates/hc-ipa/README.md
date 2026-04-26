# hc-ipa

Height-compressed Bulletproofs-style Inner Product Argument.

## What it does

Implements the IPA reduction in `O(√n)` prover memory by streaming the
witness vectors `a` and `b` from an on-demand source. Drop-in compatible
with standard Bulletproofs verification — the round structure and transcript
are unchanged.

## Why height compression matters here

Bulletproofs already has logarithmic interaction rounds, but the prover
materializes the full vectors `a` and `b` at round zero. For wide range
proofs (256-bit values), confidential-transaction batches, or aggregated
proofs over thousands of inputs, that round-zero peak dominates RAM.

The height-compressed prover:

- Holds one tile of `(a, b)` at a time (`O(√n)` group elements).
- Replays vector entries from a witness commitment instead of storing them.
- Folds round-by-round in place, writing the folded result back into the
  source for the next round.

## Status

Trait surface, statement/proof types, and config are stable. Cryptographic
body returns `HcError::unimplemented`. Tracked in `ROADMAP_EXTENSIONS.md`
Phase 4.

## Roadmap

See [`ROADMAP_EXTENSIONS.md`](../../ROADMAP_EXTENSIONS.md) for the phased
delivery plan and target commercial templates (`confidential_range`,
`aggregated_attestation`).
