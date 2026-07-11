# Plonky3 0.6.1 transcript-equivalence map

TinyZKP does not define a transcript. The bounded prover follows the pinned
`p3-uni-stark` 0.6.1 order and emits its official `Proof` type.

| Pinned upstream 0.6.1 source | TinyZKP implementation | Observed/sampled value |
|---|---|---|
| `p3-uni-stark/src/prover.rs::prove_with_preprocessed` degree observations | `bounded_prover::continue_from_trace_lde` | trace degree bits, quotient degree bits, log random rows (zero) |
| `p3-fri/src/two_adic_pcs.rs::commit` trace commitment | `DurableGoldilocksMmcs::try_commit_bit_reversed` | official trace Merkle cap |
| `p3-uni-stark/src/prover.rs::prove_with_preprocessed` constraint sample | bounded prover orchestration | quadratic-extension `constraint_alpha` |
| `p3-fri/src/two_adic_pcs.rs::commit_ldes` quotient commitment | streamed quotient + durable MMCS | official quotient Merkle cap |
| `p3-uni-stark/src/prover.rs::prove_with_preprocessed` OOD sample | `finish_after_quotient` | quadratic-extension `zeta` |
| `p3-fri/src/two_adic_pcs.rs::open` opened values | bounded interpolation | trace local/next and quotient chunks in upstream order |
| `p3-fri/src/two_adic_pcs.rs::open` batching sample | bounded opening reduction | quadratic-extension `batching_alpha` |
| `p3-fri/src/prover.rs::commit_phase` | `fri::continue_durable_fri_batched` | cap, commitment PoW, fold challenge for every layer |
| `p3-fri/src/prover.rs::prove_fri` final polynomial | durable FRI | coefficients in official order |
| `p3-fri/src/prover.rs::prove_fri` and `open_input` | durable FRI sorted scans | arities, query PoW, query indices and openings restored to transcript order |

`ChallengerSnapshotV1` serializes only the field-valued sponge state and input
and output buffers. The frozen Poseidon2 permutation is reconstructed from the
profile. Checkpoint continuation at every durable phase from trace generation
through verified proof assembly is covered by subprocess abort tests requiring
proof-byte equality with an uninterrupted run.

Any change to the order above, the Poseidon2 seed, proof serializer, dependency
lock, or Plonky3 version requires a new compatibility profile.
