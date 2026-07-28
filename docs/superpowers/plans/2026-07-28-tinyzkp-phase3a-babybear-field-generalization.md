# TinyZKP Phase 3A: BabyBear field generalization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove and verify a single-table BabyBear AIR through the bounded, durable pipeline — the first profile beyond Goldilocks — using the stock `p3_uni_stark` verifier, with the existing Goldilocks path byte-identical throughout.

**Architecture:** Introduce a `DurableFieldProfile` trait bundling the field, extension field, permutation, hash, compression, and durable-word types that `prover.rs`, `mmcs.rs`, `fri.rs`, `dft.rs`, `quotient.rs`, and `bounded_pcs.rs` currently hardcode to concrete Goldilocks types. Refactor each module to be generic over `P: DurableFieldProfile` one file at a time, proving byte-identical Goldilocks output at every step before adding the second, `BabyBearProfile`, instantiation. Wire the result through the existing admission gate (`tinyzkp-contracts`) and estimator (already field-generic since Phase 1a).

**Tech Stack:** Rust 1.95.0 (pinned), Plonky3 0.6.1 (exact-pinned), `p3-baby-bear`, `p3-poseidon2`, `p3-mds`, `p3-monty-31` (new crates, dependencies of `p3-baby-bear` already resolved in the frozen lock — see Task 1).

## Global Constraints

- Rust `1.95.0` pinned; every existing Plonky3 crate stays exactly `0.6.1`; the new `p3-baby-bear` dependency is pinned `=0.6.1` in `Cargo.toml`, matching every other `p3-*` entry.
- **`Cargo.lock` WILL change** (one new top-level package, `p3-baby-bear`). Its dependency closure — `p3-mds`, `p3-monty-31`, `p3-poseidon1`, `p3-poseidon2`, `p3-symmetric`, `p3-field`, `p3-challenger`, `rand ^0.10.1` — is **already present** in the frozen lock (verified: each already has exactly one package entry; `rand 0.10.2` already satisfies `^0.10.1`). Confirm this with `cargo tree -p p3-baby-bear --manifest-path crates/hc-plonky3/Cargo.toml` after Task 1 Step 1 — if it pulls anything beyond `p3-baby-bear` itself, STOP and re-verify against Global Constraints before continuing; the plan's every-lock-hash-refreeze step assumes exactly one new package.
- The current lock hash `e124d2c46bf7e313edc2c4b06ea90633d9a929a430d5d1657d032a581f760990` is pinned in exactly these 8 places (verified by `grep -rl` against the repo root): `.github/workflows/evaluation-doctor.yml`, `crates/hc-cli/tests/cli_roundtrip.rs`, `crates/hc-plonky3/src/prover.rs` (constant `DEPENDENCY_LOCK_SHA256`), `release/plonky3-compatibility-v1.json`, `scripts/ci/backend_release_ready.py`, `scripts/ci/test_backend_release_ready.py`, `scripts/release/build_external_records.py`, `scripts/release/test_build_external_records.py`. Every task that changes `Cargo.lock` must re-freeze all 8, plus regenerate `fuzz/Cargo.lock` and `clients/rust/Cargo.lock` (standalone workspaces, no root gate covers them). `release/evidence/` is signed historical attestation — **never edit it**; a diff there after any task is a bug in that task.
- `scripts/ci/claim_containment_scan.py` scans `docs/**/*.md`, `README.md`, and `site/`/`release/` trees for `\bzero[- ]knowledge\b` and similar unsupported-claim patterns. Run it after every task that touches a doc file.
- **Every existing Goldilocks fixture must produce byte-identical output after every task in this plan.** This is the plan's core safety net: `cargo test --workspace` must stay green throughout, and the specific byte-equality parity tests in `hc-plonky3` (see Task 2) must not change their expected values. If a task changes a byte-equality assertion's expected constant, treat that as a plan-conflict and stop — ask before proceeding, per this repo's fix-loop rules.
- No task in this plan touches `site/`, pricing, or commerce copy. Site/estimator copy changes (the scalar-fallback caveat, BabyBear benchmark publication) are Task 10 only, and only additive.
- This plan does **not** implement KoalaBear or Mersenne31, multi-table scheduling (Phase 3B), or LogUp (Phase 3C). Once `DurableFieldProfile` exists, adding KoalaBear is expected to be a small follow-on (a second profile impl, no further trait changes) — track it as a fast-follow, not a task here.

## Fix round 2 (post-review, before Task 3) — READ BEFORE TASKS 4-8

A code review of Tasks 1-2 produced four findings that change how the
remaining tasks must be executed. All were verified by compiling, not by
reasoning.

1. **`DurableFieldProfile` needed 8 more bounds, and now carries them.**
   Task 2's note said rustc "cannot normalize the projection inside a
   higher-ranked bound". That was WRONG. `crates/hc-plonky3/src/generic_prover_guard.rs`
   builds a fully generic `prove_to_bytes` with exactly that `for<'a>` bound
   and it compiles and produces real proof bytes. The original 15 E0277s
   were missing bounds: `Val: PrimeField64`, the three **`Packing` (SIMD)**
   variants of Permutation/Hash/Compression, `Sync` on Hash and Compression,
   and `[Val; DIGEST_ELEMS]: Serialize + Deserialize`. Seven are now stated
   once on the trait; only the serde one must be restated at generic use
   sites (trait `where`-clauses over non-`Self` types are not elaborated to
   callers).

2. **Task 8 must go fully generic in ONE step.** Making `prover.rs`'s `Val`
   alias a projection while its callers stay concrete still fails, with a
   DIFFERENT error (`Dft: TwoAdicSubgroupDft<Goldilocks>` unsatisfied).
   That is an artifact of the half-generic intermediate state. Flipping
   `Val` first and chasing fallout does not converge — convert
   `prove_to_bytes` and its generic parameters together.

3. **The byte-identity safety net was self-referential.** Every existing
   byte-equality test compared the bounded prover against the reference
   prover *in the same build*; both call the same `profile_permutation()`,
   so a changed seed would move both sides together and stay green.
   `bounded_prover.rs::goldilocks_fibonacci_proof_matches_frozen_known_answer`
   now pins the fibonacci(0,1,16) proof to a blake3 constant. That constant
   was verified equal at `main` (f17930c) and on this branch, which is the
   only external evidence Tasks 1-2 were byte-preserving. **If it ever
   fails, stop and ask — do not update the constant.**

4. **`PERM_WIDTH` vs `CanonicalElement::WIDTH`.** The trait's permutation
   width is now spelled `PERM_WIDTH`, because `hc_stream::CanonicalElement::WIDTH`
   means BYTES PER SCRATCH ELEMENT — a different quantity that coincidentally
   also equals 8 for Goldilocks (and is 4, not 16, for BabyBear). Never
   write bare `WIDTH` for either. `checkpoint.rs` likewise now separates
   `RATE` from `DIGEST_ELEMS` with a static assertion.

Still open, deliberately deferred: FRI security parameters are field-blind
(`prover.rs` calls `FriParameters::new_benchmark` with no field awareness).
BabyBear's challenge field is 124 bits vs Goldilocks' 128. Task 8 or 10
should compute `p3_uni_stark::security::ConjecturedSecurity` for both
profiles and assert BabyBear meets a stated floor before Task 10 publishes
any benchmark.

## ✅ RESOLVED (was a blocking prerequisite for Task 9): live estimator degree bug + wasm32 build

`estimate_params.rs` priced the quotient DFT with a hardcoded `2` — the extension degree, missed when `fri.rs`/`quotient.rs` were swept. Correct for Goldilocks (degree 2); **half the true column count for BabyBear/KoalaBear/Mersenne31** (degree 4). It is now derived from the widths already in `params`, since `field_widths` returns `(base, base * degree)`:

```rust
let extension_degree = ext_field_bytes.checked_div(field_bytes).unwrap_or(2).max(1) as usize;
```

**Measured correction** on `test-vectors/estimate/babybear-multi-table.json`:

| metric | before (shipped) | after | delta |
|---|---|---|---|
| `total_read_bytes` | 59,458,455,408 | 60,129,544,048 | +671,088,640 (+1.13%) |
| `total_write_bytes` | 38,052,155,280 | 38,723,243,920 | +671,088,640 (+1.76%) |
| `scratch_high_water_bytes` / `peak_resident_bytes` | — | unchanged | — |

Goldilocks is byte-identical (16/8 = 2), confirmed by the parity gate. The correction moves BabyBear estimates UP; the previously shipped numbers understated I/O.

### The wasm32 blocker, and how it was cleared

Landing any cost-model change requires rebuilding the committed `site/vendor/tinyzkp-estimate/tinyzkp-estimate_bg.wasm`, because `estimate_wasm_cli_parity_gate.mjs` compares `hc-cli` against those exact bytes — and that gate runs in **`deploy-site.yml`**, the production Pages deploy, so a source-only change would have blocked the site deploy.

`hc-wasm` could not build for `wasm32-unknown-unknown`: `zstd-sys`'s build script compiles `zstd/lib/decompress/huf_decompress_amd64.S` — x86-64 assembly — even for wasm32, and clang rejects it. Verified identical at `main`, so it predated this plan.

**Fix:** `zstd` is now scoped to `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` in `crates/hc-plonky3/Cargo.toml`, with a small `compression` shim in `declarative.rs` keeping both call sites identical across targets (the uploaded-trace path reads chunk FILES, so it is already unreachable on a target with no filesystem; the wasm arm fails closed rather than returning empty data). **`Cargo.lock` is byte-unchanged** — the lock is target-agnostic, so the hash pinned in 8 places still matches. Side benefit: the vendored wasm shrank 428,793 → 394,572 bytes (−8%), since zstd was dead weight there.

### ⚠️ THE RE-VENDORING PROCEDURE (reverse-engineered; write it down or it will be lost)

The vendored files are named `tinyzkp-estimate.*` but the wasm's compiled-in import module name is `tinyzkp-verify`. Build with `--out-name tinyzkp-verify`, then rename only the `.wasm` FILENAME reference — never the import key at `tinyzkp-estimate.js:88` (`"./tinyzkp-verify_bg.js"`), which must keep matching the binary's import section:

```bash
RUSTFLAGS=" " wasm-pack build --target web --out-name tinyzkp-verify --out-dir <tmp> crates/hc-wasm
sed 's/tinyzkp-verify_bg\.wasm/tinyzkp-estimate_bg.wasm/g; s|@ts-self-types="./tinyzkp-verify.d.ts"|@ts-self-types="./tinyzkp-estimate.d.ts"|' \
  <tmp>/tinyzkp-verify.js > site/vendor/tinyzkp-estimate/tinyzkp-estimate.js
cp <tmp>/tinyzkp-verify_bg.wasm site/vendor/tinyzkp-estimate/tinyzkp-estimate_bg.wasm
```

Applying that transform to a fresh build reproduces the committed `.js` **byte-identically**, which is the check that the toolchain and ABI still match — do it every time before replacing the `.wasm`. `RUSTFLAGS=" "` is required on this Mac because `~/.cargo/config.toml` sets a global `target-cpu=native`, which leaks `apple-m4` into wasm32 builds.

Gates confirming the result: `estimate_wasm_cli_parity_gate.mjs` (BOTH fixtures), `test_worker_estimate.mjs`, `site_worker_dispatch_test.mjs`.

---

### Task 1: Add the `p3-baby-bear` dependency and re-freeze the lock

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]` section, alongside the existing `p3-goldilocks.workspace = true` line)
- Modify: `crates/hc-plonky3/Cargo.toml` (add `p3-baby-bear.workspace = true` next to `p3-goldilocks.workspace = true`)
- Modify (re-freeze only, no logic change): `.github/workflows/evaluation-doctor.yml`, `crates/hc-cli/tests/cli_roundtrip.rs`, `crates/hc-plonky3/src/prover.rs`, `release/plonky3-compatibility-v1.json`, `scripts/ci/backend_release_ready.py`, `scripts/ci/test_backend_release_ready.py`, `scripts/release/build_external_records.py`, `scripts/release/test_build_external_records.py`
- Modify: `fuzz/Cargo.lock`, `clients/rust/Cargo.lock` (regenerate, standalone workspaces)

**Interfaces:**
- Produces: `p3_baby_bear` crate available to `hc-plonky3` for Task 3 onward.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, in the `[workspace.dependencies]` block, add a line immediately after `p3-goldilocks.workspace = true`:

```toml
p3-baby-bear = "=0.6.1"
```

In `crates/hc-plonky3/Cargo.toml`, in the `[dependencies]` block, add immediately after `p3-goldilocks.workspace = true`:

```toml
p3-baby-bear.workspace = true
```

- [ ] **Step 2: Verify the dependency closure matches the Global Constraints claim**

Run:
```bash
cargo tree -p p3-baby-bear --manifest-path crates/hc-plonky3/Cargo.toml
```
Expected: every dependency listed (`p3-challenger`, `p3-field`, `p3-mds`, `p3-monty-31`, `p3-poseidon1`, `p3-poseidon2`, `p3-symmetric`, `rand`) already appears elsewhere in the existing `Cargo.lock` at the same version. If `cargo update` (invoked implicitly by the build) needs to add or bump anything besides the single new `p3-baby-bear` package entry, STOP and report back before continuing — the rest of this task assumes exactly one new entry.

- [ ] **Step 3: Build to regenerate `Cargo.lock`**

```bash
cargo check --workspace --locked 2>&1 | tail -5 || cargo check --workspace
```
(the first form will fail because the lock is stale — expected — the second regenerates it)

- [ ] **Step 4: Compute the new lock hash**

```bash
shasum -a 256 Cargo.lock
```
Record the output hash — call it `NEW_HASH` for the remaining steps.

- [ ] **Step 5: Re-freeze all 8 pin sites**

In each of the 8 files listed under Files above, replace every occurrence of the old hash
`e124d2c46bf7e313edc2c4b06ea90633d9a929a430d5d1657d032a581f760990` with `NEW_HASH`. Use
`grep -rl "e124d2c46bf7e313edc2c4b06ea90633d9a929a430d5d1657d032a581f760990" --exclude-dir=.git .`
to confirm the full set of occurrences before editing, and re-run it after editing to confirm zero remain outside `release/evidence/` (which must show zero occurrences — it never contained this hash and must not gain one).

- [ ] **Step 6: Regenerate the two standalone lockfiles**

```bash
cargo fetch --locked --manifest-path fuzz/Cargo.toml || cargo update --manifest-path fuzz/Cargo.toml
cargo fetch --locked --manifest-path clients/rust/Cargo.toml || cargo update --manifest-path clients/rust/Cargo.toml
```
Only regenerate if these actually reference the workspace dependency graph and go stale; if `cargo fetch --locked` on either succeeds with no changes, leave that lockfile untouched.

- [ ] **Step 7: Verify `release/evidence/` untouched**

```bash
git diff --stat -- release/evidence/
```
Expected: empty output.

- [ ] **Step 8: Full workspace check**

```bash
cargo check --workspace --locked
cargo test --workspace
```
Expected: both succeed. No test's expected output should have changed — this task adds a dependency and re-freezes hashes only.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml Cargo.lock crates/hc-plonky3/Cargo.toml fuzz/Cargo.lock clients/rust/Cargo.lock \
  .github/workflows/evaluation-doctor.yml crates/hc-cli/tests/cli_roundtrip.rs \
  crates/hc-plonky3/src/prover.rs release/plonky3-compatibility-v1.json \
  scripts/ci/backend_release_ready.py scripts/ci/test_backend_release_ready.py \
  scripts/release/build_external_records.py scripts/release/test_build_external_records.py
git commit -m "Add p3-baby-bear dependency and re-freeze Cargo.lock hash"
```

---

### Task 2: Introduce `DurableFieldProfile` as a no-op refactor of the existing Goldilocks path

This task changes **no behavior**. Its only goal is to extract the trait shape from the Goldilocks-concrete code that already exists, so the abstraction is proven correct against a known-working field before a second field is added in Task 3.

**Correction to this plan's earlier assumption, verified by reading the code before writing this task:** `Permutation`/`Hash`/`Compression` are indeed defined in `prover.rs:48-50` (`Permutation = Poseidon2Goldilocks<8>`), but the actual seeded *construction* — the function this plan needs to copy verbatim — is `profile_permutation()` in **`crates/hc-plonky3/src/checkpoint.rs:171-177`**, not `prover.rs`. `checkpoint.rs` separately defines its own `ProfilePermutation`/`ProfileChallenger` type aliases (`checkpoint.rs:13-15`) that are the ones actually used by `fri.rs`, `mmcs.rs`, and `bounded_pcs.rs` (confirmed: `use crate::checkpoint::profile_permutation;` appears in `fri.rs:1132`, `mmcs.rs:855`, `prover.rs:1` — `prover.rs`'s own `Permutation`/`Hash`/`Compression` aliases at `:48-50` are a second, separately-named copy of the same concrete types, not what downstream code actually calls). Treat `checkpoint.rs`'s aliases as the canonical ones this task extracts from.

**Additional real coupling found, scoped out of this task and named explicitly rather than silently ignored:** `checkpoint.rs` also defines `ChallengerSnapshotV1` (`:29-35`), the checkpoint/resume wire format, which hardcodes `sponge_state: [u64; WIDTH]` and validates every element against a Goldilocks-specific modulus constant (`checkpoint.rs:10,68,243`). Making checkpoint/resume itself field-generic is real additional work this task does **not** do. See the scope note at the end of Task 8.

**Files:**
- Create: `crates/hc-plonky3/src/profile.rs`
- Modify: `crates/hc-plonky3/src/prover.rs:46-55` (the `Val`/`Challenge`/`ValMmcs`/`ChallengeMmcs`/`Pcs` aliases that are built from, but distinct from, `checkpoint.rs`'s permutation/hash/compression)
- Modify: `crates/hc-plonky3/src/checkpoint.rs:13-15,171-177` (`ProfilePermutation`, `ProfileChallenger`, `profile_permutation()` — these move to being `GoldilocksProfile`'s trait-method implementations; `checkpoint.rs` keeps thin re-exports or direct calls to `GoldilocksProfile::profile_permutation()` so every existing caller in `fri.rs`/`mmcs.rs`/`prover.rs` keeps compiling unchanged in this task)
- Modify: `crates/hc-plonky3/src/lib.rs` (add `pub mod profile;` and re-export)

**Interfaces:**
- Produces: `pub trait DurableFieldProfile` with associated types `Val`, `Challenge`, `Permutation`, `Hash`, `Compression`; `pub struct GoldilocksProfile;` implementing it. Every later task (3 onward) is generic over `P: DurableFieldProfile`.
- Consumes: nothing new — this task only extracts what `prover.rs` already concretely defines.

- [ ] **Step 1: Read the exact current definitions before changing anything**

```bash
sed -n '1,60p' crates/hc-plonky3/src/prover.rs
sed -n '1,20p;160,180p' crates/hc-plonky3/src/checkpoint.rs
```
Confirm the trait bounds below match what you see (Plonky3's exact trait bounds are intricate; adjust the sketch below to what actually compiles rather than forcing it — this is expected exploratory work for this task, not a sign the plan is wrong).

- [ ] **Step 2: Define the trait**

Create `crates/hc-plonky3/src/profile.rs`:

```rust
//! `DurableFieldProfile` bundles every field-specific type the durable
//! prover needs, so `dft`, `mmcs`, `fri`, `quotient`, `bounded_pcs`, and
//! `bounded_prover` can be written once and instantiated per field.
//! `GoldilocksProfile` (this file) is the extracted, behavior-preserving
//! form of what `prover.rs` previously hardcoded. See task-2-report.md for
//! the exact trait bounds this compiled against, if they differ from the
//! sketch in the plan that introduced this file.

use hc_stream::CanonicalElement;
use p3_challenger::{CanBeChallenger, CanObserve, CanSample, DuplexChallenger, FieldChallenger};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_symmetric::{CryptographicHasher, CryptographicPermutation, PseudoCompressionFunction};

/// Every field-specific type and constant the durable prover needs.
/// Implement once per supported field profile.
pub trait DurableFieldProfile: Clone + Send + Sync + 'static {
    /// The base field. Must support two-adic FFT (Plonky3's DFT requires it).
    type Val: Field + TwoAdicField + PrimeCharacteristicRing;
    /// The extension field used for FRI challenges.
    type Challenge: ExtensionField<Self::Val>;
    /// The Poseidon2 (or equivalent) permutation over `Val`.
    type Permutation: CryptographicPermutation<[Self::Val; 8]> + Clone;
    /// Sponge hash built from `Permutation`.
    type Hash: CryptographicHasher<Self::Val, [Self::Val; 4]> + Clone;
    /// Merkle compression built from `Permutation`.
    type Compression: PseudoCompressionFunction<[Self::Val; 4], 2> + Clone;
    /// The durable on-SSD scratch word for this field. Bridges `Val` to
    /// `hc_stream::CanonicalElement` — see `dft::GoldilocksWord` for the
    /// existing Goldilocks form Task 4 will generalize.
    type Word: CanonicalElement + From<Self::Val> + Into<Self::Val>;

    /// Machine-readable field name, matching `tinyzkp_contracts::FIELD` /
    /// `canonical_extension_degree` in `estimate_params.rs`. Exactly
    /// `"goldilocks"` or `"babybear"` for the two profiles this plan adds.
    const FIELD_NAME: &'static str;
    const EXTENSION_DEGREE: u8;

    /// Constructs a fresh permutation instance. Profiles differ here only
    /// in which concrete Poseidon2 instantiation they call.
    fn profile_permutation() -> Self::Permutation;

    /// Upper bound (exclusive) on values this profile's workloads may seed
    /// with, so generated fixtures (Fibonacci's `initial_a`/`initial_b`,
    /// etc.) never exceed the field's modulus. Generalizes
    /// `GOLDILOCKS_MODULUS_U64` in `prover.rs`.
    fn modulus_u64() -> u64;
}
```

- [ ] **Step 3: Implement `GoldilocksProfile` using exactly the existing construction from `checkpoint.rs`**

Append to `crates/hc-plonky3/src/profile.rs`:

```rust
use crate::dft::GoldilocksWord;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_field::extension::BinomialExtensionField;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::Xoshiro256PlusPlus;
use rand::SeedableRng;

#[derive(Clone, Debug, Default)]
pub struct GoldilocksProfile;

impl DurableFieldProfile for GoldilocksProfile {
    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Goldilocks, 2>;
    type Permutation = Poseidon2Goldilocks<8>;
    type Hash = PaddingFreeSponge<Self::Permutation, 8, 4, 4>;
    type Compression = TruncatedPermutation<Self::Permutation, 2, 4, 8>;
    type Word = GoldilocksWord;

    const FIELD_NAME: &'static str = "goldilocks";
    const EXTENSION_DEGREE: u8 = 2;

    fn profile_permutation() -> Self::Permutation {
        // Copied verbatim from checkpoint.rs::profile_permutation (the
        // function fri.rs/mmcs.rs/prover.rs actually call, via
        // `use crate::checkpoint::profile_permutation` — NOT a same-named
        // function that ever lived in prover.rs). Same seed (1), same RNG
        // algorithm (Xoshiro256PlusPlus, named explicitly so 32-bit WASM
        // reconstructs the identical frozen transcript), same constructor.
        // Byte-identical output depends on this being an exact copy.
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Self::Permutation::new_from_rng_128(&mut rng)
    }

    fn modulus_u64() -> u64 {
        crate::prover::GOLDILOCKS_MODULUS_U64
    }
}
```

Leave `checkpoint.rs`'s own `profile_permutation()` (`:171-177`) in place, unchanged, for this task — every existing caller in `fri.rs`, `mmcs.rs`, and `prover.rs` keeps calling it exactly as before. Task 6 (`fri.rs`) and Task 5 (`mmcs.rs`) are where those call sites are repointed at `P::profile_permutation()`; `checkpoint.rs` itself is not touched until Task 8's scope note, since its `ChallengerSnapshotV1` format is Goldilocks-only by design for this plan.

- [ ] **Step 4: Point `prover.rs`'s existing aliases at the new profile, without changing any other line**

In `crates/hc-plonky3/src/prover.rs`, replace the block at lines 46-55 (`type Val = Goldilocks; ... type Pcs<Dft> = ...`) with type aliases derived from `GoldilocksProfile`:

```rust
pub(crate) type Val = <crate::profile::GoldilocksProfile as crate::profile::DurableFieldProfile>::Val;
pub(crate) type Challenge = <crate::profile::GoldilocksProfile as crate::profile::DurableFieldProfile>::Challenge;
pub(crate) type Hash = <crate::profile::GoldilocksProfile as crate::profile::DurableFieldProfile>::Hash;
pub(crate) type Compression = <crate::profile::GoldilocksProfile as crate::profile::DurableFieldProfile>::Compression;
// ValPacking, ValMmcs, ChallengeMmcs, Challenger, Pcs<Dft> keep their
// existing definitions unchanged — they're built FROM Val/Challenge/Hash/
// Compression, not part of the profile trait itself.
```

Update `profile_components()` (`prover.rs:538-543`) to call `GoldilocksProfile::profile_permutation()` instead of the old free function `profile_permutation()`; delete the old free function once nothing calls it.

- [ ] **Step 5: Register the module**

In `crates/hc-plonky3/src/lib.rs`, add `pub mod profile;` alongside the other `pub mod` declarations.

- [ ] **Step 6: Prove byte-identical output**

```bash
cargo test --workspace 2>&1 | tail -40
```
Expected: every existing test passes, in particular any test that compares a Goldilocks proof or checkpoint against a fixed expected byte sequence (search `grep -rn "assert_eq.*proof\|byte" crates/hc-plonky3/src/prover.rs crates/hc-plonky3/src/bounded_prover.rs` to locate them if unsure which). If any such assertion's *expected* value needed to change to pass, this task has altered behavior — stop and report, do not "fix" the test.

- [ ] **Step 7: Commit**

```bash
git add crates/hc-plonky3/src/profile.rs crates/hc-plonky3/src/prover.rs crates/hc-plonky3/src/lib.rs
git commit -m "Extract DurableFieldProfile trait from prover.rs's Goldilocks constants (no-op)"
```

---

### Task 3: Implement `BabyBearProfile` standalone (not yet wired into any prover code)

**Files:**
- Modify: `crates/hc-plonky3/src/profile.rs` (add `BabyBearProfile`)
- Modify: `crates/hc-plonky3/src/dft.rs` (add `BabyBearWord`, alongside the existing `GoldilocksWord` at line 36 — do not remove or rename `GoldilocksWord`)
- Test: `crates/hc-plonky3/src/profile.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `DurableFieldProfile` from Task 2.
- Produces: `pub struct BabyBearProfile;` implementing `DurableFieldProfile`, `pub struct BabyBearWord(pub p3_baby_bear::BabyBear);` implementing `CanonicalElement`. Nothing outside this task and its test references either yet.

- [ ] **Step 1: Add `BabyBearWord`**

In `crates/hc-plonky3/src/dft.rs`, immediately after the existing `GoldilocksWord` definition and its `CanonicalElement` impl (around line 36-65), add:

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BabyBearWord(pub p3_baby_bear::BabyBear);

impl From<p3_baby_bear::BabyBear> for BabyBearWord {
    fn from(value: p3_baby_bear::BabyBear) -> Self {
        Self(value)
    }
}

impl From<BabyBearWord> for p3_baby_bear::BabyBear {
    fn from(value: BabyBearWord) -> Self {
        value.0
    }
}

impl CanonicalElement for BabyBearWord {
    // BabyBear is a 31-bit field (fits u32); canonical_extension_degree in
    // estimate_params.rs already prices it at 4 bytes per base element —
    // this WIDTH must match that or the estimator and the real durable
    // scratch footprint disagree.
    const WIDTH: usize = 4;

    fn encode(self, output: &mut [u8]) {
        use p3_field::PrimeField32;
        output.copy_from_slice(&self.0.as_canonical_u32().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> hc_stream::Result<Self> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| hc_stream::StreamError::Corrupt("invalid BabyBear width"))?;
        let value = u32::from_le_bytes(bytes);
        // REQUIRED, and absent from this plan's first draft.
        // `GoldilocksWord::decode` (dft.rs:62) rejects `value >= modulus`:
        // that check is the durable scratch layer's corruption detector and
        // it makes decode injective. `BabyBear::new` accepts ANY u32 and
        // silently reduces mod p ("Any `u32` value is accepted",
        // p3-monty-31-0.6.1/src/monty_31.rs:47), so omitting this makes `x`
        // and `x + 0x78000001` decode to the same element and loses
        // corruption detection on the BabyBear scratch path.
        if value >= 0x7800_0001 {
            return Err(hc_stream::StreamError::Corrupt(
                "non-canonical BabyBear element",
            ));
        }
        Ok(Self(p3_baby_bear::BabyBear::new(value)))
    }
}
```

The constructor is `BabyBear::new(u32)` — VERIFIED against the vendored crate; this plan's original guess of `from_u32` is WRONG. `as_canonical_u32` comes from `p3_field::PrimeField32`. Confirm any further method names against the crate as vendored by Task 1 — `cargo doc -p p3-baby-bear --open` or reading `~/.cargo/registry/src/*/p3-baby-bear-0.6.1/src/` directly, since this plan was written without that crate checked out locally. If the method names differ, use the real ones; the round-trip property (`decode(encode(x)) == x` for every canonical value) is what Step 3's test enforces, not the exact method names above.

- [ ] **Step 2: Implement `BabyBearProfile`**

In `crates/hc-plonky3/src/profile.rs`, add:

```rust
use crate::dft::BabyBearWord;
use p3_baby_bear::BabyBear;

#[derive(Clone, Debug, Default)]
pub struct BabyBearProfile;

// CORRECTED (fix rounds 1 + 2). BabyBear's Poseidon2 exists ONLY at widths
// 16/24/32, and Plonky3's reference BabyBear config uses an 8-element
// digest. Goldilocks' <8, 4, 4> / <2, 4, 8> here would be BOTH a compile
// error AND a silent soundness regression (a 4-element BabyBear digest is
// ~62-bit collision resistance vs Goldilocks' ~128). These exact numbers
// are already proven satisfiable by profile.rs's BabyBearShapeStub.
impl DurableFieldProfile<16, 8> for BabyBearProfile {
    type Val = BabyBear;
    type Challenge = p3_field::extension::BinomialExtensionField<BabyBear, 4>;
    type Permutation = p3_baby_bear::Poseidon2BabyBear<16>;
    type Hash = PaddingFreeSponge<Self::Permutation, 16, 8, 8>;
    type Compression = TruncatedPermutation<Self::Permutation, 2, 8, 16>;
    type Word = BabyBearWord;

    const FIELD_NAME: &'static str = "babybear";
    const EXTENSION_DEGREE: u8 = 4;

    fn profile_permutation() -> Self::Permutation {
        // Same construction GoldilocksProfile uses, already compiled in
        // profile.rs's BabyBearShapeStub.
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        Self::Permutation::new_from_rng_128(&mut rng)
    }

    fn modulus_u64() -> u64 {
        // BabyBear's modulus is 2^31 - 2^27 + 1 = 0x78000001.
        0x7800_0001
    }
}
```

`EXTENSION_DEGREE = 4` matches `canonical_extension_degree("babybear") = (4, 4)` already in `estimate_params.rs:369` — do not use degree 2 here, or the estimator (already shipped and answering real BabyBear queries in production) will silently disagree with what the prover actually builds.

- [ ] **Step 3: Write the standalone round-trip test**

Add to `crates/hc-plonky3/src/profile.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn babybear_word_round_trips_through_canonical_encoding() {
        for raw in [0u32, 1, 2, BabyBear::ORDER_U32 - 1] {
            let value = BabyBear::from_u32(raw);
            let word = BabyBearWord::from(value);
            let mut bytes = vec![0u8; BabyBearWord::WIDTH];
            word.encode(&mut bytes);
            let decoded = BabyBearWord::decode(&bytes).expect("decode");
            assert_eq!(p3_baby_bear::BabyBear::from(decoded), value);
        }
    }

    #[test]
    fn babybear_profile_constructs_a_permutation() {
        // Just prove it doesn't panic and produces a usable permutation —
        // full hash-value testing happens once Task 6 wires it into MMCS.
        let _permutation = BabyBearProfile::profile_permutation();
    }
}
```

Adjust `BabyBear::ORDER_U32` to whatever constant `p3_baby_bear` actually exposes for its modulus (check the crate; it may be `BabyBear::ORDER_U32`, a free constant, or accessible only via `PrimeField32`).

- [ ] **Step 4: Run the new tests only**

```bash
cargo test -p hc-plonky3 profile:: 2>&1 | tail -30
```
Expected: both new tests pass. This task adds code that nothing else calls yet, so the rest of `cargo test --workspace` is unaffected by construction — run it anyway as a sanity check.

- [ ] **Step 5: Commit**

```bash
git add crates/hc-plonky3/src/profile.rs crates/hc-plonky3/src/dft.rs
git commit -m "Add standalone BabyBearProfile and BabyBearWord (not yet wired into the prover)"
```

---

### Task 4: Genericize `dft.rs` over `P: DurableFieldProfile`

**Files:**
- Modify: `crates/hc-plonky3/src/dft.rs` (every concrete `GoldilocksWord`/`Goldilocks` reference in `ResourceBoundedDft`/`ResourceBoundedMatrix`)

**Interfaces:**
- Consumes: `DurableFieldProfile` (Task 2), `BabyBearProfile`/`BabyBearWord` (Task 3, for the new test only — production call sites still only instantiate `GoldilocksProfile` until Task 8).
- Produces: `ResourceBoundedDft<P: DurableFieldProfile>`, `ResourceBoundedMatrix<P: DurableFieldProfile>` (renamed from the current non-generic types). Task 5 consumes these generic forms.

- [ ] **Step 1: Read the current file in full**

```bash
sed -n '1,60p' crates/hc-plonky3/src/dft.rs
```
(and the rest, as needed — this file is ~1300 lines with 100 Goldilocks references per the earlier audit).

- [ ] **Step 2: Add the generic parameter**

For every struct and impl block in `dft.rs` currently naming `Goldilocks` or `GoldilocksWord` concretely, add a type parameter `P: DurableFieldProfile` and replace:
- `Goldilocks` → `P::Val`
- `GoldilocksWord` → `P::Word`

Worked example for the one function shown in the earlier audit (`try_dft_block_matrix`, `dft.rs:485`):

```rust
// Before:
pub fn try_dft_block_matrix<M: BlockMatrix<GoldilocksWord>>(&self, matrix: &M, ...) -> ... { ... }

// After:
pub fn try_dft_block_matrix<M: BlockMatrix<P::Word>>(&self, matrix: &M, ...) -> ... { ... }
```

Apply the same substitution pattern to every other function and struct field in the file. `ResourceBoundedMatrix` becomes `ResourceBoundedMatrix<P>`; its `store: Mutex<Option<ScratchMatrixStore<GoldilocksWord>>>` field becomes `store: Mutex<Option<ScratchMatrixStore<P::Word>>>`.

- [ ] **Step 3: Update call sites within the same file**

Any free function or test in `dft.rs` that currently constructs `ResourceBoundedDft` or `ResourceBoundedMatrix` concretely must now name `ResourceBoundedDft::<GoldilocksProfile>` / `ResourceBoundedMatrix::<GoldilocksProfile>` explicitly — production behavior is unchanged, only the type parameter becomes explicit instead of implicit.

- [ ] **Step 4: Compile and fix trait bounds**

```bash
cargo check -p hc-plonky3 2>&1 | tail -60
```
This will surface errors in files that call into `dft.rs` (expected — Task 5 onward fixes those). For this task, get `dft.rs` itself compiling standalone by adding a temporary `#[allow(dead_code)]` shim or by proceeding directly into Task 5 in the same sitting if the errors are exactly the expected downstream ones in `mmcs.rs`/`fri.rs`/`bounded_prover.rs`. Do not leave the workspace non-compiling at the end of this task — if fully isolating `dft.rs`'s compilation is impractical, fold Task 5's minimum necessary changes into this task's commit and note the scope change in the report.

- [ ] **Step 5: Run the byte-equality regression**

```bash
cargo test -p hc-plonky3 2>&1 | tail -60
```
Expected: every existing Goldilocks-instantiated test still passes with unchanged expected values.

- [ ] **Step 6: Commit**

```bash
git add crates/hc-plonky3/src/dft.rs
git commit -m "Genericize dft.rs over DurableFieldProfile (GoldilocksProfile-only call sites unchanged)"
```

---

### Task 5: Genericize `mmcs.rs` over `P: DurableFieldProfile`

**Files:**
- Modify: `crates/hc-plonky3/src/mmcs.rs` (`DurableGoldilocksMmcs` → `DurableMmcs<P>`, every concrete `Goldilocks`/`GoldilocksWord` reference)

**Interfaces:**
- Consumes: `DurableFieldProfile`, `ResourceBoundedMatrix<P>` (Task 4).
- Produces: `DurableMmcs<P: DurableFieldProfile>` (renamed from `DurableGoldilocksMmcs<H, C>` — note the profile trait now supplies `Hash`/`Compression` via `P::Hash`/`P::Compression`, so the old separate `H, C` generic parameters collapse into the single `P` parameter). Task 6 (`fri.rs`) and Task 7 (`bounded_pcs.rs`) consume this rename.

- [ ] **Step 1: Read the current file in full, focusing on the `H, C` generic parameters**

```bash
grep -n "impl<H\|impl<H:" crates/hc-plonky3/src/mmcs.rs
```
`DurableGoldilocksMmcs<H, C>` is currently generic over hash/compression but concrete over the field (`Goldilocks`, `GoldilocksWord`). This task's job is the reverse direction from `dft.rs`: collapse `H, C` into `P::Hash, P::Compression` while making the field generic too.

- [ ] **Step 2: Rename and re-parameterize**

```rust
// Before:
pub struct DurableGoldilocksMmcs<H, C> { /* ... */ }
impl<H: Clone, C: Clone> DurableGoldilocksMmcs<H, C> { /* ... */ }

// After:
pub struct DurableMmcs<P: DurableFieldProfile> {
    hash: P::Hash,
    compression: P::Compression,
    // ...
}
impl<P: DurableFieldProfile> DurableMmcs<P> { /* body: replace every Goldilocks with P::Val, every GoldilocksWord with P::Word, every H/C-typed field with self.hash/self.compression */ }
```

Apply the same `Goldilocks → P::Val`, `GoldilocksWord → P::Word` substitution used in Task 4 to every remaining function in the file (`open_batches_sorted`, `commit`, `finish_tree`, etc. — the full list is at the ~100 Goldilocks references found in the earlier audit).

- [ ] **Step 3: Update `DurableFriMmcs`/`ExtensionMmcs` type aliases in `fri.rs`**

`fri.rs:28` (`ExtensionMmcs<Goldilocks, ProfileChallenge, DurableGoldilocksMmcs<H, C>>`) references the renamed type — update to `ExtensionMmcs<P::Val, P::Challenge, DurableMmcs<P>>`, deferring the rest of `fri.rs`'s generalization to Task 6 (this step only needs to keep the workspace compiling; if `fri.rs` needs more than this one alias touched to compile, that is Task 6's scope — coordinate by doing Tasks 5 and 6 in the same sitting if needed, same allowance as Task 4 Step 4).

- [ ] **Step 4: Compile and regression-test**

```bash
cargo check -p hc-plonky3 2>&1 | tail -60
cargo test -p hc-plonky3 2>&1 | tail -60
```

- [ ] **Step 5: Commit**

```bash
git add crates/hc-plonky3/src/mmcs.rs crates/hc-plonky3/src/fri.rs
git commit -m "Genericize mmcs.rs over DurableFieldProfile, rename DurableGoldilocksMmcs to DurableMmcs<P>"
```

---

### Task 6: Genericize `fri.rs` over `P: DurableFieldProfile`

**Files:**
- Modify: `crates/hc-plonky3/src/fri.rs` (every remaining concrete `Goldilocks`/`GoldilocksWord`/`ProfileChallenge` reference — 111 Goldilocks references per the earlier audit, most already addressed if Task 5 Step 3's alias update was sufficient; this task finishes the rest)

**Interfaces:**
- Consumes: `DurableMmcs<P>` (Task 5).
- Produces: `prove_durable_fri<P: DurableFieldProfile, ...>`, `DurableFriCommitment<P>` (was a concrete `MerkleCap<Goldilocks, [Goldilocks; 4]>` — becomes `MerkleCap<P::Val, [P::Val; 4]>`). Task 7 (`bounded_pcs.rs`, `bounded_prover.rs`) consumes these.

- [ ] **Step 1: Enumerate remaining concrete references**

```bash
grep -n "Goldilocks\b" crates/hc-plonky3/src/fri.rs
```

- [ ] **Step 2: Apply the same substitution pattern as Tasks 4-5**

`Goldilocks → P::Val`, `GoldilocksWord → P::Word`, `ProfileChallenge` (currently `BinomialExtensionField<Goldilocks, 2>`, `fri.rs:26`) → `P::Challenge`. Every free function (`prove_durable_fri`, `prove_durable_fri_observed_batched`, `resume_durable_fri_observed_batched`, etc.) gains a `P: DurableFieldProfile` type parameter alongside its existing `H, C, InputProof, OpenInput` parameters — or, if Task 5 already collapsed `H, C` into `P`, those parameters are removed here in favor of `P::Hash`/`P::Compression` accessed through `DurableMmcs<P>`.

- [ ] **Step 3: Compile and regression-test**

```bash
cargo check -p hc-plonky3 2>&1 | tail -60
cargo test -p hc-plonky3 2>&1 | tail -60
```

- [ ] **Step 4: Commit**

```bash
git add crates/hc-plonky3/src/fri.rs
git commit -m "Genericize fri.rs over DurableFieldProfile"
```

---

### Task 7: Genericize `quotient.rs` and `bounded_pcs.rs` over `P: DurableFieldProfile`

**Files:**
- Modify: `crates/hc-plonky3/src/quotient.rs`
- Modify: `crates/hc-plonky3/src/bounded_pcs.rs` (`ResourceBoundedVerifierPcs` → generic over `P`; `ProfileChallenger` similarly)

**Interfaces:**
- Consumes: `DurableFieldProfile`, `DurableMmcs<P>`, `fri.rs`'s generic forms (Tasks 5-6).
- Produces: `ResourceBoundedVerifierPcs<P: DurableFieldProfile>`, `BoundedConfig<P>` (was `StarkConfig<ResourceBoundedVerifierPcs, Challenge, ProfileChallenger>`, `bounded_pcs.rs:131`). Task 8 consumes these.

- [ ] **Step 1: `quotient.rs` — apply the established substitution**

```bash
grep -n "Goldilocks\b\|p3_uni_stark::VerifierConstraintFolder\|EvaluationConfig" crates/hc-plonky3/src/quotient.rs
```
Same `Goldilocks → P::Val` pattern as prior tasks, applied to `build_quotient_chunk_ldes`, `stream_quotient_values`, and the `EvaluationConfig` test helper type at `quotient.rs:329-331,444-446`.

- [ ] **Step 2: `bounded_pcs.rs` — genericize `ResourceBoundedVerifierPcs`**

```rust
// Before (bounded_pcs.rs:24-40):
pub struct ResourceBoundedVerifierPcs {
    official: OfficialPcs,
}

// After:
pub struct ResourceBoundedVerifierPcs<P: DurableFieldProfile> {
    official: OfficialPcs<P>,
}
```

`ProfileChallenger` (referenced throughout `bounded_pcs.rs` and `fri.rs`, currently `DuplexChallenger<Val, Permutation, 8, 4>` per `prover.rs:54`) becomes generic: `ProfileChallenger<const PERM_WIDTH: usize, const DIGEST_ELEMS: usize, P> = DuplexChallenger<P::Val, P::Permutation, PERM_WIDTH, DIGEST_ELEMS>`. **Do NOT leave the literal `8, 4`** — BabyBear needs `16, 8` (`p3-uni-stark-0.6.1/tests/mul_fib_pair.rs:190`), so hardcoding `8, 4` here stalls Task 8. `crates/hc-plonky3/src/generic_prover_guard.rs` already holds a COMPILING generic form of this entire alias chain (ValPacking -> ValMmcs -> ChallengeMmcs -> Challenger -> Pcs -> Config); copy its shapes rather than re-deriving them. `BoundedConfig` (`bounded_pcs.rs:131`) becomes `BoundedConfig<P> = StarkConfig<ResourceBoundedVerifierPcs<P>, P::Challenge, ProfileChallenger<P>>`.

- [ ] **Step 3: Compile and regression-test**

```bash
cargo check -p hc-plonky3 2>&1 | tail -60
cargo test -p hc-plonky3 2>&1 | tail -60
```

- [ ] **Step 4: Commit**

```bash
git add crates/hc-plonky3/src/quotient.rs crates/hc-plonky3/src/bounded_pcs.rs
git commit -m "Genericize quotient.rs and bounded_pcs.rs over DurableFieldProfile"
```

---

### Task 8: Genericize `bounded_prover.rs`, finish `prover.rs`, and prove a real BabyBear round trip

This is the task that first produces an actual BabyBear proof.

**Files:**
- Modify: `crates/hc-plonky3/src/bounded_prover.rs` (every public entry point — `prove_resource_bounded`, `verify_resource_bounded_proof`, checkpoint/resume functions)
- Modify: `crates/hc-plonky3/src/prover.rs` (finish removing any remaining Goldilocks-concrete code not already covered by Task 2)
- Modify: `crates/hc-plonky3/src/workloads.rs` (`FibonacciWorkload`'s seed-value bound: replace the `GOLDILOCKS_MODULUS_U64` literal check at **`workloads.rs:191-192`** with `P::modulus_u64()`; `FibonacciAir` itself needs no change — it is already `impl<F> BaseAir<F> for FibonacciAir` / `impl<AB: AirBuilder> Air<AB> for FibonacciAir`, field-agnostic since before this plan)
- Test: `crates/hc-plonky3/tests/babybear_fibonacci_roundtrip.rs` (new)

**Interfaces:**
- Consumes: every generic type from Tasks 2-7.
- Produces: `prove_resource_bounded<P: DurableFieldProfile, W: ResourceBoundedWorkload>(...)`, callable with either `GoldilocksProfile` (existing behavior) or `BabyBearProfile` (new).

**Scope note carried from Task 2: checkpoint/resume stays Goldilocks-only in this plan.** `checkpoint.rs`'s `ChallengerSnapshotV1` hardcodes a Goldilocks-modulus validation (`checkpoint.rs:10,68,243`) and is not genericized by this plan. This task's BabyBear round trip must therefore run with `CheckpointPolicy::DeleteOnSuccess` (single-shot, no interrupt/resume), matching whichever existing Goldilocks integration test uses that same policy. If every existing Goldilocks test instead exercises resume, add one that doesn't rather than generalizing `ChallengerSnapshotV1` here — resumable BabyBear checkpoints are a fast-follow once this plan's core round trip is proven, not a requirement of "prove and verify a single-table BabyBear AIR."

- [ ] **Step 1: Genericize `bounded_prover.rs`'s public entry points**

Apply the established substitution to every function currently concrete over `Goldilocks`/`GoldilocksWord`/`Val`/`Challenge` (the file's own local `Val`/`Challenge` aliases, imported from `prover.rs`, become `P::Val`/`P::Challenge`). The `p3_uni_stark::{prove, verify, ...}` calls at the bottom of the pipeline (`bounded_prover.rs:40-43`) become generic over `SC: StarkGenericConfig` where `SC = BoundedConfig<P>` — this is exactly what `p3_uni_stark::prove`/`verify` already expect (they are field-generic upstream; this file was the one place forcing them concrete).

- [ ] **Step 2: Fix `FibonacciWorkload`'s modulus check**

In `crates/hc-plonky3/src/workloads.rs`, replace the site currently comparing against the literal `GOLDILOCKS_MODULUS_U64` with a comparison against `P::modulus_u64()`. **CORRECTED SCOPE — the original line numbers were wrong:** `workloads.rs` is only 419 lines, so `:494,637` do not exist; the real check is the single two-line condition at **`workloads.rs:191-192`**. Repo-wide the constant is referenced at **31 sites across 10 files** (`workloads.rs`, `declarative.rs`, `beta_fixtures.rs`, `contracts.rs`, `bounded_prover.rs`, `prover.rs`, `lib.rs`, `profile.rs`, `hc-cli/src/commands/plonky3.rs`, `hc-cli/tests/cli_roundtrip.rs`). Enumerate them first with `grep -rn GOLDILOCKS_MODULUS_U64 crates/ --include='*.rs'` and explicitly declare which stay Goldilocks-only — do NOT assume all 31 must generalize. threading `P: DurableFieldProfile` through `FibonacciWorkload` the same way `bounded_prover.rs` now does. `GOLDILOCKS_MODULUS_U64` itself stays defined (Task 3's `GoldilocksProfile::modulus_u64()` already returns it) — only the two call sites change to go through the profile instead of the bare constant.

- [ ] **Step 3: Write the failing test first**

Create `crates/hc-plonky3/tests/babybear_fibonacci_roundtrip.rs`:

```rust
use hc_plonky3::profile::BabyBearProfile;
use hc_plonky3::workloads::FibonacciWorkload;
use hc_plonky3::{prove_resource_bounded, verify_resource_bounded_proof};
// (adjust imports to whatever bounded_prover.rs actually re-exports publicly
//  by this point in the plan — check lib.rs's pub use list)

#[test]
fn babybear_fibonacci_proves_and_verifies_through_the_bounded_pipeline() {
    let workload = FibonacciWorkload::small_fixture(); // or however existing
                                                        // Goldilocks tests in
                                                        // bounded_prover.rs
                                                        // construct a small
                                                        // fixture — reuse
                                                        // that helper's shape
    let proof = prove_resource_bounded::<BabyBearProfile, _>(&workload, /* policy, roots, etc. matching the existing Goldilocks integration test's argument shape */)
        .expect("BabyBear proof generation");
    verify_resource_bounded_proof::<BabyBearProfile, _>(&proof, &workload)
        .expect("BabyBear proof verifies");
}
```

Adjust this sketch to match `bounded_prover.rs`'s actual existing Goldilocks integration test (search `grep -n "#\[test\]" crates/hc-plonky3/src/bounded_prover.rs` for the closest existing end-to-end test and mirror its exact setup) — the point of this test is that it is the BabyBear analogue of an already-passing Goldilocks test, constructed the same way.

- [ ] **Step 4: Run it, confirm it fails for the right reason (compile error, not yet a logic bug)**

```bash
cargo test -p hc-plonky3 --test babybear_fibonacci_roundtrip 2>&1 | tail -40
```

- [ ] **Step 5: Fix compilation and logic until it passes**

```bash
cargo test -p hc-plonky3 --test babybear_fibonacci_roundtrip 2>&1 | tail -40
```
Expected eventually: PASS. This is the task's real work — expect several iterations against the compiler and against Plonky3's own trait bounds (`StarkGenericConfig`, `Pcs`, `Mmcs` all carry associated-type constraints that must line up for `BoundedConfig<BabyBearProfile>` the same way they already do for `BoundedConfig<GoldilocksProfile>`).

- [ ] **Step 6: Confirm Goldilocks is still byte-identical**

```bash
cargo test --workspace 2>&1 | tail -80
```
Expected: full green, no expected-value changes anywhere.

- [ ] **Step 7: Commit**

```bash
git add crates/hc-plonky3/src/bounded_prover.rs crates/hc-plonky3/src/prover.rs \
  crates/hc-plonky3/src/workloads.rs crates/hc-plonky3/tests/babybear_fibonacci_roundtrip.rs
git commit -m "Genericize bounded_prover.rs; prove and verify the first BabyBear proof"
```

---

### Task 9: Wire BabyBear through the admission gate and CLI

**Files:**
- Modify: `crates/tinyzkp-contracts/src/lib.rs` (`ProfileIdentifierV1` enum at `:397-400`; `blocking_reasons()` at `:613-627`; the equivalent field check in `JobManifestV1::compatibility_reasons()` — search for its second occurrence, since the file has two near-identical gates per the earlier audit at `:193` and `:408` in `hc-plonky3/src/contracts.rs`)
- Modify: `crates/hc-plonky3/src/contracts.rs:193,408` (the `expected_verifier`/field gates mirrored from `tinyzkp-contracts`)
- Modify: `crates/hc-cli/src/commands/plonky3.rs` (wherever the CLI currently hardcodes `--field` to only accept `goldilocks`, if it does — check `grep -n "goldilocks" crates/hc-cli/src/commands/plonky3.rs`)
- Test: `crates/hc-cli/tests/estimate_config.rs` (extend), `crates/tinyzkp-contracts` inline tests

**Interfaces:**
- Consumes: nothing from Tasks 1-8 directly (this task is contract-layer only) — but its correctness depends on Task 8 having actually shipped a working BabyBear prove/verify path, since this task is what makes that path *reachable* from the CLI.
- Produces: `ProfileIdentifierV1::TinyzkpP3BabyBearV1` — a new enum variant. This is additive to a `#[serde(rename_all = "snake_case")]` enum that is part of `PUBLISHED_SCHEMA_NAMES`, but the schemas are **not yet published** (`PUBLIC_SCHEMA_NAMES` excludes them per the existing follow-up note in project memory) — so there are no external consumers to break yet. Decision made here, not left open: add the variant directly, do not introduce a parallel versioned schema for it.

- [ ] **Step 1: Add the enum variant**

In `crates/tinyzkp-contracts/src/lib.rs`, extend `ProfileIdentifierV1` (`:397-400`):

```rust
pub enum ProfileIdentifierV1 {
    TinyzkpP3GoldilocksV1,
    TinyzkpP3BabyBearV1,
    Other,
}
```

**⚠️ SCOPED WORK DISCOVERED BEFORE TASK 8 — the admission gates are a canonicality hazard, not just an enum check.**

"Loosening" the field-admission check is NOT sufficient on its own. `GOLDILOCKS_MODULUS_U64` is referenced at 31 sites across 10 files, and the load-bearing ones are **public-input canonicality validators**, not definitions:

| file | sites | role |
|---|---|---|
| `declarative.rs` | 146, 225, 320, 377 | declarative-AIR public values |
| `contracts.rs` | 145, 352, 424, 425 | admission gate |
| `prover.rs` | 532 (`validate_workload`) | workload seeds |
| `workloads.rs` | 191-192 | Fibonacci seeds (Task 8 handles this one) |
| `hc-cli/src/commands/plonky3.rs` | 299 | CLI input |

Every one of these compares a user-supplied `u64` against **Goldilocks'** modulus (~2^64). Left as-is on a BabyBear job they admit any value below 2^64, and the field constructor then silently reduces it mod 2^31-2^27+1. That is precisely the failure `prover.rs:23-25` already warns about in prose — *"distinct manifests collapse to the same public field element"* — and is the same defect class as the `BabyBearWord::decode` bug this plan's fix round 2 caught: a constructor that accepts anything and reduces, with no canonicality gate in front of it.

So this step must make each of those validators compare against **the profile's** modulus (`P::modulus_u64()`), not merely accept a new `field` string. A test must assert that a BabyBear job with a public input in `[BABYBEAR_MODULUS, GOLDILOCKS_MODULUS)` is REJECTED — that range passes every check today.

- [ ] **Step 2: Loosen the field-admission check**

Replace the single-field comparison in `blocking_reasons()` (`:613-614`, currently `self.field != FIELD || self.extension_degree != EXTENSION_DEGREE`) with a check against both supported profiles:

```rust
const SUPPORTED_PROFILES: &[(&str, u8)] = &[(FIELD, EXTENSION_DEGREE), ("babybear", 4)];

// in blocking_reasons():
if !SUPPORTED_PROFILES.contains(&(self.field.as_str(), self.extension_degree))
    || !(MIN_ROWS..=MAX_ROWS).contains(&self.logical_rows)
    || !self.logical_rows.is_power_of_two()
    || !(1..=MAX_TRACE_WIDTH).contains(&self.trace_width)
    || !(1..=MAX_CONSTRAINT_DEGREE).contains(&self.max_constraint_degree)
{
    push_unique(
        &mut reasons,
        ReasonV1::new(ReasonCodeV1::UnsupportedProfile).profiles(
            Some(if self.field == "babybear" {
                ProfileIdentifierV1::TinyzkpP3BabyBearV1
            } else {
                ProfileIdentifierV1::TinyzkpP3GoldilocksV1
            }),
            Some(ProfileIdentifierV1::Other),
        ),
    );
}
```

- [ ] **Step 3: Apply the same change to `hc-plonky3/src/contracts.rs`'s two mirrored gates**

Both `:193` and `:408` currently check `self.expected_verifier != "p3_uni_stark_0.6.1"` combined with a field check — locate the exact field-comparison condition at each site (`grep -n -B5 -A2 "expected_verifier != \"p3_uni_stark_0.6.1\"" crates/hc-plonky3/src/contracts.rs`) and apply the identical `SUPPORTED_PROFILES`-style widening. The `expected_verifier` check itself is unchanged — this plan does not touch the verifier, only the field.

- [ ] **Step 4: Confirm/relax the CLI's field argument**

```bash
grep -n "goldilocks\|--field\|\"field\"" crates/hc-cli/src/commands/plonky3.rs crates/hc-cli/src/commands/doctor.rs
```
If a hardcoded `"goldilocks"` literal gates CLI acceptance, widen it to accept `"babybear"` as well, mirroring whatever pattern is already there for extensibility (or, if the CLI already passes `field` through verbatim from a config file with no hardcoded gate — likely, since the estimator already accepted `babybear` before this plan — no change is needed here; confirm and note in the report rather than changing code that doesn't need it).

- [ ] **Step 5: Extend tests**

In `crates/hc-cli/tests/estimate_config.rs`, add a BabyBear fixture analogous to the existing ones (`:24-52`) but using a config shape the pipeline can *actually* prove now (small rows, no unsupported AIR features) and assert `provable_today: true` — this is the first test in the whole codebase where a non-Goldilocks config is expected to be provable, not just priced.

- [ ] **Step 6: Full regression**

```bash
cargo test --workspace 2>&1 | tail -80
```

- [ ] **Step 7: Commit**

```bash
git add crates/tinyzkp-contracts/src/lib.rs crates/hc-plonky3/src/contracts.rs \
  crates/hc-cli/src/commands/plonky3.rs crates/hc-cli/tests/estimate_config.rs
git commit -m "Admit BabyBear through the compatibility gate and CLI"
```

---

### Task 10: Measure BabyBear, correct the estimator's documented uncertainty, publish honestly

**Files:**
- Create: `examples/plonky3/fibonacci-babybear-1m.json` (or wherever existing Goldilocks fixtures like `fibonacci-1m.json` live — mirror that location)
- Modify: `crates/hc-plonky3/src/estimate_params.rs:145-158` (the `quotient_transform_peak` comment and, if measurement contradicts it, the `+3`/`192` term itself)
- Modify: `site/index.html` or wherever benchmark figures are published (only if this repo's site currently publishes Goldilocks benchmark numbers — check `grep -rn "CPU-s\|peak_resident\|benchmark" site/*.html`)

**Interfaces:**
- Consumes: the working BabyBear pipeline from Task 8.
- Produces: a measured BabyBear resident-memory and CPU figure, and a corrected or confirmed `quotient_transform_peak` term.

- [ ] **Step 1: Build a BabyBear fixture at the same shape as the existing Goldilocks ones**

Mirror `examples/plonky3/fibonacci-1m.json`'s row count and structure, changing only `field` to `babybear` and `extension_degree` to `4`.

- [ ] **Step 2: Run the real prover and record peak resident bytes**

```bash
cargo run -p hc-cli --release -- prove --config examples/plonky3/fibonacci-babybear-1m.json --mode bounded 2>&1 | tail -30
```
(adjust the exact CLI invocation to match however the existing Goldilocks benchmark is run — check any existing benchmark-running script or doc for the precise command)

- [ ] **Step 3: Compare measured peak resident bytes against the estimator's prediction**

```bash
cargo run -p hc-cli -- estimate --config examples/plonky3/fibonacci-babybear-1m.json 2>&1
```
Compare the `bounded.peak_resident_bytes` figure against Step 2's measured value.

- [ ] **Step 4: Resolve the documented uncertainty**

**FIRST READ THIS — a BabyBear measurement is only PARTLY discriminating, computed before the fact (fix round 2):**

`canonical_extension_degree` (`estimate_params.rs:366-372`) gives Goldilocks `(8, 2)` and BabyBear/KoalaBear/Mersenne31 `(4, 4)`. So `ext_field_bytes = base * degree` is **16 for every field this codebase supports**, and `digest_bytes` is **32 for every one of them** (Goldilocks 4 elements x 8 bytes; BabyBear 8 elements x 4 bytes). The three candidate readings of the `192` term therefore evaluate as:

| field | `12 * ext_field_bytes` | `6 * digest_bytes` | `24 * field_bytes` |
|---|---|---|---|
| goldilocks | 192 | 192 | 192 |
| babybear / koalabear / mersenne31 | 192 | 192 | **96** |

Consequences, which the existing comment does NOT say and which this step must not overstate:

1. A BabyBear measurement **CAN falsify the `24 * field_bytes` reading** — that reading predicts half the term (96 vs 192), a difference large enough to see.
2. It **CANNOT separate `12 * ext_field_bytes` from `6 * digest_bytes`**. Those two coincide in *every* field on this codebase's roadmap, so no measurement reachable from here distinguishes them. A field with `digest_bytes != 2 * ext_field_bytes` would be required, and none is planned.

So the honest outcomes of this step are "the `24 * field_bytes` reading is falsified (or confirmed)", NOT "the term is now resolved". If the measurement matches, update the comment at `estimate_params.rs:145-158` to say the term is measured and confirmed for BabyBear (cite this fixture) and that the `24 * field_bytes` reading is excluded — but **keep a hedge recording that `12 * ext_field_bytes` and `6 * digest_bytes` remain confounded**, because they do. Removing the hedge entirely would be a false claim of resolution. If it does not match, use the discrepancy to correct the `+3`/`192` term's field-byte-width attribution — the comment itself names this as the expected remedy ("if a BabyBear/KoalaBear/Mersenne31 estimate is ever contradicted by measurement, start here"). Either outcome is a valid result of this step; do not force a match.

- [ ] **Step 5: Publish the honest benchmark, with the scalar-fallback caveat**

If this repo publishes benchmark figures on the site or in docs, add the BabyBear figure alongside the existing Goldilocks ones, with an explicit note that BabyBear currently runs the scalar path (no packed SIMD kernel exists yet — `hc-simd` selects packed Goldilocks only, via the runtime `TypeId` check in `hc-fri/Cargo.toml:24-25`) — per the Phase 3 spec's claim-discipline section, this qualifier must ship in the same change as the number, not as a later correction.

- [ ] **Step 6: Run the claim containment scan**

```bash
python3 scripts/ci/claim_containment_scan.py
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add examples/plonky3/fibonacci-babybear-1m.json crates/hc-plonky3/src/estimate_params.rs
git commit -m "Measure BabyBear, resolve the quotient_transform_peak uncertainty, publish honestly"
```

---

### Task 11: Whole-plan regression seal

**Files:** none (verification only)

- [ ] **Step 1: Full workspace test suite**

```bash
cargo check --workspace --locked
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

- [ ] **Step 2: WASM target still compiles**

```bash
cargo check --locked -p hc-wasm --target wasm32-unknown-unknown
```

- [ ] **Step 3: Estimator WASM/CLI parity gate**

```bash
node scripts/ci/estimate_wasm_cli_parity_gate.mjs
```
Note: this gate covers the *estimator's* WASM/CLI parity, which was already field-generic before this plan — it is not expected to need changes, but must still pass, since this plan touched files the estimator's cost model reads from (`estimate_params.rs`).

- [ ] **Step 4: Claim containment**

```bash
python3 scripts/ci/claim_containment_scan.py
```

- [ ] **Step 5: Confirm `release/evidence/` still untouched across the whole plan**

```bash
git diff --stat main -- release/evidence/
```
Expected: empty, across every commit this plan made.

- [ ] **Step 6: Confirm the lock hash is consistent everywhere**

```bash
NEW_HASH=$(shasum -a 256 Cargo.lock | cut -d' ' -f1)
grep -rl "$NEW_HASH" --exclude-dir=.git . | wc -l
```
Expected: 8 (the same 8 sites from Task 1's Global Constraints, none missed, none extra).

---

## Explicitly out of scope for this plan

KoalaBear and Mersenne31 (expected to be small follow-ons once `DurableFieldProfile` exists — a third/fourth profile impl, no further trait changes), multi-table scheduling (Phase 3B), LogUp (Phase 3C), packed-SIMD kernels for BabyBear, raising `MAX_ROWS`, resumable checkpoint/resume for any non-Goldilocks profile (`ChallengerSnapshotV1` stays Goldilocks-only — see Task 8's scope note), and any site/pricing/commerce change beyond Task 10's benchmark publication.
