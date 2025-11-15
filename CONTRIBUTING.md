 # Contributing to `hc-stark`

Thank you for helping build a production-grade, height-compressed STARK stack.
This document captures the conventions we follow across the workspace. Treat it
as the single source of truth for coding standards, review requirements, and CI
expectations.

## Toolchain & Workflow

- **Rust version:** pinned via `rust-toolchain.toml` (stable channel, minimal
  profile) to guarantee reproducible builds.
- **Formatting:** run `cargo fmt --all` before pushing. CI rejects unformatted
  code.
- **Linting:** `cargo clippy --workspace --all-targets -- -D warnings`. Keep the
  codebase warning-free.
- **Testing:** `cargo test --workspace --all-targets` must pass locally.
- **Docs:** `cargo doc --workspace --no-deps` should build without warnings.

## Coding Standards

- Prefer **pure functions** and **immutable data**. Side effects must be explicit
  and documented.
- Each crate uses `#![forbid(unsafe_code)]`. Unsafe Rust requires an RFC-style
  design review before it lands.
- Provide **module-level docs** (`//!`) summarizing intent, constraints, and
  invariants.
- Favor **small, composable modules** over monoliths. Keep files <500 LOC when
  possible.
- Use **explicit types**. Avoid implicit conversions and magical constants; store
  constants in `const` blocks with descriptive names.
- **Logging & metrics:** prefer structured logging via the future observability
  crate (placeholder for now) and expose metrics through `hc-prover::metrics`.

## Error Handling

- Use `hc_core::HcError`/`HcResult` everywhere. Extend the enum rather than
  defining new error trees.
- Leverage the `ResultExt::context` helper to preserve call-site information.
- Use the `hc_ensure!` macro instead of `assert!`/`expect` for input validation;
  never panic in library code.

## Testing Strategy

- Every new module ships with unit tests that cover happy paths and edge cases.
- Add property/fuzz tests for algebra-heavy code (FFT, field arithmetic, FRI).
- Integration tests live in `hc-examples` and `hc-cli` to validate end-to-end
  proving/verification flows.
- Performance-sensitive changes must include benchmark updates in `hc-bench`.

## Documentation

- Update `docs/design_notes/*` whenever you introduce a new architecture concept
  or algorithmic trade-off.
- Keep the `README` and `docs/whtiepaper.md` aligned with the code as we move
  from blueprint to production implementation.
- Provide runnable snippets in documentation comments where feasible.

## Git & Reviews

- Prefer focused commits with descriptive messages (`feat:`, `fix:`, `docs:`,
  etc.).
- Leave actionable review comments when modifying shared components (field math,
  replay engine, FRI).
- Security-sensitive changes must reference (and update when needed)
  `docs/design_notes/security_considerations.md`.

## Continuous Integration

CI enforces the following pipeline for every push and pull request:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace --all-targets`
4. `cargo doc --workspace --no-deps`

Benchmarks live in `.github/workflows/benches.yml` and run nightly to avoid
slowing down the main CI loop. Keep them deterministic and bounded so they can
run on GitHub-hosted runners.

## Security & Responsible Disclosure

- Never commit private keys, API tokens, or traces derived from real customers.
- When in doubt, prefer constant-time algorithms and avoid data-dependent
  branching on secret inputs.
- Report vulnerabilities privately to the maintainers before filing an issue.

By following these guidelines we can deliver a world-class prover with clean,
reviewable code and predictable production behavior. Happy hacking!

