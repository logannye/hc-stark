# Changelog

## 0.1.1 — 2026-04-27

### Fixed
- **CommonJS support.** `require("tinyzkp")` now works alongside `import`. The
  package ships dual builds (`dist/esm/`, `dist/cjs/`) with proper `exports`
  conditional resolution. Older CJS-only codebases can consume the SDK without
  a bundler.
- **`ProofBytes` is now a runtime class.** Previously a TypeScript-only
  interface that erased at compile time, so `import { ProofBytes }` threw
  `SyntaxError: does not provide an export named 'ProofBytes'`. It is now a
  real class with a `constructor(version, bytes)` and a `.toJSON()` helper.
  Object literals matching `{ version, bytes }` are still accepted everywhere
  a `ProofBytes` is expected, via TypeScript structural typing — no source
  changes required.
- **`proveStatus` wraps the returned proof.** When status is `succeeded`, the
  embedded proof is now a real `ProofBytes` instance, so `instanceof` checks
  work as expected.

## 0.1.0 — 2026-04-27

Initial release.
- ESM-only TypeScript client for the TinyZKP proving API.
- Methods: `prove`, `proveTemplate`, `proveStatus`, `waitForProof`, `verify`,
  `templates`, `template`, `healthz`.
- Works in Node 18+, Bun, Deno, and modern browsers.
