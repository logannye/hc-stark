#!/usr/bin/env node
// Behavioral parity gate for the committed `site/vendor/tinyzkp-estimate`
// WASM artifact.
//
// This is deliberately NOT a digest/hash comparison of the `.wasm` file
// against `crates/hc-plonky3`'s source: wasm builds are not guaranteed
// byte-reproducible across toolchain/wasm-opt versions, so a digest gate
// would be flaky and would get disabled the first time it cried wolf.
// Instead it drives the SAME `EstimateRequestV1` fixture through the two
// real code paths a caller can reach today — (a) the native `hc-cli`
// binary built straight from this checkout's `crates/hc-plonky3`, and (b)
// the exact bytes already committed at `site/vendor/tinyzkp-estimate/` —
// and asserts they compute byte-identical `EstimateResponseV1` values. If
// someone edits the cost model and forgets to rebuild+recommit the vendored
// `.wasm`, this is what catches it: `cargo test --workspace` alone cannot,
// because Task 1's parity test is Rust-to-Rust and never touches the
// committed binary.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { register } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();

// `tinyzkp-estimate_bg.wasm` is imported the Wrangler-native way elsewhere
// (a static ES `.wasm` import resolving to a `WebAssembly.Module` — see
// `site/_worker.js` and `scripts/ci/test_worker_estimate.mjs`). Plain Node
// has no built-in support for that extension, so this registers the same
// loader hook used there: scoped to this process only, never shipped,
// reproducing the "give me a Module" contract from the real committed
// bytes on disk.
const WASM_LOADER_SOURCE = `
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
export async function load(url, context, nextLoad) {
  if (url.endsWith(".wasm")) {
    const bytes = await readFile(fileURLToPath(url));
    const source = "const bytes = Uint8Array.from(atob(" +
      JSON.stringify(bytes.toString("base64")) +
      "), (c) => c.charCodeAt(0));\\nexport default new WebAssembly.Module(bytes);\\n";
    return { format: "module", source, shortCircuit: true };
  }
  return nextLoad(url, context);
}
`;
register(`data:text/javascript,${encodeURIComponent(WASM_LOADER_SOURCE)}`, import.meta.url);

// At least one unprovable config (exercises `blocking_reasons`) and one
// fully in-profile config (exercises the `provable_today: true` path),
// matching `crates/hc-cli/tests/estimate_config.rs`'s `BABYBEAR_MULTI_TABLE`
// and `crates/tinyzkp-contracts/src/lib.rs`'s `in_profile_request()`
// respectively, so this gate and those Rust-side tests stay pointed at the
// same known-shape fixtures rather than inventing a third set of numbers.
//
// The last two fixtures exist because the first two do not span the input
// range, only its comfortable middle — both sit at or below 2^22 rows and
// 180 columns, and the defect they missed lives above them. The native CLI
// and the deployed wasm differ in POINTER WIDTH (`usize` is 64-bit on the
// host, 32-bit on wasm32), so any `as usize` on a row count is a divergence
// this gate exists to catch, and can only catch where the fixtures reach:
//
//   goldilocks-max-envelope   `rows * width >= 2^31` — the top corner of the
//                             contract's own provable envelope (MAX_ROWS x
//                             MAX_TRACE_WIDTH). Overflows a 32-bit
//                             `checked_mul` and returns `internal_error`.
//   goldilocks-beyond-envelope
//                             `lde_rows >= 2^32` — out-of-profile, which the
//                             estimator deliberately prices. A 32-bit cast
//                             TRUNCATES here rather than erroring, so the
//                             response stays a confident HTTP 200 carrying a
//                             number that is wrong by orders of magnitude.
//                             This is the worse of the two failures and the
//                             one no error path would ever surface.
const FIXTURES = [
  "test-vectors/estimate/babybear-multi-table.json",
  "test-vectors/estimate/goldilocks-in-profile.json",
  "test-vectors/estimate/goldilocks-max-envelope.json",
  "test-vectors/estimate/goldilocks-beyond-envelope.json",
];

// Recursively sort object keys (arrays keep their order — order is
// semantic there, e.g. `blocking_reasons`) so a compact re-serialization is
// comparable byte-for-byte regardless of whether the source used
// `to_string` (compact) or `to_string_pretty` (indented). This is a
// canonical-form comparison, not a tolerant/semantic diff: any actual value
// difference, however small, still fails the comparison.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalize(value[key]);
    return sorted;
  }
  return value;
}

function canonicalJson(rawText) {
  return JSON.stringify(canonicalize(JSON.parse(rawText)));
}

function runCli(fixtureRelPath) {
  return execFileSync(
    "cargo",
    ["run", "-q", "-p", "hc-cli", "--locked", "--", "estimate", "--config", fixtureRelPath],
    { cwd: root, encoding: "utf8" },
  );
}

async function runWasm(fixtureRawText) {
  const glueUrl = pathToFileURL(
    path.join(root, "site", "vendor", "tinyzkp-estimate", "tinyzkp-estimate.js"),
  ).href;
  const wasmUrl = pathToFileURL(
    path.join(root, "site", "vendor", "tinyzkp-estimate", "tinyzkp-estimate_bg.wasm"),
  ).href;
  const { initSync, estimate_json: estimateJson } = await import(glueUrl);
  const { default: wasmModule } = await import(wasmUrl);
  initSync({ module: wasmModule });
  return estimateJson(fixtureRawText);
}

async function main() {
  let mismatches = 0;

  for (const fixtureRelPath of FIXTURES) {
    const fixturePath = path.join(root, fixtureRelPath);
    const fixtureRawText = readFileSync(fixturePath, "utf8");

    const cliOutput = runCli(fixtureRelPath);
    const wasmOutput = await runWasm(fixtureRawText);

    const cliCanonical = canonicalJson(cliOutput);
    const wasmCanonical = canonicalJson(wasmOutput);

    if (cliCanonical !== wasmCanonical) {
      mismatches += 1;
      console.error(`PARITY MISMATCH: ${fixtureRelPath}`);
      console.error("--- native hc-cli output ---");
      console.error(cliOutput);
      console.error("--- committed wasm estimate_json output ---");
      console.error(wasmOutput);
    } else {
      console.log(`PASS parity (hc-cli == committed wasm): ${fixtureRelPath}`);
    }
  }

  if (mismatches > 0) {
    console.error(
      `FAIL: ${mismatches} of ${FIXTURES.length} fixture(s) diverged between hc-cli and ` +
        "site/vendor/tinyzkp-estimate/tinyzkp-estimate_bg.wasm. Rebuild and recommit the " +
        "vendored wasm (see crates/hc-wasm/build.sh) so it matches the current crates/hc-plonky3 source.",
    );
    process.exit(1);
  }

  console.log(
    `PASS hc-cli <-> committed wasm behavioral parity (${FIXTURES.length} fixtures, byte-identical canonical JSON)`,
  );
}

await main();
