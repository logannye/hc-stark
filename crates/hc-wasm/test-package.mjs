import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

const packageDir = process.env.TINYZKP_WASM_OUT_DIR
  ? resolve(process.env.TINYZKP_WASM_OUT_DIR)
  : resolve(new URL("./pkg", import.meta.url).pathname);
const modulePath = pathToFileURL(resolve(packageDir, "tinyzkp-verify.js")).href;
const { default: init, verify_bundle: verifyBundle, version } = await import(modulePath);
const wasm = await readFile(resolve(packageDir, "tinyzkp-verify_bg.wasm"));
await init({ module_or_path: wasm });

const fixtureUrl = new URL(
  "../../test-vectors/plonky3/fibonacci-16.bundle.json",
  import.meta.url,
);
const fixture = JSON.parse(await readFile(fixtureUrl, "utf8"));
const accepted = verifyBundle(JSON.stringify(fixture));
if (accepted.ok !== true) {
  throw new Error(`golden ProofBundleV1 was rejected: ${accepted.error}`);
}

const last = fixture.proof_digest_hex.at(-1);
fixture.proof_digest_hex = `${fixture.proof_digest_hex.slice(0, -1)}${last === "0" ? "1" : "0"}`;
const rejected = verifyBundle(JSON.stringify(fixture));
if (rejected.ok !== false || !rejected.error) {
  throw new Error("mutated ProofBundleV1 was accepted");
}

if (!version().includes("tinyzkp-p3-goldilocks-v1:0.6.1")) {
  throw new Error("WASM package release identity is incomplete");
}

console.log("PASS @tinyzkp/verify golden bundle and mutation smoke");
