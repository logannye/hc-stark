import { readFile } from "node:fs/promises";

import init, {
  verify_bundle as verifyBundle,
  version,
} from "./pkg/tinyzkp-verify.js";

const wasm = await readFile(new URL("./pkg/tinyzkp-verify_bg.wasm", import.meta.url));
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
