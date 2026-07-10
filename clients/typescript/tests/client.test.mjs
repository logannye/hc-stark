import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ArtifactError,
  canonicalDigestHex,
  canonicalJsonV1,
  decodeBase64Url,
  fibonacciManifest,
  loadBundle,
  loadReport,
  manifestDigestHex,
  loadManifest,
  validateManifest,
} from "../dist/esm/client.js";

const policy = {
  mode: "scratch",
  max_resident_bytes: 128 * 1024 * 1024,
  max_scratch_bytes: 2 * 1024 * 1024 * 1024,
  scratch_dir: "/tmp/tinyzkp-test",
  max_threads: 1,
  checkpoint_policy: "retain_on_failure",
};

test("canonical JSON and BLAKE3 match the shared golden vector", () => {
  const value = { z: [3, { b: true, a: "value" }], a: 1 };
  assert.equal(
    new TextDecoder().decode(canonicalJsonV1(value)),
    '{"a":1,"z":[3,{"a":"value","b":true}]}',
  );
  assert.equal(
    canonicalDigestHex(value),
    "75cb2762f02e1cf0c67805150ce6179cf7f05e6eb28e5353d5923dcccbf7598c",
  );
});

test("manifest construction, validation, and digest are deterministic", () => {
  const manifest = fibonacciManifest(0, 1, 1024, policy);
  validateManifest(manifest);
  assert.match(manifestDigestHex(manifest), /^[0-9a-f]{64}$/);
  assert.equal(manifestDigestHex(manifest), manifestDigestHex(structuredClone(manifest)));
});

test("shared manifest vector matches the Rust digest", () => {
  const manifest = loadManifest(
    new URL("../../../test-vectors/plonky3/fibonacci-16.manifest.json", import.meta.url).pathname,
  );
  assert.equal(
    manifestDigestHex(manifest),
    "9d131602e27428ca290c5ca87d543d085873840e4dba22dd3d8074945e57efcd",
  );
});

test("full Goldilocks values load losslessly and match the Rust digest", () => {
  const manifest = loadManifest(
    new URL(
      "../../../test-vectors/plonky3/fibonacci-max-field.manifest.json",
      import.meta.url,
    ).pathname,
  );
  assert.equal(manifest.input_generator.kind, "fibonacci");
  assert.equal(typeof manifest.input_generator.initial_a, "bigint");
  assert.equal(manifest.input_generator.initial_a, 18446744069414584320n);
  assert.equal(
    manifestDigestHex(manifest),
    "d66d868441137e6db964add9d7e4a2164ca3a722c66e73cbf06c2a576efee653",
  );
  assert.equal(
    new TextDecoder().decode(canonicalJsonV1({ value: 18446744069414584320n })),
    '{"value":18446744069414584320}',
  );
  assert.throws(() => canonicalJsonV1({ value: 1n << 64n }), ArtifactError);
});

test("bundle public values remain lossless across canonical file loading", () => {
  const fixture = new URL(
    "../../../test-vectors/plonky3/fibonacci-16.bundle.json",
    import.meta.url,
  ).pathname;
  const source = loadBundle(fixture);
  source.public_values = [18446744069414584320n];
  const directory = mkdtempSync(join(tmpdir(), "tinyzkp-u64-bundle-"));
  const path = join(directory, "bundle.json");
  writeFileSync(path, canonicalJsonV1(source));

  const loaded = loadBundle(path);
  assert.equal(loaded.public_values[0], 18446744069414584320n);
});

test("shared bundle fixture rejects truncation, dependency skew, and unknown fields", () => {
  const fixture = new URL(
    "../../../test-vectors/plonky3/fibonacci-16.bundle.json",
    import.meta.url,
  ).pathname;
  const bundle = loadBundle(fixture);
  assert.equal(bundle.provenance.dependency_profile, "tinyzkp-p3-goldilocks-v1");

  const source = JSON.parse(readFileSync(fixture, "utf8"));
  const mutations = [
    { ...structuredClone(source), proof_base64url: source.proof_base64url.slice(0, -1) },
    {
      ...structuredClone(source),
      provenance: { ...source.provenance, dependency_profile: "unreviewed-profile" },
    },
    { ...structuredClone(source), unknown: true },
  ];
  for (const [index, mutation] of mutations.entries()) {
    const directory = mkdtempSync(join(tmpdir(), `tinyzkp-sdk-${index}-`));
    const path = join(directory, "bundle.json");
    writeFileSync(path, JSON.stringify(mutation));
    assert.throws(() => loadBundle(path), ArtifactError);
  }
});

test("shared report fixture rejects unknown fields", () => {
  const fixture = new URL(
    "../../../test-vectors/plonky3/benchmark-report-v1.json",
    import.meta.url,
  ).pathname;
  const report = loadReport(fixture);
  assert.equal(report.mode, "bounded");
  const mutated = { ...report, unbound_metric: 1 };
  const directory = mkdtempSync(join(tmpdir(), "tinyzkp-report-"));
  const path = join(directory, "report.json");
  writeFileSync(path, JSON.stringify(mutated));
  assert.throws(() => loadReport(path), ArtifactError);

  writeFileSync(path, JSON.stringify({ ...report, benchmark_session_id: "not-a-session" }));
  assert.throws(() => loadReport(path), ArtifactError);

  writeFileSync(
    path,
    readFileSync(fixture, "utf8").replace(
      '"total_memory_bytes": 17179869184',
      '"total_memory_bytes": 18446744073709551616',
    ),
  );
  assert.throws(() => loadReport(path), ArtifactError);

  writeFileSync(
    path,
    JSON.stringify({
      ...report,
      storage_available_bytes: 1000000000001,
      storage_total_bytes: 1000000000000,
    }),
  );
  assert.throws(() => loadReport(path), ArtifactError);

  writeFileSync(
    path,
    JSON.stringify({
      ...report,
      scratch_directory_mode: 0o755,
      scratch_owned_by_runner: false,
    }),
  );
  assert.throws(() => loadReport(path), ArtifactError);
});

test("unknown fields and non-power-of-two rows fail closed", () => {
  const manifest = fibonacciManifest(0, 1, 1024, policy);
  assert.throws(
    () => validateManifest({ ...manifest, unknown: true }),
    ArtifactError,
  );
  assert.throws(
    () => validateManifest({ ...manifest, logical_rows: 1000 }),
    ArtifactError,
  );
});

test("canonical base64url is enforced", () => {
  assert.deepEqual(Array.from(decodeBase64Url("AQID")), [1, 2, 3]);
  assert.throws(() => decodeBase64Url("AQID="), ArtifactError);
});
