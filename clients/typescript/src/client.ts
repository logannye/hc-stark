/** Local artifact SDK for TinyZKP's resource-bounded Plonky3 backend. */

import { blake3 } from "@noble/hashes/blake3";
import JSONbigFactory from "json-bigint";
import { readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import type {
  BenchmarkReportV1,
  ProofBundleV1,
  ResourcePolicyV1,
  UInt64,
  WorkloadManifestV1,
} from "./schema-models.js";

export type {
  BenchmarkMode,
  BenchmarkReportV1,
  CheckpointPolicy,
  InputGeneratorV1,
  PhaseEstimateV1,
  ProofBundleV1,
  ReleaseProvenanceV1,
  ResourceEstimateV1,
  ResourceMode,
  ResourcePolicyV1,
  UInt64,
  WorkloadId,
  WorkloadManifestV1,
} from "./schema-models.js";

export const COMPATIBILITY_PROFILE = "tinyzkp-p3-goldilocks-v1";
export const PLONKY3_VERSION = "0.6.1";
export const MAX_MANIFEST_JSON_BYTES = 1024 * 1024;
export const MAX_BUNDLE_JSON_BYTES = 96 * 1024 * 1024;
export const MAX_REPORT_JSON_BYTES = 1024 * 1024;
const MAX_U64 = (1n << 64n) - 1n;
const GOLDILOCKS_MODULUS = 0xffff_ffff_0000_0001n;
const MIN_I64 = -(1n << 63n);
const LOSSLESS_JSON = JSONbigFactory({
  useNativeBigInt: true,
  strict: true,
  protoAction: "error",
  constructorAction: "error",
});

export class ArtifactError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArtifactError";
  }
}

export function fibonacciManifest(
  initialA: UInt64,
  initialB: UInt64,
  logicalRows: number,
  resourcePolicy: ResourcePolicyV1,
): WorkloadManifestV1 {
  const manifest: WorkloadManifestV1 = {
    schema_version: 1,
    workload_id: "fibonacci",
    backend: "plonky3",
    profile: COMPATIBILITY_PROFILE,
    input_generator: {
      kind: "fibonacci",
      initial_a: initialA,
      initial_b: initialB,
    },
    logical_rows: logicalRows,
    deterministic_seed: 0,
    resource_policy: resourcePolicy,
    expected_verifier: "p3_uni_stark_0.6.1",
  };
  validateManifest(manifest);
  return manifest;
}

export function poseidon2Manifest(
  logicalRows: number,
  resourcePolicy: ResourcePolicyV1,
): WorkloadManifestV1 {
  const manifest: WorkloadManifestV1 = {
    schema_version: 1,
    workload_id: "poseidon2_goldilocks",
    backend: "plonky3",
    profile: COMPATIBILITY_PROFILE,
    input_generator: { kind: "poseidon2", seed: 0 },
    logical_rows: logicalRows,
    deterministic_seed: 0,
    resource_policy: resourcePolicy,
    expected_verifier: "p3_uni_stark_0.6.1",
  };
  validateManifest(manifest);
  return manifest;
}

export function canonicalJsonV1(value: unknown): Uint8Array {
  return new TextEncoder().encode(writeCanonical(value));
}

export function canonicalDigestHex(value: unknown): string {
  return hex(blake3(canonicalJsonV1(value)));
}

export function manifestDigestHex(manifest: WorkloadManifestV1): string {
  validateManifest(manifest);
  return canonicalDigestHex(manifest);
}

export function validateManifest(value: unknown): asserts value is WorkloadManifestV1 {
  const manifest = object(value, "manifest");
  exactKeys(manifest, [
    "schema_version",
    "workload_id",
    "backend",
    "profile",
    "input_generator",
    "logical_rows",
    "deterministic_seed",
    "resource_policy",
    "expected_verifier",
  ]);
  if (
    manifest.schema_version !== 1 ||
    manifest.backend !== "plonky3" ||
    manifest.profile !== COMPATIBILITY_PROFILE ||
    manifest.expected_verifier !== "p3_uni_stark_0.6.1" ||
    !u64Equals(manifest.deterministic_seed, 0n) ||
    !isPowerOfTwo(manifest.logical_rows, 1 << 30)
  ) {
    throw new ArtifactError("invalid manifest profile or row count");
  }
  validateResourcePolicy(manifest.resource_policy);
  const generator = object(manifest.input_generator, "input generator");
  if (manifest.workload_id === "fibonacci") {
    exactKeys(generator, ["kind", "initial_a", "initial_b"]);
    if (
      generator.kind !== "fibonacci" ||
      !isU64(generator.initial_a) ||
      !isU64(generator.initial_b) ||
      BigInt(generator.initial_a) >= GOLDILOCKS_MODULUS ||
      BigInt(generator.initial_b) >= GOLDILOCKS_MODULUS
    ) {
      throw new ArtifactError("invalid Fibonacci input generator");
    }
  } else if (manifest.workload_id === "poseidon2_goldilocks") {
    exactKeys(generator, ["kind", "seed"]);
    if (generator.kind !== "poseidon2" || !u64Equals(generator.seed, 0n)) {
      throw new ArtifactError("invalid Poseidon2 input generator");
    }
  } else {
    throw new ArtifactError("unknown workload");
  }
}

export function validateBundle(value: unknown): asserts value is ProofBundleV1 {
  const bundle = object(value, "proof bundle");
  exactKeys(bundle, [
    "schema_version",
    "manifest",
    "manifest_digest_hex",
    "proof_base64url",
    "proof_digest_hex",
    "public_values",
    "provenance",
  ]);
  if (bundle.schema_version !== 1) {
    throw new ArtifactError("unknown proof bundle version");
  }
  validateManifest(bundle.manifest);
  if (bundle.manifest_digest_hex !== manifestDigestHex(bundle.manifest)) {
    throw new ArtifactError("manifest digest mismatch");
  }
  if (typeof bundle.proof_base64url !== "string") {
    throw new ArtifactError("proof must be base64url text");
  }
  const proof = decodeBase64Url(bundle.proof_base64url);
  if (proof.length > 64 * 1024 * 1024 || bundle.proof_digest_hex !== hex(blake3(proof))) {
    throw new ArtifactError("proof size or digest mismatch");
  }
  if (!Array.isArray(bundle.public_values) || !bundle.public_values.every(isU64)) {
    throw new ArtifactError("public values must be canonical integers");
  }
  const provenance = object(bundle.provenance, "provenance");
  exactKeys(provenance, [
    "prover_version",
    "verifier_version",
    "release_sha",
    "dependency_profile",
    "proof_serializer",
  ]);
  if (
    provenance.prover_version !== PLONKY3_VERSION ||
    provenance.verifier_version !== PLONKY3_VERSION ||
    provenance.dependency_profile !== COMPATIBILITY_PROFILE ||
    provenance.proof_serializer !== "postcard-1.1.3" ||
    typeof provenance.release_sha !== "string" ||
    provenance.release_sha.length === 0 ||
    provenance.release_sha.length > 128
  ) {
    throw new ArtifactError("proof provenance mismatch");
  }
}

export function validateReport(value: unknown): asserts value is BenchmarkReportV1 {
  const report = object(value, "benchmark report");
  const required = [
    "schema_version", "scope", "mode", "benchmark_session_id", "hardware",
    "logical_cpu_count", "total_memory_bytes", "operating_system", "storage",
    "storage_device", "storage_is_rotational", "storage_is_nvme",
    "storage_total_bytes", "storage_available_bytes", "scratch_directory_mode",
    "scratch_owned_by_runner",
    "release_sha", "dependency_profile", "exact_command", "normalized_manifest_path",
    "workload_manifest_digest_hex", "normalized_manifest_digest_hex", "preflight_estimate",
    "cpu_seconds", "wall_time_ms", "peak_rss_bytes", "scratch_high_water_bytes",
    "cgroup_peak_bytes", "read_bytes", "write_bytes", "proof_size_bytes", "verification_time_ms",
    "verification_succeeded", "exit_status",
  ];
  const allowed = new Set([...required, "failure_diagnostic"]);
  if (
    required.some((key) => !(key in report)) ||
    Object.keys(report).some((key) => !allowed.has(key))
  ) {
    throw new ArtifactError("benchmark report fields do not match BenchmarkReportV1");
  }
  if (
    report.schema_version !== 1 ||
    report.scope !== "full_pipeline" ||
    (report.mode !== "baseline" && report.mode !== "bounded") ||
    typeof report.benchmark_session_id !== "string" ||
    !/^[0-9a-f]{32}$/.test(report.benchmark_session_id) ||
    typeof report.hardware !== "string" ||
    report.hardware.length === 0 ||
    !Number.isSafeInteger(report.logical_cpu_count) ||
    (report.logical_cpu_count as number) <= 0 ||
    (report.logical_cpu_count as number) > 0xffff_ffff ||
    !isPositiveU64(report.total_memory_bytes) ||
    typeof report.operating_system !== "string" ||
    report.operating_system.length === 0 ||
    typeof report.storage !== "string" ||
    report.storage.length === 0 ||
    typeof report.storage_device !== "string" ||
    report.storage_device.length === 0 ||
    typeof report.storage_is_rotational !== "boolean" ||
    typeof report.storage_is_nvme !== "boolean" ||
    !isPositiveU64(report.storage_total_bytes) ||
    !isPositiveU64(report.storage_available_bytes) ||
    BigInt(report.storage_available_bytes as UInt64) >
      BigInt(report.storage_total_bytes as UInt64) ||
    !Number.isSafeInteger(report.scratch_directory_mode) ||
    report.scratch_directory_mode !== 0o700 ||
    report.scratch_owned_by_runner !== true ||
    report.dependency_profile !== COMPATIBILITY_PROFILE ||
    report.verification_succeeded !== true ||
    report.exit_status !== 0 ||
    typeof report.normalized_manifest_path !== "string" ||
    report.normalized_manifest_path.length === 0 ||
    typeof report.workload_manifest_digest_hex !== "string" ||
    !/^[0-9a-f]{64}$/.test(report.workload_manifest_digest_hex) ||
    typeof report.normalized_manifest_digest_hex !== "string" ||
    !/^[0-9a-f]{64}$/.test(report.normalized_manifest_digest_hex)
  ) {
    throw new ArtifactError("invalid benchmark report");
  }
  const nonNegativeIntegers = [
    "wall_time_ms", "peak_rss_bytes", "cgroup_peak_bytes", "scratch_high_water_bytes", "read_bytes",
    "write_bytes", "proof_size_bytes", "verification_time_ms",
  ];
  if (
    !Array.isArray(report.exact_command) ||
    report.exact_command.length === 0 ||
    !report.exact_command.every((item) => typeof item === "string" && item.length > 0) ||
    nonNegativeIntegers.some((field) => !isU64(report[field])) ||
    BigInt(report.wall_time_ms as UInt64) === 0n ||
    BigInt(report.peak_rss_bytes as UInt64) === 0n ||
    BigInt(report.cgroup_peak_bytes as UInt64) < BigInt(report.peak_rss_bytes as UInt64) ||
    BigInt(report.proof_size_bytes as UInt64) === 0n ||
    typeof report.cpu_seconds !== "number" ||
    !Number.isFinite(report.cpu_seconds) ||
    report.cpu_seconds < 0 ||
    ("failure_diagnostic" in report &&
      report.failure_diagnostic !== null &&
      (typeof report.failure_diagnostic !== "string" || report.failure_diagnostic.length > 4000))
  ) {
    throw new ArtifactError("invalid benchmark metrics");
  }
  const estimate = object(report.preflight_estimate, "preflight estimate");
  exactKeys(estimate, [
    "peak_resident_bytes",
    "scratch_high_water_bytes",
    "total_read_bytes",
    "total_write_bytes",
    "phases",
  ]);
  if (
    !isPositiveU64(estimate.peak_resident_bytes) ||
    !isPositiveU64(estimate.scratch_high_water_bytes) ||
    !isU64(estimate.total_read_bytes) ||
    !isU64(estimate.total_write_bytes) ||
    !Array.isArray(estimate.phases)
  ) {
    throw new ArtifactError("invalid benchmark preflight estimate");
  }
  for (const value of estimate.phases) {
    const phase = object(value, "phase estimate");
    exactKeys(phase, ["phase", "read_bytes", "write_bytes"]);
    if (
      typeof phase.phase !== "string" ||
      phase.phase.length === 0 ||
      !isU64(phase.read_bytes) ||
      !isU64(phase.write_bytes)
    ) {
      throw new ArtifactError("invalid benchmark phase estimate");
    }
  }
}

export function loadManifest(path: string): WorkloadManifestV1 {
  const value: unknown = loadJson(path, MAX_MANIFEST_JSON_BYTES);
  validateManifest(value);
  return value;
}

export function loadBundle(path: string): ProofBundleV1 {
  const value: unknown = loadJson(path, MAX_BUNDLE_JSON_BYTES);
  validateBundle(value);
  return value;
}

export function loadReport(path: string): BenchmarkReportV1 {
  const value: unknown = loadJson(path, MAX_REPORT_JSON_BYTES);
  validateReport(value);
  return value;
}

export function decodeBase64Url(value: string): Uint8Array {
  if (!value || value.includes("=") || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new ArtifactError("proof must use canonical unpadded base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new ArtifactError("non-canonical base64url");
  }
  return decoded;
}

export class Cli {
  constructor(public readonly binary = "hc-cli") {}

  prove(manifest: string, output: string): void {
    this.run(["plonky3", "prove", "--manifest", manifest, "--output", output]);
  }

  resume(checkpoint: string, output: string): void {
    this.run(["plonky3", "resume", "--checkpoint", checkpoint, "--output", output]);
  }

  verify(bundle: string): void {
    this.run(["plonky3", "verify", "--bundle", bundle]);
  }

  private run(arguments_: string[]): void {
    const result = spawnSync(this.binary, arguments_, { stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new ArtifactError(`hc-cli exited with status ${String(result.status)}`);
    }
  }
}

function validateResourcePolicy(value: unknown): asserts value is ResourcePolicyV1 {
  const policy = object(value, "resource policy");
  exactKeys(policy, [
    "mode",
    "max_resident_bytes",
    "max_scratch_bytes",
    "scratch_dir",
    "max_threads",
    "checkpoint_policy",
  ]);
  if (
    !["auto", "memory", "scratch"].includes(String(policy.mode)) ||
    !isU64AtLeast(policy.max_resident_bytes, 16n * 1024n * 1024n) ||
    !isPositiveU64(policy.max_scratch_bytes) ||
    !Number.isSafeInteger(policy.max_threads) ||
    (policy.max_threads as number) <= 0 ||
    typeof policy.scratch_dir !== "string" ||
    policy.scratch_dir.length === 0 ||
    policy.scratch_dir.split(/[\\/]/).includes("..") ||
    !["disabled", "delete_on_success", "retain_on_failure"].includes(
      String(policy.checkpoint_policy),
    )
  ) {
    throw new ArtifactError("invalid resource policy");
  }
}

function writeCanonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ArtifactError("canonical artifact JSON accepts only safe integers");
    }
    return String(value);
  }
  if (typeof value === "bigint") {
    if (value < MIN_I64 || value > MAX_U64) {
      throw new ArtifactError("canonical artifact JSON integer is outside i64/u64");
    }
    return value.toString(10);
  }
  if (Array.isArray(value)) return `[${value.map(writeCanonical).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${writeCanonical(item)}`)
      .join(",")}}`;
  }
  throw new ArtifactError("unsupported canonical JSON value");
}

function loadJson(path: string, limit: number): unknown {
  const size = statSync(path).size;
  if (size > limit) throw new ArtifactError(`${path} exceeds the ${limit} byte limit`);
  return LOSSLESS_JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ArtifactError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new ArtifactError("artifact contains missing or unknown fields");
  }
}

function isPowerOfTwo(value: unknown, maximum: number): value is UInt64 {
  if (!isU64(value)) {
    return false;
  }
  const integer = typeof value === "bigint" ? value : BigInt(value);
  if (integer === 0n || integer > BigInt(maximum)) return false;
  const exponent = Math.log2(Number(integer));
  return Number.isInteger(exponent);
}

function isU64(value: unknown): value is UInt64 {
  return (
    (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ||
    (typeof value === "bigint" && value >= 0n && value <= MAX_U64)
  );
}

function isPositiveU64(value: unknown): value is UInt64 {
  return isU64(value) && (typeof value === "bigint" ? value > 0n : value > 0);
}

function isU64AtLeast(value: unknown, minimum: bigint): value is UInt64 {
  return isU64(value) && BigInt(value) >= minimum;
}

function u64Equals(value: unknown, expected: bigint): boolean {
  return isU64(value) && BigInt(value) === expected;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
