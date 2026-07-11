"""Local artifact SDK for TinyZKP's resource-bounded Plonky3 backend.

There are intentionally no hosted proving, polling, template, receipt, or
remote-verification APIs in this replacement package.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from blake3 import blake3

COMPATIBILITY_PROFILE = "tinyzkp-p3-goldilocks-v1"
PLONKY3_VERSION = "0.6.1"
MAX_MANIFEST_JSON_BYTES = 1024 * 1024
MAX_BUNDLE_JSON_BYTES = 96 * 1024 * 1024
MAX_REPORT_JSON_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1
GOLDILOCKS_MODULUS = 0xFFFF_FFFF_0000_0001
MIN_I64 = -(1 << 63)
MAX_AIR_NODES = 8192
MAX_AIR_CONSTRAINTS = 1024
MAX_TRACE_WIDTH = 256


class ArtifactError(ValueError):
    """Raised when an artifact is malformed, oversized, or incompatible."""


class AirBuilder:
    """Build the beta's declarative degree-3 AIR without executable callbacks."""

    def __init__(self, trace_width: int, public_value_count: int = 0) -> None:
        self.trace_width = trace_width
        self.public_value_count = public_value_count
        self.expressions: list[dict[str, Any]] = []
        self.constraints: list[dict[str, Any]] = []

    def _push(self, expression: dict[str, Any]) -> int:
        self.expressions.append(expression)
        return len(self.expressions) - 1

    def constant(self, value: int) -> int:
        return self._push({"op": "constant", "value": value})

    def current(self, column: int) -> int:
        return self._push({"op": "current", "column": column})

    def next(self, column: int) -> int:
        return self._push({"op": "next", "column": column})

    def public(self, index: int) -> int:
        return self._push({"op": "public", "index": index})

    def add(self, left: int, right: int) -> int:
        return self._push({"op": "add", "left": left, "right": right})

    def sub(self, left: int, right: int) -> int:
        return self._push({"op": "sub", "left": left, "right": right})

    def mul(self, left: int, right: int) -> int:
        return self._push({"op": "mul", "left": left, "right": right})

    def constrain(self, kind: Literal["transition", "first_row", "last_row"], expression: int) -> None:
        self.constraints.append({"kind": kind, "expression": expression})

    def build(self) -> dict[str, Any]:
        package = {
            "schema_version": 1,
            "backend": "plonky3",
            "profile": COMPATIBILITY_PROFILE,
            "field": "goldilocks",
            "expected_verifier": "p3_uni_stark_0.6.1",
            "trace_width": self.trace_width,
            "public_value_count": self.public_value_count,
            "expressions": list(self.expressions),
            "constraints": list(self.constraints),
        }
        validate_air_package(package)
        return package


def validate_air_package(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "backend", "profile", "field", "expected_verifier",
        "trace_width", "public_value_count", "expressions", "constraints",
    }:
        raise ArtifactError("AIR fields do not match AirPackageV1")
    width = value["trace_width"]
    public_count = value["public_value_count"]
    expressions = value["expressions"]
    constraints = value["constraints"]
    if (
        value["schema_version"] != 1
        or value["backend"] != "plonky3"
        or value["profile"] != COMPATIBILITY_PROFILE
        or value["field"] != "goldilocks"
        or value["expected_verifier"] != "p3_uni_stark_0.6.1"
        or not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= MAX_TRACE_WIDTH
        or not isinstance(public_count, int) or isinstance(public_count, bool) or not 0 <= public_count <= 1024
        or not isinstance(expressions, list) or not 1 <= len(expressions) <= MAX_AIR_NODES
        or not isinstance(constraints, list) or not 1 <= len(constraints) <= MAX_AIR_CONSTRAINTS
    ):
        raise ArtifactError("invalid AIR profile or bounds")
    degrees: list[int] = []
    for position, expression in enumerate(expressions):
        if not isinstance(expression, dict) or not isinstance(expression.get("op"), str):
            raise ArtifactError("invalid AIR expression")
        op = expression["op"]
        if op == "constant" and set(expression) == {"op", "value"}:
            item = expression["value"]
            degree = 0 if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < GOLDILOCKS_MODULUS else 4
        elif op in {"current", "next"} and set(expression) == {"op", "column"}:
            item = expression["column"]
            degree = 1 if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < width else 4
        elif op == "public" and set(expression) == {"op", "index"}:
            item = expression["index"]
            degree = 0 if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < public_count else 4
        elif op in {"add", "sub", "mul"} and set(expression) == {"op", "left", "right"}:
            left, right = expression["left"], expression["right"]
            if not all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item < position for item in (left, right)):
                raise ArtifactError("AIR graph references must point backward")
            degree = max(degrees[left], degrees[right]) if op != "mul" else degrees[left] + degrees[right]
        else:
            raise ArtifactError("unsupported AIR expression")
        if degree > 3:
            raise ArtifactError("AIR degree exceeds three")
        degrees.append(degree)
    for constraint in constraints:
        if (
            not isinstance(constraint, dict)
            or set(constraint) != {"kind", "expression"}
            or constraint["kind"] not in {"transition", "first_row", "last_row"}
            or not isinstance(constraint["expression"], int)
            or isinstance(constraint["expression"], bool)
            or not 0 <= constraint["expression"] < len(expressions)
        ):
            raise ArtifactError("invalid AIR constraint")
    if len(canonical_json_v1(value)) > 4 * 1024 * 1024:
        raise ArtifactError("AIR exceeds the 4 MiB limit")


@dataclass(frozen=True)
class ResourcePolicyV1:
    mode: Literal["auto", "memory", "scratch"]
    max_resident_bytes: int
    max_scratch_bytes: int
    scratch_dir: str
    max_threads: int
    checkpoint_policy: Literal[
        "disabled", "delete_on_success", "retain_on_failure"
    ]

    def validate(self) -> None:
        if self.mode not in {"auto", "memory", "scratch"}:
            raise ArtifactError("unknown resource mode")
        if not _is_u64(self.max_resident_bytes) or self.max_resident_bytes < 16 * 1024 * 1024:
            raise ArtifactError("resident cap must be at least 16 MiB")
        if (
            not _is_u64(self.max_scratch_bytes)
            or self.max_scratch_bytes == 0
            or not _is_positive_int(self.max_threads)
        ):
            raise ArtifactError("scratch cap and thread count must be positive")
        if not self.scratch_dir or ".." in Path(self.scratch_dir).parts:
            raise ArtifactError("unsafe scratch directory")
        if self.checkpoint_policy not in {
            "disabled",
            "delete_on_success",
            "retain_on_failure",
        }:
            raise ArtifactError("unknown checkpoint policy")


@dataclass(frozen=True)
class WorkloadManifestV1:
    schema_version: int
    workload_id: Literal["fibonacci", "poseidon2_goldilocks"]
    backend: str
    profile: str
    input_generator: dict[str, Any]
    logical_rows: int
    deterministic_seed: int
    resource_policy: ResourcePolicyV1
    expected_verifier: str

    @classmethod
    def fibonacci(
        cls,
        initial_a: int,
        initial_b: int,
        logical_rows: int,
        resource_policy: ResourcePolicyV1,
    ) -> WorkloadManifestV1:
        return cls(
            schema_version=1,
            workload_id="fibonacci",
            backend="plonky3",
            profile=COMPATIBILITY_PROFILE,
            input_generator={
                "kind": "fibonacci",
                "initial_a": initial_a,
                "initial_b": initial_b,
            },
            logical_rows=logical_rows,
            deterministic_seed=0,
            resource_policy=resource_policy,
            expected_verifier="p3_uni_stark_0.6.1",
        )

    @classmethod
    def poseidon2(
        cls, logical_rows: int, resource_policy: ResourcePolicyV1
    ) -> WorkloadManifestV1:
        return cls(
            schema_version=1,
            workload_id="poseidon2_goldilocks",
            backend="plonky3",
            profile=COMPATIBILITY_PROFILE,
            input_generator={"kind": "poseidon2", "seed": 0},
            logical_rows=logical_rows,
            deterministic_seed=0,
            resource_policy=resource_policy,
            expected_verifier="p3_uni_stark_0.6.1",
        )

    def validate(self) -> None:
        self.resource_policy.validate()
        if (
            self.schema_version != 1
            or self.backend != "plonky3"
            or self.profile != COMPATIBILITY_PROFILE
            or self.expected_verifier != "p3_uni_stark_0.6.1"
            or not _is_positive_int(self.logical_rows)
            or self.logical_rows <= 0
            or self.logical_rows > 1 << 30
            or self.logical_rows & (self.logical_rows - 1)
            or not _is_u64(self.deterministic_seed)
            or self.deterministic_seed != 0
        ):
            raise ArtifactError("invalid manifest profile or row count")
        expected_kind = (
            "fibonacci" if self.workload_id == "fibonacci" else "poseidon2"
        )
        if self.input_generator.get("kind") != expected_kind:
            raise ArtifactError("input generator does not match workload")
        expected_generator_keys = (
            {"kind", "initial_a", "initial_b"}
            if self.workload_id == "fibonacci"
            else {"kind", "seed"}
        )
        if set(self.input_generator) != expected_generator_keys:
            raise ArtifactError("input generator contains missing or unknown fields")
        for field in expected_generator_keys - {"kind"}:
            if not _is_u64(self.input_generator[field]):
                raise ArtifactError("input generator integer exceeds uint64")
        if self.workload_id == "fibonacci" and any(
            self.input_generator[field] >= GOLDILOCKS_MODULUS
            for field in ("initial_a", "initial_b")
        ):
            raise ArtifactError("Fibonacci inputs must be canonical Goldilocks elements")
        if self.workload_id == "poseidon2_goldilocks" and self.input_generator.get(
            "seed"
        ) != 0:
            raise ArtifactError("the frozen Poseidon2 generator uses seed zero")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def digest_hex(self) -> str:
        self.validate()
        return blake3(canonical_json_v1(self.to_dict())).hexdigest()


@dataclass(frozen=True)
class ProofBundleV1:
    schema_version: int
    manifest: WorkloadManifestV1
    manifest_digest_hex: str
    proof_base64url: str
    proof_digest_hex: str
    public_values: list[int]
    provenance: dict[str, Any]

    def validate_envelope(self) -> None:
        self.manifest.validate()
        if self.schema_version != 1:
            raise ArtifactError("unknown proof bundle version")
        if self.manifest_digest_hex != self.manifest.digest_hex():
            raise ArtifactError("manifest digest mismatch")
        proof = decode_base64url(self.proof_base64url)
        if len(proof) > 64 * 1024 * 1024:
            raise ArtifactError("proof exceeds the binary size limit")
        if blake3(proof).hexdigest() != self.proof_digest_hex:
            raise ArtifactError("proof digest mismatch")
        if set(self.provenance) != {
            "prover_version",
            "verifier_version",
            "release_sha",
            "dependency_profile",
            "proof_serializer",
        } or any(
            (
                self.provenance.get("prover_version") != PLONKY3_VERSION,
                self.provenance.get("verifier_version") != PLONKY3_VERSION,
                self.provenance.get("dependency_profile") != COMPATIBILITY_PROFILE,
                self.provenance.get("proof_serializer") != "postcard-1.1.3",
                not isinstance(self.provenance.get("release_sha"), str),
                not 0 < len(self.provenance.get("release_sha", "")) <= 128,
            )
        ):
            raise ArtifactError("proof provenance mismatch")
        if any(not _is_u64(value) for value in self.public_values):
            raise ArtifactError("public values must be uint64 integers")


@dataclass(frozen=True)
class PhaseEstimateV1:
    phase: str
    read_bytes: int
    write_bytes: int

    def validate(self) -> None:
        if not self.phase or not _is_nonnegative_int(self.read_bytes) or not _is_nonnegative_int(self.write_bytes):
            raise ArtifactError("invalid phase estimate")


@dataclass(frozen=True)
class ResourceEstimateV1:
    peak_resident_bytes: int
    scratch_high_water_bytes: int
    total_read_bytes: int
    total_write_bytes: int
    phases: list[PhaseEstimateV1]

    def validate(self) -> None:
        if (
            not _is_nonnegative_int(self.peak_resident_bytes)
            or self.peak_resident_bytes == 0
            or not _is_nonnegative_int(self.scratch_high_water_bytes)
            or self.scratch_high_water_bytes == 0
            or not _is_nonnegative_int(self.total_read_bytes)
            or not _is_nonnegative_int(self.total_write_bytes)
        ):
            raise ArtifactError("invalid resource estimate")
        for phase in self.phases:
            phase.validate()


@dataclass(frozen=True)
class BenchmarkReportV1:
    schema_version: int
    scope: str
    mode: Literal["baseline", "bounded"]
    benchmark_session_id: str
    hardware: str
    logical_cpu_count: int
    total_memory_bytes: int
    operating_system: str
    storage: str
    storage_device: str
    storage_is_rotational: bool
    storage_is_nvme: bool
    storage_total_bytes: int
    storage_available_bytes: int
    scratch_directory_mode: int
    scratch_owned_by_runner: bool
    release_sha: str
    dependency_profile: str
    exact_command: list[str]
    normalized_manifest_path: str
    workload_manifest_digest_hex: str
    normalized_manifest_digest_hex: str
    preflight_estimate: ResourceEstimateV1
    cpu_seconds: float
    wall_time_ms: int
    peak_rss_bytes: int
    cgroup_peak_bytes: int
    scratch_high_water_bytes: int
    read_bytes: int
    write_bytes: int
    proof_size_bytes: int
    verification_time_ms: int
    verification_succeeded: bool
    exit_status: int
    failure_diagnostic: str | None = None

    def validate(self) -> None:
        self.preflight_estimate.validate()
        if (
            self.schema_version != 1
            or self.scope != "full_pipeline"
            or self.mode not in {"baseline", "bounded"}
            or self.dependency_profile != COMPATIBILITY_PROFILE
            or len(self.benchmark_session_id) != 32
            or any(character not in "0123456789abcdef" for character in self.benchmark_session_id)
            or any(
                not isinstance(value, str) or not value
                for value in (
                    self.hardware,
                    self.operating_system,
                    self.storage,
                    self.storage_device,
                )
            )
            or not _is_u32(self.logical_cpu_count)
            or self.logical_cpu_count == 0
            or not _is_u64(self.total_memory_bytes)
            or self.total_memory_bytes == 0
            or not isinstance(self.storage_is_rotational, bool)
            or not isinstance(self.storage_is_nvme, bool)
            or not _is_u64(self.storage_total_bytes)
            or self.storage_total_bytes == 0
            or not _is_u64(self.storage_available_bytes)
            or self.storage_available_bytes == 0
            or self.storage_available_bytes > self.storage_total_bytes
            or not _is_u32(self.scratch_directory_mode)
            or self.scratch_directory_mode != 0o700
            or self.scratch_owned_by_runner is not True
            or self.verification_succeeded is not True
            or self.exit_status != 0
            or not self.normalized_manifest_path
            or not self.exact_command
            or any(not isinstance(item, str) or not item for item in self.exact_command)
            or any(
                not _is_nonnegative_int(value)
                for value in (
                    self.wall_time_ms, self.peak_rss_bytes, self.cgroup_peak_bytes,
                    self.scratch_high_water_bytes,
                    self.read_bytes, self.write_bytes, self.proof_size_bytes,
                    self.verification_time_ms,
                )
            )
            or isinstance(self.cpu_seconds, bool)
            or not isinstance(self.cpu_seconds, (int, float))
            or self.cpu_seconds < 0
            or self.wall_time_ms == 0
            or self.peak_rss_bytes == 0
            or self.cgroup_peak_bytes < self.peak_rss_bytes
            or self.proof_size_bytes == 0
            or any(
                len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
                for value in (
                    self.workload_manifest_digest_hex,
                    self.normalized_manifest_digest_hex,
                )
            )
            or self.failure_diagnostic is not None
            and (not isinstance(self.failure_diagnostic, str) or len(self.failure_diagnostic) > 4000)
        ):
            raise ArtifactError("invalid benchmark report")


class Cli:
    """Safe subprocess wrapper for the local `hc-cli` artifact commands."""

    def __init__(self, binary: str | Path = "hc-cli") -> None:
        self.binary = str(binary)

    def prove(self, manifest: str | Path, output: str | Path) -> None:
        self._run("plonky3", "prove", "--manifest", manifest, "--output", output)

    def validate_air(self, air: str | Path) -> None:
        self._run("plonky3", "validate-air", "--air", air)

    def pack_trace(
        self,
        air: str | Path,
        trace: str | Path,
        rows: int,
        output_dir: str | Path,
        chunk_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._run(
            "plonky3", "pack-trace", "--air", air, "--trace", trace,
            "--rows", str(rows), "--output-dir", output_dir,
            "--chunk-bytes", str(chunk_bytes),
        )

    def resume(self, checkpoint: str | Path, output: str | Path) -> None:
        self._run(
            "plonky3", "resume", "--checkpoint", checkpoint, "--output", output
        )

    def verify(self, bundle: str | Path) -> None:
        self._run("plonky3", "verify", "--bundle", bundle)

    def _run(self, *arguments: str | Path) -> None:
        subprocess.run(
            [self.binary, *(str(argument) for argument in arguments)],
            check=True,
            stdin=subprocess.DEVNULL,
        )


def canonical_json_v1(value: Any) -> bytes:
    _validate_canonical_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest_hex(value: Any) -> str:
    return blake3(canonical_json_v1(value)).hexdigest()


def load_manifest(path: str | Path) -> WorkloadManifestV1:
    raw = _load_json(path, MAX_MANIFEST_JSON_BYTES)
    try:
        policy = ResourcePolicyV1(**raw.pop("resource_policy"))
        manifest = WorkloadManifestV1(resource_policy=policy, **raw)
    except (KeyError, TypeError) as error:
        raise ArtifactError("manifest fields do not match WorkloadManifestV1") from error
    manifest.validate()
    return manifest


def load_bundle(path: str | Path) -> ProofBundleV1:
    raw = _load_json(path, MAX_BUNDLE_JSON_BYTES)
    try:
        manifest_raw = raw.pop("manifest")
        policy = ResourcePolicyV1(**manifest_raw.pop("resource_policy"))
        manifest = WorkloadManifestV1(resource_policy=policy, **manifest_raw)
        bundle = ProofBundleV1(manifest=manifest, **raw)
    except (KeyError, TypeError) as error:
        raise ArtifactError("bundle fields do not match ProofBundleV1") from error
    bundle.validate_envelope()
    return bundle


def load_report(path: str | Path) -> BenchmarkReportV1:
    raw = _load_json(path, MAX_REPORT_JSON_BYTES)
    try:
        estimate_raw = raw.pop("preflight_estimate")
        phase_values = estimate_raw.pop("phases")
        estimate = ResourceEstimateV1(
            phases=[PhaseEstimateV1(**phase) for phase in phase_values],
            **estimate_raw,
        )
        report = BenchmarkReportV1(preflight_estimate=estimate, **raw)
    except (KeyError, TypeError) as error:
        raise ArtifactError("report fields do not match BenchmarkReportV1") from error
    report.validate()
    return report


def decode_base64url(value: str) -> bytes:
    if not value or "=" in value:
        raise ArtifactError("proof must use unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
            raise ArtifactError("non-canonical base64url")
        return decoded
    except (ValueError, UnicodeError) as error:
        raise ArtifactError("malformed base64url") from error


def _validate_canonical_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not MIN_I64 <= value <= MAX_U64:
            raise ArtifactError("canonical artifact JSON integer is outside i64/u64")
        return
    if isinstance(value, float):
        raise ArtifactError("canonical artifact JSON forbids floating-point numbers")
    if isinstance(value, list):
        for item in value:
            _validate_canonical_value(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate_canonical_value(item)
        return
    raise ArtifactError("unsupported canonical JSON value")


def _is_nonnegative_int(value: Any) -> bool:
    return _is_u64(value)


def _is_u64(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_U64


def _is_u32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= (1 << 32) - 1


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _load_json(path: str | Path, limit: int) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > limit:
        raise ArtifactError(f"{path} exceeds the {limit} byte artifact limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ArtifactError("artifact root must be an object")
    return value
