"""Generated schema models. Do not edit by hand."""

from __future__ import annotations

from typing import Any, Literal, TypedDict, Union

RUST_SCHEMA_SET_SHA256 = "12900d249f6fb347d57e8f253d47b0fad816366575a7e7730a3bdc54beb38f62"

BenchmarkModeModel = Literal['baseline', 'bounded']

CheckpointPolicyModel = Literal['disabled', 'delete_on_success', 'retain_on_failure']

class InputGeneratorV1FibonacciModel(TypedDict):
    initial_a: int
    initial_b: int
    kind: Literal['fibonacci']

class InputGeneratorV1Poseidon2Model(TypedDict):
    kind: Literal['poseidon2']
    seed: int

class InputGeneratorV1DigestModel(TypedDict):
    blake3_hex: str
    kind: Literal['digest']

InputGeneratorV1Model = Union[InputGeneratorV1FibonacciModel, InputGeneratorV1Poseidon2Model, InputGeneratorV1DigestModel]

class PhaseEstimateV1Model(TypedDict):
    phase: str
    read_bytes: int
    write_bytes: int

class ReleaseProvenanceV1Model(TypedDict):
    dependency_profile: str
    proof_serializer: str
    prover_version: str
    release_sha: str
    verifier_version: str

class ResourceEstimateV1Model(TypedDict):
    peak_resident_bytes: int
    phases: list[PhaseEstimateV1Model]
    scratch_high_water_bytes: int
    total_read_bytes: int
    total_write_bytes: int

ResourceModeModel = Literal['auto', 'memory', 'scratch']

class ResourcePolicyV1Model(TypedDict):
    checkpoint_policy: CheckpointPolicyModel
    max_resident_bytes: int
    max_scratch_bytes: int
    max_threads: int
    mode: ResourceModeModel
    scratch_dir: str

WorkloadIdModel = Literal['fibonacci', 'poseidon2_goldilocks']

class WorkloadManifestV1Model(TypedDict):
    backend: str
    deterministic_seed: int
    expected_verifier: str
    input_generator: InputGeneratorV1Model
    logical_rows: int
    profile: str
    resource_policy: ResourcePolicyV1Model
    schema_version: int
    workload_id: WorkloadIdModel

class ProofBundleV1Model(TypedDict):
    manifest: WorkloadManifestV1Model
    manifest_digest_hex: str
    proof_base64url: str
    proof_digest_hex: str
    provenance: ReleaseProvenanceV1Model
    public_values: list[int]
    schema_version: int

class _BenchmarkReportV1ModelRequired(TypedDict):
    benchmark_session_id: str
    cgroup_peak_bytes: int
    cpu_seconds: float
    dependency_profile: str
    exact_command: list[str]
    exit_status: int
    hardware: str
    logical_cpu_count: int
    mode: BenchmarkModeModel
    normalized_manifest_digest_hex: str
    normalized_manifest_path: str
    operating_system: str
    peak_rss_bytes: int
    preflight_estimate: ResourceEstimateV1Model
    proof_size_bytes: int
    read_bytes: int
    release_sha: str
    schema_version: int
    scope: str
    scratch_high_water_bytes: int
    storage: str
    storage_device: str
    storage_is_nvme: bool
    storage_is_rotational: bool
    total_memory_bytes: int
    verification_succeeded: bool
    verification_time_ms: int
    wall_time_ms: int
    workload_manifest_digest_hex: str
    write_bytes: int

class BenchmarkReportV1Model(_BenchmarkReportV1ModelRequired, total=False):
    failure_diagnostic: Union[str, None]
