"""Generated schema models. Do not edit by hand."""

from __future__ import annotations

from typing import Literal, TypedDict, Union

RUST_SCHEMA_SET_SHA256 = "b55ca8233029f4fac580d9790e8e7fad5f39c9fdfcd9bcb3cf9642b02219bc29"

AirConstraintKindV1Model = Literal['transition', 'first_row', 'last_row']

class AirConstraintV1Model(TypedDict):
    expression: int
    kind: AirConstraintKindV1Model

class AirExpressionV1Variant1Model(TypedDict):
    op: Literal['constant']
    value: int

class AirExpressionV1Variant2Model(TypedDict):
    column: int
    op: Literal['current']

class AirExpressionV1Variant3Model(TypedDict):
    column: int
    op: Literal['next']

class AirExpressionV1Variant4Model(TypedDict):
    index: int
    op: Literal['public']

class AirExpressionV1Variant5Model(TypedDict):
    left: int
    op: Literal['add']
    right: int

class AirExpressionV1Variant6Model(TypedDict):
    left: int
    op: Literal['sub']
    right: int

class AirExpressionV1Variant7Model(TypedDict):
    left: int
    op: Literal['mul']
    right: int

AirExpressionV1Model = Union[AirExpressionV1Variant1Model, AirExpressionV1Variant2Model, AirExpressionV1Variant3Model, AirExpressionV1Variant4Model, AirExpressionV1Variant5Model, AirExpressionV1Variant6Model, AirExpressionV1Variant7Model]

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

class TraceChunkV1Model(TypedDict):
    blake3_hex: str
    compressed_bytes: int
    index: int
    uncompressed_bytes: int

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
    scratch_directory_mode: int
    scratch_high_water_bytes: int
    scratch_owned_by_runner: bool
    storage: str
    storage_available_bytes: int
    storage_device: str
    storage_is_nvme: bool
    storage_is_rotational: bool
    storage_total_bytes: int
    total_memory_bytes: int
    verification_succeeded: bool
    verification_time_ms: int
    wall_time_ms: int
    workload_manifest_digest_hex: str
    write_bytes: int

class BenchmarkReportV1Model(_BenchmarkReportV1ModelRequired, total=False):
    failure_diagnostic: Union[str, None]

class AirPackageV1Model(TypedDict):
    backend: str
    constraints: list[AirConstraintV1Model]
    expected_verifier: str
    expressions: list[AirExpressionV1Model]
    field: str
    profile: str
    public_value_count: int
    schema_version: int
    trace_width: int

class TraceManifestV1Model(TypedDict):
    air_digest_hex: str
    chunk_uncompressed_bytes: int
    chunks: list[TraceChunkV1Model]
    compression: str
    field_encoding: str
    logical_rows: int
    schema_version: int
    trace_digest_hex: str
    trace_width: int
