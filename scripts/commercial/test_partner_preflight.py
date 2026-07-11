import json
from pathlib import Path

import pytest

from evidence_common import EvidenceError, canonical_bytes, sha256_bytes
import evaluation_qualification as qualification
import partner_preflight as preflight


ROOT = Path(__file__).resolve().parents[2]
COMPATIBILITY = ROOT / "release" / "plonky3-compatibility-v1.json"


def qualification_request():
    return {
        "schema_version": qualification.INPUT_SCHEMA,
        "application_id": "eval_0123456789abcdef",
        "reviewed_at": "2026-07-10T20:00:00Z",
        "reviewer_id": "operator-01",
        "compatibility": {
            "profile": preflight.PROFILE,
            "plonky3_version": preflight.PLONKY3_VERSION,
            "expected_verifier": preflight.VERIFIER,
        },
        "workload": {
            "workload_id": "partner_poseidon_air",
            "description": "Partner AIR",
            "revision": "a" * 40,
            "logical_rows": 1_048_576,
            "generator_kind": "deterministic_non_sensitive",
            "generator_reference": "public-generator",
            "generator_sha256": "b" * 64,
        },
        "memory_constraint": {
            "evidence_kind": "oom",
            "current_peak_rss_bytes": None,
            "oom_limit_bytes": 17_179_869_184,
            "target_resident_bytes": 2_147_483_648,
            "available_scratch_bytes": 107_374_182_400,
            "scratch_medium": "local_nvme",
        },
        "owners": {
            "technical_owner_confirmed": True,
            "budget_owner_confirmed": True,
            "decision_by": "2026-08-31",
        },
        "data_boundary": dict(qualification.SAFE_DATA_BOUNDARY),
    }


def workload_spec():
    return {
        "schema_version": preflight.WORKLOAD_SCHEMA,
        "workload_id": "partner_poseidon_air",
        "revision": "a" * 40,
        "logical_rows": 1_048_576,
        "generator_kind": "deterministic_non_sensitive",
        "generator_sha256": "b" * 64,
        "profile": preflight.PROFILE,
        "plonky3_version": preflight.PLONKY3_VERSION,
        "expected_verifier": preflight.VERIFIER,
        "data_boundary": dict(qualification.SAFE_DATA_BOUNDARY),
    }


def policy():
    return {
        "mode": "scratch",
        "max_resident_bytes": 2_147_483_648,
        "max_scratch_bytes": 85_899_345_920,
        "scratch_dir": "/var/lib/tinyzkp-evaluation/scratch",
        "max_threads": 8,
        "checkpoint_policy": "retain_on_failure",
    }


def estimate():
    return {
        "selected_mode": "scratch",
        "available_scratch_bytes": 107_374_182_400,
        "memory_selection_threshold_bytes": 1_503_238_553,
        "estimate": {
            "peak_resident_bytes": 1_900_000_000,
            "scratch_high_water_bytes": 80_000_000_000,
            "total_read_bytes": 200_000_000_000,
            "total_write_bytes": 160_000_000_000,
            "phases": [],
        },
    }


def write_json(path, value, *, canonical=False):
    path.write_bytes(
        canonical_bytes(value) if canonical else json.dumps(value).encode()
    )
    path.chmod(0o600)


def setup_inputs(tmp_path):
    qualification_input = tmp_path / "qualification-input.json"
    qualification_evidence = tmp_path / "qualification.json"
    workload = tmp_path / "workload.json"
    source = tmp_path / "partner-source.bundle"
    artifact = tmp_path / "partner-binary"
    resource_policy = tmp_path / "policy.json"
    resource_estimate = tmp_path / "estimate.json"
    write_json(qualification_input, qualification_request())
    qualification.issue(qualification_input, qualification_evidence, COMPATIBILITY)
    write_json(workload, workload_spec())
    source.write_bytes(b"git bundle source at revision " + b"c" * 40)
    artifact.write_bytes(b"ELF test fixture; commands must never execute")
    source.chmod(0o600)
    artifact.chmod(0o700)
    write_json(resource_policy, policy())
    write_json(resource_estimate, estimate())
    paths = {
        "qualification_input": qualification_input,
        "qualification": qualification_evidence,
        "workload_spec": workload,
        "adapter_source": source,
        "adapter_artifact": artifact,
        "resource_policy": resource_policy,
        "resource_estimate": resource_estimate,
    }
    digests = {
        "qualification_input_file_sha256": sha256_bytes(
            qualification_input.read_bytes()
        ),
        "qualification_evidence_sha256": sha256_bytes(
            qualification_evidence.read_bytes()
        ),
        "workload_spec_sha256": sha256_bytes(workload.read_bytes()),
        "adapter_source_sha256": sha256_bytes(source.read_bytes()),
        "adapter_artifact_sha256": sha256_bytes(artifact.read_bytes()),
        "resource_policy_sha256": sha256_bytes(resource_policy.read_bytes()),
        "resource_estimate_sha256": sha256_bytes(resource_estimate.read_bytes()),
    }
    request = {
        "schema_version": preflight.INPUT_SCHEMA,
        "preflight_id": "preflight_partner_001",
        "application_id": "eval_0123456789abcdef",
        "checked_at": "2026-07-10T21:00:00Z",
        "operator_id": "operator-01",
        "inputs": digests,
        "adapter": {
            "crate_name": "partner-adapter",
            "source_revision": "c" * 40,
            "api": "ResourceBoundedWorkloadV1",
            "artifact_kind": "statically_linked_partner_binary",
        },
        "commands": {
            "build": [
                "cargo",
                "build",
                "--locked",
                "--release",
                "-p",
                "partner-adapter",
            ],
            "conventional": ["partner-adapter", "benchmark", "--mode", "baseline"],
            "bounded": ["partner-adapter", "benchmark", "--mode", "bounded"],
            "verify": ["partner-adapter", "verify", "--official"],
        },
        "host": {
            "host_id": "fixed-host-01",
            "host_fingerprint_sha256": "d" * 64,
            "operating_system": "linux",
            "architecture": "x86_64",
            "logical_cpus": 8,
            "resident_capacity_bytes": 17_179_869_184,
            "available_scratch_bytes": 107_374_182_400,
            "scratch_medium": "local_nvme",
            "cgroup_v2": True,
        },
    }
    request_path = tmp_path / "preflight-input.json"
    write_json(request_path, request)
    paths["input"] = request_path
    return paths, request


def namespace(paths, **overrides):
    values = {
        **paths,
        "compatibility_manifest": COMPATIBILITY,
        "output": paths["input"].parent / "preflight.json",
        "evidence": paths["input"].parent / "preflight.json",
    }
    values.update(overrides)
    return type("Args", (), values)()


def test_issue_and_verify_binds_every_input_without_executing_commands(tmp_path):
    paths, _request = setup_inputs(tmp_path)
    marker = tmp_path / "must-not-exist"
    request_payload = json.loads(paths["input"].read_text())
    request_payload["commands"]["build"] = [str(marker), "--would-create-if-run"]
    write_json(paths["input"], request_payload)

    result = preflight.issue(namespace(paths))
    evidence = json.loads((tmp_path / "preflight.json").read_text())

    assert result["status"] == "preflight_passed"
    assert result["network_accessed"] is False
    assert result["commands_executed"] is False
    assert not marker.exists()
    assert (tmp_path / "preflight.json").read_bytes() == canonical_bytes(evidence)
    assert all(evidence["feasibility"].values())
    assert (
        preflight.verify(namespace(paths))["evidence_sha256"]
        == result["evidence_sha256"]
    )


def test_rejects_any_bound_input_digest_mismatch(tmp_path):
    paths, request = setup_inputs(tmp_path)
    request["inputs"]["adapter_artifact_sha256"] = "0" * 64
    write_json(paths["input"], request)
    with pytest.raises(EvidenceError, match="adapter_artifact_sha256"):
        preflight.issue(namespace(paths))


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda workload, policy, estimate, request: workload.update(
                profile="other"
            ),
            "unsupported profile",
        ),
        (
            lambda workload, policy, estimate, request: workload.update(
                revision="e" * 40
            ),
            "differs from qualification",
        ),
        (
            lambda workload, policy, estimate, request: workload[
                "data_boundary"
            ].update(witness_transfer_allowed=True),
            "unsafe",
        ),
        (
            lambda workload, policy, estimate, request: policy.update(mode="auto"),
            "mode must be scratch",
        ),
        (
            lambda workload, policy, estimate, request: policy.update(
                checkpoint_policy="disabled"
            ),
            "retain_on_failure",
        ),
        (
            lambda workload, policy, estimate, request: estimate["estimate"].update(
                peak_resident_bytes=3_000_000_000
            ),
            "infeasible",
        ),
        (
            lambda workload, policy, estimate, request: request["host"].update(
                available_scratch_bytes=1
            ),
            "infeasible",
        ),
        (
            lambda workload, policy, estimate, request: request["host"].update(
                cgroup_v2=False
            ),
            "cgroup_v2",
        ),
        (
            lambda workload, policy, estimate, request: request["adapter"].update(
                source_revision="main"
            ),
            "full lowercase Git commit",
        ),
        (
            lambda workload, policy, estimate, request: request.update(
                checked_at="2026-07-10T19:00:00Z"
            ),
            "cannot precede qualification",
        ),
        (
            lambda workload, policy, estimate, request: request["commands"].update(
                bounded=request["commands"]["conventional"]
            ),
            "must be distinct",
        ),
    ],
)
def test_fails_closed_on_profile_data_resource_host_or_command_skew(
    tmp_path, mutator, message
):
    paths, request = setup_inputs(tmp_path)
    workload = json.loads(paths["workload_spec"].read_text())
    resource_policy = json.loads(paths["resource_policy"].read_text())
    resource_estimate = json.loads(paths["resource_estimate"].read_text())
    mutator(workload, resource_policy, resource_estimate, request)
    write_json(paths["workload_spec"], workload)
    write_json(paths["resource_policy"], resource_policy)
    write_json(paths["resource_estimate"], resource_estimate)
    request["inputs"]["workload_spec_sha256"] = sha256_bytes(
        paths["workload_spec"].read_bytes()
    )
    request["inputs"]["resource_policy_sha256"] = sha256_bytes(
        paths["resource_policy"].read_bytes()
    )
    request["inputs"]["resource_estimate_sha256"] = sha256_bytes(
        paths["resource_estimate"].read_bytes()
    )
    write_json(paths["input"], request)
    with pytest.raises(EvidenceError, match=message):
        preflight.issue(namespace(paths))


def test_verify_detects_artifact_change_after_issue(tmp_path):
    paths, _request = setup_inputs(tmp_path)
    preflight.issue(namespace(paths))
    paths["adapter_artifact"].write_bytes(b"changed after preflight")
    with pytest.raises(EvidenceError, match="adapter_artifact_sha256"):
        preflight.verify(namespace(paths))


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda evidence: evidence["workload"].update(expected_verifier="custom"),
            "unsupported profile or verifier",
        ),
        (
            lambda evidence: evidence["workload"]["data_boundary"].update(
                customer_data_transfer_allowed=True
            ),
            "unsafe",
        ),
        (
            lambda evidence: evidence["adapter"].update(api="OtherApi"),
            "ResourceBoundedWorkloadV1",
        ),
        (
            lambda evidence: evidence["commands"].update(verify=[]),
            "argv array",
        ),
        (
            lambda evidence: evidence["resource_policy"].update(mode="memory"),
            "mode must be scratch",
        ),
        (
            lambda evidence: evidence["host"].update(cgroup_v2=False),
            "cgroup_v2",
        ),
        (
            lambda evidence: evidence["resource_estimate"]["estimate"].update(
                peak_resident_bytes=9_000_000_000
            ),
            "inconsistent or failed",
        ),
        (
            lambda evidence: evidence["bound_inputs"].update(
                adapter_source_sha256="not-a-digest"
            ),
            "lowercase SHA-256",
        ),
        (
            lambda evidence: evidence["feasibility"].update(
                commands_reviewed_not_executed=False
            ),
            "inconsistent or failed",
        ),
    ],
)
def test_public_shape_validator_deeply_rejects_nested_mutations(
    tmp_path, mutator, message
):
    paths, _request = setup_inputs(tmp_path)
    preflight.issue(namespace(paths))
    evidence = json.loads((tmp_path / "preflight.json").read_text())
    mutator(evidence)
    with pytest.raises(EvidenceError, match=message):
        preflight.validate_evidence(
            evidence, preflight.compatibility_identity(COMPATIBILITY)
        )


def test_noncanonical_qualification_cannot_enter_preflight(tmp_path):
    paths, _request = setup_inputs(tmp_path)
    payload = json.loads(paths["qualification"].read_text())
    paths["qualification"].write_text(json.dumps(payload, indent=2))
    request = json.loads(paths["input"].read_text())
    request["inputs"]["qualification_evidence_sha256"] = sha256_bytes(
        paths["qualification"].read_bytes()
    )
    write_json(paths["input"], request)
    with pytest.raises(EvidenceError, match="canonical JSON"):
        preflight.issue(namespace(paths))


def test_bound_source_and_artifact_must_be_owner_only(tmp_path):
    paths, _request = setup_inputs(tmp_path)
    paths["adapter_source"].chmod(0o644)
    with pytest.raises(EvidenceError, match="owner-only"):
        preflight.issue(namespace(paths))

    paths["adapter_source"].chmod(0o600)
    paths["adapter_artifact"].chmod(0o755)
    with pytest.raises(EvidenceError, match="owner-only"):
        preflight.issue(namespace(paths))


def test_cli_issue_and_verify_round_trip(tmp_path, capsys):
    paths, _request = setup_inputs(tmp_path)
    evidence = tmp_path / "preflight.json"
    common = [
        "--input",
        str(paths["input"]),
        "--qualification-input",
        str(paths["qualification_input"]),
        "--qualification",
        str(paths["qualification"]),
        "--workload-spec",
        str(paths["workload_spec"]),
        "--adapter-source",
        str(paths["adapter_source"]),
        "--adapter-artifact",
        str(paths["adapter_artifact"]),
        "--resource-policy",
        str(paths["resource_policy"]),
        "--resource-estimate",
        str(paths["resource_estimate"]),
        "--compatibility-manifest",
        str(COMPATIBILITY),
    ]
    assert preflight.main(["issue", *common, "--output", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "preflight_passed"
    assert preflight.main(["verify", "--evidence", str(evidence), *common]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "preflight_passed"
