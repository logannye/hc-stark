import hashlib
import json
import os
from pathlib import Path

import pytest

import public_beta_gate


def fixture_root(tmp_path: Path) -> tuple[Path, dict]:
    required = ["clean_merged_ci", "official_verifier_equivalence"]
    release = tmp_path / "release"
    release.mkdir()
    (release / "release-channels-v1.json").write_text(
        json.dumps(
            {"channels": {"public_beta": {"required_gate_ids": required}}}
        ),
        encoding="utf-8",
    )
    artifacts = {
        "clean_merged_ci": {
            "schema_version": "public-beta-clean-ci-v1",
            "status": "passed",
            "release_sha": "a" * 40,
            "branch": "main",
            "source_clean": True,
            "merged_source": True,
            "candidate_workflow_conclusion": "success",
            "candidate_workflow_run_id": 123,
            "required_checks": [
                {"name": f"check-{index}", "status": "success"}
                for index in range(4)
            ],
        },
        "official_verifier_equivalence": {
            "schema_version": "public-beta-verifier-equivalence-v1",
            "status": "passed",
            "release_sha": "a" * 40,
            "workloads": {
                workload: {
                    "official_verification": True,
                    "proof_sha256_by_mode": {
                        mode: str(index + 1) * 64
                        for mode in ("memory", "scratch", "uninterrupted", "resumed")
                    },
                }
                for index, workload in enumerate(
                    ("fibonacci", "poseidon2", "customer_cubic8")
                )
            },
        },
    }
    references = {}
    for gate, value in artifacts.items():
        artifact = tmp_path / f"{gate}.json"
        artifact.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(artifact, 0o600)
        references[gate] = [
            {
                "path": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ]
    evidence = {
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": "a" * 40,
        "gates": references,
    }
    return tmp_path, evidence


def test_complete_hash_bound_evidence_is_ready(tmp_path):
    root, evidence = fixture_root(tmp_path)
    path = root / "manifest.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    report = public_beta_gate.audit(path, root=root, expected_sha="a" * 40)
    assert report["status"] == "ready"
    assert not report["failures"]


def test_missing_gate_and_digest_mismatch_fail_closed(tmp_path):
    root, evidence = fixture_root(tmp_path)
    evidence["gates"].pop("official_verifier_equivalence")
    evidence["gates"]["clean_merged_ci"][0]["sha256"] = "0" * 64
    path = root / "manifest.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    report = public_beta_gate.audit(path, root=root, expected_sha="b" * 40)
    assert report["status"] == "blocked"
    assert any("gate set" in failure for failure in report["failures"])
    assert any("digest mismatch" in failure for failure in report["failures"])
    assert any("candidate" in failure for failure in report["failures"])


def test_generic_passing_json_cannot_satisfy_a_gate(tmp_path):
    root, evidence = fixture_root(tmp_path)
    artifact = root / "generic.json"
    artifact.write_text(
        json.dumps({"status": "passed", "release_sha": "a" * 40}),
        encoding="utf-8",
    )
    os.chmod(artifact, 0o600)
    evidence["gates"]["clean_merged_ci"] = [
        {
            "path": artifact.name,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }
    ]
    path = root / "manifest.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    report = public_beta_gate.audit(path, root=root, expected_sha="a" * 40)
    assert report["status"] == "blocked"
    assert any("clean_merged_ci" in failure for failure in report["failures"])


def test_every_public_beta_gate_has_a_dedicated_validator():
    required = json.loads(public_beta_gate.CHANNELS.read_text(encoding="utf-8"))[
        "channels"
    ]["public_beta"]["required_gate_ids"]
    registered = set(public_beta_gate.GATE_VALIDATORS) | {
        "fixed_host_1m",
        "fixed_host_16m",
    }
    assert set(required) == registered


def test_fixed_host_semantic_validator_module_loads():
    module = public_beta_gate.load_module(
        "public_beta_gate_test_fixed_host",
        public_beta_gate.ROOT
        / "scripts"
        / "benchmark"
        / "run_fixed_host_release_matrix.py",
    )
    assert {entry.entry_id for entry in module.MATRIX} == {
        "fibonacci_1m",
        "poseidon2_1m",
        "fibonacci_16m",
        "poseidon2_16m",
    }


def fault_cases():
    values = []
    for case_id, outcome in public_beta_gate.REQUIRED_FAULT_OUTCOMES.items():
        value = {"id": case_id, "status": "passed", "outcome": outcome}
        if outcome == "completed_verified":
            value.update(
                {
                    "official_verification": True,
                    "settlement_count": 1,
                    "charged_millicredits": 1,
                    "residual_reservation_released": True,
                }
            )
        else:
            value.update(
                {"charged_millicredits": 0, "reservation_released": True}
            )
        if outcome == "stale_rejected":
            value["stale_completion_rejected"] = True
        values.append(value)
    return values


def test_fault_semantics_distinguish_recovery_from_platform_failure():
    cases = fault_cases()
    public_beta_gate.validate_fault_cases(cases)
    next(item for item in cases if item["id"] == "disk_full")[
        "charged_millicredits"
    ] = 1
    with pytest.raises(ValueError, match="retained a charge"):
        public_beta_gate.validate_fault_cases(cases)


def test_fault_semantics_require_one_verified_settlement_after_resume():
    cases = fault_cases()
    next(item for item in cases if item["id"] == "sigterm_resume")[
        "settlement_count"
    ] = 2
    with pytest.raises(ValueError, match="settled once"):
        public_beta_gate.validate_fault_cases(cases)
