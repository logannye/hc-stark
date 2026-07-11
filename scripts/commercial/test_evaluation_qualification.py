import copy
import json
from pathlib import Path
import stat

import pytest

import evidence_common
import evaluation_qualification as qualification
from evidence_common import EvidenceError, canonical_bytes


ROOT = Path(__file__).resolve().parents[2]
COMPATIBILITY = ROOT / "release" / "plonky3-compatibility-v1.json"


def request(*, evidence_kind="measured_rss"):
    memory = {
        "evidence_kind": evidence_kind,
        "current_peak_rss_bytes": 3_221_225_472,
        "oom_limit_bytes": None,
        "target_resident_bytes": 2_147_483_648,
        "available_scratch_bytes": 107_374_182_400,
        "scratch_medium": "local_nvme",
    }
    if evidence_kind == "oom":
        memory["current_peak_rss_bytes"] = None
        memory["oom_limit_bytes"] = 17_179_869_184
    return {
        "schema_version": qualification.INPUT_SCHEMA,
        "application_id": "eval_0123456789abcdef",
        "reviewed_at": "2026-07-10T20:00:00Z",
        "reviewer_id": "operator-01",
        "compatibility": {
            "profile": qualification.PROFILE,
            "plonky3_version": qualification.PLONKY3_VERSION,
            "expected_verifier": qualification.VERIFIER,
        },
        "workload": {
            "workload_id": "partner_poseidon_air",
            "description": "Partner Poseidon2 AIR with a public deterministic generator",
            "revision": "a" * 40,
            "logical_rows": 1_048_576,
            "generator_kind": "deterministic_non_sensitive",
            "generator_reference": "https://github.com/example/partner/tree/"
            + "a" * 40,
            "generator_sha256": "b" * 64,
        },
        "memory_constraint": memory,
        "owners": {
            "technical_owner_confirmed": True,
            "budget_owner_confirmed": True,
            "decision_by": "2026-08-31",
        },
        "data_boundary": dict(qualification.SAFE_DATA_BOUNDARY),
    }


def write_json(path, value, *, canonical=False):
    path.write_bytes(
        canonical_bytes(value) if canonical else json.dumps(value).encode()
    )
    path.chmod(0o600)


@pytest.mark.parametrize("evidence_kind", ["measured_rss", "oom"])
def test_issue_and_verify_canonical_qualification(evidence_kind, tmp_path):
    input_path = tmp_path / "qualification-input.json"
    output_path = tmp_path / "qualification.json"
    write_json(input_path, request(evidence_kind=evidence_kind))

    result = qualification.issue(input_path, output_path, COMPATIBILITY)
    evidence = json.loads(output_path.read_text())

    assert result["status"] == "qualified"
    assert result["network_accessed"] is False
    assert result["commands_executed"] is False
    assert output_path.read_bytes() == canonical_bytes(evidence)
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    assert (
        qualification.verify(output_path, input_path, COMPATIBILITY)["evidence_sha256"]
        == result["evidence_sha256"]
    )
    assert (
        evidence["memory_constraint"]["qualifying_basis"]
        == {
            "measured_rss": "measured_rss_at_least_1_5x_target",
            "oom": "numeric_oom_at_or_above_target",
        }[evidence_kind]
    )


def test_rejects_sub_1_5x_measured_gap_and_unnumbered_oom(tmp_path):
    payload = request()
    payload["memory_constraint"]["current_peak_rss_bytes"] = 3_221_225_471
    raw = json.dumps(payload).encode()
    with pytest.raises(EvidenceError, match="at least 1.5x"):
        qualification.build_evidence(
            payload, raw, qualification.compatibility_identity(COMPATIBILITY)
        )

    payload = request(evidence_kind="oom")
    payload["memory_constraint"]["oom_limit_bytes"] = None
    with pytest.raises(EvidenceError, match="oom_limit_bytes"):
        qualification.build_evidence(
            payload,
            json.dumps(payload).encode(),
            qualification.compatibility_identity(COMPATIBILITY),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["compatibility"].update(profile="other"), "profile"),
        (
            lambda value: value["compatibility"].update(expected_verifier="custom"),
            "verifier",
        ),
        (
            lambda value: value["workload"].update(generator_kind="private_witness"),
            "generator_kind",
        ),
        (
            lambda value: value["workload"].update(revision="main"),
            "full lowercase Git commit",
        ),
        (
            lambda value: value["owners"].update(budget_owner_confirmed=False),
            "budget_owner",
        ),
        (
            lambda value: value["owners"].update(decision_by="2026-07-09"),
            "cannot precede",
        ),
        (
            lambda value: value["data_boundary"].update(witness_transfer_allowed=True),
            "data_boundary",
        ),
    ],
)
def test_rejects_unsupported_or_unqualified_inputs(mutation, message):
    payload = request()
    mutation(payload)
    with pytest.raises(EvidenceError, match=message):
        qualification.build_evidence(
            payload,
            json.dumps(payload).encode(),
            qualification.compatibility_identity(COMPATIBILITY),
        )


def test_verification_rejects_mutation_noncanonical_json_and_profile_skew(tmp_path):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "evidence.json"
    write_json(input_path, request())
    qualification.issue(input_path, output_path, COMPATIBILITY)

    payload = json.loads(output_path.read_text())
    payload["memory_constraint"]["observed_to_target_milli_ratio"] += 1
    write_json(output_path, payload, canonical=True)
    with pytest.raises(EvidenceError, match="milli_ratio"):
        qualification.verify(output_path, input_path, COMPATIBILITY)

    qualification.issue(input_path, output_path, COMPATIBILITY)
    payload = json.loads(output_path.read_text())
    output_path.write_text(json.dumps(payload, indent=2))
    with pytest.raises(EvidenceError, match="not canonical"):
        qualification.verify(output_path, input_path, COMPATIBILITY)

    qualification.issue(input_path, output_path, COMPATIBILITY)
    compatibility = json.loads(COMPATIBILITY.read_text())
    compatibility["known_limits"] = copy.deepcopy(compatibility["known_limits"]) + [
        "changed"
    ]
    changed = tmp_path / "compatibility.json"
    write_json(changed, compatibility)
    with pytest.raises(EvidenceError, match="different compatibility manifest"):
        qualification.verify(output_path, input_path, changed)


def test_compatibility_manifest_rejects_any_unpinned_plonky3_crate(tmp_path):
    compatibility = json.loads(COMPATIBILITY.read_text())
    next(
        crate
        for crate in compatibility["pinned_crates"]
        if crate["name"] == "p3-matrix"
    )["version"] = "0.6.2"
    changed = tmp_path / "compatibility.json"
    write_json(changed, compatibility)
    with pytest.raises(EvidenceError, match="must equal 0.6.1"):
        qualification.compatibility_identity(changed)


@pytest.mark.parametrize("field", ["permutation_rng", "poseidon2_trace_rng"])
def test_compatibility_manifest_rejects_rng_profile_skew(tmp_path, field):
    compatibility = json.loads(COMPATIBILITY.read_text())
    compatibility["configuration"][field] = "rand::rngs::StdRng"
    changed = tmp_path / "compatibility.json"
    write_json(changed, compatibility)
    with pytest.raises(EvidenceError, match="unsupported Plonky3 compatibility profile"):
        qualification.compatibility_identity(changed)


def test_strict_loader_rejects_duplicate_input_keys(tmp_path):
    input_path = tmp_path / "duplicate.json"
    input_path.write_text('{"schema_version":"one","schema_version":"two"}')
    input_path.chmod(0o600)
    with pytest.raises(EvidenceError, match="duplicate JSON key"):
        qualification.issue(input_path, tmp_path / "out.json", COMPATIBILITY)


def test_commercial_verifier_identifier_matches_frozen_acceptance_contract():
    acceptance = json.loads(
        (ROOT / "commercial" / "acceptance-matrix.template.json").read_text()
    )
    assert acceptance["workload"]["verifier_target"] == qualification.VERIFIER


def test_private_input_must_be_owner_only_and_owned_by_operator(tmp_path, monkeypatch):
    input_path = tmp_path / "input.json"
    write_json(input_path, request())
    input_path.chmod(0o640)
    with pytest.raises(EvidenceError, match="owner-only"):
        qualification.issue(input_path, tmp_path / "out.json", COMPATIBILITY)

    input_path.chmod(0o600)
    monkeypatch.setattr(
        evidence_common.os, "geteuid", lambda: input_path.stat().st_uid + 1
    )
    with pytest.raises(EvidenceError, match="owned by the current operator"):
        qualification.issue(input_path, tmp_path / "out.json", COMPATIBILITY)


def test_private_input_symlink_fails_closed(tmp_path):
    target = tmp_path / "target.json"
    linked = tmp_path / "linked.json"
    write_json(target, request())
    linked.symlink_to(target)
    with pytest.raises(EvidenceError, match="cannot read qualification input"):
        qualification.issue(linked, tmp_path / "out.json", COMPATIBILITY)


def test_cli_issue_and_verify_round_trip(tmp_path, capsys):
    input_path = tmp_path / "input.json"
    evidence_path = tmp_path / "evidence.json"
    write_json(input_path, request())
    assert (
        qualification.main(
            [
                "issue",
                "--input",
                str(input_path),
                "--output",
                str(evidence_path),
                "--compatibility-manifest",
                str(COMPATIBILITY),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "qualified"
    assert (
        qualification.main(
            [
                "verify",
                "--input",
                str(input_path),
                "--evidence",
                str(evidence_path),
                "--compatibility-manifest",
                str(COMPATIBILITY),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "qualified"
