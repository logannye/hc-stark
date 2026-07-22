import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import build_guard_owner_evidence as owner  # noqa: E402
import guard_launch_gate as gate  # noqa: E402


IDENTITY = {
    "guard_release": "tinyzkp-guard-v1",
    "guard_version": "0.1.0",
    "guard_source_sha": "a" * 40,
    "engine_source_sha": "b" * 40,
    "compatibility_profile": gate.PROFILE_ID,
}
WORKFLOW_SOURCE_SHA = "c" * 40
ENGINE_CLAIMS = {
    "backend_gate_status": "qualified",
    "engine_release_tag": "backend-v0.1.0",
    "official_verifier_acceptance": True,
    "proof_byte_equality": True,
    "resource_1m_target": True,
    "resource_16m_target": True,
    "fixed_host_matrix": True,
    "durable_recovery_matrix": True,
    "enospc_recovery": True,
    "fuzzing": True,
    "cli_smoke": True,
    "oci_smoke": True,
    "signed_artifacts": True,
    "checksums": True,
    "sbom": True,
    "provenance": True,
    "immutable_source_identity": True,
    "artifact_identity_bound": True,
    "engine_artifact_sha256": "1" * 64,
    "engine_oci_digest": "sha256:" + "2" * 64,
}
DECOMMISSION_CLAIMS = {
    **{
        field: 0
        for field in (
            "production_servers",
            "databases",
            "queues",
            "workers",
            "pagers",
            "monitoring_services",
            "alerting_services",
            "backup_jobs",
            "unused_r2_buckets",
            "customer_artifacts_pending_deletion",
            "active_oauth_apps",
            "active_legacy_credentials",
        )
    },
    "retired_hosts": [
        "api.tinyzkp.com",
        "mcp.tinyzkp.com",
        "webhook.tinyzkp.com",
    ],
    "retired_hosts_return_410": True,
    "writes_disabled": True,
    "jobs_disabled": True,
    "credentials_revoked": True,
    "records_retained": True,
    "observation_period_days_planned": 90,
}


def prepared_root(tmp_path: Path) -> tuple[Path, Path]:
    release = tmp_path / "release"
    release.mkdir()
    source = gate.load_json(gate.DEFAULT_SOURCE, "source")
    source["release_identity"] = copy.deepcopy(IDENTITY)
    # Tests must remain valid after any real evidence PR marks one or more
    # canonical gates passed. Build a synthetic all-blocked baseline instead
    # of inheriting mutable launch status from the checkout.
    source["gates"] = {
        name: {
            "status": "blocked",
            "reason_code": gate.BLOCKED_REASONS[name],
            "evidence": [],
        }
        for name in gate.REQUIRED_GATES
    }
    (release / "guard-launch-evidence-v2.json").write_bytes(
        gate.canonical_bytes(source)
    )
    claims = tmp_path / "claims.json"
    claims.write_bytes(gate.canonical_bytes(ENGINE_CLAIMS))
    return tmp_path, claims


def test_build_owns_wire_identity_expiry_and_semantics(tmp_path: Path) -> None:
    root, claims = prepared_root(tmp_path)
    output = root / "release/evidence/guard-launch-v2/engine.json"
    envelope = owner.build_envelope(
        root=root,
        gate_name="engine_release_ready",
        claims_path=claims,
        issued_at_value="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=output,
    )
    assert output.read_bytes() == gate.canonical_bytes(envelope)
    assert envelope["authorization_policy"] == gate.AUTHORIZATION_POLICY
    assert envelope["qualification_basis"] == gate.QUALIFICATION_BASIS
    assert envelope["release_identity"] == IDENTITY
    assert envelope["workflow_source_sha"] == WORKFLOW_SOURCE_SHA
    issued = datetime(2026, 7, 21, 12, tzinfo=timezone.utc)
    assert envelope["expires_at"] == (
        issued + timedelta(days=gate.GATE_POLICIES["engine_release_ready"][1])
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_attach_binds_exact_digests_signer_purpose_and_source_clock(
    tmp_path: Path,
) -> None:
    root, claims = prepared_root(tmp_path)
    output = root / "release/evidence/guard-launch-v2/engine.json"
    owner.build_envelope(
        root=root,
        gate_name="engine_release_ready",
        claims_path=claims,
        issued_at_value="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=output,
    )
    signature = output.with_name("engine.sigstore.json")
    signature.write_bytes(gate.canonical_bytes({"bundle": "test-only"}))
    source = owner.attach_envelope(
        root=root,
        gate_name="engine_release_ready",
        evidence=output,
        signature=signature,
    )
    record = source["gates"]["engine_release_ready"]
    assert source["evaluated_at"] == "2026-07-21T12:00:00Z"
    assert record["status"] == "passed"
    assert record["reason_code"] is None
    assert record["evidence"] == [
        {
            "path": "release/evidence/guard-launch-v2/engine.json",
            "sha256": gate.sha256_bytes(output.read_bytes()),
            "signature_path": (
                "release/evidence/guard-launch-v2/engine.sigstore.json"
            ),
            "signature_sha256": gate.sha256_bytes(signature.read_bytes()),
            "signer_id": owner.OWNER_SIGNER_ID,
            "purpose": gate.GATE_PURPOSES["engine_release_ready"],
        }
    ]


def test_owner_workflow_rejects_advisory_gate_and_untyped_claims(
    tmp_path: Path,
) -> None:
    root, claims = prepared_root(tmp_path)
    output = root / "release/evidence/guard-launch-v2/evidence.json"
    with pytest.raises(owner.EvidenceError, match="owner-verifiable"):
        owner.build_envelope(
            root=root,
            gate_name="three_external_workloads",
            claims_path=claims,
            issued_at_value="2026-07-21T12:00:00Z",
            workflow_source_sha=WORKFLOW_SOURCE_SHA,
            output=output,
        )

    with pytest.raises(owner.EvidenceError, match="workflow source SHA"):
        owner.build_envelope(
            root=root,
            gate_name="engine_release_ready",
            claims_path=claims,
            issued_at_value="2026-07-21T12:00:00Z",
            workflow_source_sha="main",
            output=output,
        )

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"fuzzing":true,"fuzzing":true}', encoding="utf-8")
    with pytest.raises(owner.EvidenceError, match="strict JSON"):
        owner.build_envelope(
            root=root,
            gate_name="engine_release_ready",
            claims_path=malformed,
            issued_at_value="2026-07-21T12:00:00Z",
            workflow_source_sha=WORKFLOW_SOURCE_SHA,
            output=output,
        )


def test_attach_rejects_policy_tampering_and_outside_paths(tmp_path: Path) -> None:
    root, claims = prepared_root(tmp_path)
    output = root / "release/evidence/guard-launch-v2/engine.json"
    envelope = owner.build_envelope(
        root=root,
        gate_name="engine_release_ready",
        claims_path=claims,
        issued_at_value="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=output,
    )
    envelope["qualification_basis"] = "outside_review"
    output.write_bytes(gate.canonical_bytes(envelope))
    signature = output.with_name("engine.sigstore.json")
    signature.write_text(json.dumps({"bundle": "test"}), encoding="utf-8")
    with pytest.raises(owner.EvidenceError, match="exact launch source"):
        owner.attach_envelope(
            root=root,
            gate_name="engine_release_ready",
            evidence=output,
            signature=signature,
        )

    with pytest.raises(owner.EvidenceError, match="outside the repository"):
        owner.build_envelope(
            root=root,
            gate_name="engine_release_ready",
            claims_path=claims,
            issued_at_value="2026-07-21T12:00:00Z",
            workflow_source_sha=WORKFLOW_SOURCE_SHA,
            output=tmp_path.parent / "outside.json",
        )


def test_point_in_time_decommission_and_immutable_engine_cannot_be_replaced(
    tmp_path: Path,
) -> None:
    root, engine_claims = prepared_root(tmp_path)
    decommission_claims = root / "decommission.json"
    decommission_claims.write_bytes(gate.canonical_bytes(DECOMMISSION_CLAIMS))
    first = root / "release/evidence/guard-launch-v2/decommission-first.json"
    owner.build_envelope(
        root=root,
        gate_name="hosted_infrastructure_decommissioned",
        claims_path=decommission_claims,
        issued_at_value="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=first,
    )
    first_signature = first.with_name("decommission-first.sigstore.json")
    first_signature.write_bytes(gate.canonical_bytes({"bundle": "first"}))
    owner.attach_envelope(
        root=root,
        gate_name="hosted_infrastructure_decommissioned",
        evidence=first,
        signature=first_signature,
    )

    assert gate.GATE_POLICIES["hosted_infrastructure_decommissioned"][1] == 3650
    with pytest.raises(owner.EvidenceError, match="mutable passed gate"):
        owner.build_envelope(
            root=root,
            gate_name="hosted_infrastructure_decommissioned",
            claims_path=decommission_claims,
            issued_at_value="2026-08-15T12:00:00Z",
            workflow_source_sha=WORKFLOW_SOURCE_SHA,
            output=(
                root
                / "release/evidence/guard-launch-v2/decommission-refresh.json"
            ),
        )

    engine = root / "release/evidence/guard-launch-v2/engine.json"
    owner.build_envelope(
        root=root,
        gate_name="engine_release_ready",
        claims_path=engine_claims,
        issued_at_value="2026-07-21T12:00:00Z",
        workflow_source_sha=WORKFLOW_SOURCE_SHA,
        output=engine,
    )
    engine_signature = engine.with_name("engine.sigstore.json")
    engine_signature.write_bytes(gate.canonical_bytes({"bundle": "engine"}))
    owner.attach_envelope(
        root=root,
        gate_name="engine_release_ready",
        evidence=engine,
        signature=engine_signature,
    )
    with pytest.raises(owner.EvidenceError, match="mutable passed gate"):
        owner.build_envelope(
            root=root,
            gate_name="engine_release_ready",
            claims_path=engine_claims,
            issued_at_value="2026-08-15T12:00:00Z",
            workflow_source_sha=WORKFLOW_SOURCE_SHA,
            output=root / "release/evidence/guard-launch-v2/engine-refresh.json",
        )


def test_only_live_merchant_smoke_is_a_refreshable_runtime_fact() -> None:
    passed = {
        "status": "passed",
        "reason_code": None,
        "evidence": [{"path": "existing"}],
    }
    assert owner._gate_can_receive_evidence(
        "merchant_live_owner_smoke_passed", passed
    )
    assert not owner._gate_can_receive_evidence(
        "hosted_infrastructure_decommissioned", passed
    )
    assert gate.MUTABLE_FACT_FRESH_GATES == {"merchant_live_owner_smoke_passed"}
