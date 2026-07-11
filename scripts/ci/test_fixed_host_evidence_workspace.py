from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil

import pytest

import fixed_host_backup_evidence as backup
import fixed_host_evidence_workspace as workspace
import installer_drill_evidence as installer
from test_fixed_host_backup_evidence import (
    DEPLOYMENT,
    HOST,
    NOW,
    RELEASE,
    RUN_ID,
    build_bundle,
)


def test_installer_scaffold_is_complete_pending_and_owner_only(tmp_path: Path):
    root = tmp_path / "installer-workspace"
    report = workspace.scaffold_installer(
        root,
        release_sha=RELEASE,
        host_identity_sha256=HOST,
        deployment_id=DEPLOYMENT,
        run_id=RUN_ID,
    )

    assert report["status"] == "pending_privileged_execution"
    assert report["case_count"] == len(installer.REQUIRED_CASES)
    assert root.stat().st_mode & 0o777 == 0o700
    assert (root / "raw").stat().st_mode & 0o777 == 0o700
    assert list((root / "raw").iterdir()) == []
    for name in ("plan.json", "observations.template.json", "review.template.json"):
        assert (root / name).stat().st_mode & 0o777 == 0o600

    plan = json.loads((root / "plan.json").read_text(encoding="ascii"))
    assert plan["production_gate_eligible"] is False
    assert plan["tool_executes_cases"] is False
    assert plan["tool_creates_review"] is False
    assert plan["tool_creates_signature"] is False
    assert [case["case_id"] for case in plan["required_cases"]] == [
        case[0] for case in installer.REQUIRED_CASES
    ]

    observations = json.loads(
        (root / "observations.template.json").read_text(encoding="ascii")
    )
    assert observations["captured_at"] is None
    assert observations["effective_uid"] is None
    assert observations["prior_runtime_identity_sha256"] is None
    assert observations["candidate_runtime_identity_sha256"] is None
    assert len(observations["cases"]) == len(installer.REQUIRED_CASES)
    assert all(case["primary_exit_code"] is None for case in observations["cases"])
    assert all(case["injection_observed"] is None for case in observations["cases"])
    assert all(case["staging_absent"] is None for case in observations["cases"])

    review = json.loads((root / "review.template.json").read_text(encoding="ascii"))
    assert review == {
        "reviewed_at": None,
        "reviewer_name": None,
        "reviewer_organization": None,
        "signature": None,
        "status": "external_review_required",
        "subject_sha256": None,
    }


def test_backup_scaffold_has_every_raw_shape_but_no_evidence(tmp_path: Path):
    root = tmp_path / "backup-workspace"
    report = workspace.scaffold_backup(
        root,
        release_sha=RELEASE,
        host_identity_sha256=HOST,
        deployment_id=DEPLOYMENT,
        run_id=RUN_ID,
        contracts_present=True,
    )

    assert report["status"] == "pending_privileged_execution"
    assert report["artifact_count"] == len(backup._expected_artifact_ids())
    assert list((root / "raw").iterdir()) == []
    assert not (root / backup.FIXED_BUNDLE_NAME).exists()
    assert not (root / backup.FIXED_REVIEW_NAME).exists()

    plan = json.loads((root / "plan.json").read_text(encoding="ascii"))
    assert plan["production_gate_eligible"] is False
    assert plan["tool_executes_cases"] is False
    assert plan["tool_creates_review"] is False
    assert plan["tool_creates_signature"] is False
    assert {item["artifact_id"] for item in plan["required_artifacts"]} == set(
        backup._expected_artifact_ids()
    )
    assert len(plan["failure_cases"]) == len(backup.FAILURE_CASES)
    assert len(plan["signal_cases"]) == len(backup.SIGNALS) * len(backup.SIGNAL_PHASES)

    templates = root / "templates"
    assert templates.stat().st_mode & 0o777 == 0o700
    assert {path.name for path in templates.iterdir()} == {
        f"{artifact_id}.template.json" for artifact_id in backup.CORE_JSON_ARTIFACTS
    }
    restore = json.loads(
        (templates / "scratch_restore_report.template.json").read_text(encoding="ascii")
    )
    assert {check["target"] for check in restore["checks"]} == {
        *backup.SQLITE_RESTORE_TARGETS,
        "api_keys.txt",
        "contracts",
    }
    assert all(
        check.get("source_semantic_sha256", check.get("source_tree_sha256")) is None
        for check in restore["checks"]
    )

    bundle = json.loads((root / "bundle.template.json").read_text(encoding="ascii"))
    assert bundle["status"] == "observations_pending"
    assert bundle["evidence_id"] is None
    assert bundle["subject_artifact_set_sha256"] is None
    assert all(item["sha256"] is None for item in bundle["artifacts"].values())
    review = json.loads((root / "review.template.json").read_text(encoding="ascii"))
    assert review["status"] == "external_review_required"
    assert review["independence_attested"] is None
    assert review["open_critical_findings"] is None


def _copy_valid_raw(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for path in (source / "raw").iterdir():
        target = destination / path.name
        shutil.copyfile(path, target)
        target.chmod(0o600)


def test_backup_capture_semantically_validates_but_cannot_approve(tmp_path: Path):
    reviewed_source = build_bundle(tmp_path / "source")
    observation_workspace = tmp_path / "observation-workspace"
    observation_workspace.mkdir(mode=0o700)
    _copy_valid_raw(reviewed_source, observation_workspace / "raw")
    output = tmp_path / "captured-observations"

    report = workspace.capture_backup(
        observation_workspace,
        output,
        release_sha=RELEASE,
        host_identity_sha256=HOST,
        deployment_id=DEPLOYMENT,
        run_id=RUN_ID,
        now=NOW,
    )

    assert report["status"] == "external_review_required"
    assert report["artifact_count"] == len(backup._expected_artifact_ids())
    assert set(path.name for path in output.iterdir()) == {"bundle.json", "raw"}
    assert not (output / "review.json").exists()
    bundle = json.loads((output / "bundle.json").read_text(encoding="ascii"))
    assert bundle["schema_version"] == backup.SCHEMA_VERSION
    assert bundle["status"] == backup.BUNDLE_STATUS
    expected_id = backup._sha256(
        backup._canonical_json(
            {key: value for key, value in bundle.items() if key != "evidence_id"}
        )
    )
    assert bundle["evidence_id"] == expected_id

    with pytest.raises(backup.EvidenceError, match="missing or unexpected"):
        backup.validate_evidence(
            expected_release_sha=RELEASE,
            expected_host_identity_sha256=HOST,
            expected_deployment_id=DEPLOYMENT,
            evidence_root=output,
            required_uid=os.geteuid(),
            now=NOW,
            enforce_fixed_host=False,
            enforce_fixed_path=False,
        )

    shutil.copyfile(reviewed_source / "review.json", output / "review.json")
    (output / "review.json").chmod(0o600)
    assert (
        backup.validate_evidence(
            expected_release_sha=RELEASE,
            expected_host_identity_sha256=HOST,
            expected_deployment_id=DEPLOYMENT,
            evidence_root=output,
            required_uid=os.geteuid(),
            now=NOW,
            enforce_fixed_host=False,
            enforce_fixed_path=False,
        )["status"]
        == "reviewed_pass"
    )


def test_backup_capture_rejects_missing_raw_and_templates(tmp_path: Path):
    root = tmp_path / "workspace"
    workspace.scaffold_backup(
        root,
        release_sha=RELEASE,
        host_identity_sha256=HOST,
        deployment_id=DEPLOYMENT,
        run_id=RUN_ID,
        contracts_present=False,
    )
    with pytest.raises(workspace.WorkspaceError, match="exactly the required"):
        workspace.capture_backup(
            root,
            tmp_path / "capture",
            release_sha=RELEASE,
            host_identity_sha256=HOST,
            deployment_id=DEPLOYMENT,
            run_id=RUN_ID,
            now=datetime.now(timezone.utc),
        )


def test_scaffold_refuses_unsafe_or_existing_output(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(workspace.WorkspaceError, match="already exists"):
        workspace.scaffold_installer(
            existing,
            release_sha=RELEASE,
            host_identity_sha256=HOST,
            deployment_id=DEPLOYMENT,
            run_id=RUN_ID,
        )
    with pytest.raises(workspace.WorkspaceError, match="canonical absolute"):
        workspace.scaffold_installer(
            Path("relative"),
            release_sha=RELEASE,
            host_identity_sha256=HOST,
            deployment_id=DEPLOYMENT,
            run_id=RUN_ID,
        )


def test_scaffold_rejects_symlinked_ancestor(tmp_path: Path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(workspace.WorkspaceError, match="symlink-free"):
        workspace.scaffold_backup(
            linked_parent / "workspace",
            release_sha=RELEASE,
            host_identity_sha256=HOST,
            deployment_id=DEPLOYMENT,
            run_id=RUN_ID,
            contracts_present=False,
        )


def test_scaffold_rejects_group_writable_ancestor(tmp_path: Path):
    mutable_parent = tmp_path / "mutable-parent"
    mutable_parent.mkdir(mode=0o770)
    mutable_parent.chmod(0o770)

    with pytest.raises(workspace.WorkspaceError, match="not group/world writable"):
        workspace.scaffold_installer(
            mutable_parent / "workspace",
            release_sha=RELEASE,
            host_identity_sha256=HOST,
            deployment_id=DEPLOYMENT,
            run_id=RUN_ID,
        )
