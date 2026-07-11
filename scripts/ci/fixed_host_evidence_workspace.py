#!/usr/bin/env python3
"""Create and package fixed-host drill observations without approving them.

This tool is intentionally observation-only.  It never invokes the billing
runtime installer, runs a backup, restores production data, contacts an
off-box store, creates a review, or signs anything.  It provides complete,
owner-only workspaces so a privileged external drill harness can write raw
observations without hand-inventing case names or evidence shapes.

The backup capture command packages an already-complete raw directory into an
``observations_complete`` bundle and validates every semantic observation.  It
does not create ``review.json``; consequently the production verifier remains
fail closed until an independent reviewer supplies the separate review.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
import pathlib
import platform
import secrets
import shutil
import stat
import sys
import fixed_host_backup_evidence as backup
import installer_drill_evidence as installer


WORKSPACE_SCHEMA = "tinyzkp-fixed-host-evidence-workspace-v1"
INSTALLER_TEMPLATE_SCHEMA = "tinyzkp-installer-observation-template-v1"
BACKUP_TEMPLATE_SCHEMA = "tinyzkp-backup-observation-template-v1"
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024


class WorkspaceError(ValueError):
    """A workspace or observation package is unsafe or incomplete."""


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _validate_identity(
    release_sha: str, host_identity_sha256: str, deployment_id: str, run_id: str
) -> None:
    if installer.SHA1_RE.fullmatch(release_sha) is None:
        raise WorkspaceError("release SHA must be a lowercase 40-character digest")
    if backup.SHA256_RE.fullmatch(host_identity_sha256) is None:
        raise WorkspaceError("host identity must be a lowercase SHA-256 digest")
    if backup.DEPLOYMENT_RE.fullmatch(deployment_id) is None:
        raise WorkspaceError("deployment ID is not canonical")
    if backup.RUN_ID_RE.fullmatch(run_id) is None:
        raise WorkspaceError("run ID must be a lowercase 32-character digest")


def _safe_parent(path: pathlib.Path) -> None:
    if (
        not path.is_absolute()
        or path != pathlib.Path(os.path.abspath(path))
        or path.name in {"", ".", ".."}
    ):
        raise WorkspaceError("workspace output must be a canonical absolute path")
    _validate_ancestor_chain(path.parent)
    if path.exists() or path.is_symlink():
        raise WorkspaceError("workspace output already exists")


def _validate_ancestor_chain(path: pathlib.Path) -> None:
    """Reject any mutable, unowned, non-directory, or symlinked path component."""

    if not path.is_absolute() or path != pathlib.Path(os.path.abspath(path)):
        raise WorkspaceError("owner-controlled path must be canonical and absolute")
    current = pathlib.Path(path.anchor)
    allowed_owners = {0, os.geteuid()}
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise WorkspaceError(
                "workspace output parent chain must already exist"
            ) from error
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in allowed_owners
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise WorkspaceError(
                "workspace path ancestors must be root/owner-controlled, "
                "symlink-free, and not group/world writable"
            )


def _canonical_existing_directory(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute() or path != pathlib.Path(os.path.abspath(path)):
        raise WorkspaceError("owner-controlled path must be canonical and absolute")
    _validate_ancestor_chain(path)
    return path.resolve(strict=True)


def _mkdir_private(path: pathlib.Path) -> None:
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)


def _write_private(
    path: pathlib.Path,
    value: object | bytes,
    *,
    max_bytes: int = MAX_TEMPLATE_BYTES,
) -> None:
    raw = value if isinstance(value, bytes) else _canonical(value)
    if not 1 <= len(raw) <= max_bytes:
        raise WorkspaceError(f"private artifact {path.name} is outside its size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise WorkspaceError(f"short write for {path.name}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _identity(
    release_sha: str, host_identity_sha256: str, deployment_id: str, run_id: str
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "release_sha": release_sha,
        "host_identity_sha256": host_identity_sha256,
        "deployment_id": deployment_id,
    }


def _installer_case_template(
    case_id: str, kind: str, phase: str, signal_name: str
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "kind": kind,
        "phase": phase,
        "signal": signal_name,
        "started_at": None,
        "completed_at": None,
        "effective_uid": None,
        "command_argv_sha256": None,
        "stdout_log": f"{case_id}.stdout.log",
        "stderr_log": f"{case_id}.stderr.log",
        "primary_exit_code": None,
        "contender_exit_code": None,
        "injection_observed": None,
        "lock_contention_observed": None,
        "before_runtime_identity_sha256": None,
        "after_runtime_identity_sha256": None,
        "prior_runtime_restored": None,
        "candidate_runtime_activated": None,
        "staging_absent": None,
        "rollback_absent": None,
        "lock_reacquired": None,
        "retry_exit_code": None,
        "retry_runtime_identity_sha256": None,
    }


def scaffold_installer(
    output_root: pathlib.Path,
    *,
    release_sha: str,
    host_identity_sha256: str,
    deployment_id: str,
    run_id: str,
) -> dict[str, object]:
    """Create a pending installer drill workspace with every required case."""

    _validate_identity(release_sha, host_identity_sha256, deployment_id, run_id)
    _safe_parent(output_root)
    _mkdir_private(output_root)
    try:
        raw_root = output_root / "raw"
        _mkdir_private(raw_root)
        cases = [
            _installer_case_template(case_id, kind, phase, signal_name)
            for case_id, kind, phase, signal_name in installer.REQUIRED_CASES
        ]
        observations = {
            "schema_version": installer.OBSERVATION_SCHEMA,
            "captured_at": None,
            "release_sha": release_sha,
            "host_identity_sha256": host_identity_sha256,
            "deployment_id": deployment_id,
            "run_id": run_id,
            "effective_uid": None,
            "prior_runtime_identity_sha256": None,
            "candidate_runtime_identity_sha256": None,
            "cases": cases,
        }
        plan = {
            "schema_version": WORKSPACE_SCHEMA,
            "template_schema": INSTALLER_TEMPLATE_SCHEMA,
            "status": "pending_privileged_execution",
            "production_gate_eligible": False,
            "tool_executes_cases": False,
            "tool_creates_review": False,
            "tool_creates_signature": False,
            "identity": _identity(
                release_sha, host_identity_sha256, deployment_id, run_id
            ),
            "observation_template": "observations.template.json",
            "raw_directory": "raw",
            "required_cases": [
                {
                    "case_id": case_id,
                    "kind": kind,
                    "phase": phase,
                    "signal": signal_name,
                    "stdout_log": f"raw/{case_id}.stdout.log",
                    "stderr_log": f"raw/{case_id}.stderr.log",
                }
                for case_id, kind, phase, signal_name in installer.REQUIRED_CASES
            ],
            "required_external_steps": [
                "run every case as root on the production-equivalent fixed Linux host",
                "replace every null with a directly observed value and retain the exact nonempty logs",
                "capture an unreviewed subject with installer_drill_evidence.py capture",
                "obtain an allowlisted independent reviewer signature over that exact subject",
                "capture and verify the signed evidence at the fixed production path",
            ],
        }
        review_template = {
            "status": "external_review_required",
            "reviewer_name": None,
            "reviewer_organization": None,
            "reviewed_at": None,
            "subject_sha256": None,
            "signature": None,
        }
        _write_private(output_root / "plan.json", plan)
        _write_private(output_root / "observations.template.json", observations)
        _write_private(output_root / "review.template.json", review_template)
        return {
            "status": "pending_privileged_execution",
            "run_id": run_id,
            "case_count": len(cases),
            "workspace": str(output_root),
        }
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _pending_identity(identity: dict[str, object]) -> dict[str, object]:
    return dict(identity)


def _backup_templates(
    identity: dict[str, object], *, contracts_present: bool
) -> dict[str, dict[str, object]]:
    pending = None
    services = {
        "hc-billing-webhook.service": pending,
        "hc-stark.service": pending,
    }
    restore_checks: list[dict[str, object]] = [
        {
            "target": target,
            "kind": None,
            "schema_profile": profile,
            "quick_check": None,
            "schema_sha256": None,
            "source_semantic_sha256": None,
            "restored_semantic_sha256": None,
            "source_row_count": None,
            "restored_row_count": None,
        }
        for target, profile in sorted(backup.SQLITE_RESTORE_TARGETS.items())
    ]
    restore_checks.append(
        {
            "target": "api_keys.txt",
            "kind": None,
            "validation": None,
            "source_semantic_sha256": None,
            "restored_semantic_sha256": None,
            "source_record_count": None,
            "restored_record_count": None,
        }
    )
    if contracts_present:
        restore_checks.append(
            {
                "target": "contracts",
                "kind": None,
                "validation": None,
                "source_tree_sha256": None,
                "restored_tree_sha256": None,
                "source_member_count": None,
                "restored_member_count": None,
            }
        )
    templates: dict[str, dict[str, object]] = {
        "local_manifest": {
            "schema_version": 1,
            "timestamp": None,
            "required_artifacts": [],
            "artifacts": [],
        },
        "happy_path_report": {
            **_pending_identity(identity),
            "started_at": None,
            "completed_at": None,
            "effective_uid": None,
            "source_branch": None,
            "source_tree_clean": None,
            "published_origin_main": None,
            "backup_script": None,
            "backup_exit_code": None,
            "backup_timestamp": None,
            "remote_date": None,
            "services": services,
            "writer_handles_after_stop": None,
            "local_manifest_source": None,
            "local_manifest_verified": None,
            "local_manifest_sha256": None,
            "staging_removed": None,
            "lock_released": None,
        },
        "lock_contention_report": {
            **_pending_identity(identity),
            "lock_path": None,
            "lock_owner_uid": None,
            "lock_mode": None,
            "primary_acquired": None,
            "contender_effective_uid": None,
            "contender_exit_code": None,
            "contender_error": None,
            "primary_completed": None,
            "lock_reacquired_after": None,
        },
        "service_uid_staging_report": {
            **_pending_identity(identity),
            "staging_root": None,
            "staging_root_owner_uid": None,
            "staging_root_group_gid": None,
            "staging_root_mode": None,
            "staging_leaf": None,
            "staging_leaf_owner_uid": None,
            "staging_leaf_group_gid": None,
            "staging_leaf_mode": None,
            "service_user": None,
            "service_uid": None,
            "service_gid": None,
            "snapshot_executor": None,
            "snapshot_effective_uid": None,
            "sqlite_snapshots": [],
            "root_copy_effective_uid": None,
            "root_descriptor_copy_count": None,
            "source_identity_stable": None,
            "staging_removed": None,
        },
        "offbox_roundtrip_report": {
            **_pending_identity(identity),
            "transport": None,
            "rclone_config": None,
            "remote_date": None,
            "upload_exit_code": None,
            "remote_object_count": None,
            "local_manifest_sha256": None,
            "download_exit_code": None,
            "downloaded_manifest_sha256": None,
            "downloaded_manifest_verified": None,
            "downloaded_artifact_digests_match_manifest": None,
            "encryption_verified": None,
            "anonymous_read_denied": None,
            "retention_verified": None,
            "scratch_download_root": None,
            "scratch_owner_uid": None,
            "scratch_mode": None,
            "scratch_removed": None,
        },
        "scratch_restore_report": {
            **_pending_identity(identity),
            "effective_uid": None,
            "source": None,
            "manifest_sha256": None,
            "manifest_verified": None,
            "scratch_root": None,
            "scratch_owner_uid": None,
            "scratch_mode": None,
            "production_paths_mutated": None,
            "checks": restore_checks,
            "scratch_removed": None,
        },
        "failure_cleanup_matrix": {
            **_pending_identity(identity),
            "cases": [
                {
                    "case_id": case_id,
                    "phase": phase,
                    "exit_code": None,
                    "services_after": services,
                    "staging_removed": None,
                    "lock_released": None,
                    "cleanup_verified": None,
                    "retry_succeeded": None,
                    "log_artifact": f"failure_log_{case_id}",
                }
                for case_id, phase in backup.FAILURE_CASES
            ],
        },
        "signal_cleanup_matrix": {
            **_pending_identity(identity),
            "cases": [
                {
                    "case_id": f"{signal_name}_{phase}",
                    "phase": phase,
                    "signal": signal_name.upper(),
                    "exit_code": None,
                    "services_after": services,
                    "staging_removed": None,
                    "lock_released": None,
                    "cleanup_verified": None,
                    "retry_succeeded": None,
                    "log_artifact": f"signal_log_{signal_name}_{phase}",
                }
                for signal_name, _exit_code in backup.SIGNALS
                for phase in backup.SIGNAL_PHASES
            ],
        },
    }
    return templates


def scaffold_backup(
    output_root: pathlib.Path,
    *,
    release_sha: str,
    host_identity_sha256: str,
    deployment_id: str,
    run_id: str,
    contracts_present: bool,
) -> dict[str, object]:
    """Create complete pending backup templates without raw success claims."""

    _validate_identity(release_sha, host_identity_sha256, deployment_id, run_id)
    _safe_parent(output_root)
    _mkdir_private(output_root)
    try:
        raw_root = output_root / "raw"
        templates_root = output_root / "templates"
        _mkdir_private(raw_root)
        _mkdir_private(templates_root)
        identity = _identity(release_sha, host_identity_sha256, deployment_id, run_id)
        templates = _backup_templates(identity, contracts_present=contracts_present)
        for artifact_id, value in templates.items():
            _write_private(templates_root / f"{artifact_id}.template.json", value)

        artifacts = {
            artifact_id: {
                "path": backup._artifact_path(artifact_id),
                "media_type": backup._artifact_media(artifact_id),
                "sha256": None,
                "size_bytes": None,
            }
            for artifact_id in backup._expected_artifact_ids()
        }
        bundle_template = {
            "schema_version": backup.SCHEMA_VERSION,
            "status": "observations_pending",
            "evidence_id": None,
            "captured_at": None,
            "release_sha": release_sha,
            "host": {
                "identity_sha256": host_identity_sha256,
                "os_id": "debian",
                "os_version_id": "12",
                "architecture": "x86_64",
                "effective_uid": 0,
            },
            "deployment_id": deployment_id,
            "run_id": run_id,
            "subject_artifact_set_sha256": None,
            "artifacts": artifacts,
        }
        review_template = {
            **identity,
            "status": "external_review_required",
            "reviewer_name": None,
            "reviewer_organization": None,
            "independence_attested": None,
            "reviewed_at": None,
            "bundle_sha256": None,
            "subject_artifact_set_sha256": None,
            "scope": list(backup.REVIEW_SCOPE),
            "open_critical_findings": None,
            "open_high_findings": None,
            "attestation_reference": None,
        }
        plan = {
            "schema_version": WORKSPACE_SCHEMA,
            "template_schema": BACKUP_TEMPLATE_SCHEMA,
            "status": "pending_privileged_execution",
            "production_gate_eligible": False,
            "tool_executes_cases": False,
            "tool_creates_review": False,
            "tool_creates_signature": False,
            "contracts_present": contracts_present,
            "identity": identity,
            "raw_directory": "raw",
            "template_directory": "templates",
            "bundle_template": "bundle.template.json",
            "review_template": "review.template.json",
            "required_artifacts": [
                {
                    "artifact_id": artifact_id,
                    "path": backup._artifact_path(artifact_id),
                    "media_type": backup._artifact_media(artifact_id),
                }
                for artifact_id in backup._expected_artifact_ids()
            ],
            "failure_cases": [
                {"case_id": case_id, "phase": phase}
                for case_id, phase in backup.FAILURE_CASES
            ],
            "signal_cases": [
                {
                    "case_id": f"{signal_name}_{phase}",
                    "phase": phase,
                    "signal": signal_name.upper(),
                    "expected_exit_code": exit_code,
                }
                for signal_name, exit_code in backup.SIGNALS
                for phase in backup.SIGNAL_PHASES
            ],
            "review_scope": list(backup.REVIEW_SCOPE),
            "required_external_steps": [
                "run the complete root fixed-host backup, off-box readback, and scratch-restore drill",
                "write canonical structured observations and exact nonempty logs beneath raw/",
                "run the observation-only backup capture command",
                "obtain a separate independent review bound to the exact bundle and artifact subject",
                "install review.json only after that review and run the production verifier",
            ],
        }
        _write_private(output_root / "plan.json", plan)
        _write_private(output_root / "bundle.template.json", bundle_template)
        _write_private(output_root / "review.template.json", review_template)
        return {
            "status": "pending_privileged_execution",
            "run_id": run_id,
            "artifact_count": len(artifacts),
            "failure_case_count": len(backup.FAILURE_CASES),
            "signal_case_count": len(backup.SIGNALS) * len(backup.SIGNAL_PHASES),
            "workspace": str(output_root),
        }
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _capture_bundle(
    raw_root: pathlib.Path,
    *,
    release_sha: str,
    host_identity_sha256: str,
    deployment_id: str,
    run_id: str,
    required_uid: int,
) -> tuple[dict[str, object], dict[str, bytes]]:
    raw_identity = backup._validate_directory(
        raw_root, uid=required_uid, label="raw observation root"
    )
    expected_ids = backup._expected_artifact_ids()
    expected_names = {
        pathlib.PurePosixPath(backup._artifact_path(item)).name for item in expected_ids
    }
    entries = list(os.scandir(raw_root))
    if {entry.name for entry in entries} != expected_names or any(
        not entry.is_file(follow_symlinks=False) for entry in entries
    ):
        raise WorkspaceError(
            "raw observation directory must contain exactly the required artifact files"
        )
    contents: dict[str, bytes] = {}
    descriptors: dict[str, dict[str, object]] = {}
    total = 0
    for artifact_id in expected_ids:
        limit = (
            backup.MAX_STRUCTURED_ARTIFACT_BYTES
            if artifact_id in backup.CORE_JSON_ARTIFACTS
            else backup.MAX_LOG_ARTIFACT_BYTES
        )
        name = pathlib.PurePosixPath(backup._artifact_path(artifact_id)).name
        raw, _metadata = backup._read_private_file(
            raw_root / name,
            uid=required_uid,
            label=f"raw observation {artifact_id}",
            limit=limit,
        )
        if artifact_id in backup.CORE_JSON_ARTIFACTS:
            backup._parse_canonical_json(raw, label=f"raw observation {artifact_id}")
        total += len(raw)
        if total > backup.MAX_TOTAL_ARTIFACT_BYTES:
            raise WorkspaceError("raw observation set exceeds the total byte limit")
        contents[artifact_id] = raw
        descriptors[artifact_id] = {
            "path": backup._artifact_path(artifact_id),
            "media_type": backup._artifact_media(artifact_id),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    final_raw = raw_root.lstat()
    if (final_raw.st_dev, final_raw.st_ino) != (
        raw_identity.st_dev,
        raw_identity.st_ino,
    ):
        raise WorkspaceError("raw observation directory changed during capture")
    happy = backup._parse_canonical_json(
        contents["happy_path_report"], label="happy-path report"
    )
    captured_at = happy.get("completed_at")
    if not isinstance(captured_at, str):
        raise WorkspaceError("happy-path report must provide the bundle capture time")
    subject = {item: descriptors[item] for item in sorted(descriptors)}
    subject_sha256 = hashlib.sha256(_canonical({"artifacts": subject})).hexdigest()
    bundle: dict[str, object] = {
        "schema_version": backup.SCHEMA_VERSION,
        "status": backup.BUNDLE_STATUS,
        "evidence_id": "",
        "captured_at": captured_at,
        "release_sha": release_sha,
        "host": {
            "identity_sha256": host_identity_sha256,
            "os_id": "debian",
            "os_version_id": "12",
            "architecture": "x86_64",
            "effective_uid": 0,
        },
        "deployment_id": deployment_id,
        "run_id": run_id,
        "subject_artifact_set_sha256": subject_sha256,
        "artifacts": descriptors,
    }
    bundle["evidence_id"] = hashlib.sha256(
        _canonical(
            {key: value for key, value in bundle.items() if key != "evidence_id"}
        )
    ).hexdigest()
    return bundle, contents


def capture_backup(
    workspace: pathlib.Path,
    output_root: pathlib.Path,
    *,
    release_sha: str,
    host_identity_sha256: str,
    deployment_id: str,
    run_id: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Package raw backup observations; never create independent review data."""

    _validate_identity(release_sha, host_identity_sha256, deployment_id, run_id)
    required_uid = os.geteuid()
    canonical_workspace = _canonical_existing_directory(workspace)
    workspace_identity = backup._validate_directory(
        workspace, uid=required_uid, label="backup observation workspace"
    )
    raw_root = workspace / "raw"
    if output_root == backup.FIXED_EVIDENCE_ROOT:
        if (
            required_uid != 0
            or sys.platform != "linux"
            or platform.machine().lower()
            not in {
                "x86_64",
                "amd64",
            }
        ):
            raise WorkspaceError(
                "the fixed production evidence root requires root on Linux x86-64"
            )
        backup._enforce_fixed_host(host_identity_sha256, backup.FIXED_MACHINE_ID)
    _safe_parent(output_root)
    try:
        canonical_output = output_root.parent.resolve(strict=True) / output_root.name
        if (
            pathlib.Path(os.path.commonpath((canonical_workspace, canonical_output)))
            == canonical_workspace
        ):
            raise WorkspaceError(
                "capture output must not be nested inside its workspace"
            )
    except ValueError as error:
        raise WorkspaceError("workspace and capture output are incomparable") from error

    bundle, contents = _capture_bundle(
        raw_root,
        release_sha=release_sha,
        host_identity_sha256=host_identity_sha256,
        deployment_id=deployment_id,
        run_id=run_id,
        required_uid=required_uid,
    )
    temporary = (
        output_root.parent / f".{output_root.name}.capture-{secrets.token_hex(8)}"
    )
    _safe_parent(temporary)
    _mkdir_private(temporary)
    try:
        captured_raw = temporary / backup.FIXED_RAW_NAME
        _mkdir_private(captured_raw)
        for artifact_id, raw in contents.items():
            name = pathlib.PurePosixPath(backup._artifact_path(artifact_id)).name
            limit = (
                backup.MAX_STRUCTURED_ARTIFACT_BYTES
                if artifact_id in backup.CORE_JSON_ARTIFACTS
                else backup.MAX_LOG_ARTIFACT_BYTES
            )
            _write_private(captured_raw / name, raw, max_bytes=limit)
        _write_private(temporary / backup.FIXED_BUNDLE_NAME, bundle)
        report = backup.validate_observations(
            expected_release_sha=release_sha,
            expected_host_identity_sha256=host_identity_sha256,
            expected_deployment_id=deployment_id,
            evidence_root=temporary,
            required_uid=required_uid,
            now=now,
        )
        current_workspace = workspace.lstat()
        if (current_workspace.st_dev, current_workspace.st_ino) != (
            workspace_identity.st_dev,
            workspace_identity.st_ino,
        ):
            raise WorkspaceError("backup observation workspace changed during capture")
        os.rename(temporary, output_root)
        parent_descriptor = os.open(
            output_root.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return {**report, "evidence_root": str(output_root)}
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _run_id(value: str | None) -> str:
    return value or secrets.token_hex(16)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    installer_parser = commands.add_parser("installer-scaffold")
    backup_parser = commands.add_parser("backup-scaffold")
    capture_parser = commands.add_parser("backup-capture")
    for command in (installer_parser, backup_parser, capture_parser):
        command.add_argument("--release-sha", required=True)
        command.add_argument("--host-identity-sha256", required=True)
        command.add_argument("--deployment-id", required=True)
        command.add_argument("--run-id")
    installer_parser.add_argument("--output-root", type=pathlib.Path, required=True)
    backup_parser.add_argument("--output-root", type=pathlib.Path, required=True)
    backup_parser.add_argument("--contracts-present", action="store_true")
    capture_parser.add_argument("--workspace", type=pathlib.Path, required=True)
    capture_parser.add_argument("--output-root", type=pathlib.Path, required=True)

    args = parser.parse_args(argv)
    run_id = _run_id(args.run_id)
    try:
        common = {
            "release_sha": args.release_sha,
            "host_identity_sha256": args.host_identity_sha256,
            "deployment_id": args.deployment_id,
            "run_id": run_id,
        }
        if args.command == "installer-scaffold":
            report = scaffold_installer(args.output_root, **common)
        elif args.command == "backup-scaffold":
            report = scaffold_backup(
                args.output_root,
                contracts_present=args.contracts_present,
                **common,
            )
        else:
            report = capture_backup(
                args.workspace,
                args.output_root,
                **common,
            )
    except (
        WorkspaceError,
        backup.EvidenceError,
        installer.EvidenceError,
        OSError,
    ) as error:
        print(f"FAIL fixed-host observation workspace - {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
