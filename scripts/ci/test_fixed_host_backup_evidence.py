from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib

import pytest

import fixed_host_backup_evidence as evidence


RELEASE = "a" * 40
HOST = "b" * 64
DEPLOYMENT = "tinyzkp-production-primary"
RUN_ID = "c" * 32
CAPTURED = "2026-07-10T20:00:00Z"
TIMESTAMP = "20260710_195500"
NOW = datetime(2026, 7, 11, 0, 0, tzinfo=timezone.utc)


def canonical(value):
    return evidence._canonical_json(value)


def identity():
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "release_sha": RELEASE,
        "host_identity_sha256": HOST,
        "deployment_id": DEPLOYMENT,
    }


def services_active():
    return {
        "hc-billing-webhook.service": "active",
        "hc-stark.service": "active",
    }


def write_private(path: pathlib.Path, raw: bytes):
    path.write_bytes(raw)
    path.chmod(0o600)


def build_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "fixed-host-evidence"
    raw_root = root / "raw"
    raw_root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    raw_root.chmod(0o700)

    required = [
        f"api_keys_{TIMESTAMP}.txt",
        f"contract_billing_{TIMESTAMP}.sqlite",
        f"evaluation_applications_{TIMESTAMP}.sqlite",
        f"tenant_store_{TIMESTAMP}.sqlite",
        f"usage_{TIMESTAMP}.sqlite",
    ]
    ordered = [
        f"tenant_store_{TIMESTAMP}.sqlite",
        f"usage_{TIMESTAMP}.sqlite",
        f"evaluation_applications_{TIMESTAMP}.sqlite",
        f"contract_billing_{TIMESTAMP}.sqlite",
        f"api_keys_{TIMESTAMP}.txt",
    ]
    manifest = {
        "schema_version": 1,
        "timestamp": TIMESTAMP,
        "required_artifacts": required,
        "artifacts": [
            {
                "name": name,
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "size": 10,
            }
            for name in ordered
        ],
    }
    manifest_raw = canonical(manifest)
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()

    reports = {
        "local_manifest": manifest,
        "happy_path_report": {
            **identity(),
            "started_at": "2026-07-10T19:50:00Z",
            "completed_at": CAPTURED,
            "effective_uid": 0,
            "source_branch": "main",
            "source_tree_clean": True,
            "published_origin_main": True,
            "backup_script": "/opt/hc-stark/billing/backup.sh",
            "backup_exit_code": 0,
            "backup_timestamp": TIMESTAMP,
            "remote_date": "2026-07-10",
            "services": {
                name: {"before": "active", "during": "inactive", "after": "active"}
                for name in services_active()
            },
            "writer_handles_after_stop": 0,
            "local_manifest_source": f"/opt/hc-stark/backups/manifest_{TIMESTAMP}.json",
            "local_manifest_verified": True,
            "local_manifest_sha256": manifest_digest,
            "staging_removed": True,
            "lock_released": True,
        },
        "lock_contention_report": {
            **identity(),
            "lock_path": "/var/lib/tinyzkp-private/backup/backup.lock",
            "lock_owner_uid": 0,
            "lock_mode": "0600",
            "primary_acquired": True,
            "contender_effective_uid": 0,
            "contender_exit_code": 17,
            "contender_error": "another TinyZKP backup is already active",
            "primary_completed": True,
            "lock_reacquired_after": True,
        },
        "service_uid_staging_report": {
            **identity(),
            "staging_root": "/var/lib/tinyzkp-backup-staging",
            "staging_root_owner_uid": 0,
            "staging_root_group_gid": 1001,
            "staging_root_mode": "0710",
            "staging_leaf": f"/var/lib/tinyzkp-backup-staging/run_{TIMESTAMP}",
            "staging_leaf_owner_uid": 1001,
            "staging_leaf_group_gid": 1001,
            "staging_leaf_mode": "0700",
            "service_user": "tinyzkp-billing",
            "service_uid": 1001,
            "service_gid": 1001,
            "snapshot_executor": "runuser:tinyzkp-billing",
            "snapshot_effective_uid": 1001,
            "sqlite_snapshots": [
                "evaluation_applications.sqlite",
                "tenant_store.sqlite",
                "usage.sqlite",
            ],
            "root_copy_effective_uid": 0,
            "root_descriptor_copy_count": 3,
            "source_identity_stable": True,
            "staging_removed": True,
        },
        "offbox_roundtrip_report": {
            **identity(),
            "transport": "rclone_crypt",
            "rclone_config": "/var/lib/tinyzkp-private/backup/rclone.conf",
            "remote_date": "2026-07-10",
            "upload_exit_code": 0,
            "remote_object_count": 6,
            "local_manifest_sha256": manifest_digest,
            "download_exit_code": 0,
            "downloaded_manifest_sha256": manifest_digest,
            "downloaded_manifest_verified": True,
            "downloaded_artifact_digests_match_manifest": True,
            "encryption_verified": True,
            "anonymous_read_denied": True,
            "retention_verified": True,
            "scratch_download_root": f"/var/lib/tinyzkp-backup-evidence-scratch/{RUN_ID}",
            "scratch_owner_uid": 0,
            "scratch_mode": "0700",
            "scratch_removed": True,
        },
    }
    restore_checks = []
    for index, (target, profile) in enumerate(
        sorted(evidence.SQLITE_RESTORE_TARGETS.items())
    ):
        digest = f"{index + 1:x}" * 64
        restore_checks.append(
            {
                "target": target,
                "kind": "sqlite",
                "schema_profile": profile,
                "quick_check": "ok",
                "schema_sha256": "d" * 64,
                "source_semantic_sha256": digest,
                "restored_semantic_sha256": digest,
                "source_row_count": 3,
                "restored_row_count": 3,
            }
        )
    restore_checks.append(
        {
            "target": "api_keys.txt",
            "kind": "api_keys",
            "validation": "ok",
            "source_semantic_sha256": "e" * 64,
            "restored_semantic_sha256": "e" * 64,
            "source_record_count": 1,
            "restored_record_count": 1,
        }
    )
    reports["scratch_restore_report"] = {
        **identity(),
        "effective_uid": 0,
        "source": "offbox_roundtrip",
        "manifest_sha256": manifest_digest,
        "manifest_verified": True,
        "scratch_root": f"/var/lib/tinyzkp-backup-evidence-scratch/{RUN_ID}/restore",
        "scratch_owner_uid": 0,
        "scratch_mode": "0700",
        "production_paths_mutated": False,
        "checks": restore_checks,
        "scratch_removed": True,
    }
    reports["failure_cleanup_matrix"] = {
        **identity(),
        "cases": [
            {
                "case_id": case_id,
                "phase": phase,
                "exit_code": 1,
                "services_after": services_active(),
                "staging_removed": True,
                "lock_released": True,
                "cleanup_verified": True,
                "retry_succeeded": True,
                "log_artifact": f"failure_log_{case_id}",
            }
            for case_id, phase in evidence.FAILURE_CASES
        ],
    }
    reports["signal_cleanup_matrix"] = {
        **identity(),
        "cases": [
            {
                "case_id": f"{signal}_{phase}",
                "phase": phase,
                "signal": signal.upper(),
                "exit_code": exit_code,
                "services_after": services_active(),
                "staging_removed": True,
                "lock_released": True,
                "cleanup_verified": True,
                "retry_succeeded": True,
                "log_artifact": f"signal_log_{signal}_{phase}",
            }
            for signal, exit_code in evidence.SIGNALS
            for phase in evidence.SIGNAL_PHASES
        ],
    }

    descriptors = {}
    for artifact_id in evidence._expected_artifact_ids():
        raw = (
            canonical(reports[artifact_id])
            if artifact_id in reports
            else f"raw fixed-host log: {artifact_id}\n".encode()
        )
        relative = evidence._artifact_path(artifact_id)
        write_private(raw_root / pathlib.PurePosixPath(relative).name, raw)
        descriptors[artifact_id] = {
            "path": relative,
            "media_type": evidence._artifact_media(artifact_id),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }
    subject = hashlib.sha256(
        canonical({"artifacts": {key: descriptors[key] for key in sorted(descriptors)}})
    ).hexdigest()
    bundle = {
        "schema_version": 1,
        "status": "reviewed_pass",
        "evidence_id": "f" * 64,
        "captured_at": CAPTURED,
        "release_sha": RELEASE,
        "host": {
            "identity_sha256": HOST,
            "os_id": "debian",
            "os_version_id": "12",
            "architecture": "x86_64",
            "effective_uid": 0,
        },
        "deployment_id": DEPLOYMENT,
        "run_id": RUN_ID,
        "subject_artifact_set_sha256": subject,
        "artifacts": descriptors,
    }
    bundle_raw = canonical(bundle)
    write_private(root / "bundle.json", bundle_raw)
    review = {
        **identity(),
        "status": "approved",
        "reviewer_name": "External Reviewer",
        "reviewer_organization": "Independent Security LLC",
        "independence_attested": True,
        "reviewed_at": "2026-07-10T21:00:00Z",
        "bundle_sha256": hashlib.sha256(bundle_raw).hexdigest(),
        "subject_artifact_set_sha256": subject,
        "scope": list(evidence.REVIEW_SCOPE),
        "open_critical_findings": 0,
        "open_high_findings": 0,
        "attestation_reference": "review-report-sha256:" + "1" * 64,
    }
    write_private(root / "review.json", canonical(review))
    return root


def validate(root: pathlib.Path, **overrides):
    options = {
        "expected_release_sha": RELEASE,
        "expected_host_identity_sha256": HOST,
        "expected_deployment_id": DEPLOYMENT,
        "evidence_root": root,
        "required_uid": os.geteuid(),
        "now": NOW,
        "enforce_fixed_host": False,
        "enforce_fixed_path": False,
    }
    options.update(overrides)
    return evidence.validate_evidence(**options)


def rewrite_structured(root: pathlib.Path, artifact_id: str, mutate):
    bundle_path = root / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    descriptor = bundle["artifacts"][artifact_id]
    artifact = root / descriptor["path"]
    value = json.loads(artifact.read_text(encoding="utf-8"))
    mutate(value)
    raw = canonical(value)
    write_private(artifact, raw)
    descriptor["sha256"] = hashlib.sha256(raw).hexdigest()
    descriptor["size_bytes"] = len(raw)
    bundle["subject_artifact_set_sha256"] = hashlib.sha256(
        canonical(
            {
                "artifacts": {
                    key: bundle["artifacts"][key] for key in sorted(bundle["artifacts"])
                }
            }
        )
    ).hexdigest()
    bundle_raw = canonical(bundle)
    write_private(bundle_path, bundle_raw)
    review_path = root / "review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["bundle_sha256"] = hashlib.sha256(bundle_raw).hexdigest()
    review["subject_artifact_set_sha256"] = bundle["subject_artifact_set_sha256"]
    write_private(review_path, canonical(review))


def test_complete_reviewed_fixed_host_bundle_passes_policy(tmp_path):
    root = build_bundle(tmp_path)
    report = validate(root)
    assert report["status"] == "reviewed_pass"
    assert report["artifact_count"] == len(evidence._expected_artifact_ids())
    assert len(report["evidence_identity_sha256"]) == 64


def test_rejects_changed_artifact_and_noncanonical_or_public_bundle(tmp_path):
    root = build_bundle(tmp_path)
    artifact = root / "raw" / "happy_path_log.log"
    artifact.write_text("changed\n", encoding="utf-8")
    artifact.chmod(0o600)
    with pytest.raises(evidence.EvidenceError, match="differs from its descriptor"):
        validate(root)

    root = build_bundle(tmp_path / "canonical")
    bundle = root / "bundle.json"
    value = json.loads(bundle.read_text(encoding="utf-8"))
    bundle.write_text(json.dumps(value, indent=2), encoding="utf-8")
    bundle.chmod(0o600)
    with pytest.raises(evidence.EvidenceError, match="not canonical"):
        validate(root)
    bundle.chmod(0o644)
    with pytest.raises(evidence.EvidenceError, match="mode 0600"):
        validate(root)


def test_rejects_identity_mismatch_and_stale_capture(tmp_path):
    root = build_bundle(tmp_path)
    with pytest.raises(evidence.EvidenceError, match="release does not match"):
        validate(root, expected_release_sha="9" * 40)
    with pytest.raises(evidence.EvidenceError, match="stale"):
        validate(root, now=datetime(2026, 9, 1, tzinfo=timezone.utc))


def test_rejects_false_service_restore_and_semantic_restore(tmp_path):
    root = build_bundle(tmp_path)
    rewrite_structured(
        root,
        "happy_path_report",
        lambda value: value["services"]["hc-stark.service"].update(after="inactive"),
    )
    with pytest.raises(evidence.EvidenceError, match="service transition"):
        validate(root)

    root = build_bundle(tmp_path / "semantic")
    rewrite_structured(
        root,
        "scratch_restore_report",
        lambda value: value["checks"][0].update(restored_semantic_sha256="0" * 64),
    )
    with pytest.raises(evidence.EvidenceError, match="SQLite semantics differ"):
        validate(root)


def test_rejects_incomplete_cleanup_matrix_and_unbound_review(tmp_path):
    root = build_bundle(tmp_path)
    rewrite_structured(
        root, "signal_cleanup_matrix", lambda value: value["cases"].pop()
    )
    with pytest.raises(evidence.EvidenceError, match="case set is incomplete"):
        validate(root)

    root = build_bundle(tmp_path / "review")
    review = root / "review.json"
    value = json.loads(review.read_text(encoding="utf-8"))
    value["bundle_sha256"] = "0" * 64
    write_private(review, canonical(value))
    with pytest.raises(evidence.EvidenceError, match="does not approve"):
        validate(root)
