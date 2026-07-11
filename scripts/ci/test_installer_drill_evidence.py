from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path

import pytest

import installer_drill_evidence as evidence


RELEASE = "a" * 40
HOST = "b" * 64
DEPLOYMENT = "tinyzkp-production-primary"
RUN_ID = "c" * 32
PRIOR = "d" * 64
CANDIDATE = "e" * 64


def _case(
    case_id: str,
    kind: str,
    phase: str,
    signal: str,
    timestamp: str,
    stdout_log: str,
    stderr_log: str,
) -> dict[str, object]:
    if kind == "success":
        exit_code = 0
        contender = None
        injection = False
        contention = False
        after = CANDIDATE
        restored = False
        activated = True
        retry_exit = None
        retry_identity = None
    elif kind == "concurrency":
        exit_code = 0
        contender = 1
        injection = False
        contention = True
        after = CANDIDATE
        restored = False
        activated = True
        retry_exit = None
        retry_identity = None
    else:
        exit_code = dict(evidence.SIGNALS)[signal] if kind == "signal" else 71
        contender = None
        injection = True
        contention = False
        after = PRIOR
        restored = True
        activated = False
        retry_exit = 0
        retry_identity = CANDIDATE
    return {
        "case_id": case_id,
        "kind": kind,
        "phase": phase,
        "signal": signal,
        "started_at": timestamp,
        "completed_at": timestamp,
        "effective_uid": 0,
        "command_argv_sha256": "f" * 64,
        "stdout_log": stdout_log,
        "stderr_log": stderr_log,
        "primary_exit_code": exit_code,
        "contender_exit_code": contender,
        "injection_observed": injection,
        "lock_contention_observed": contention,
        "before_runtime_identity_sha256": PRIOR,
        "after_runtime_identity_sha256": after,
        "prior_runtime_restored": restored,
        "candidate_runtime_activated": activated,
        "staging_absent": True,
        "rollback_absent": True,
        "lock_reacquired": True,
        "retry_exit_code": retry_exit,
        "retry_runtime_identity_sha256": retry_identity,
    }


def write_observations(tmp_path: Path, now: datetime) -> tuple[Path, Path]:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir(parents=True)
    timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    cases = []
    for case_id, kind, phase, signal in evidence.REQUIRED_CASES:
        stdout = f"{case_id}.stdout.log"
        stderr = f"{case_id}.stderr.log"
        (raw_dir / stdout).write_text(f"{case_id} stdout\n", encoding="utf-8")
        (raw_dir / stderr).write_text(f"{case_id} stderr\n", encoding="utf-8")
        cases.append(_case(case_id, kind, phase, signal, timestamp, stdout, stderr))
    observations = {
        "schema_version": evidence.OBSERVATION_SCHEMA,
        "captured_at": timestamp,
        "release_sha": RELEASE,
        "host_identity_sha256": HOST,
        "deployment_id": DEPLOYMENT,
        "run_id": RUN_ID,
        "effective_uid": 0,
        "prior_runtime_identity_sha256": PRIOR,
        "candidate_runtime_identity_sha256": CANDIDATE,
        "cases": cases,
    }
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(observations), encoding="utf-8")
    return path, raw_dir


def capture(tmp_path: Path, now: datetime) -> Path:
    observations, raw_dir = write_observations(tmp_path, now)
    output = tmp_path / "installer-evidence.json"
    report = evidence.capture_evidence(observations, raw_dir, output)
    assert report["case_count"] == len(evidence.REQUIRED_CASES)
    assert report["review_status"] == "unreviewed"
    assert output.stat().st_mode & 0o777 == 0o600
    return output


def unsigned_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "unsigned-reviewers.json"
    path.write_bytes(
        evidence._canonical(
            {
                "schema_version": 1,
                "signature_required_for": [],
                "reviewers": [],
            }
        )
    )
    return path


def test_capture_and_verify_complete_installer_drill(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)

    report = evidence.validate_evidence(
        output,
        expected_release_sha=RELEASE,
        expected_host_identity_sha256=HOST,
        expected_deployment_id=DEPLOYMENT,
        reviewer_manifest_path=unsigned_manifest(tmp_path),
        now=now,
        enforce_fixed_path=False,
        enforce_host=False,
    )

    assert report["status"] == "pass"
    assert report["run_id"] == RUN_ID
    assert len(report["evidence_identity_sha256"]) == 64


def test_checked_in_policy_blocks_unreviewed_installer_evidence(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)
    with pytest.raises(evidence.EvidenceError, match="pinned reviewer signature"):
        evidence.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_host_identity_sha256=HOST,
            expected_deployment_id=DEPLOYMENT,
            now=now,
            enforce_fixed_path=False,
            enforce_host=False,
        )


def test_rejects_missing_case_and_wrong_signal_exit(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    observations, raw_dir = write_observations(tmp_path, now)
    payload = json.loads(observations.read_text(encoding="utf-8"))
    payload["cases"].pop()
    observations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="case set is incomplete"):
        evidence.capture_evidence(observations, raw_dir, tmp_path / "missing.json")

    observations, raw_dir = write_observations(tmp_path / "second", now)
    payload = json.loads(observations.read_text(encoding="utf-8"))
    signal = next(case for case in payload["cases"] if case["kind"] == "signal")
    signal["primary_exit_code"] = 1
    observations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="rollback/retry semantics"):
        evidence.capture_evidence(observations, raw_dir, tmp_path / "wrong-signal.json")


def test_rejects_false_rollback_retry_and_changed_log(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    observations, raw_dir = write_observations(tmp_path, now)
    payload = json.loads(observations.read_text(encoding="utf-8"))
    failed = next(case for case in payload["cases"] if case["kind"] == "failure")
    failed["prior_runtime_restored"] = False
    observations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="rollback/retry semantics"):
        evidence.capture_evidence(observations, raw_dir, tmp_path / "false.json")

    output = capture(tmp_path / "valid", now)
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["cases"][0]["stdout"]["sha256"] = "0" * 64
    output.write_text(evidence._canonical(payload).decode("ascii"), encoding="ascii")
    with pytest.raises(evidence.EvidenceError, match="subject hash"):
        evidence.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_host_identity_sha256=HOST,
            expected_deployment_id=DEPLOYMENT,
            now=now,
            enforce_fixed_path=False,
            enforce_host=False,
        )


def test_pinned_signature_policy_rejects_unreviewed_evidence(tmp_path: Path):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path, now)
    manifest = tmp_path / "reviewers.json"
    manifest.write_bytes(
        evidence._canonical(
            {
                "schema_version": 1,
                "signature_required_for": ["installer_drill"],
                "reviewers": [],
            }
        )
    )

    with pytest.raises(evidence.EvidenceError, match="pinned reviewer signature"):
        evidence.validate_evidence(
            output,
            expected_release_sha=RELEASE,
            expected_host_identity_sha256=HOST,
            expected_deployment_id=DEPLOYMENT,
            reviewer_manifest_path=manifest,
            now=now,
            enforce_fixed_path=False,
            enforce_host=False,
        )


def test_pinned_signature_contract_verifies_approved_review(
    tmp_path: Path, monkeypatch
):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    output = capture(tmp_path / "capture", now)
    key_root = tmp_path / "keys-root"
    key_path = key_root / "reviewer.pem"
    key_path.parent.mkdir(parents=True)
    key_raw = b"-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
    key_path.write_bytes(key_raw)
    manifest = tmp_path / "reviewers.json"
    manifest.write_bytes(
        evidence._canonical(
            {
                "schema_version": 1,
                "signature_required_for": ["installer_drill"],
                "reviewers": [
                    {
                        "key_id": "external-reviewer-v1",
                        "algorithm": "ed25519",
                        "public_key_path": "reviewer.pem",
                        "public_key_sha256": hashlib.sha256(key_raw).hexdigest(),
                    }
                ],
            }
        )
    )
    payload = json.loads(output.read_text(encoding="ascii"))
    payload["review"] = {
        "status": "approved",
        "reviewer_name": "Independent Reviewer",
        "reviewer_organization": "External Review LLC",
        "reviewed_at": now.isoformat().replace("+00:00", "Z"),
        "subject_sha256": payload["subject_sha256"],
        "signature": {
            "algorithm": "ed25519",
            "key_id": "external-reviewer-v1",
            "signature_base64url": base64.urlsafe_b64encode(b"s" * 64)
            .decode("ascii")
            .rstrip("="),
        },
    }
    output.write_bytes(evidence._canonical(payload))
    observed: dict[str, object] = {}

    def fake_verify(message, signature, public_key, **_kwargs):
        observed.update(
            message=message,
            signature=signature,
            public_key=public_key,
        )

    monkeypatch.setattr(evidence, "ROOT", key_root)
    monkeypatch.setattr(evidence, "_verify_openssl_signature", fake_verify)

    report = evidence.validate_evidence(
        output,
        expected_release_sha=RELEASE,
        expected_host_identity_sha256=HOST,
        expected_deployment_id=DEPLOYMENT,
        reviewer_manifest_path=manifest,
        now=now,
        enforce_fixed_path=False,
        enforce_host=False,
        root=Path(__file__).resolve().parents[2],
    )

    assert report["review_status"] == "approved"
    assert observed["signature"] == b"s" * 64
    assert observed["public_key"] == key_path


def test_rejects_stale_evidence(tmp_path: Path):
    captured = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=31)
    observations, raw_dir = write_observations(tmp_path, captured)
    with pytest.raises(evidence.EvidenceError, match="stale"):
        evidence.capture_evidence(observations, raw_dir, tmp_path / "stale.json")
