#!/usr/bin/env python3
"""Capture and verify fixed-host billing-runtime installer drill evidence.

The capture command never performs an installation or injects a failure.  It
turns raw, root-drill observations and their logs into one canonical artifact.
The verifier rejects missing phases, invented success shortcuts, source drift,
stale evidence, and inconsistent rollback/retry identities.  Production uses
the fixed owner-only artifact path and binds its identity into deployment
preflight evidence.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import os
import pathlib
import platform
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXED_EVIDENCE = pathlib.Path(
    "/var/lib/tinyzkp-private/deploy/installer-drill-evidence.json"
)
FIXED_MACHINE_ID = pathlib.Path("/etc/machine-id")
DEFAULT_REVIEWER_MANIFEST = ROOT / "release/operator-evidence-reviewers-v1.json"
SCHEMA = "tinyzkp-installer-drill-evidence-v1"
OBSERVATION_SCHEMA = "tinyzkp-installer-drill-observations-v1"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_AGE = timedelta(days=30)
MAX_CLOCK_SKEW = timedelta(minutes=5)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DEPLOYMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}$")

FAILURE_PHASES = (
    "venv_creation",
    "previous_runtime_rename",
    "candidate_activation_rename",
    "final_path_verification",
)
SIGNALS = (("HUP", 129), ("INT", 130), ("TERM", 143))
REQUIRED_CASES = (
    ("success_initial", "success", "complete", ""),
    ("concurrency", "concurrency", "lock", ""),
    *((f"failure_{phase}", "failure", phase, "") for phase in FAILURE_PHASES),
    *(
        (f"signal_{signal.lower()}_{phase}", "signal", phase, signal)
        for signal, _exit_code in SIGNALS
        for phase in FAILURE_PHASES
    ),
)
SOURCE_PATHS = {
    "evidence_tool": "scripts/ci/installer_drill_evidence.py",
    "installer": "deploy/hetzner/install_billing_runtime.sh",
    "runtime_lock_tool": "billing/runtime_lock.py",
    "runtime_profile": "billing/runtime-profile.json",
    "requirements_lock": "billing/requirements.lock",
    "bootstrap_lock": "billing/requirements-bootstrap.lock",
    "wheelhouse_manifest": "billing/wheelhouse-manifest.json",
    "host_runtime_provenance": "billing/host-runtime-provenance.json",
    "reviewer_manifest": "release/operator-evidence-reviewers-v1.json",
}


class EvidenceError(ValueError):
    """Installer drill evidence is absent, unsafe, incomplete, or stale."""


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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"JSON object duplicates {key!r}")
        result[key] = value
    return result


def _parse_json(raw: bytes, *, label: str, require_canonical: bool) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvidenceError(f"{label} contains invalid number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} must be strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must contain one JSON object")
    if require_canonical and raw != _canonical(value):
        raise EvidenceError(f"{label} is not canonically encoded")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        missing = ", ".join(sorted(expected - set(value))) or "none"
        extra = ", ".join(sorted(set(value) - expected)) or "none"
        raise EvidenceError(f"{label} fields differ (missing: {missing}; extra: {extra})")


def _digest(value: object, *, label: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise EvidenceError(f"{label} is not a real UTC time") from error


def _read_regular(
    path: pathlib.Path,
    *,
    label: str,
    limit: int,
    exact_mode: int | None = None,
    required_uid: int | None = None,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= limit
        or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
        or (required_uid is not None and before.st_uid != required_uid)
    ):
        raise EvidenceError(f"{label} is not a safe bounded regular file")
    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceError(f"{label} verification requires O_NOFOLLOW")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise EvidenceError(f"{label} changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise EvidenceError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise EvidenceError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        raise EvidenceError(f"{label} was not read completely")
    return raw


def _host_identity(path: pathlib.Path) -> str:
    raw = _read_regular(path, label="machine identity", limit=256)
    try:
        value = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as error:
        raise EvidenceError("machine identity is malformed") from error
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise EvidenceError("machine identity is malformed")
    return _sha256(value.encode("ascii"))


def source_identity(root: pathlib.Path = ROOT) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, relative in SOURCE_PATHS.items():
        raw = _read_regular(
            root / relative,
            label=f"installer source {relative}",
            limit=16 * 1024 * 1024,
        )
        result[f"{key}_sha256"] = _sha256(raw)
    return result


def _log_descriptor(path: pathlib.Path, *, label: str) -> dict[str, object]:
    raw = _read_regular(path, label=label, limit=MAX_LOG_BYTES)
    return {"sha256": _sha256(raw), "size_bytes": len(raw)}


def _validate_log_descriptor(value: object, *, label: str) -> None:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} descriptor must be an object")
    _exact_keys(value, {"sha256", "size_bytes"}, label=label)
    _digest(value["sha256"], label=f"{label} hash")
    if type(value["size_bytes"]) is not int or not 1 <= value["size_bytes"] <= MAX_LOG_BYTES:
        raise EvidenceError(f"{label} size is invalid")


def _case_expected_exit(kind: str, signal: str) -> int | None:
    if kind == "success" or kind == "concurrency":
        return 0
    if kind == "signal":
        return dict(SIGNALS)[signal]
    return None


def _validate_case(
    case: dict[str, Any],
    *,
    expected: tuple[str, str, str, str],
    prior_identity: str | None,
    candidate_identity: str,
    captured_at: datetime,
) -> None:
    _exact_keys(
        case,
        {
            "case_id",
            "kind",
            "phase",
            "signal",
            "started_at",
            "completed_at",
            "effective_uid",
            "command_argv_sha256",
            "stdout",
            "stderr",
            "primary_exit_code",
            "contender_exit_code",
            "injection_observed",
            "lock_contention_observed",
            "before_runtime_identity_sha256",
            "after_runtime_identity_sha256",
            "prior_runtime_restored",
            "candidate_runtime_activated",
            "staging_absent",
            "rollback_absent",
            "lock_reacquired",
            "retry_exit_code",
            "retry_runtime_identity_sha256",
        },
        label=f"installer case {expected[0]}",
    )
    case_id, kind, phase, signal = expected
    if (case["case_id"], case["kind"], case["phase"], case["signal"]) != expected:
        raise EvidenceError(f"installer case {case_id} identity/order is invalid")
    started = _timestamp(case["started_at"], label=f"{case_id} start")
    completed = _timestamp(case["completed_at"], label=f"{case_id} completion")
    if not started <= completed <= captured_at + MAX_CLOCK_SKEW:
        raise EvidenceError(f"installer case {case_id} timing is invalid")
    if case["effective_uid"] != 0:
        raise EvidenceError(f"installer case {case_id} did not run as root")
    _digest(case["command_argv_sha256"], label=f"{case_id} command hash")
    _validate_log_descriptor(case["stdout"], label=f"{case_id} stdout")
    _validate_log_descriptor(case["stderr"], label=f"{case_id} stderr")
    before = _digest(
        case["before_runtime_identity_sha256"],
        label=f"{case_id} before runtime",
        optional=True,
    )
    after = _digest(
        case["after_runtime_identity_sha256"],
        label=f"{case_id} after runtime",
        optional=True,
    )
    retry_identity = _digest(
        case["retry_runtime_identity_sha256"],
        label=f"{case_id} retry runtime",
        optional=True,
    )
    if before != prior_identity:
        raise EvidenceError(f"installer case {case_id} starts from the wrong runtime")
    for field in (
        "injection_observed",
        "lock_contention_observed",
        "prior_runtime_restored",
        "candidate_runtime_activated",
        "staging_absent",
        "rollback_absent",
        "lock_reacquired",
    ):
        if type(case[field]) is not bool:
            raise EvidenceError(f"installer case {case_id} {field} is not boolean")
    for field in ("primary_exit_code", "contender_exit_code", "retry_exit_code"):
        value = case[field]
        if value is not None and (type(value) is not int or not 0 <= value <= 255):
            raise EvidenceError(f"installer case {case_id} {field} is invalid")

    cleanup_ok = (
        case["staging_absent"] is True
        and case["rollback_absent"] is True
        and case["lock_reacquired"] is True
    )
    if not cleanup_ok:
        raise EvidenceError(f"installer case {case_id} did not prove cleanup/lock release")

    if kind == "success":
        if (
            case["primary_exit_code"] != 0
            or case["contender_exit_code"] is not None
            or case["retry_exit_code"] is not None
            or retry_identity is not None
            or case["injection_observed"]
            or case["lock_contention_observed"]
            or not case["candidate_runtime_activated"]
            or case["prior_runtime_restored"]
            or after != candidate_identity
        ):
            raise EvidenceError("successful installer case semantics are invalid")
        return
    if kind == "concurrency":
        contender = case["contender_exit_code"]
        if (
            case["primary_exit_code"] != 0
            or type(contender) is not int
            or not 1 <= contender <= 255
            or case["injection_observed"]
            or not case["lock_contention_observed"]
            or not case["candidate_runtime_activated"]
            or case["prior_runtime_restored"]
            or case["retry_exit_code"] is not None
            or retry_identity is not None
            or after != candidate_identity
        ):
            raise EvidenceError("installer concurrency semantics are invalid")
        return

    expected_exit = _case_expected_exit(kind, signal)
    if (
        type(case["primary_exit_code"]) is not int
        or not 1 <= case["primary_exit_code"] <= 255
        or (expected_exit is not None and case["primary_exit_code"] != expected_exit)
        or case["contender_exit_code"] is not None
        or not case["injection_observed"]
        or case["lock_contention_observed"]
        or case["candidate_runtime_activated"]
        or case["prior_runtime_restored"] is not (prior_identity is not None)
        or after != prior_identity
        or case["retry_exit_code"] != 0
        or retry_identity != candidate_identity
    ):
        raise EvidenceError(f"installer {kind} case {case_id} rollback/retry semantics are invalid")


def _review_subject(evidence: dict[str, Any]) -> bytes:
    return _canonical(
        {key: value for key, value in evidence.items() if key not in {"subject_sha256", "review"}}
    )


def _load_reviewer_manifest(path: pathlib.Path) -> dict[str, Any]:
    raw = _read_regular(path, label="reviewer key manifest", limit=256 * 1024)
    value = _parse_json(raw, label="reviewer key manifest", require_canonical=True)
    _exact_keys(
        value,
        {"schema_version", "signature_required_for", "reviewers"},
        label="reviewer key manifest",
    )
    if value["schema_version"] != 1 or not isinstance(value["signature_required_for"], list):
        raise EvidenceError("reviewer key manifest schema is invalid")
    if any(item not in {"installer_drill"} for item in value["signature_required_for"]):
        raise EvidenceError("reviewer key manifest contains an unknown evidence type")
    if not isinstance(value["reviewers"], list):
        raise EvidenceError("reviewer key manifest reviewers must be an array")
    return value


def _verify_openssl_signature(
    message: bytes,
    signature: bytes,
    public_key: pathlib.Path,
    *,
    openssl: pathlib.Path = pathlib.Path("/usr/bin/openssl"),
) -> None:
    if not openssl.is_absolute() or not openssl.is_file() or not os.access(openssl, os.X_OK):
        raise EvidenceError("pinned reviewer signature requires /usr/bin/openssl")
    with tempfile.TemporaryDirectory(prefix="tinyzkp-review-") as temporary:
        root = pathlib.Path(temporary)
        message_path = root / "subject"
        signature_path = root / "signature"
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            (
                str(openssl),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ),
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    if completed.returncode != 0:
        raise EvidenceError("reviewer signature verification failed")


def _validate_review(
    evidence: dict[str, Any],
    *,
    reviewer_manifest_path: pathlib.Path,
    now: datetime,
    allow_unreviewed: bool,
) -> None:
    review = evidence["review"]
    if not isinstance(review, dict):
        raise EvidenceError("installer drill review must be an object")
    _exact_keys(
        review,
        {
            "status",
            "reviewer_name",
            "reviewer_organization",
            "reviewed_at",
            "subject_sha256",
            "signature",
        },
        label="installer drill review",
    )
    subject = _review_subject(evidence)
    subject_sha256 = _sha256(subject)
    if evidence["subject_sha256"] != subject_sha256 or review["subject_sha256"] != subject_sha256:
        raise EvidenceError("installer drill review subject hash is invalid")
    manifest = _load_reviewer_manifest(reviewer_manifest_path)
    signature_required = "installer_drill" in manifest["signature_required_for"]

    if review["status"] == "unreviewed":
        if signature_required and not allow_unreviewed:
            raise EvidenceError("installer drill requires a pinned reviewer signature")
        if any(review[key] != "" for key in ("reviewer_name", "reviewer_organization", "reviewed_at")) or review["signature"] is not None:
            raise EvidenceError("unreviewed installer evidence contains review claims")
        return
    if review["status"] != "approved":
        raise EvidenceError("installer drill review status is unsupported")
    for key in ("reviewer_name", "reviewer_organization"):
        value = review[key]
        if not isinstance(value, str) or not 2 <= len(value.strip()) <= 200:
            raise EvidenceError(f"installer drill {key} is invalid")
    reviewed_at = _timestamp(review["reviewed_at"], label="installer review time")
    captured_at = _timestamp(evidence["captured_at"], label="installer capture time")
    if not captured_at <= reviewed_at <= now + MAX_CLOCK_SKEW:
        raise EvidenceError("installer review time does not follow capture")
    signature_record = review["signature"]
    if signature_record is None:
        if signature_required:
            raise EvidenceError("installer drill requires a pinned reviewer signature")
        return
    if not isinstance(signature_record, dict):
        raise EvidenceError("installer reviewer signature must be an object")
    _exact_keys(
        signature_record,
        {"algorithm", "key_id", "signature_base64url"},
        label="installer reviewer signature",
    )
    if signature_record["algorithm"] != "ed25519":
        raise EvidenceError("installer reviewer signature algorithm is unsupported")
    key_id = signature_record["key_id"]
    if not isinstance(key_id, str) or SAFE_ID_RE.fullmatch(key_id) is None:
        raise EvidenceError("installer reviewer key ID is invalid")
    matches = [record for record in manifest["reviewers"] if isinstance(record, dict) and record.get("key_id") == key_id]
    if len(matches) != 1:
        raise EvidenceError("installer reviewer key is not uniquely pinned")
    key = matches[0]
    _exact_keys(
        key,
        {"key_id", "algorithm", "public_key_path", "public_key_sha256"},
        label="pinned reviewer key",
    )
    if key["algorithm"] != "ed25519" or _digest(key["public_key_sha256"], label="reviewer public key hash") is None:
        raise EvidenceError("pinned reviewer key metadata is invalid")
    relative = pathlib.PurePosixPath(str(key["public_key_path"]))
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise EvidenceError("reviewer public key path is unsafe")
    public_key = ROOT.joinpath(*relative.parts)
    public_raw = _read_regular(public_key, label="reviewer public key", limit=64 * 1024)
    if _sha256(public_raw) != key["public_key_sha256"]:
        raise EvidenceError("reviewer public key differs from its pin")
    encoded = signature_record["signature_base64url"]
    if not isinstance(encoded, str) or not 80 <= len(encoded) <= 100 or "=" in encoded:
        raise EvidenceError("reviewer signature encoding is invalid")
    try:
        signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, base64.binascii.Error) as error:
        raise EvidenceError("reviewer signature encoding is invalid") from error
    if len(signature) != 64:
        raise EvidenceError("reviewer Ed25519 signature length is invalid")
    _verify_openssl_signature(subject, signature, public_key)


def validate_evidence(
    path: pathlib.Path,
    *,
    expected_release_sha: str,
    expected_host_identity_sha256: str,
    expected_deployment_id: str,
    reviewer_manifest_path: pathlib.Path = DEFAULT_REVIEWER_MANIFEST,
    now: datetime | None = None,
    enforce_fixed_path: bool = True,
    enforce_host: bool = True,
    required_uid: int = 0,
    root: pathlib.Path = ROOT,
    machine_id_file: pathlib.Path = FIXED_MACHINE_ID,
    allow_unreviewed: bool = False,
) -> dict[str, object]:
    if SHA1_RE.fullmatch(expected_release_sha) is None:
        raise EvidenceError("expected installer release SHA is invalid")
    _digest(expected_host_identity_sha256, label="expected installer host identity")
    if DEPLOYMENT_RE.fullmatch(expected_deployment_id) is None:
        raise EvidenceError("expected installer deployment ID is invalid")
    if enforce_fixed_path and path != FIXED_EVIDENCE:
        raise EvidenceError("installer drill evidence must use its fixed production path")
    if enforce_host:
        architecture = platform.machine().lower()
        if os.geteuid() != 0 or sys.platform != "linux" or architecture not in {"x86_64", "amd64"}:
            raise EvidenceError("installer evidence requires root on Linux x86-64")
        if _host_identity(machine_id_file) != expected_host_identity_sha256:
            raise EvidenceError("installer evidence host identity differs from this host")
    raw = _read_regular(
        path,
        label="installer drill evidence",
        limit=MAX_EVIDENCE_BYTES,
        exact_mode=0o600 if enforce_fixed_path else None,
        required_uid=required_uid if enforce_fixed_path else None,
    )
    evidence = _parse_json(raw, label="installer drill evidence", require_canonical=True)
    _exact_keys(
        evidence,
        {
            "schema_version",
            "status",
            "captured_at",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "run_id",
            "effective_uid",
            "source",
            "prior_runtime_identity_sha256",
            "candidate_runtime_identity_sha256",
            "cases",
            "subject_sha256",
            "review",
        },
        label="installer drill evidence",
    )
    if evidence["schema_version"] != SCHEMA or evidence["status"] != "pass":
        raise EvidenceError("installer drill evidence is not a passing supported schema")
    if (
        evidence["release_sha"] != expected_release_sha
        or evidence["host_identity_sha256"] != expected_host_identity_sha256
        or evidence["deployment_id"] != expected_deployment_id
        or evidence["effective_uid"] != 0
        or not isinstance(evidence["run_id"], str)
        or RUN_ID_RE.fullmatch(evidence["run_id"]) is None
    ):
        raise EvidenceError("installer drill identity does not match the deployment")
    captured_at = _timestamp(evidence["captured_at"], label="installer capture time")
    checked_at = now or datetime.now(timezone.utc)
    age = checked_at - captured_at
    if age < -MAX_CLOCK_SKEW or age > MAX_AGE:
        raise EvidenceError("installer drill evidence is stale or future-dated")
    source = evidence["source"]
    expected_source = source_identity(root)
    if not isinstance(source, dict) or source != expected_source:
        raise EvidenceError("installer drill source hashes differ from the reviewed release")
    prior_identity = _digest(
        evidence["prior_runtime_identity_sha256"],
        label="prior installer runtime",
        optional=True,
    )
    candidate_identity = _digest(
        evidence["candidate_runtime_identity_sha256"],
        label="candidate installer runtime",
    )
    if prior_identity == candidate_identity:
        raise EvidenceError("installer drill prior and candidate runtimes must differ")
    cases = evidence["cases"]
    if not isinstance(cases, list) or len(cases) != len(REQUIRED_CASES):
        raise EvidenceError("installer drill case set is incomplete")
    for case, expected in zip(cases, REQUIRED_CASES):
        if not isinstance(case, dict):
            raise EvidenceError("installer drill case must be an object")
        _validate_case(
            case,
            expected=expected,
            prior_identity=prior_identity,
            candidate_identity=str(candidate_identity),
            captured_at=captured_at,
        )
    _digest(evidence["subject_sha256"], label="installer drill subject")
    _validate_review(
        evidence,
        reviewer_manifest_path=reviewer_manifest_path,
        now=checked_at,
        allow_unreviewed=allow_unreviewed,
    )
    identity = _sha256(raw)
    return {
        "schema_version": 1,
        "status": "pass",
        "run_id": evidence["run_id"],
        "captured_at": evidence["captured_at"],
        "case_count": len(cases),
        "subject_sha256": evidence["subject_sha256"],
        "evidence_identity_sha256": identity,
        "review_status": evidence["review"]["status"],
    }


def _capture_case(raw_case: dict[str, Any], raw_root: pathlib.Path) -> dict[str, Any]:
    expected = {
        "case_id",
        "kind",
        "phase",
        "signal",
        "started_at",
        "completed_at",
        "effective_uid",
        "command_argv_sha256",
        "stdout_log",
        "stderr_log",
        "primary_exit_code",
        "contender_exit_code",
        "injection_observed",
        "lock_contention_observed",
        "before_runtime_identity_sha256",
        "after_runtime_identity_sha256",
        "prior_runtime_restored",
        "candidate_runtime_activated",
        "staging_absent",
        "rollback_absent",
        "lock_reacquired",
        "retry_exit_code",
        "retry_runtime_identity_sha256",
    }
    _exact_keys(raw_case, expected, label="raw installer case")
    result = {key: value for key, value in raw_case.items() if key not in {"stdout_log", "stderr_log"}}
    for field, target in (("stdout_log", "stdout"), ("stderr_log", "stderr")):
        name = raw_case[field]
        if not isinstance(name, str) or pathlib.PurePosixPath(name).name != name or name in {".", ".."}:
            raise EvidenceError(f"raw installer {field} is unsafe")
        result[target] = _log_descriptor(raw_root / name, label=f"raw installer {field}")
    return result


def capture_evidence(
    observations_path: pathlib.Path,
    raw_root: pathlib.Path,
    output: pathlib.Path,
    *,
    reviewer_manifest_path: pathlib.Path = DEFAULT_REVIEWER_MANIFEST,
    review_path: pathlib.Path | None = None,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    raw = _read_regular(observations_path, label="installer observations", limit=MAX_EVIDENCE_BYTES)
    observations = _parse_json(raw, label="installer observations", require_canonical=False)
    _exact_keys(
        observations,
        {
            "schema_version",
            "captured_at",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "run_id",
            "effective_uid",
            "prior_runtime_identity_sha256",
            "candidate_runtime_identity_sha256",
            "cases",
        },
        label="installer observations",
    )
    if observations["schema_version"] != OBSERVATION_SCHEMA or not isinstance(observations["cases"], list):
        raise EvidenceError("installer observation schema is unsupported")
    evidence: dict[str, Any] = {
        **{key: value for key, value in observations.items() if key != "cases"},
        "schema_version": SCHEMA,
        "status": "pass",
        "source": source_identity(root),
        "cases": [_capture_case(case, raw_root) for case in observations["cases"]],
    }
    evidence["subject_sha256"] = _sha256(_review_subject({**evidence, "review": {}}))
    if review_path is None:
        evidence["review"] = {
            "status": "unreviewed",
            "reviewer_name": "",
            "reviewer_organization": "",
            "reviewed_at": "",
            "subject_sha256": evidence["subject_sha256"],
            "signature": None,
        }
    else:
        review_raw = _read_regular(review_path, label="installer drill review input", limit=256 * 1024)
        review = _parse_json(review_raw, label="installer drill review input", require_canonical=False)
        evidence["review"] = {**review, "subject_sha256": evidence["subject_sha256"]}
    encoded = _canonical(evidence)
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("installer drill evidence exceeds its size limit")
    if output.exists() or output.is_symlink():
        raise EvidenceError("installer drill evidence output already exists")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return validate_evidence(
        output,
        expected_release_sha=observations["release_sha"],
        expected_host_identity_sha256=observations["host_identity_sha256"],
        expected_deployment_id=observations["deployment_id"],
        reviewer_manifest_path=reviewer_manifest_path,
        enforce_fixed_path=False,
        enforce_host=False,
        required_uid=os.geteuid(),
        root=root,
        allow_unreviewed=True,
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence", type=pathlib.Path, default=FIXED_EVIDENCE)
    verify.add_argument("--expected-release-sha", required=True)
    verify.add_argument("--expected-host-identity-sha256")
    verify.add_argument("--expected-deployment-id", required=True)
    verify.add_argument("--machine-id-file", type=pathlib.Path, default=FIXED_MACHINE_ID)
    verify.add_argument("--reviewer-manifest", type=pathlib.Path, default=DEFAULT_REVIEWER_MANIFEST)
    verify.add_argument("--json", action="store_true")

    capture = subparsers.add_parser("capture")
    capture.add_argument("--observations", type=pathlib.Path, required=True)
    capture.add_argument("--raw-dir", type=pathlib.Path, required=True)
    capture.add_argument("--output", type=pathlib.Path, default=FIXED_EVIDENCE)
    capture.add_argument("--review", type=pathlib.Path)
    capture.add_argument("--reviewer-manifest", type=pathlib.Path, default=DEFAULT_REVIEWER_MANIFEST)
    subparsers.add_parser(
        "required-cases",
        help="Print the exact ordered case identities required in raw observations",
    )
    args = parser.parse_args(argv)
    if args.command == "required-cases":
        print(
            json.dumps(
                [
                    {
                        "case_id": case_id,
                        "kind": kind,
                        "phase": phase,
                        "signal": signal,
                    }
                    for case_id, kind, phase, signal in REQUIRED_CASES
                ],
                sort_keys=True,
            )
        )
        return 0
    try:
        if args.command == "capture":
            report = capture_evidence(
                args.observations,
                args.raw_dir,
                args.output,
                reviewer_manifest_path=args.reviewer_manifest,
                review_path=args.review,
            )
        else:
            derived = _host_identity(args.machine_id_file)
            if args.expected_host_identity_sha256 and not hmac.compare_digest(
                args.expected_host_identity_sha256, derived
            ):
                raise EvidenceError("explicit installer host identity differs from machine ID")
            report = validate_evidence(
                args.evidence,
                expected_release_sha=args.expected_release_sha,
                expected_host_identity_sha256=derived,
                expected_deployment_id=args.expected_deployment_id,
                reviewer_manifest_path=args.reviewer_manifest,
                machine_id_file=args.machine_id_file,
            )
    except (EvidenceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAIL installer drill evidence - {error}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "PASS installer drill evidence "
            f"({report['case_count']} cases; run {report['run_id']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
