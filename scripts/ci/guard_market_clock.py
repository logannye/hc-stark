#!/usr/bin/env python3
"""Derive the closed TinyZKP market clock from signed artifact/outreach evidence."""

from __future__ import annotations

import argparse
import calendar
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import guard_launch_gate as launch  # noqa: E402
import strict_json  # noqa: E402


SOURCE = ROOT / "release" / "guard-market-evidence-v1.json"
OUTPUT = ROOT / "release" / "guard-market-clock-v1.json"
EVIDENCE_PREFIX = PurePosixPath("release/evidence/guard-market-v1")
INITIAL_DECISION_DATE = "2026-10-16"
MARKET_EVIDENCE_MAX_AGE = timedelta(days=180)
SUBJECTS = {
    "doctor_evaluation_release": (
        "DoctorEvaluationReleaseEvidenceV1",
        "guard_market:doctor_evaluation_release",
        "signed-doctor-evaluation-release-missing",
    ),
    "community_announcement": (
        "CommunityAnnouncementEvidenceV1",
        "guard_market:community_announcement",
        "moderator-approved-plonky3-announcement-missing",
    ),
    "ecosystem_submission": (
        "EcosystemSubmissionEvidenceV1",
        "guard_market:ecosystem_submission",
        "post-qualification-ecosystem-submission-not-made",
    ),
}


class MarketError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return launch.canonical_bytes(value)


def load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = strict_json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise MarketError(f"cannot read strict {label}: {error}") from error
    if not isinstance(value, dict):
        raise MarketError(f"{label} must be an object")
    return value


def safe_file(root: Path, relative: str) -> tuple[Path, bytes]:
    pure = PurePosixPath(relative)
    if (
        not isinstance(relative, str)
        or pure.is_absolute()
        or pure.parts[: len(EVIDENCE_PREFIX.parts)] != EVIDENCE_PREFIX.parts
        or pure.suffix != ".json"
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != relative
    ):
        raise MarketError("market evidence path is outside the locked directory")
    path = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise MarketError("market evidence path contains a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise MarketError("market evidence must be a single-link regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > launch.MAX_EVIDENCE_BYTES:
        raise MarketError("market evidence size is invalid")
    return path, raw


def iso(value: Any, label: str) -> datetime:
    try:
        parsed = launch.parse_timestamp(value, label)
    except launch.GateError as error:
        raise MarketError(str(error)) from error
    return parsed


def https_url(value: Any, label: str) -> str:
    try:
        return launch._validate_https_url(
            value,
            label,
            required=True,
            allowed_hosts=("github.com", "githubusercontent.com"),
        )
    except launch.GateError as error:
        raise MarketError(str(error)) from error


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    try:
        return launch.exact_object(value, fields, label)
    except launch.GateError as error:
        raise MarketError(str(error)) from error


def validate_claims(subject: str, claims: dict[str, Any]) -> dict[str, Any]:
    if subject == "doctor_evaluation_release":
        booleans = {
            "signature_verified",
            "attestation_verified",
            "exact_contract_doctor_command",
            "prerelease",
        }
        exact(
            claims,
            {
                "release_tag",
                "release_url",
                "engine_source_sha",
                "engine_artifact_sha256",
                "oci_digest",
                "schema_bundle_sha256",
                "synthetic_job_sha256",
                "published_at",
                *booleans,
            },
            "doctor evaluation claims",
        )
        if not isinstance(claims["release_tag"], str) or not claims[
            "release_tag"
        ].startswith("doctor-eval-v"):
            raise MarketError("doctor evaluation tag must use doctor-eval-v*")
        https_url(claims["release_url"], "doctor evaluation release URL")
        if not launch.GIT_SHA_RE.fullmatch(claims["engine_source_sha"]):
            raise MarketError("doctor evaluation engine source SHA is malformed")
        for field in (
            "engine_artifact_sha256",
            "schema_bundle_sha256",
            "synthetic_job_sha256",
        ):
            if not launch.SHA256_RE.fullmatch(claims[field]):
                raise MarketError(f"doctor evaluation {field} is malformed")
        if not isinstance(claims["oci_digest"], str) or not claims[
            "oci_digest"
        ].startswith("sha256:") or not launch.SHA256_RE.fullmatch(
            claims["oci_digest"][7:]
        ):
            raise MarketError("doctor evaluation OCI digest is malformed")
        if any(claims[field] is not True for field in booleans):
            raise MarketError("doctor evaluation release is not fully signed/attested")
        iso(claims["published_at"], "doctor evaluation published_at")
    elif subject == "community_announcement":
        exact(
            claims,
            {
                "community",
                "announcement_url",
                "announced_at",
                "doctor_release_tag",
                "moderator_approved",
                "announcement_count",
                "direct_messages_sent",
                "outbound_campaign",
                "recurring_campaign",
            },
            "community announcement claims",
        )
        if (
            claims["community"] != "plonky3"
            or claims["moderator_approved"] is not True
            or claims["announcement_count"] != 1
            or claims["direct_messages_sent"] != 0
            or claims["outbound_campaign"] is not False
            or claims["recurring_campaign"] is not False
        ):
            raise MarketError("community announcement violates the one-shot policy")
        https_url(claims["announcement_url"], "community announcement URL")
        iso(claims["announced_at"], "community announcement announced_at")
    else:
        exact(
            claims,
            {
                "list",
                "submission_url",
                "submitted_at",
                "submission_count",
                "launch_qualified_at_submission",
            },
            "ecosystem submission claims",
        )
        if (
            claims["list"] != "awesome-plonky3"
            or claims["submission_count"] != 1
            or claims["launch_qualified_at_submission"] is not True
        ):
            raise MarketError("ecosystem submission violates the locked policy")
        https_url(claims["submission_url"], "ecosystem submission URL")
        iso(claims["submitted_at"], "ecosystem submission submitted_at")
    return claims


def validate_evidence(
    root: Path,
    subject: str,
    references: Any,
    trust: dict[str, Any],
    evaluated_at: datetime,
    *,
    current_time: datetime | None,
    signature_runner: Callable[..., subprocess.CompletedProcess[str]],
    cosign_path: Path | None,
) -> dict[str, Any]:
    if not isinstance(references, list) or len(references) != 1:
        raise MarketError(f"{subject} requires exactly one signed evidence record")
    reference = exact(
        references[0],
        {
            "path",
            "sha256",
            "signature_path",
            "signature_sha256",
            "signer_id",
            "purpose",
        },
        f"{subject} evidence reference",
    )
    kind, purpose, _reason = SUBJECTS[subject]
    if reference["purpose"] != purpose:
        raise MarketError(f"{subject} evidence purpose differs")
    path, raw = safe_file(root, reference["path"])
    bundle, bundle_raw = safe_file(root, reference["signature_path"])
    if (
        hashlib.sha256(raw).hexdigest() != reference["sha256"]
        or hashlib.sha256(bundle_raw).hexdigest()
        != reference["signature_sha256"]
    ):
        raise MarketError(f"{subject} evidence digest differs")
    try:
        launch._verify_signature(
            claim=path,
            bundle=bundle,
            signer_id=reference["signer_id"],
            purpose=purpose,
            trust_policy=trust,
            runner=signature_runner,
            cosign_path=cosign_path,
        )
    except launch.GateError as error:
        raise MarketError(str(error)) from error
    envelope = exact(
        strict_json.loads(raw),
        {
            "schema_version",
            "document_type",
            "evidence_kind",
            "subject",
            "result",
            "issued_at",
            "claims",
        },
        f"{subject} evidence",
    )
    if (
        envelope["schema_version"] != 1
        or envelope["document_type"] != "GuardMarketEvidenceRecordV1"
        or envelope["evidence_kind"] != kind
        or envelope["subject"] != subject
        or envelope["result"] != "passed"
    ):
        raise MarketError(f"{subject} evidence type/result differs")
    issued_at = iso(envelope["issued_at"], f"{subject} issued_at")
    if issued_at > evaluated_at:
        raise MarketError(f"{subject} evidence is future-dated")
    if current_time is not None:
        if issued_at > current_time:
            raise MarketError(f"{subject} evidence is future-dated at action time")
        if current_time - issued_at > MARKET_EVIDENCE_MAX_AGE:
            raise MarketError(f"{subject} evidence is older than 180 days")
    return validate_claims(subject, envelope["claims"])


def add_months(value: datetime, months: int) -> datetime:
    index = value.month - 1 + months
    year = value.year + index // 12
    month = index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def derive(
    source: dict[str, Any],
    *,
    root: Path = ROOT,
    trusted_policy_sha256: str | None = None,
    signature_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    cosign_path: Path | None = None,
    require_current_evaluation: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    exact(
        source,
        {
            "schema_version",
            "document_type",
            "evaluated_at",
            "trust_policy",
            *SUBJECTS,
            "acquisition_policy",
        },
        "GuardMarketEvidenceV1",
    )
    if source["schema_version"] != 1 or source["document_type"] != "GuardMarketEvidenceV1":
        raise MarketError("market source schema/type is invalid")
    evaluated_at = iso(source["evaluated_at"], "market evaluated_at")
    statuses = {
        subject: exact(
            source[subject],
            {"status", "reason_code", "evidence"},
            subject,
        )
        for subject in SUBJECTS
    }
    any_passed = any(record["status"] == "passed" for record in statuses.values())
    current: datetime | None = None
    if require_current_evaluation and any_passed:
        current = now or datetime.now(timezone.utc).replace(microsecond=0)
        if current.tzinfo != timezone.utc:
            raise MarketError("current market-gate time must be UTC")
        if evaluated_at > current:
            raise MarketError("market evaluated_at is future-dated")
        if current - evaluated_at > launch.CURRENT_EVALUATION_MAX_AGE:
            raise MarketError("market evaluated_at is older than 24 hours")
    if any_passed and trusted_policy_sha256 is None:
        raise MarketError("market evidence requires an independently protected trust root")
    try:
        trust = launch._load_trust_policy(
            root,
            source["trust_policy"],
            externally_trusted_sha256=trusted_policy_sha256,
            expected_path="release/guard-market-trust-v1.json",
        )
    except launch.GateError as error:
        raise MarketError(str(error)) from error
    if any_passed and not trust["signers"]:
        raise MarketError("market evidence requires an externally trusted signer")
    if not any_passed and trust["signers"]:
        raise MarketError("prelaunch market trust must remain empty")

    claims: dict[str, dict[str, Any]] = {}
    output_status: dict[str, Any] = {}
    for subject, record in statuses.items():
        _kind, _purpose, reason = SUBJECTS[subject]
        if record["status"] == "blocked":
            if record["reason_code"] != reason or record["evidence"] != []:
                raise MarketError(f"blocked {subject} record differs")
        elif record["status"] == "passed":
            if record["reason_code"] is not None:
                raise MarketError(f"passed {subject} must have no reason")
            claims[subject] = validate_evidence(
                root,
                subject,
                record["evidence"],
                trust,
                evaluated_at,
                current_time=current,
                signature_runner=signature_runner,
                cosign_path=cosign_path,
            )
        else:
            raise MarketError(f"{subject} status must be blocked or passed")
        output_status[subject] = {
            "status": record["status"],
            "reason_code": record["reason_code"],
        }

    policy = exact(
        source["acquisition_policy"],
        {
            "community",
            "announcement_limit",
            "ecosystem_submission_limit",
            "direct_messages_allowed",
            "outbound_campaigns_allowed",
            "recurring_campaigns_allowed",
            "ongoing_blog_required",
            "newsletter_allowed",
        },
        "acquisition_policy",
    )
    if policy != {
        "community": "plonky3",
        "announcement_limit": 1,
        "ecosystem_submission_limit": 1,
        "direct_messages_allowed": False,
        "outbound_campaigns_allowed": False,
        "recurring_campaigns_allowed": False,
        "ongoing_blog_required": False,
        "newsletter_allowed": False,
    }:
        raise MarketError("acquisition policy differs from the locked one-shot policy")

    doctor = claims.get("doctor_evaluation_release")
    announcement = claims.get("community_announcement")
    started = doctor is not None and announcement is not None
    if started and announcement["doctor_release_tag"] != doctor["release_tag"]:
        raise MarketError("announcement references a different doctor release")
    started_at = iso(announcement["announced_at"], "announced_at") if started else None
    if announcement is not None and doctor is None:
        raise MarketError("community announcement cannot precede signed doctor evidence")
    return {
        "schema_version": 1,
        "document_type": "GuardMarketClockV1",
        "generated_from": "release/guard-market-evidence-v1.json",
        "source_sha256": hashlib.sha256(canonical(source)).hexdigest(),
        "evaluated_at": source["evaluated_at"],
        "status": "running" if started else "not_started",
        "started_at": (
            started_at.isoformat().replace("+00:00", "Z") if started_at else None
        ),
        "initial_decision_date": INITIAL_DECISION_DATE,
        "day_90_deadline": (
            (started_at + timedelta(days=90)).isoformat().replace("+00:00", "Z")
            if started_at
            else None
        ),
        "six_month_stop_deadline": (
            add_months(started_at, 6).isoformat().replace("+00:00", "Z")
            if started_at
            else None
        ),
        "doctor_evaluation_release": {
            **output_status["doctor_evaluation_release"],
            "identity": (
                {
                    key: doctor[key]
                    for key in (
                        "release_tag",
                        "release_url",
                        "engine_source_sha",
                        "engine_artifact_sha256",
                        "oci_digest",
                        "schema_bundle_sha256",
                        "synthetic_job_sha256",
                        "published_at",
                    )
                }
                if doctor
                else None
            ),
        },
        "community_announcement": output_status["community_announcement"],
        "ecosystem_submission": output_status["ecosystem_submission"],
        "acquisition_policy": policy,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument(
        "--trusted-policy-sha256",
        default=os.environ.get("TINYZKP_GUARD_MARKET_TRUST_POLICY_SHA256"),
    )
    args = parser.parse_args(argv)
    if args.check and args.write:
        parser.error("--check and --write are mutually exclusive")
    try:
        derived = derive(
            load(args.source, "market source"),
            root=args.root.resolve(),
            trusted_policy_sha256=args.trusted_policy_sha256,
            require_current_evaluation=args.write,
        )
        if args.check or not args.write:
            if OUTPUT.read_bytes() != canonical(derived):
                raise MarketError("guard-market-clock-v1.json is not generated")
        if args.write:
            temporary = OUTPUT.with_suffix(".json.tmp")
            temporary.write_bytes(canonical(derived))
            os.replace(temporary, OUTPUT)
    except (OSError, MarketError, ValueError) as error:
        print(f"guard market clock: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": derived["status"], "started_at": derived["started_at"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
