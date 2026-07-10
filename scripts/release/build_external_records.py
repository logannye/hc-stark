#!/usr/bin/env python3
"""Build hash-bound external review, reproduction, and partner records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import backend_release_ready as release_gate


PROFILE = "tinyzkp-p3-goldilocks-v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024


def resource_roles(*, baseline: bool) -> tuple[str, ...]:
    suffixes = ["manifest", "candidate_report", "candidate_normalized_manifest"]
    if baseline:
        suffixes.extend(("baseline_report", "baseline_normalized_manifest"))
    return tuple(
        f"{workload}_{suffix}"
        for workload in ("fibonacci", "poseidon2")
        for suffix in suffixes
    )


INDEPENDENT_RESOURCE_ROLES = tuple(
    [f"one_million_{role}" for role in resource_roles(baseline=True)]
    + [f"ten_million_{role}" for role in resource_roles(baseline=False)]
)


def safe_file(raw: Path) -> Path:
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"input is outside the repository: {raw}") from error
    current = ROOT
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"input contains a symlink: {raw}")
    if not candidate.is_file() or candidate.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input is missing or oversized: {raw}")
    return candidate


def safe_output(raw: Path) -> Path:
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"output is outside the repository: {raw}") from error
    current = ROOT
    for part in relative.parent.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"output parent contains a symlink: {raw}")
    if candidate.is_symlink():
        raise ValueError(f"output is a symlink: {raw}")
    return candidate


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def staged_record_path(output: Path) -> Path:
    return output.with_name(f".{output.name}.validation-{os.getpid()}.json")


def parse_artifacts(values: list[str], expected: tuple[str, ...]) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("artifact must be ROLE=REPOSITORY_RELATIVE_PATH")
        role, raw_path = value.split("=", 1)
        if not role or role in parsed:
            raise ValueError(f"artifact role is missing or duplicated: {role}")
        parsed[role] = safe_file(Path(raw_path))
    if set(parsed) != set(expected):
        missing = sorted(set(expected) - set(parsed))
        extra = sorted(set(parsed) - set(expected))
        raise ValueError(f"artifact roles mismatch; missing={missing}, extra={extra}")
    return parsed


def reproduction_record(
    *,
    release_sha: str,
    reproducer: str,
    organization: str,
    completed_at: str,
    artifacts: dict[str, Path],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "independent": True,
        "reproducer": reproducer,
        "organization": organization,
        "completed_at": completed_at,
        "official_verification": True,
        "workloads": ["fibonacci", "poseidon2_goldilocks"],
        "gates": ["one-million", "ten-million"],
        "artifact_sha256": {role: sha256(path) for role, path in sorted(artifacts.items())},
    }


def validate_findings(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ValueError("findings input must contain a JSON array")
    findings: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != {
            "id",
            "severity",
            "status",
            "reviewer_verified",
        }:
            raise ValueError("each finding must contain exactly id/severity/status/reviewer_verified")
        identifier = finding.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("finding IDs must be unique non-empty strings")
        identifiers.add(identifier)
        if finding.get("severity") not in {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
        } or finding.get("status") not in {
            "open",
            "remediated",
            "accepted_by_reviewer",
        } or not isinstance(finding.get("reviewer_verified"), bool):
            raise ValueError(f"finding is malformed: {identifier}")
        findings.append(finding)
    return findings


def review_ledger(
    *,
    release_sha: str,
    scope: str,
    reviewer: str,
    completed_at: str,
    report: Path,
    findings: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "review_scope": scope,
        "completed_at": completed_at,
        "reviewer": reviewer,
        "reviewer_independent": True,
        "review_report_sha256": sha256(report),
        "findings": findings,
    }


def partner_acceptance(
    *,
    release_sha: str,
    acceptance_id: str,
    partner_id: str,
    accepted_at: str,
    adapter_result: Path,
    resource_report: Path,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "acceptance_id": acceptance_id,
        "partner_id": partner_id,
        "accepted_at": accepted_at,
        "official_verification": True,
        "bounded_equals_conventional": True,
        "witness_data_committed": False,
        "adapter_result_sha256": sha256(adapter_result),
        "resource_report_sha256": sha256(resource_report),
    }


def nonempty(value: str, label: str) -> str:
    if not value or len(value) > 256:
        raise ValueError(f"{label} must be non-empty and at most 256 characters")
    return value


def build_reproduction(args: argparse.Namespace) -> None:
    release_sha = nonempty(args.release_sha, "release SHA")
    artifacts = parse_artifacts(args.artifact, INDEPENDENT_RESOURCE_ROLES)
    for kind, marker in (
        ("resource_one_million", "one_million_"),
        ("resource_ten_million", "ten_million_"),
    ):
        selected = [
            (path, {"role": role.removeprefix(marker)})
            for role, path in artifacts.items()
            if role.startswith(marker)
        ]
        failures = release_gate.validate_resource_gate(kind, selected, release_sha)
        if failures:
            raise ValueError("independent resource evidence failed validation: " + "; ".join(failures))
    record = reproduction_record(
        release_sha=release_sha,
        reproducer=nonempty(args.reproducer, "reproducer"),
        organization=nonempty(args.organization, "organization"),
        completed_at=nonempty(args.completed_at, "completion time"),
        artifacts=artifacts,
    )
    output = safe_output(args.output)
    staged = staged_record_path(output)
    write_json_atomic(staged, record)
    evidence = [(staged, {"role": "reproduction_record"})] + [
        (path, {"role": role}) for role, path in artifacts.items()
    ]
    metadata = {
        "release_sha": release_sha,
        "independent": True,
        "reproducer": args.reproducer,
        "organization": args.organization,
        "completed_at": args.completed_at,
    }
    try:
        failures = release_gate.validate_independent_reproduction(
            evidence, metadata, release_sha
        )
        if failures:
            raise ValueError(
                "independent record failed validation: " + "; ".join(failures)
            )
        os.replace(staged, output)
    except Exception:
        staged.unlink(missing_ok=True)
        raise


def build_review(args: argparse.Namespace) -> None:
    findings_path = safe_file(args.findings)
    findings = validate_findings(json.loads(findings_path.read_text(encoding="utf-8")))
    record = review_ledger(
        release_sha=nonempty(args.release_sha, "release SHA"),
        scope=args.scope,
        reviewer=nonempty(args.reviewer, "reviewer"),
        completed_at=nonempty(args.completed_at, "completion time"),
        report=safe_file(args.review_report),
        findings=findings,
    )
    write_json_atomic(safe_output(args.output), record)


def build_partner(args: argparse.Namespace) -> None:
    release_sha = nonempty(args.release_sha, "release SHA")
    adapter = safe_file(args.adapter_result)
    resource = safe_file(args.resource_report)
    record = partner_acceptance(
        release_sha=release_sha,
        acceptance_id=nonempty(args.acceptance_id, "acceptance ID"),
        partner_id=nonempty(args.partner_id, "partner ID"),
        accepted_at=nonempty(args.accepted_at, "acceptance time"),
        adapter_result=adapter,
        resource_report=resource,
    )
    output = safe_output(args.output)
    staged = staged_record_path(output)
    write_json_atomic(staged, record)
    try:
        failures = release_gate.validate_partner_evidence(
            [
                (adapter, {"role": "adapter_result"}),
                (resource, {"role": "resource_report"}),
                (staged, {"role": "acceptance_record"}),
            ],
            release_sha,
            {"partner_acceptance_id": args.acceptance_id},
        )
        if failures:
            raise ValueError(
                "partner acceptance failed validation: " + "; ".join(failures)
            )
        os.replace(staged, output)
    except Exception:
        staged.unlink(missing_ok=True)
        raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    reproduction = commands.add_parser("reproduction")
    reproduction.add_argument("--release-sha", required=True)
    reproduction.add_argument("--reproducer", required=True)
    reproduction.add_argument("--organization", required=True)
    reproduction.add_argument("--completed-at", required=True)
    reproduction.add_argument("--artifact", action="append", default=[])
    reproduction.add_argument("--output", type=Path, required=True)

    review = commands.add_parser("review-ledger")
    review.add_argument("--release-sha", required=True)
    review.add_argument("--scope", choices=("plonky3_specialist", "implementation"), required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--completed-at", required=True)
    review.add_argument("--review-report", type=Path, required=True)
    review.add_argument("--findings", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)

    partner = commands.add_parser("partner-acceptance")
    partner.add_argument("--release-sha", required=True)
    partner.add_argument("--acceptance-id", required=True)
    partner.add_argument("--partner-id", required=True)
    partner.add_argument("--accepted-at", required=True)
    partner.add_argument("--adapter-result", type=Path, required=True)
    partner.add_argument("--resource-report", type=Path, required=True)
    partner.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.command == "reproduction":
            build_reproduction(args)
        elif args.command == "review-ledger":
            build_review(args)
        else:
            build_partner(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"external evidence record failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
