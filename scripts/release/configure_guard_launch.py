#!/usr/bin/env python3
"""Apply a strict owner-reviewed Guard launch configuration or freeze sales."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import guard_launch_gate as gate  # noqa: E402
import strict_json  # noqa: E402


class ConfigurationError(ValueError):
    pass


CONFIG_FIELDS = {
    "schema_version",
    "document_type",
    "expected_current_commerce_state",
    "requested_commerce_state",
    "release_change_class",
    "release_identity",
    "merchant",
    "legal_action",
    "legal_release_date",
}
FORWARD_TRANSITIONS = {
    ("unconfigured", "test_published"),
    ("test_published", "test_verified"),
    ("test_verified", "live_hidden"),
}


def _load_strict(path: Path, label: str) -> dict:
    try:
        value = strict_json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise ConfigurationError(f"cannot read strict {label}: {error}") from error
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be an object")
    return value


def _atomic_source_write(path: Path, source: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(gate.canonical_bytes(source))
    os.replace(temporary, path)


def apply_configuration(*, root: Path, configuration_path: Path, issued_at: str) -> dict:
    source_path = root / "release/guard-launch-evidence-v2.json"
    source = gate.load_json(source_path, "GuardLaunchEvidenceV2")
    configuration = gate.exact_object(
        _load_strict(configuration_path, "owner launch configuration"),
        CONFIG_FIELDS,
        "GuardOwnerLaunchConfigurationV1",
    )
    if (
        configuration["schema_version"] != 1
        or configuration["document_type"] != "GuardOwnerLaunchConfigurationV1"
    ):
        raise ConfigurationError("owner launch configuration identity differs")
    current_state = source.get("requested_commerce_state")
    target_state = configuration["requested_commerce_state"]
    if (
        configuration["expected_current_commerce_state"] != current_state
        or (current_state, target_state) not in FORWARD_TRANSITIONS
    ):
        raise ConfigurationError("commerce transition is not the expected next state")
    if current_state == "unconfigured":
        if any(record.get("status") != "blocked" for record in source["gates"].values()):
            raise ConfigurationError("bootstrap requires every launch gate blocked")
        if source["prior_qualified_release"].get("status") != "blocked":
            raise ConfigurationError("bootstrap cannot overwrite prior release evidence")
    identity = gate._validate_identity(
        configuration["release_identity"], qualified=True
    )
    current_identity = source["release_identity"]
    if current_state != "unconfigured" and current_identity != identity:
        raise ConfigurationError("configuration cannot change the active candidate identity")
    if configuration["release_change_class"] not in {
        "proof_critical",
        "guard_package_only",
        "site_legal_pricing",
    }:
        raise ConfigurationError("release change class is invalid")
    if current_state != "unconfigured" and (
        source["release_change_class"] != configuration["release_change_class"]
    ):
        raise ConfigurationError("configuration cannot change the release change class")
    legal_action = configuration["legal_action"]
    if legal_action == "approve_exact_repository_bytes":
        release_date = configuration["legal_release_date"]
        try:
            parsed_date = datetime.strptime(release_date, "%Y-%m-%d")
        except (TypeError, ValueError) as error:
            raise ConfigurationError("legal_release_date must be YYYY-MM-DD") from error
        if parsed_date.strftime("%Y-%m-%d") != release_date:
            raise ConfigurationError("legal_release_date must be YYYY-MM-DD")
        legal = {
            "seller_status": "confirmed",
            "owner_approval_status": "approved",
            "release_date": release_date,
            **{
                field: gate._legal_document_sha256(root, field)
                for field in gate.LEGAL_DOCUMENT_PATHS
            },
        }
    elif legal_action == "retain":
        if configuration["legal_release_date"] is not None:
            raise ConfigurationError("retained legal configuration cannot set a date")
        legal = source["legal"]
    else:
        raise ConfigurationError("legal_action is invalid")
    try:
        evaluated = gate.parse_timestamp(issued_at, "issued_at")
    except gate.GateError as error:
        raise ConfigurationError(str(error)) from error
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if evaluated > now:
        raise ConfigurationError("issued_at is future-dated")
    candidate = {
        **source,
        "evaluated_at": issued_at,
        "release_identity": identity,
        "release_change_class": configuration["release_change_class"],
        "requested_commerce_state": target_state,
        "merchant": configuration["merchant"],
        "legal": legal,
    }
    # A first bootstrap has no signatures and can be completely validated here.
    # Later transitions are revalidated with Cosign by the protected workflow.
    if current_state == "unconfigured":
        try:
            gate.derive(candidate, root=root)
        except gate.GateError as error:
            raise ConfigurationError(str(error)) from error
    _atomic_source_write(source_path, candidate)
    return candidate


def _freeze_live_source(root: Path) -> tuple[Path, dict, str]:
    source_path = root / "release/guard-launch-evidence-v2.json"
    source = gate.load_json(source_path, "GuardLaunchEvidenceV2")
    state = gate.load_json(
        root / "release/guard-launch-state-v2.json", "GuardLaunchStateV2"
    )
    if (
        source.get("requested_commerce_state") != "public_live"
        or state.get("commerce_state") != "public_live"
        or state.get("launch_state") != "qualified"
        or state.get("checkout_enabled") is not True
        or source.get("sales_freeze") != gate.INACTIVE_SALES_FREEZE
    ):
        raise ConfigurationError("sales freeze requires the canonical qualified live state")
    source_sha256 = gate.sha256_bytes(gate.canonical_bytes(source))
    if state.get("source_sha256") != source_sha256:
        raise ConfigurationError("sales freeze state does not bind the exact live source")
    return source_path, source, source_sha256


def _freeze_evidence_path(root: Path, path: Path, *, signature: bool) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ConfigurationError("sales-freeze evidence is outside the repository") from error
    if not relative.startswith(gate.EVIDENCE_PREFIX.as_posix() + "/"):
        raise ConfigurationError("sales-freeze evidence must use the launch evidence directory")
    if signature:
        if not relative.endswith(".sigstore.json"):
            raise ConfigurationError("sales-freeze signature must be a Sigstore bundle")
    elif not relative.endswith(".json") or relative.endswith(".sigstore.json"):
        raise ConfigurationError("sales-freeze envelope path is invalid")
    return relative


def build_freeze_envelope(
    *, root: Path, issued_at: str, workflow_source_sha: str, output: Path
) -> dict:
    _source_path, source, source_sha256 = _freeze_live_source(root)
    _freeze_evidence_path(root, output, signature=False)
    try:
        issued = gate.parse_timestamp(issued_at, "issued_at")
    except gate.GateError as error:
        raise ConfigurationError(str(error)) from error
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if issued > now:
        raise ConfigurationError("sales-freeze issued_at is future-dated")
    if gate.GIT_SHA_RE.fullmatch(workflow_source_sha) is None:
        raise ConfigurationError("sales-freeze workflow source SHA is malformed")
    envelope = {
        "schema_version": 1,
        "document_type": "GuardSalesFreezeEvidenceV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "signer_id": gate.SALES_FREEZE_SIGNER_ID,
        "purpose": gate.SALES_FREEZE_PURPOSE,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_source_sha": workflow_source_sha,
        "prior_source_sha256": source_sha256,
        "release_identity": source["release_identity"],
        "prior_commerce_state": "public_live",
        "requested_commerce_state": "sales_frozen",
        "checkout_enabled": False,
        "preserve_customer_portal": True,
        "preserve_published_artifacts": True,
        "reason": "owner_emergency_sales_freeze",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ConfigurationError("sales-freeze evidence output already exists")
    output.write_bytes(gate.canonical_bytes(envelope))
    return envelope


def freeze_sales(*, root: Path, evidence: Path, signature: Path) -> dict:
    source_path, source, source_sha256 = _freeze_live_source(root)
    evidence_relative = _freeze_evidence_path(root, evidence, signature=False)
    signature_relative = _freeze_evidence_path(root, signature, signature=True)
    envelope = _load_strict(evidence, "sales-freeze envelope")
    signature_value = _load_strict(signature, "sales-freeze signature")
    expected = {
        "schema_version": 1,
        "document_type": "GuardSalesFreezeEvidenceV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "signer_id": gate.SALES_FREEZE_SIGNER_ID,
        "purpose": gate.SALES_FREEZE_PURPOSE,
        "issued_at": envelope.get("issued_at"),
        "workflow_source_sha": envelope.get("workflow_source_sha"),
        "prior_source_sha256": source_sha256,
        "release_identity": source["release_identity"],
        "prior_commerce_state": "public_live",
        "requested_commerce_state": "sales_frozen",
        "checkout_enabled": False,
        "preserve_customer_portal": True,
        "preserve_published_artifacts": True,
        "reason": "owner_emergency_sales_freeze",
    }
    if (
        envelope != expected
        or not isinstance(envelope.get("workflow_source_sha"), str)
        or gate.GIT_SHA_RE.fullmatch(envelope["workflow_source_sha"]) is None
        or not isinstance(signature_value, dict)
    ):
        raise ConfigurationError("sales-freeze envelope differs from the exact live source")
    try:
        gate.parse_timestamp(envelope["issued_at"], "sales-freeze issued_at")
    except gate.GateError as error:
        raise ConfigurationError(str(error)) from error
    source["requested_commerce_state"] = "sales_frozen"
    source["sales_freeze"] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": evidence_relative,
                "sha256": gate.sha256_bytes(evidence.read_bytes()),
                "signature_path": signature_relative,
                "signature_sha256": gate.sha256_bytes(signature.read_bytes()),
                "signer_id": gate.SALES_FREEZE_SIGNER_ID,
                "purpose": gate.SALES_FREEZE_PURPOSE,
            }
        ],
    }
    _atomic_source_write(source_path, source)
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    configure = subparsers.add_parser("configure")
    configure.add_argument("--configuration", type=Path, required=True)
    configure.add_argument("--issued-at", required=True)
    build_freeze = subparsers.add_parser("build-freeze")
    build_freeze.add_argument("--issued-at", required=True)
    build_freeze.add_argument("--workflow-source-sha", required=True)
    build_freeze.add_argument("--output", type=Path, required=True)
    freeze = subparsers.add_parser("freeze-sales")
    freeze.add_argument("--evidence", type=Path, required=True)
    freeze.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            apply_configuration(
                root=args.root.resolve(),
                configuration_path=args.configuration,
                issued_at=args.issued_at,
            )
        elif args.command == "build-freeze":
            build_freeze_envelope(
                root=args.root.resolve(),
                issued_at=args.issued_at,
                workflow_source_sha=args.workflow_source_sha,
                output=args.output,
            )
        else:
            freeze_sales(
                root=args.root.resolve(),
                evidence=args.evidence,
                signature=args.signature,
            )
    except (ConfigurationError, gate.GateError) as error:
        print(f"Guard owner configuration: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS Guard owner configuration: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
