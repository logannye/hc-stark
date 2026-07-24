#!/usr/bin/env python3
"""Build and attach one owner-attested Guard market evidence envelope.

The workflow caller supplies strict subject-specific claims. This helper owns
the evidence envelope, repository paths, signer identity, purpose, trust-policy
transition, and source attachment. It never signs evidence and it never
replaces a subject that has already passed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import guard_launch_gate as launch  # noqa: E402
import guard_market_clock as market  # noqa: E402
import strict_json  # noqa: E402


OWNER_SIGNER_ID = "tinyzkp-owner-market-main"
OWNER_SIGNER = {
    "certificate_identity_regexp": (
        "^https://github\\.com/logannye/hc-stark/"
        "\\.github/workflows/owner-market-evidence\\.yml@refs/heads/main$"
    ),
    "id": OWNER_SIGNER_ID,
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "purposes": sorted(item[1] for item in market.SUBJECTS.values()),
}


class EvidenceError(ValueError):
    """Market evidence input is incomplete, unsafe, or inconsistent."""


def _strict_json_file(path: Path, label: str) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {label}: {path}") from exc
    if not raw or len(raw) > launch.MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"{label} size is invalid")
    try:
        value = strict_json.loads(raw)
    except ValueError as exc:
        raise EvidenceError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value, raw


def _source(root: Path) -> tuple[Path, dict]:
    path = root / "release" / "guard-market-evidence-v1.json"
    source = market.load(path, "GuardMarketEvidenceV1")
    if (
        source.get("schema_version") != 1
        or source.get("document_type") != "GuardMarketEvidenceV1"
        or set(source) != {
            "schema_version",
            "document_type",
            "evaluated_at",
            "trust_policy",
            *market.SUBJECTS,
            "acquisition_policy",
        }
    ):
        raise EvidenceError("market source is not the owner-only V1 contract")
    return path, source


def _relative_evidence_path(root: Path, path: Path, *, signature: bool) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError("market evidence output is outside the repository") from exc
    prefix = market.EVIDENCE_PREFIX.as_posix() + "/"
    if not relative.startswith(prefix):
        raise EvidenceError(f"market evidence must be below {market.EVIDENCE_PREFIX}")
    if signature:
        if not relative.endswith(".sigstore.json"):
            raise EvidenceError("market evidence signature must be a Sigstore JSON bundle")
    elif relative.endswith(".sigstore.json") or not relative.endswith(".json"):
        raise EvidenceError("market evidence envelope must be a non-signature JSON file")
    return relative


def _subject_is_blocked(subject: str, source: dict) -> bool:
    _kind, _purpose, reason = market.SUBJECTS[subject]
    return source.get(subject) == {
        "status": "blocked",
        "reason_code": reason,
        "evidence": [],
    }


def build_envelope(
    *,
    root: Path,
    subject: str,
    claims_path: Path,
    issued_at_value: str,
    output: Path,
) -> dict:
    if subject not in market.SUBJECTS:
        raise EvidenceError("subject is not a Guard market evidence subject")
    _relative_evidence_path(root, output, signature=False)
    _source_path, source = _source(root)
    if not _subject_is_blocked(subject, source):
        raise EvidenceError("market workflow cannot replace passed evidence")
    claims, _claims_raw = _strict_json_file(claims_path, "market claims")
    try:
        market.validate_claims(subject, claims)
        issued_at = market.iso(issued_at_value, "issued_at")
    except market.MarketError as exc:
        raise EvidenceError(str(exc)) from exc
    evidence_kind, _purpose, _reason = market.SUBJECTS[subject]
    envelope = {
        "schema_version": 1,
        "document_type": "GuardMarketEvidenceRecordV1",
        "evidence_kind": evidence_kind,
        "subject": subject,
        "result": "passed",
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claims": claims,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise EvidenceError("market evidence output already exists")
    output.write_bytes(market.canonical(envelope))
    return envelope


def _update_trust_policy(root: Path, source: dict) -> tuple[dict, bytes]:
    path = root / "release" / "guard-market-trust-v1.json"
    trust, _raw = _strict_json_file(path, "market trust policy")
    if set(trust) != {"document_type", "schema_version", "signers"}:
        raise EvidenceError("market trust policy fields differ")
    if (
        trust.get("document_type") != "GuardLaunchTrustV1"
        or trust.get("schema_version") != 1
        or not isinstance(trust.get("signers"), list)
    ):
        raise EvidenceError("market trust policy type/schema differs")
    if trust["signers"] == []:
        trust["signers"] = [OWNER_SIGNER]
    elif trust["signers"] != [OWNER_SIGNER]:
        raise EvidenceError("market trust policy signer differs")
    raw = market.canonical(trust)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)
    source["trust_policy"] = {
        "path": "release/guard-market-trust-v1.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return trust, raw


def attach_envelope(
    *,
    root: Path,
    subject: str,
    evidence: Path,
    signature: Path,
) -> dict:
    if subject not in market.SUBJECTS:
        raise EvidenceError("subject is not a Guard market evidence subject")
    evidence_relative = _relative_evidence_path(root, evidence, signature=False)
    signature_relative = _relative_evidence_path(root, signature, signature=True)
    try:
        _evidence_path, evidence_raw = market.safe_file(root, evidence_relative)
        _signature_path, signature_raw = market.safe_file(root, signature_relative)
    except (OSError, market.MarketError) as exc:
        raise EvidenceError(str(exc)) from exc
    envelope, _envelope_raw = _strict_json_file(evidence, "market envelope")
    _strict_json_file(signature, "market Sigstore bundle")
    expected_fields = {
        "schema_version",
        "document_type",
        "evidence_kind",
        "subject",
        "result",
        "issued_at",
        "claims",
    }
    evidence_kind, purpose, _reason = market.SUBJECTS[subject]
    if (
        set(envelope) != expected_fields
        or envelope.get("schema_version") != 1
        or envelope.get("document_type") != "GuardMarketEvidenceRecordV1"
        or envelope.get("evidence_kind") != evidence_kind
        or envelope.get("subject") != subject
        or envelope.get("result") != "passed"
    ):
        raise EvidenceError("market envelope differs from the exact subject contract")
    try:
        issued_at = market.iso(envelope["issued_at"], "issued_at")
        market.validate_claims(subject, envelope["claims"])
    except market.MarketError as exc:
        raise EvidenceError(str(exc)) from exc
    source_path, source = _source(root)
    if not _subject_is_blocked(subject, source):
        raise EvidenceError("market workflow cannot replace passed evidence")
    if (
        subject == "community_announcement"
        and source["doctor_evaluation_release"]["status"] != "passed"
    ):
        raise EvidenceError("community announcement cannot precede doctor evidence")
    _trust, _trust_raw = _update_trust_policy(root, source)
    source["evaluated_at"] = issued_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    source[subject] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": evidence_relative,
                "sha256": hashlib.sha256(evidence_raw).hexdigest(),
                "signature_path": signature_relative,
                "signature_sha256": hashlib.sha256(signature_raw).hexdigest(),
                "signer_id": OWNER_SIGNER_ID,
                "purpose": purpose,
            }
        ],
    }
    temporary = source_path.with_name(source_path.name + ".tmp")
    temporary.write_bytes(market.canonical(source))
    os.replace(temporary, source_path)
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--subject", required=True)
    build.add_argument("--claims", type=Path, required=True)
    build.add_argument("--issued-at", required=True)
    build.add_argument("--output", type=Path, required=True)
    attach = subparsers.add_parser("attach")
    attach.add_argument("--subject", required=True)
    attach.add_argument("--evidence", type=Path, required=True)
    attach.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if args.command == "build":
            build_envelope(
                root=root,
                subject=args.subject,
                claims_path=args.claims,
                issued_at_value=args.issued_at,
                output=args.output,
            )
        else:
            attach_envelope(
                root=root,
                subject=args.subject,
                evidence=args.evidence,
                signature=args.signature,
            )
    except (EvidenceError, launch.GateError, market.MarketError) as exc:
        print(f"owner Guard market evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS owner Guard market evidence {args.command}: {args.subject}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
