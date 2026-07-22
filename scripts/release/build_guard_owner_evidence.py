#!/usr/bin/env python3
"""Build and attach one owner-attested Guard gate evidence envelope.

The workflow caller supplies claims, but this helper owns every wire field,
release binding, expiry, path, digest, signer, and purpose.  It never signs and
never marks more than one gate passed; the caller must keyless-sign the exact
envelope and run ``guard_launch_gate.py`` to verify the complete source.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import guard_launch_gate as gate  # noqa: E402
import strict_json  # noqa: E402


OWNER_SIGNER_ID = "tinyzkp-owner-main"


class EvidenceError(ValueError):
    """Owner evidence input is incomplete, unsafe, or inconsistent."""


def _gate_can_receive_evidence(gate_name: str, current: object) -> bool:
    blocked = {
        "status": "blocked",
        "reason_code": gate.BLOCKED_REASONS[gate_name],
        "evidence": [],
    }
    if current == blocked:
        return True
    return bool(
        gate_name in gate.MUTABLE_FACT_FRESH_GATES
        and isinstance(current, dict)
        and current.get("status") == "passed"
        and current.get("reason_code") is None
        and isinstance(current.get("evidence"), list)
        and current["evidence"]
    )


def _strict_json_file(path: Path, label: str) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {label}: {path}") from exc
    if not raw or len(raw) > gate.MAX_EVIDENCE_BYTES:
        raise EvidenceError(f"{label} size is invalid")
    try:
        value = strict_json.loads(raw)
    except ValueError as exc:
        raise EvidenceError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _source(root: Path) -> tuple[Path, dict]:
    path = root / "release" / "guard-launch-evidence-v2.json"
    source = gate.load_json(path, "GuardLaunchEvidenceV2")
    if (
        source.get("schema_version") != 2
        or source.get("document_type") != "GuardLaunchEvidenceV2"
        or source.get("authorization_policy") != gate.AUTHORIZATION_POLICY
        or source.get("qualification_basis") != gate.QUALIFICATION_BASIS
    ):
        raise EvidenceError("launch source is not the owner-only V2 contract")
    return path, source


def _relative_evidence_path(root: Path, path: Path, *, signature: bool) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError("owner evidence output is outside the repository") from exc
    if signature:
        if not relative.endswith(".sigstore.json"):
            raise EvidenceError("owner evidence signature must be a Sigstore JSON bundle")
    elif relative.endswith(".sigstore.json") or not relative.endswith(".json"):
        raise EvidenceError("owner evidence envelope must be a non-signature JSON file")
    prefix = gate.EVIDENCE_PREFIX.as_posix() + "/"
    if not relative.startswith(prefix):
        raise EvidenceError(f"owner evidence must be below {gate.EVIDENCE_PREFIX}")
    return relative


def build_envelope(
    *,
    root: Path,
    gate_name: str,
    claims_path: Path,
    issued_at_value: str,
    workflow_source_sha: str,
    output: Path,
) -> dict:
    if gate_name not in gate.REQUIRED_GATES:
        raise EvidenceError("gate is not an owner-verifiable launch gate")
    _relative_evidence_path(root, output, signature=False)
    _source_path, source = _source(root)
    gates = source.get("gates")
    if not isinstance(gates, dict) or set(gates) != set(gate.REQUIRED_GATES):
        raise EvidenceError("launch source gate inventory differs")
    current = gates[gate_name]
    if not _gate_can_receive_evidence(gate_name, current):
        raise EvidenceError(
            "owner workflow may attach a blocked gate or refresh one mutable passed gate"
        )
    try:
        identity = gate._validate_identity(source["release_identity"], qualified=True)
    except gate.GateError as exc:
        raise EvidenceError(str(exc)) from exc
    claims = _strict_json_file(claims_path, "owner gate claims")
    try:
        gate.SEMANTIC_VALIDATORS[gate_name](claims)
        issued_at = gate.parse_timestamp(issued_at_value, "issued_at")
    except gate.GateError as exc:
        raise EvidenceError(str(exc)) from exc
    kind, max_age_days = gate.GATE_POLICIES[gate_name]
    if gate.GIT_SHA_RE.fullmatch(workflow_source_sha) is None:
        raise EvidenceError("workflow source SHA must be lowercase 40-hex")
    expires_at = issued_at + timedelta(days=max_age_days)
    envelope = {
        "schema_version": 1,
        "document_type": "GuardGateEvidenceV1",
        "authorization_policy": gate.AUTHORIZATION_POLICY,
        "qualification_basis": gate.QUALIFICATION_BASIS,
        "evidence_kind": kind,
        "gate": gate_name,
        "result": "passed",
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_source_sha": workflow_source_sha,
        "release_identity": identity,
        "claims": claims,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise EvidenceError("owner evidence output already exists")
    output.write_bytes(gate.canonical_bytes(envelope))
    return envelope


def attach_envelope(
    *,
    root: Path,
    gate_name: str,
    evidence: Path,
    signature: Path,
) -> dict:
    if gate_name not in gate.REQUIRED_GATES:
        raise EvidenceError("gate is not an owner-verifiable launch gate")
    evidence_relative = _relative_evidence_path(root, evidence, signature=False)
    signature_relative = _relative_evidence_path(root, signature, signature=True)
    try:
        _evidence_path, evidence_raw = gate._safe_evidence_file(
            root, evidence_relative
        )
        _signature_path, signature_raw = gate._safe_evidence_file(
            root, signature_relative
        )
    except gate.GateError as exc:
        raise EvidenceError(str(exc)) from exc
    envelope = _strict_json_file(evidence, "owner gate envelope")
    _strict_json_file(signature, "owner Sigstore bundle")
    _source_path, source = _source(root)
    if (
        envelope.get("schema_version") != 1
        or envelope.get("document_type") != "GuardGateEvidenceV1"
        or envelope.get("authorization_policy") != gate.AUTHORIZATION_POLICY
        or envelope.get("qualification_basis") != gate.QUALIFICATION_BASIS
        or envelope.get("gate") != gate_name
        or envelope.get("result") != "passed"
        or not isinstance(envelope.get("workflow_source_sha"), str)
        or gate.GIT_SHA_RE.fullmatch(envelope["workflow_source_sha"]) is None
        or envelope.get("release_identity") != source.get("release_identity")
    ):
        raise EvidenceError("owner envelope differs from the exact launch source")
    current = source.get("gates", {}).get(gate_name)
    if not _gate_can_receive_evidence(gate_name, current):
        raise EvidenceError(
            "owner workflow may attach a blocked gate or refresh one mutable passed gate"
        )
    source["evaluated_at"] = envelope["issued_at"]
    source["gates"][gate_name] = {
        "status": "passed",
        "reason_code": None,
        "evidence": [
            {
                "path": evidence_relative,
                "sha256": gate.sha256_bytes(evidence_raw),
                "signature_path": signature_relative,
                "signature_sha256": gate.sha256_bytes(signature_raw),
                "signer_id": OWNER_SIGNER_ID,
                "purpose": gate.GATE_PURPOSES[gate_name],
            }
        ],
    }
    source_path = root / "release" / "guard-launch-evidence-v2.json"
    temporary = source_path.with_name(source_path.name + ".tmp")
    temporary.write_bytes(gate.canonical_bytes(source))
    os.replace(temporary, source_path)
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--gate", required=True)
    build.add_argument("--claims", type=Path, required=True)
    build.add_argument("--issued-at", required=True)
    build.add_argument("--workflow-source-sha", required=True)
    build.add_argument("--output", type=Path, required=True)
    attach = subparsers.add_parser("attach")
    attach.add_argument("--gate", required=True)
    attach.add_argument("--evidence", type=Path, required=True)
    attach.add_argument("--signature", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve()
        if args.command == "build":
            build_envelope(
                root=root,
                gate_name=args.gate,
                claims_path=args.claims,
                issued_at_value=args.issued_at,
                workflow_source_sha=args.workflow_source_sha,
                output=args.output,
            )
        else:
            attach_envelope(
                root=root,
                gate_name=args.gate,
                evidence=args.evidence,
                signature=args.signature,
            )
    except (EvidenceError, gate.GateError) as exc:
        print(f"owner Guard evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS owner Guard evidence {args.command}: {args.gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
