#!/usr/bin/env python3
"""Validate a counsel-approved evaluation agreement form and exact execution.

The tool cannot provide legal approval. It makes that external approval
machine-enforceable by binding the approved template, counsel approval record,
completed agreement source, exact signed document, scope, qualification, and
partner preflight into one canonical owner-only evidence record.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OFFERS_PATH = ROOT / "site" / "pricing.json"
PROFILE_SCHEMA = "tinyzkp-agreement-form-profile-v1"
GATE_SCHEMA = "tinyzkp-agreement-gate-v1"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
PROFILE_KEYS = {
    "schema_version",
    "status",
    "form_id",
    "form_version",
    "approved_template_sha256",
    "counsel_approval_sha256",
    "approved_by",
    "approved_at",
    "approval_scope",
}
GATE_KEYS = {
    "schema_version",
    "status",
    "agreement_id",
    "offer_id",
    "form_id",
    "form_version",
    "form_profile_sha256",
    "approved_template_sha256",
    "counsel_approval_sha256",
    "agreement_source_sha256",
    "signed_agreement_sha256",
    "scope_sha256",
    "qualification_sha256",
    "partner_preflight_sha256",
    "required_terms",
    "placeholders_absent",
    "material_deviations_reviewed",
    "approved_for_execution",
    "execution_reviewed_by",
    "execution_reviewed_at",
}
REQUIRED_TERMS = {
    "one_workload": ("exactly one", "plonky3", "workload"),
    "fixed_fee": (),
    "offer_duration": (),
    "engineering_cap": (),
    "change_orders": ("written change order",),
    "deposit_and_delivery": ("50% deposit", "remaining 50%"),
    "no_production_sla": (
        "not hosted proving",
        "security certification",
        "sla",
        "does not guarantee",
    ),
    "safe_data_boundary": (
        "non-sensitive deterministic input generator",
        "must not transfer witnesses",
        "credentials",
        "private keys",
        "customer data",
        "private source code",
        "production secrets",
        "regulated data",
    ),
    "written_acceptance": ("written delivery acceptance",),
    "open_source_and_adapter_ip": ("mit-licensed core", "customer-specific adapter"),
    "retention_and_deletion": ("retention", "deletion"),
    "signatures": ("signature",),
}
PLACEHOLDER_PATTERNS = (
    re.compile(
        r"\[(?:COUNSEL|CUSTOMER|PROVIDER|DATE|NAME|TITLE|SIGNATURE|AGREEMENT|REPLACE)[^\]]*\]",
        re.I,
    ),
    re.compile(r"\b(?:REPLACE_ME|TODO|TBD)\b", re.I),
    re.compile(r"DO NOT SIGN|DO NOT SEND|DRAFT FOR COUNSEL", re.I),
)

ROOT = Path(__file__).resolve().parents[1]
COMMERCIAL_SCRIPTS = ROOT / "scripts" / "commercial"
if str(COMMERCIAL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(COMMERCIAL_SCRIPTS))

import evaluation_qualification  # noqa: E402
import evidence_common  # noqa: E402
import partner_preflight  # noqa: E402


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"{label} contains forbidden number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} must be strict UTF-8 JSON") from error


def digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_timestamp(raw: Any, field: str) -> datetime:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError(f"{field} must include a UTC offset and second precision")
    if raw != parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise ValueError(f"{field} must use canonical UTC Z form")
    if parsed > datetime.now(timezone.utc):
        raise ValueError(f"{field} cannot be in the future")
    return parsed


def read_owner_only(path: Path, label: str, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    try:
        if path.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if (
                stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_uid != os.geteuid()
            ):
                raise ValueError(f"{label} must be owner-only and operator-owned")
            payload = handle.read(max_bytes + 1)
        if not payload or len(payload) > max_bytes:
            raise ValueError(f"{label} is empty or oversized")
        return payload
    except OSError as error:
        raise ValueError(f"{label} is unavailable or unsafe") from error


def load_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    raw = read_owner_only(path, label, 64 * 1024)
    payload = decode_json(raw, label)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload, digest_bytes(raw)


def validate_profile(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != PROFILE_KEYS:
        raise ValueError("agreement form profile fields are missing or unknown")
    if payload["schema_version"] != PROFILE_SCHEMA or payload["status"] != "approved":
        raise ValueError("agreement form profile is not counsel-approved v1")
    for field in ("form_id", "form_version"):
        if (
            not isinstance(payload[field], str)
            or SAFE_ID.fullmatch(payload[field]) is None
        ):
            raise ValueError(f"agreement form profile {field} is malformed")
    for field in ("approved_template_sha256", "counsel_approval_sha256"):
        if (
            not isinstance(payload[field], str)
            or HEX_SHA256.fullmatch(payload[field]) is None
        ):
            raise ValueError(f"agreement form profile {field} must be SHA-256")
    if (
        not isinstance(payload["approved_by"], str)
        or len(payload["approved_by"].strip()) < 3
    ):
        raise ValueError("agreement form profile approved_by is required")
    canonical_timestamp(payload["approved_at"], "approved_at")
    if payload["approval_scope"] != "evaluation-msa-sow-for-execution":
        raise ValueError("agreement form profile approval scope is insufficient")
    return payload


def evaluation_offer(offer_id: str) -> dict[str, Any]:
    payload = json.loads(OFFERS_PATH.read_text(encoding="utf-8"))
    offers = {
        offer.get("id"): offer
        for offer in payload.get("offers", [])
        if isinstance(offer, dict)
    }
    offer = offers.get(offer_id)
    if not isinstance(offer, dict) or offer_id not in {
        "founding_evaluation",
        "standard_evaluation",
    }:
        raise ValueError("agreement gate supports evaluation offers only")
    return offer


def number_word(value: int) -> str:
    words = {
        1: "one",
        2: "two",
        3: "three",
        4: "four",
        5: "five",
        6: "six",
        7: "seven",
        8: "eight",
        9: "nine",
        10: "ten",
        11: "eleven",
        12: "twelve",
        13: "thirteen",
        14: "fourteen",
        15: "fifteen",
        16: "sixteen",
        17: "seventeen",
        18: "eighteen",
        19: "nineteen",
        20: "twenty",
    }
    if value not in words:
        raise ValueError("agreement offer term is outside the supported range")
    return words[value]


def offer_term_requirements(offer_id: str) -> dict[str, tuple[str, ...]]:
    offer = evaluation_offer(offer_id)
    duration = offer.get("duration")
    day_cap = offer.get("engineering_day_cap")
    price = offer.get("price")
    if (
        not isinstance(duration, str)
        or not duration.endswith("_weeks")
        or not duration.removesuffix("_weeks").isdigit()
        or not isinstance(day_cap, int)
        or isinstance(day_cap, bool)
        or not isinstance(price, int)
        or isinstance(price, bool)
    ):
        raise ValueError("evaluation offer terms are invalid")
    weeks = int(duration.removesuffix("_weeks"))
    return {
        **REQUIRED_TERMS,
        "fixed_fee": (f"${price:,}",),
        "offer_duration": (f"{number_word(weeks)} weeks",),
        "engineering_cap": (number_word(day_cap), "person-days"),
    }


def validate_agreement_source(raw: bytes, offer_id: str) -> dict[str, bool]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("completed agreement source must be UTF-8") from error
    for pattern in PLACEHOLDER_PATTERNS:
        match = pattern.search(text)
        if match:
            raise ValueError(
                f"completed agreement source contains unresolved marker: {match.group(0)!r}"
            )
    lowered = " ".join(text.lower().split())
    results: dict[str, bool] = {}
    for term, phrases in offer_term_requirements(offer_id).items():
        results[term] = all(phrase in lowered for phrase in phrases)
        if not results[term]:
            raise ValueError(
                f"completed agreement source is missing required term group: {term}"
            )
    return results


def build_gate(
    *,
    profile_path: Path,
    approved_template_path: Path,
    counsel_approval_path: Path,
    agreement_source_path: Path,
    signed_agreement_path: Path,
    scope_path: Path,
    qualification_path: Path,
    partner_preflight_path: Path,
    agreement_id: str,
    offer_id: str,
    execution_reviewed_by: str,
    execution_reviewed_at: str,
    material_deviations_reviewed: bool,
) -> dict[str, Any]:
    if SAFE_ID.fullmatch(agreement_id or "") is None:
        raise ValueError("agreement_id is malformed")
    if offer_id not in {"founding_evaluation", "standard_evaluation"}:
        raise ValueError("agreement gate supports evaluation offers only")
    profile_payload, profile_digest = load_json(profile_path, "agreement form profile")
    profile = validate_profile(profile_payload)
    approved_template = read_owner_only(
        approved_template_path, "approved agreement template"
    )
    counsel_approval = read_owner_only(counsel_approval_path, "counsel approval record")
    source = read_owner_only(agreement_source_path, "completed agreement source")
    signed = read_owner_only(signed_agreement_path, "signed agreement")
    scope = read_owner_only(scope_path, "scope document")
    qualification = read_owner_only(
        qualification_path, "qualification evidence", 1024 * 1024
    )
    preflight_raw = read_owner_only(
        partner_preflight_path, "partner preflight evidence", 1024 * 1024
    )
    if digest_bytes(approved_template) != profile["approved_template_sha256"]:
        raise ValueError("approved template does not match counsel profile")
    if digest_bytes(counsel_approval) != profile["counsel_approval_sha256"]:
        raise ValueError("counsel approval record does not match profile")
    required_terms = validate_agreement_source(source, offer_id)
    try:
        qualification_payload = decode_json(qualification, "qualification evidence")
        preflight_payload = decode_json(preflight_raw, "partner preflight evidence")
    except ValueError as error:
        raise ValueError(
            "qualification and partner preflight must be UTF-8 JSON"
        ) from error
    compatibility = evidence_common.compatibility_identity(
        evaluation_qualification.DEFAULT_COMPATIBILITY
    )
    qualification_checked = evaluation_qualification.validate_evidence(
        qualification_payload, compatibility
    )
    preflight_checked = partner_preflight.validate_evidence(
        preflight_payload, compatibility
    )
    if qualification != evidence_common.canonical_bytes(qualification_payload):
        raise ValueError("qualification evidence must use canonical JSON")
    if preflight_raw != evidence_common.canonical_bytes(preflight_payload):
        raise ValueError("partner preflight evidence must use canonical JSON")
    if qualification_checked["application_id"] != preflight_checked[
        "application_id"
    ] or preflight_checked["bound_inputs"][
        "qualification_evidence_sha256"
    ] != digest_bytes(qualification):
        raise ValueError("partner preflight does not bind the qualification evidence")
    if material_deviations_reviewed is not True:
        raise ValueError(
            "execution reviewer must affirm material deviations were reviewed"
        )
    if (
        not isinstance(execution_reviewed_by, str)
        or len(execution_reviewed_by.strip()) < 3
    ):
        raise ValueError("execution reviewer identity is required")
    reviewed_at = canonical_timestamp(execution_reviewed_at, "execution_reviewed_at")
    approved_at = canonical_timestamp(profile["approved_at"], "approved_at")
    if reviewed_at < approved_at:
        raise ValueError("execution review cannot precede form approval")
    for field, raw_timestamp in (
        ("qualification reviewed_at", qualification_checked["reviewed_at"]),
        ("partner preflight checked_at", preflight_checked["checked_at"]),
    ):
        if canonical_timestamp(raw_timestamp, field) > reviewed_at:
            raise ValueError(f"{field} cannot follow agreement execution review")
    payload = {
        "schema_version": GATE_SCHEMA,
        "status": "approved",
        "agreement_id": agreement_id,
        "offer_id": offer_id,
        "form_id": profile["form_id"],
        "form_version": profile["form_version"],
        "form_profile_sha256": profile_digest,
        "approved_template_sha256": digest_bytes(approved_template),
        "counsel_approval_sha256": digest_bytes(counsel_approval),
        "agreement_source_sha256": digest_bytes(source),
        "signed_agreement_sha256": digest_bytes(signed),
        "scope_sha256": digest_bytes(scope),
        "qualification_sha256": digest_bytes(qualification),
        "partner_preflight_sha256": digest_bytes(preflight_raw),
        "required_terms": required_terms,
        "placeholders_absent": True,
        "material_deviations_reviewed": True,
        "approved_for_execution": True,
        "execution_reviewed_by": execution_reviewed_by.strip(),
        "execution_reviewed_at": execution_reviewed_at,
    }
    return validate_gate(payload)


def validate_gate(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != GATE_KEYS:
        raise ValueError("agreement gate fields are missing or unknown")
    if payload["schema_version"] != GATE_SCHEMA or payload["status"] != "approved":
        raise ValueError("agreement gate is not approved v1 evidence")
    for field in ("agreement_id", "form_id", "form_version"):
        if (
            not isinstance(payload[field], str)
            or SAFE_ID.fullmatch(payload[field]) is None
        ):
            raise ValueError(f"agreement gate {field} is malformed")
    if payload["offer_id"] not in {"founding_evaluation", "standard_evaluation"}:
        raise ValueError("agreement gate offer is unsupported")
    for field in (
        "form_profile_sha256",
        "approved_template_sha256",
        "counsel_approval_sha256",
        "agreement_source_sha256",
        "signed_agreement_sha256",
        "scope_sha256",
        "qualification_sha256",
        "partner_preflight_sha256",
    ):
        if (
            not isinstance(payload[field], str)
            or HEX_SHA256.fullmatch(payload[field]) is None
        ):
            raise ValueError(f"agreement gate {field} must be SHA-256")
    terms = payload["required_terms"]
    if (
        not isinstance(terms, dict)
        or set(terms) != set(REQUIRED_TERMS)
        or any(value is not True for value in terms.values())
    ):
        raise ValueError("agreement gate required terms are incomplete")
    for field in (
        "placeholders_absent",
        "material_deviations_reviewed",
        "approved_for_execution",
    ):
        if payload[field] is not True:
            raise ValueError(f"agreement gate {field} must be true")
    if (
        not isinstance(payload["execution_reviewed_by"], str)
        or len(payload["execution_reviewed_by"].strip()) < 3
    ):
        raise ValueError("agreement gate execution reviewer is missing")
    canonical_timestamp(payload["execution_reviewed_at"], "execution_reviewed_at")
    return payload


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat()
    if stat.S_IMODE(parent.st_mode) & 0o077 or parent.st_uid != os.geteuid():
        raise ValueError("agreement gate output directory must be owner-only")
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to replace existing agreement gate")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--evidence", type=Path, required=True)
    build = sub.add_parser("build")
    build.add_argument("--profile", type=Path, required=True)
    build.add_argument("--approved-template", type=Path, required=True)
    build.add_argument("--counsel-approval", type=Path, required=True)
    build.add_argument("--agreement-source", type=Path, required=True)
    build.add_argument("--signed-agreement", type=Path, required=True)
    build.add_argument("--scope", type=Path, required=True)
    build.add_argument("--qualification", type=Path, required=True)
    build.add_argument("--partner-preflight", type=Path, required=True)
    build.add_argument("--agreement-id", required=True)
    build.add_argument("--offer-id", required=True)
    build.add_argument("--execution-reviewed-by", required=True)
    build.add_argument("--execution-reviewed-at", required=True)
    build.add_argument("--material-deviations-reviewed", action="store_true")
    build.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "verify":
        payload, digest = load_json(args.evidence, "agreement gate")
        validate_gate(payload)
        print(
            json.dumps(
                {"status": "approved", "evidence_sha256": digest}, sort_keys=True
            )
        )
        return
    payload = build_gate(
        profile_path=args.profile,
        approved_template_path=args.approved_template,
        counsel_approval_path=args.counsel_approval,
        agreement_source_path=args.agreement_source,
        signed_agreement_path=args.signed_agreement,
        scope_path=args.scope,
        qualification_path=args.qualification,
        partner_preflight_path=args.partner_preflight,
        agreement_id=args.agreement_id,
        offer_id=args.offer_id,
        execution_reviewed_by=args.execution_reviewed_by,
        execution_reviewed_at=args.execution_reviewed_at,
        material_deviations_reviewed=args.material_deviations_reviewed,
    )
    atomic_write(args.output, payload)
    print(
        json.dumps(
            {
                "status": "approved",
                "evidence_sha256": digest_bytes(canonical_json(payload) + b"\n"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
