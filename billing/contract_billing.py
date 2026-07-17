#!/usr/bin/env python3
"""Plan or create tightly scoped Stripe invoices and annual contracts.

The default is read-only. Writes require --apply, exact account identity, and
TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1. This tool never creates Checkout links.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlparse

import stripe

import agreement_gate
import evaluation_delivery_manifest
from legacy_billing_containment import STRIPE_API_VERSION, verify_account
import stripe_test_drill


ROOT = Path(__file__).resolve().parents[1]
OFFERS_PATH = ROOT / "site" / "pricing.json"
RELEASE_GATES_PATH = ROOT / "release" / "backend-v1-gates.json"
RELEASE_AUTHORIZATION_PATH_ENV = "TINYZKP_BACKEND_RELEASE_AUTHORIZATION"
RELEASE_AUTHORIZATION_SHA_ENV = "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256"
RELEASE_AUTHORIZATION_BUNDLE_PATH_ENV = "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE"
RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV = (
    "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256"
)
SIGSTORE_ISSUER = "https://token.actions.githubusercontent.com"
SIGSTORE_IDENTITY_REGEXP = (
    r"^https://github\.com/logannye/hc-stark/\.github/workflows/"
    r"release-backend\.yml@refs/tags/backend-v[^/]+$"
)
EVALUATIONS = {"founding_evaluation", "standard_evaluation"}
ANNUAL = {"tinyzkp_certified", "tinyzkp_fleet_oem"}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
AGREEMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_CONTRACT_DOCUMENT_BYTES = 16 * 1024 * 1024
ANNUAL_ORDER_SCHEMA_VERSION = "tinyzkp-annual-order-v1"
ANNUAL_ORDER_KEYS = {
    "schema_version",
    "agreement_id",
    "offer_id",
    "stripe_customer_id",
    "signed_agreement_sha256",
    "negotiated_annual_amount_cents",
    "currency",
    "billing_interval",
    "stripe_price_id",
    "stripe_product_id",
    "customer_countersigned_at",
    "tinyzkp_countersigned_at",
}
CANONICAL_JSON_NUMBER = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?"
)
JSON_NUMBER_CHARACTERS = frozenset("-+0123456789.eE")
BILLING_PHASE_ORDER = {
    "reserved": 0,
    "invoice_created": 1,
    "item_created": 2,
    "finalized": 3,
}
ACCEPTANCE_SCHEMA_VERSION = "tinyzkp-evaluation-acceptance-v1"
ACCEPTANCE_TOP_LEVEL_KEYS = {
    "schema_version",
    "agreement_id",
    "offer_id",
    "workload",
    "baseline",
    "candidate",
    "acceptance",
    "data_boundary",
    "delivery",
}
RELEASE_AUTHORIZATION_KEYS = {
    "schema_version",
    "status",
    "release_sha",
    "source_tree_sha256",
    "backend_evidence_sha256",
    "backend_release_ready_report_sha256",
    "signed_release_manifest_sha256",
    "signature_bundle_sha256",
    "verified_at",
    "validator",
    "validator_exit_code",
}
CONTRACT_EVIDENCE_KEYS = {
    "schema_version",
    "agreement_id",
    "offer_id",
    "stripe_customer_id",
    "agreement_sha256",
    "scope_sha256",
    "agreement_gate_sha256",
    "qualification_sha256",
    "partner_preflight_sha256",
    "stripe_test_drill_sha256",
    "delivery_manifest_sha256",
    "signed_at",
    "delivery_acceptance_sha256",
    "delivery_accepted_at",
    "deposit_invoice_id",
    "deposit_plan_sha256",
    "negotiated_annual_amount_cents",
}


@dataclass(frozen=True)
class PrivateDocument:
    payload: bytes
    sha256: str


@dataclass(frozen=True)
class BillingReservation:
    operation_key: str
    plan_sha256: str
    action: str
    customer_id: str
    stripe_object_id: str | None
    phase: str
    newly_reserved: bool


@dataclass(frozen=True)
class ReleaseBindingV1:
    authorization_sha256: str
    authorization_bundle_sha256: str
    release_sha: str
    source_tree_sha256: str
    verified_at: str

    def plan_fields(self) -> dict[str, str]:
        return {
            "backend_release_authorization_sha256": self.authorization_sha256,
            "backend_release_authorization_bundle_sha256": (
                self.authorization_bundle_sha256
            ),
            "backend_release_sha": self.release_sha,
            "backend_source_tree_sha256": self.source_tree_sha256,
        }

    def stripe_metadata(self) -> dict[str, str]:
        return {
            "tinyzkp_backend_authorization_sha256": self.authorization_sha256,
            "tinyzkp_backend_authorization_bundle_sha256": (
                self.authorization_bundle_sha256
            ),
            "tinyzkp_backend_release_sha": self.release_sha,
            "tinyzkp_backend_source_tree_sha256": self.source_tree_sha256,
        }


def value(item: Any, key: str, default: Any = None) -> Any:
    return (
        item.get(key, default)
        if isinstance(item, dict)
        else getattr(item, key, default)
    )


def load_offers() -> dict[str, dict[str, Any]]:
    payload = json.loads(OFFERS_PATH.read_text(encoding="utf-8"))
    return {offer["id"]: offer for offer in payload["offers"]}


def canonical_timestamp(raw: str, field: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError(f"{field} must include a UTC offset and second precision")
    canonical = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw != canonical:
        raise ValueError(f"{field} must use canonical UTC Z form")
    return canonical


@dataclass(frozen=True)
class ContractEvidenceV2:
    schema_version: int
    agreement_id: str
    offer_id: str
    stripe_customer_id: str
    agreement_sha256: str
    scope_sha256: str
    agreement_gate_sha256: str | None
    qualification_sha256: str | None
    partner_preflight_sha256: str | None
    stripe_test_drill_sha256: str | None
    delivery_manifest_sha256: str | None
    signed_at: str
    delivery_acceptance_sha256: str | None
    delivery_accepted_at: str | None
    deposit_invoice_id: str | None
    deposit_plan_sha256: str | None
    negotiated_annual_amount_cents: int | None

    @classmethod
    def from_mapping(cls, payload: Any) -> "ContractEvidenceV2":
        if not isinstance(payload, dict) or set(payload) != CONTRACT_EVIDENCE_KEYS:
            raise ValueError("contract evidence fields are missing or unknown")
        return cls(**payload)

    def validate_for(self, action: str) -> None:
        if (
            not isinstance(self.schema_version, int)
            or isinstance(self.schema_version, bool)
            or self.schema_version != 2
        ):
            raise ValueError("contract evidence schema_version must equal 2")
        if not isinstance(self.agreement_id, str) or not AGREEMENT_ID.fullmatch(
            self.agreement_id
        ):
            raise ValueError("contract evidence agreement_id is malformed")
        if (
            not isinstance(self.offer_id, str)
            or self.offer_id not in EVALUATIONS | ANNUAL
        ):
            raise ValueError("contract evidence offer_id is unsupported")
        if not isinstance(
            self.stripe_customer_id, str
        ) or not self.stripe_customer_id.startswith("cus_"):
            raise ValueError("contract evidence stripe_customer_id is malformed")
        for field in ("agreement_sha256", "scope_sha256"):
            raw = getattr(self, field)
            if not isinstance(raw, str) or not HEX_SHA256.fullmatch(raw):
                raise ValueError(f"contract evidence {field} must be lowercase SHA-256")
        evaluation_fields = (
            "agreement_gate_sha256",
            "qualification_sha256",
            "partner_preflight_sha256",
            "stripe_test_drill_sha256",
        )
        if action in {"evaluation-deposit", "evaluation-delivery"}:
            for field in evaluation_fields:
                raw = getattr(self, field)
                if not isinstance(raw, str) or not HEX_SHA256.fullmatch(raw):
                    raise ValueError(
                        f"evaluation contract evidence {field} must be lowercase SHA-256"
                    )
        elif any(getattr(self, field) is not None for field in evaluation_fields):
            raise ValueError(
                "evaluation qualification, preflight, agreement, and test-drill evidence "
                "are valid only for evaluation contracts"
            )
        canonical_timestamp(self.signed_at, "signed_at")
        signed_at = datetime.fromisoformat(self.signed_at.replace("Z", "+00:00"))
        if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("signed_at cannot be in the future")
        if action == "evaluation-delivery":
            if not isinstance(
                self.delivery_manifest_sha256, str
            ) or not HEX_SHA256.fullmatch(self.delivery_manifest_sha256):
                raise ValueError(
                    "delivery invoice requires delivery manifest SHA-256"
                )
            if not isinstance(
                self.delivery_acceptance_sha256, str
            ) or not HEX_SHA256.fullmatch(self.delivery_acceptance_sha256):
                raise ValueError(
                    "delivery invoice requires delivery acceptance SHA-256"
                )
            canonical_timestamp(self.delivery_accepted_at or "", "delivery_accepted_at")
            accepted_at = datetime.fromisoformat(
                (self.delivery_accepted_at or "").replace("Z", "+00:00")
            )
            if accepted_at < signed_at:
                raise ValueError("delivery_accepted_at cannot precede signed_at")
            if (
                not isinstance(self.deposit_invoice_id, str)
                or not re.fullmatch(r"in_[A-Za-z0-9_]+", self.deposit_invoice_id)
            ):
                raise ValueError(
                    "delivery invoice requires the exact paid deposit invoice ID"
                )
            if (
                not isinstance(self.deposit_plan_sha256, str)
                or not HEX_SHA256.fullmatch(self.deposit_plan_sha256)
            ):
                raise ValueError(
                    "delivery invoice requires the exact paid deposit plan SHA-256"
                )
        elif (
            self.delivery_manifest_sha256 is not None
            or
            self.delivery_acceptance_sha256 is not None
            or self.delivery_accepted_at is not None
            or self.deposit_invoice_id is not None
            or self.deposit_plan_sha256 is not None
        ):
            raise ValueError(
                "delivery acceptance and deposit evidence are valid only for a delivery invoice"
            )
        if action == "annual-contract":
            if (
                not isinstance(self.negotiated_annual_amount_cents, int)
                or isinstance(self.negotiated_annual_amount_cents, bool)
                or self.negotiated_annual_amount_cents <= 0
            ):
                raise ValueError(
                    "annual contract evidence requires negotiated_annual_amount_cents"
                )
        elif self.negotiated_annual_amount_cents is not None:
            raise ValueError(
                "negotiated_annual_amount_cents is valid only for an annual contract"
            )

    def digest(self) -> str:
        canonical = json.dumps(
            asdict(self), separators=(",", ":"), sort_keys=True
        ).encode()
        return hashlib.sha256(canonical).hexdigest()


def read_private_document(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_CONTRACT_DOCUMENT_BYTES,
) -> PrivateDocument:
    try:
        if path.is_symlink():
            raise ValueError(f"{label} must be a regular non-symlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} must be a regular non-symlink file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError(f"{label} must be owner-only (0600 or stricter)")
            if metadata.st_uid != os.geteuid():
                raise ValueError(f"{label} must be owned by the current operator")
            raw = handle.read(max_bytes + 1)
        if not 0 < len(raw) <= max_bytes:
            raise ValueError(f"{label} is empty or exceeds {max_bytes} bytes")
        return PrivateDocument(raw, hashlib.sha256(raw).hexdigest())
    except OSError as error:
        raise ValueError(f"{label} is unavailable or unsafe") from error


def validate_canonical_json_numbers(raw: str, label: str) -> None:
    """Reject alternate spellings so signed hashes have one numeric meaning.

    Contract JSON permits integers and ordinary decimal fractions, but not
    exponent notation, negative zero, or insignificant trailing zeroes. JSON
    strings are skipped by this lexical pass; the standard decoder performs
    the structural validation afterward.
    """
    index = 0
    in_string = False
    escaped = False
    while index < len(raw):
        character = raw[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            index += 1
            continue
        if character == "-" or character.isdigit():
            end = index + 1
            while end < len(raw) and raw[end] in JSON_NUMBER_CHARACTERS:
                end += 1
            token = raw[index:end]
            if token == "-0" or CANONICAL_JSON_NUMBER.fullmatch(token) is None:
                raise ValueError(
                    f"{label} contains a noncanonical JSON number: {token}"
                )
            index = end
            continue
        index += 1


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key is forbidden: {key}")
        result[key] = item
    return result


def decode_contract_json(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
        validate_canonical_json_numbers(text, label)
        return json.loads(
            text,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"noncanonical JSON number is forbidden: {value}")
            ),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} must be valid canonical UTF-8 JSON") from error


def load_private_json_document_with_digest(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_CONTRACT_DOCUMENT_BYTES,
    expected_sha256: str | None = None,
) -> tuple[dict[str, Any], str]:
    document = read_private_document(path, label, max_bytes=max_bytes)
    if expected_sha256 is not None and document.sha256 != expected_sha256:
        raise ValueError(f"{label} does not match contract evidence")
    payload = decode_contract_json(document.payload, label)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload, document.sha256


def load_contract_evidence(path: Path) -> ContractEvidenceV2:
    payload, _ = load_private_json_document_with_digest(
        path,
        "contract evidence",
        max_bytes=MAX_EVIDENCE_BYTES,
    )
    return ContractEvidenceV2.from_mapping(payload)


def private_document_sha256(path: Path, label: str) -> str:
    return read_private_document(path, label).sha256


def load_private_json_document(path: Path, label: str) -> dict[str, Any]:
    payload, _ = load_private_json_document_with_digest(path, label)
    return payload


def _required_string(mapping: dict[str, Any], field: str, label: str) -> str:
    raw = mapping.get(field)
    if not isinstance(raw, str) or not raw.strip() or "REPLACE" in raw.upper():
        raise ValueError(f"{label}.{field} must be completed")
    return raw.strip()


def _exact_keys(mapping: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(mapping, dict) or set(mapping) != keys:
        raise ValueError(f"{label} fields are missing or unknown")
    return mapping


def validate_acceptance_matrix(
    path: Path,
    evidence: ContractEvidenceV2,
    *,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    payload, _digest = load_private_json_document_with_digest(
        path,
        "scope document",
        expected_sha256=expected_sha256,
    )
    _exact_keys(payload, ACCEPTANCE_TOP_LEVEL_KEYS, "acceptance matrix")
    if payload.get("schema_version") != ACCEPTANCE_SCHEMA_VERSION:
        raise ValueError("acceptance matrix schema_version is unsupported")
    if (
        payload.get("agreement_id") != evidence.agreement_id
        or payload.get("offer_id") != evidence.offer_id
    ):
        raise ValueError("acceptance matrix does not bind the agreement and offer")

    workload = _exact_keys(
        payload.get("workload"),
        {
            "name",
            "repository",
            "revision",
            "manifest_sha256",
            "input_generator",
            "logical_rows",
            "plonky3_version",
            "verifier_target",
        },
        "workload",
    )
    for field in ("name", "repository", "revision", "input_generator"):
        _required_string(workload, field, "workload")
    if not isinstance(workload.get("manifest_sha256"), str) or not HEX_SHA256.fullmatch(
        workload["manifest_sha256"]
    ):
        raise ValueError("workload.manifest_sha256 must be lowercase SHA-256")
    logical_rows = workload.get("logical_rows")
    if (
        not isinstance(logical_rows, int)
        or isinstance(logical_rows, bool)
        or logical_rows <= 0
    ):
        raise ValueError("workload.logical_rows must be a positive integer")
    if workload.get("plonky3_version") != "0.6.1":
        raise ValueError("workload.plonky3_version must equal 0.6.1")
    if workload.get("verifier_target") != "unmodified-p3-uni-stark-0.6.1":
        raise ValueError(
            "workload.verifier_target must use the frozen unmodified verifier"
        )

    baseline = _exact_keys(
        payload.get("baseline"),
        {"command", "host_id", "peak_rss_bytes", "wall_time_seconds", "oom_evidence"},
        "baseline",
    )
    _required_string(baseline, "command", "baseline")
    _required_string(baseline, "host_id", "baseline")
    if baseline.get("peak_rss_bytes") is not None and (
        not isinstance(baseline["peak_rss_bytes"], int)
        or isinstance(baseline["peak_rss_bytes"], bool)
        or baseline["peak_rss_bytes"] <= 0
    ):
        raise ValueError("baseline.peak_rss_bytes must be null or positive")
    if baseline.get("wall_time_seconds") is not None and (
        not isinstance(baseline["wall_time_seconds"], (int, float))
        or isinstance(baseline["wall_time_seconds"], bool)
        or not math.isfinite(baseline["wall_time_seconds"])
        or baseline["wall_time_seconds"] <= 0
    ):
        raise ValueError("baseline.wall_time_seconds must be null or positive")
    if baseline.get("oom_evidence") is not None:
        _required_string(baseline, "oom_evidence", "baseline")

    candidate = _exact_keys(
        payload.get("candidate"),
        {"command", "max_resident_bytes", "max_scratch_bytes", "scratch_medium"},
        "candidate",
    )
    _required_string(candidate, "command", "candidate")
    _required_string(candidate, "scratch_medium", "candidate")
    for field in ("max_resident_bytes", "max_scratch_bytes"):
        if (
            not isinstance(candidate.get(field), int)
            or isinstance(candidate[field], bool)
            or candidate[field] <= 0
        ):
            raise ValueError(f"candidate.{field} must be a positive integer")

    acceptance = _exact_keys(
        payload.get("acceptance"),
        {
            "official_verifier_must_accept",
            "target_peak_rss_bytes",
            "minimum_ram_reduction_ratio",
            "maximum_wall_time_ratio",
            "performance_target_is_guaranteed",
        },
        "acceptance",
    )
    if acceptance.get("official_verifier_must_accept") is not True:
        raise ValueError("acceptance must require the official verifier")
    if acceptance.get("performance_target_is_guaranteed") is not False:
        raise ValueError(
            "evaluation performance target must not be represented as guaranteed"
        )
    if (
        not isinstance(acceptance.get("target_peak_rss_bytes"), int)
        or isinstance(acceptance["target_peak_rss_bytes"], bool)
        or acceptance["target_peak_rss_bytes"] <= 0
    ):
        raise ValueError("acceptance.target_peak_rss_bytes must be positive")
    ratio = acceptance.get("minimum_ram_reduction_ratio")
    if (
        not isinstance(ratio, (int, float))
        or isinstance(ratio, bool)
        or not math.isfinite(ratio)
        or ratio < 1.5
    ):
        raise ValueError("acceptance.minimum_ram_reduction_ratio must be at least 1.5")
    wall_ratio = acceptance.get("maximum_wall_time_ratio")
    if (
        not isinstance(wall_ratio, (int, float))
        or isinstance(wall_ratio, bool)
        or not math.isfinite(wall_ratio)
        or wall_ratio <= 0
    ):
        raise ValueError("acceptance.maximum_wall_time_ratio must be positive")

    data_boundary = _exact_keys(
        payload.get("data_boundary"),
        {
            "public_or_non_sensitive_generator_only",
            "witness_transfer_allowed",
            "credentials_transfer_allowed",
            "customer_data_transfer_allowed",
        },
        "data_boundary",
    )
    if data_boundary != {
        "public_or_non_sensitive_generator_only": True,
        "witness_transfer_allowed": False,
        "credentials_transfer_allowed": False,
        "customer_data_transfer_allowed": False,
    }:
        raise ValueError("acceptance matrix data boundary is unsafe")
    delivery = _exact_keys(
        payload.get("delivery"),
        {
            "raw_report_required",
            "reproduction_commands_required",
            "known_limitations_required",
            "written_acceptance_required_before_delivery_invoice",
        },
        "delivery",
    )
    if any(value is not True for value in delivery.values()):
        raise ValueError(
            "all evaluation delivery evidence requirements must be enabled"
        )
    return payload


def validate_annual_order(
    path: Path,
    evidence: ContractEvidenceV2,
    *,
    stripe_price_id: str | None,
    stripe_product_id: str | None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate the machine-readable scope exported with the countersigned SOW."""
    payload, _digest = load_private_json_document_with_digest(
        path,
        "countersigned annual order",
        expected_sha256=expected_sha256,
    )
    _exact_keys(payload, ANNUAL_ORDER_KEYS, "countersigned annual order")
    if payload.get("schema_version") != ANNUAL_ORDER_SCHEMA_VERSION:
        raise ValueError("countersigned annual order schema_version is unsupported")
    exact_bindings = {
        "agreement_id": evidence.agreement_id,
        "offer_id": evidence.offer_id,
        "stripe_customer_id": evidence.stripe_customer_id,
        "signed_agreement_sha256": evidence.agreement_sha256,
        "negotiated_annual_amount_cents": (
            evidence.negotiated_annual_amount_cents
        ),
        "currency": "usd",
        "billing_interval": "year",
        "stripe_price_id": stripe_price_id,
        "stripe_product_id": stripe_product_id,
    }
    if any(payload.get(field) != expected for field, expected in exact_bindings.items()):
        raise ValueError(
            "countersigned annual order does not bind the exact contract, amount, and Stripe price"
        )
    countersigned_times: list[str] = []
    for field in ("customer_countersigned_at", "tinyzkp_countersigned_at"):
        timestamp = canonical_timestamp(payload.get(field), field)
        countersigned_times.append(timestamp)
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError(f"{field} cannot be in the future")
    if evidence.signed_at != max(countersigned_times):
        raise ValueError(
            "contract evidence signed_at must equal the final countersignature time"
        )
    return payload


def verify_contract_documents(
    evidence: ContractEvidenceV2,
    action: str,
    *,
    agreement_document: Path,
    scope_document: Path,
    delivery_acceptance_document: Path | None,
    agreement_gate_document: Path | None = None,
    qualification_document: Path | None = None,
    partner_preflight_document: Path | None = None,
    stripe_test_drill_document: Path | None = None,
    expected_stripe_account_id: str | None = None,
    expected_stripe_display_name: str | None = None,
    delivery_manifest_document: Path | None = None,
    delivery_artifact_root: Path | None = None,
    stripe_price_id: str | None = None,
    stripe_product_id: str | None = None,
) -> None:
    if (
        private_document_sha256(agreement_document, "agreement document")
        != evidence.agreement_sha256
    ):
        raise ValueError("agreement document does not match contract evidence")
    if action in {"evaluation-deposit", "evaluation-delivery"}:
        validate_acceptance_matrix(
            scope_document,
            evidence,
            expected_sha256=evidence.scope_sha256,
        )
        required_documents = {
            "agreement gate": agreement_gate_document,
            "qualification evidence": qualification_document,
            "partner preflight evidence": partner_preflight_document,
            "Stripe test drill evidence": stripe_test_drill_document,
        }
        missing = [label for label, path in required_documents.items() if path is None]
        if missing:
            raise ValueError(
                "evaluation contract is missing required commercial evidence: "
                + ", ".join(missing)
            )
        if not expected_stripe_account_id or not expected_stripe_display_name:
            raise ValueError(
                "evaluation contract requires the exact expected Stripe account identity"
            )
        gate_payload, gate_digest = load_private_json_document_with_digest(
            agreement_gate_document or Path(""), "agreement gate"
        )
        qualification_payload, qualification_digest = (
            load_private_json_document_with_digest(
                qualification_document or Path(""), "qualification evidence"
            )
        )
        preflight_payload, preflight_digest = load_private_json_document_with_digest(
            partner_preflight_document or Path(""), "partner preflight evidence"
        )
        drill_payload, drill_digest = load_private_json_document_with_digest(
            stripe_test_drill_document or Path(""), "Stripe test drill evidence"
        )
        agreement_gate.validate_gate(gate_payload)
        compatibility = agreement_gate.evidence_common.compatibility_identity(
            agreement_gate.evaluation_qualification.DEFAULT_COMPATIBILITY
        )
        qualification_checked = (
            agreement_gate.evaluation_qualification.validate_evidence(
                qualification_payload, compatibility
            )
        )
        preflight_checked = agreement_gate.partner_preflight.validate_evidence(
            preflight_payload, compatibility
        )
        stripe_test_drill.validate_evidence(drill_payload)
        contracted_offer = load_offers().get(evidence.offer_id)
        if (
            contracted_offer is None
            or drill_payload.get("offer_id") != evidence.offer_id
            or drill_payload.get("offer_sha256")
            != stripe_test_drill.offer_digest(contracted_offer)
            or drill_payload.get("amount_cents")
            != evaluation_milestone_amount_cents(
                contracted_offer, "evaluation-deposit"
            )
        ):
            raise ValueError(
                "Stripe test drill does not bind the contracted offer and deposit"
            )
        exact_digests = {
            "agreement gate": (gate_digest, evidence.agreement_gate_sha256),
            "qualification": (qualification_digest, evidence.qualification_sha256),
            "partner preflight": (
                preflight_digest,
                evidence.partner_preflight_sha256,
            ),
            "Stripe test drill": (
                drill_digest,
                evidence.stripe_test_drill_sha256,
            ),
        }
        for label, (actual, expected) in exact_digests.items():
            if actual != expected:
                raise ValueError(f"{label} does not match contract evidence")
        expected_gate = {
            "agreement_id": evidence.agreement_id,
            "offer_id": evidence.offer_id,
            "signed_agreement_sha256": evidence.agreement_sha256,
            "scope_sha256": evidence.scope_sha256,
            "qualification_sha256": qualification_digest,
            "partner_preflight_sha256": preflight_digest,
        }
        if any(gate_payload.get(field) != expected for field, expected in expected_gate.items()):
            raise ValueError(
                "agreement gate does not bind the exact contract and commercial evidence"
            )
        gate_reviewed_at = datetime.fromisoformat(
            gate_payload["execution_reviewed_at"].replace("Z", "+00:00")
        )
        signed_at = datetime.fromisoformat(evidence.signed_at.replace("Z", "+00:00"))
        if gate_reviewed_at < signed_at:
            raise ValueError("agreement execution review cannot precede signature")
        for field, raw_timestamp in (
            ("qualification reviewed_at", qualification_checked.get("reviewed_at")),
            ("partner preflight checked_at", preflight_checked.get("checked_at")),
        ):
            timestamp = datetime.fromisoformat(
                canonical_timestamp(str(raw_timestamp or ""), field).replace(
                    "Z", "+00:00"
                )
            )
            if timestamp > gate_reviewed_at:
                raise ValueError(f"{field} cannot follow agreement execution review")
        if (
            qualification_checked.get("application_id")
            != preflight_checked.get("application_id")
            or value(preflight_checked.get("bound_inputs", {}), "qualification_evidence_sha256")
            != qualification_digest
        ):
            raise ValueError(
                "partner preflight does not bind the exact qualification evidence"
            )
        if (
            drill_payload.get("stripe_account_id") != expected_stripe_account_id
            or drill_payload.get("stripe_display_name")
            != expected_stripe_display_name
        ):
            raise ValueError("Stripe test drill was run against a different account")
        drill_completed = datetime.fromisoformat(
            drill_payload["completed_at"].replace("Z", "+00:00")
        )
        if not timedelta(0) <= datetime.now(timezone.utc) - drill_completed <= timedelta(
            days=30
        ):
            raise ValueError("Stripe test drill evidence must be no more than 30 days old")
    elif action == "annual-contract":
        if any(
            document is not None
            for document in (
                agreement_gate_document,
                qualification_document,
                partner_preflight_document,
                stripe_test_drill_document,
                delivery_manifest_document,
                delivery_artifact_root,
            )
        ):
            raise ValueError(
                "evaluation commercial evidence is invalid for an annual contract"
            )
        validate_annual_order(
            scope_document,
            evidence,
            stripe_price_id=stripe_price_id,
            stripe_product_id=stripe_product_id,
            expected_sha256=evidence.scope_sha256,
        )
    if action == "evaluation-delivery":
        if delivery_acceptance_document is None:
            raise ValueError(
                "delivery invoice requires the written acceptance document"
            )
        if (
            private_document_sha256(
                delivery_acceptance_document, "delivery acceptance document"
            )
            != evidence.delivery_acceptance_sha256
        ):
            raise ValueError(
                "delivery acceptance document does not match contract evidence"
            )
        if delivery_manifest_document is None or delivery_artifact_root is None:
            raise ValueError(
                "delivery invoice requires the complete delivery manifest and artifact root"
            )
        delivery_payload, delivery_digest = evaluation_delivery_manifest.validate_manifest(
            delivery_manifest_document, delivery_artifact_root
        )
        if delivery_digest != evidence.delivery_manifest_sha256:
            raise ValueError("delivery manifest does not match contract evidence")
        expected_delivery = {
            "agreement_id": evidence.agreement_id,
            "offer_id": evidence.offer_id,
            "scope_sha256": evidence.scope_sha256,
            "qualification_sha256": evidence.qualification_sha256,
            "partner_preflight_sha256": evidence.partner_preflight_sha256,
            "agreement_gate_sha256": evidence.agreement_gate_sha256,
            "accepted_at": evidence.delivery_accepted_at,
        }
        if any(
            delivery_payload.get(field) != expected
            for field, expected in expected_delivery.items()
        ):
            raise ValueError(
                "delivery manifest does not bind the exact contract and acceptance"
            )
        acceptance_descriptors = [
            descriptor
            for descriptor in delivery_payload["artifacts"]
            if descriptor["name"] == "written_acceptance"
        ]
        if (
            len(acceptance_descriptors) != 1
            or acceptance_descriptors[0]["sha256"]
            != evidence.delivery_acceptance_sha256
        ):
            raise ValueError(
                "delivery manifest does not bind the written acceptance document"
            )
    elif delivery_manifest_document is not None or delivery_artifact_root is not None:
        raise ValueError(
            "delivery manifest evidence is valid only for a delivery invoice"
        )
    elif delivery_acceptance_document is not None:
        raise ValueError(
            "delivery acceptance document is valid only for a delivery invoice"
        )


@dataclass(frozen=True)
class BillingRequest:
    action: str
    offer_id: str
    customer_id: str
    agreement_id: str
    days_until_due: int
    evidence: ContractEvidenceV2
    stripe_price_id: str | None = None
    stripe_product_id: str | None = None

    def validate(self, offers: dict[str, dict[str, Any]]) -> dict[str, Any]:
        if self.offer_id not in offers:
            raise ValueError("unknown offer")
        if not isinstance(self.customer_id, str) or not self.customer_id.startswith(
            "cus_"
        ):
            raise ValueError("customer_id must be a Stripe customer ID")
        if not isinstance(self.agreement_id, str) or not AGREEMENT_ID.fullmatch(
            self.agreement_id
        ):
            raise ValueError("agreement_id must use 1-80 safe identifier characters")
        if (
            not isinstance(self.days_until_due, int)
            or isinstance(self.days_until_due, bool)
            or not 1 <= self.days_until_due <= 60
        ):
            raise ValueError("days_until_due must be between 1 and 60")
        self.evidence.validate_for(self.action)
        if (
            self.evidence.agreement_id != self.agreement_id
            or self.evidence.offer_id != self.offer_id
            or self.evidence.stripe_customer_id != self.customer_id
        ):
            raise ValueError(
                "contract evidence does not bind this agreement, offer, and customer"
            )
        if self.action in {"evaluation-deposit", "evaluation-delivery"}:
            if self.offer_id not in EVALUATIONS:
                raise ValueError("evaluation actions require an evaluation offer")
        elif self.action == "annual-contract":
            if self.offer_id not in ANNUAL:
                raise ValueError("annual-contract requires Certified or Fleet/OEM")
            if not self.stripe_price_id or not self.stripe_price_id.startswith(
                "price_"
            ):
                raise ValueError("annual-contract requires a Stripe annual price ID")
            if not self.stripe_product_id or not self.stripe_product_id.startswith(
                "prod_"
            ):
                raise ValueError("annual-contract requires the exact Stripe product ID")
            negotiated = self.evidence.negotiated_annual_amount_cents
            floor = offer_amount(offers[self.offer_id]) * 100
            if "minimum_price" in offers[self.offer_id]:
                if negotiated is None or negotiated < floor:
                    raise ValueError(
                        "negotiated annual amount must meet the advertised minimum"
                    )
            elif negotiated != floor:
                raise ValueError(
                    "negotiated annual amount must equal the fixed annual offer"
                )
        else:
            raise ValueError("unsupported billing action")
        return offers[self.offer_id]


def offer_amount(offer: dict[str, Any]) -> int:
    return int(offer.get("price", offer.get("minimum_price")))


def evaluation_milestone_amount_cents(
    offer: dict[str, Any],
    action: str,
) -> int:
    field = {
        "evaluation-deposit": "deposit_percent",
        "evaluation-delivery": "delivery_percent",
    }.get(action)
    if field is None:
        raise ValueError("evaluation milestone amount requires an evaluation action")
    milestones = offer.get("billing_milestones")
    if (
        not isinstance(milestones, dict)
        or set(milestones) != {"deposit_percent", "delivery_percent"}
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
            for value in milestones.values()
        )
        or sum(milestones.values()) != 100
    ):
        raise ValueError("evaluation offer billing milestones are invalid")
    numerator = offer_amount(offer) * 100 * milestones[field]
    if numerator % 100:
        raise ValueError("evaluation milestone does not resolve to whole cents")
    return numerator // 100


def contract_amount_cents(
    request: BillingRequest,
    offer: dict[str, Any],
) -> int:
    if request.action == "annual-contract":
        negotiated = request.evidence.negotiated_annual_amount_cents
        if not isinstance(negotiated, int) or isinstance(negotiated, bool):
            raise ValueError("annual contract is missing its signed negotiated amount")
        return negotiated
    return evaluation_milestone_amount_cents(offer, request.action)


def _write_private_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def verify_release_authorization_signature(
    authorization: bytes,
    bundle: bytes,
) -> None:
    cosign = shutil.which("cosign")
    if cosign is None:
        raise ValueError("cosign is required to verify backend release authorization")
    try:
        with tempfile.TemporaryDirectory(
            prefix="tinyzkp-release-authorization-"
        ) as raw:
            directory = Path(raw)
            directory.chmod(0o700)
            authorization_path = directory / "authorization.json"
            bundle_path = directory / "authorization.sigstore.json"
            _write_private_file(authorization_path, authorization)
            _write_private_file(bundle_path, bundle)
            command = [
                cosign,
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity-regexp",
                SIGSTORE_IDENTITY_REGEXP,
                "--certificate-oidc-issuer",
                SIGSTORE_ISSUER,
                str(authorization_path),
            ]
            verified = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
    except OSError as error:
        raise ValueError("backend release authorization verification failed") from error
    if verified.returncode != 0:
        raise ValueError(
            "backend release authorization signature is invalid: "
            + verified.stdout[-2000:]
        )


def validate_release_availability(
    request: BillingRequest,
) -> ReleaseBindingV1 | None:
    if request.action != "annual-contract":
        return None
    authorization_path = os.environ.get(RELEASE_AUTHORIZATION_PATH_ENV, "").strip()
    expected_digest = os.environ.get(RELEASE_AUTHORIZATION_SHA_ENV, "").strip().lower()
    bundle_path = os.environ.get(RELEASE_AUTHORIZATION_BUNDLE_PATH_ENV, "").strip()
    expected_bundle_digest = (
        os.environ.get(RELEASE_AUTHORIZATION_BUNDLE_SHA_ENV, "").strip().lower()
    )
    if (
        not authorization_path
        or not bundle_path
        or not HEX_SHA256.fullmatch(expected_digest)
        or not HEX_SHA256.fullmatch(expected_bundle_digest)
    ):
        raise ValueError(
            "annual Certified and Fleet/OEM billing requires a hash-bound signed "
            "backend release authorization and Sigstore bundle"
        )
    authorization = read_private_document(
        Path(authorization_path),
        "backend release authorization",
        max_bytes=MAX_EVIDENCE_BYTES,
    )
    signature_bundle = read_private_document(
        Path(bundle_path),
        "backend release authorization Sigstore bundle",
        max_bytes=MAX_EVIDENCE_BYTES,
    )
    if authorization.sha256 != expected_digest:
        raise ValueError("backend release authorization digest mismatch")
    if signature_bundle.sha256 != expected_bundle_digest:
        raise ValueError(
            "backend release authorization Sigstore bundle digest mismatch"
        )
    payload = decode_contract_json(
        authorization.payload,
        "backend release authorization",
    )
    if not isinstance(payload, dict):
        raise ValueError("backend release authorization must be a JSON object")
    schema_version = payload.get("schema_version")
    validator_exit_code = payload.get("validator_exit_code")
    if (
        set(payload) != RELEASE_AUTHORIZATION_KEYS
        or not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise ValueError(
            "backend release authorization fields/schema_version are invalid"
        )
    if (
        payload.get("status") != "ready"
        or not isinstance(validator_exit_code, int)
        or isinstance(validator_exit_code, bool)
        or validator_exit_code != 0
    ):
        raise ValueError("backend release authorization is not ready")
    if payload.get("validator") != "scripts/ci/backend_release_ready.py":
        raise ValueError("backend release authorization used an unrecognized validator")
    if not isinstance(payload.get("release_sha"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", payload["release_sha"]
    ):
        raise ValueError("backend release authorization release_sha is invalid")
    for field in (
        "source_tree_sha256",
        "backend_evidence_sha256",
        "backend_release_ready_report_sha256",
        "signed_release_manifest_sha256",
        "signature_bundle_sha256",
    ):
        if not isinstance(payload.get(field), str) or not HEX_SHA256.fullmatch(
            payload[field]
        ):
            raise ValueError(f"backend release authorization {field} is invalid")
    verified_at = canonical_timestamp(
        str(payload.get("verified_at", "")), "verified_at"
    )
    verification_time = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
    if verification_time > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError(
            "backend release authorization verified_at cannot be in the future"
        )
    verify_release_authorization_signature(
        authorization.payload,
        signature_bundle.payload,
    )
    return ReleaseBindingV1(
        authorization_sha256=authorization.sha256,
        authorization_bundle_sha256=signature_bundle.sha256,
        release_sha=payload["release_sha"],
        source_tree_sha256=payload["source_tree_sha256"],
        verified_at=verified_at,
    )


def validate_sender_identity_gate() -> None:
    """Prevent Stripe from sending under an unrelated business identity."""
    if os.environ.get("TINYZKP_CONTRACT_SENDER_IDENTITY_CONFIRMED") != "1":
        raise ValueError(
            "contract billing is blocked until Stripe's customer-facing sender identity "
            "is verified as TinyZKP"
        )


def validate_customer_facing_sender_identity(account: Any) -> None:
    profile = value(account, "business_profile", {}) or {}
    public_name = str(value(profile, "name", "")).strip()
    support_email = str(value(profile, "support_email", "")).strip().lower()
    support_url = str(value(profile, "support_url", "")).strip()
    email_local, email_separator, email_domain = support_email.rpartition("@")
    parsed_url = urlparse(support_url)
    hostname = (parsed_url.hostname or "").lower()
    if (
        public_name.casefold() != "tinyzkp"
        or not email_local
        or email_separator != "@"
        or email_domain != "tinyzkp.com"
        or parsed_url.scheme != "https"
        or hostname not in {"tinyzkp.com", "www.tinyzkp.com"}
    ):
        raise ValueError(
            "Stripe customer-facing business name, support email, and URL must identify TinyZKP"
        )


def plan(
    request: BillingRequest,
    offer: dict[str, Any],
    release_binding: ReleaseBindingV1 | None = None,
) -> dict[str, Any]:
    if request.action == "annual-contract" and release_binding is None:
        raise ValueError(
            "annual contract plan requires a verified backend release binding"
        )
    if request.action != "annual-contract" and release_binding is not None:
        raise ValueError("backend release binding is valid only for annual contracts")
    amount_cents = contract_amount_cents(request, offer)
    bound = {
        "action": request.action,
        "offer_id": request.offer_id,
        "customer_id": request.customer_id,
        "agreement_id": request.agreement_id,
        "amount_cents": amount_cents,
        "currency": "usd",
        "collection_method": "send_invoice",
        "days_until_due": request.days_until_due,
        "public_checkout": False,
        "stripe_price_id": request.stripe_price_id,
        "stripe_product_id": request.stripe_product_id,
        "contract_evidence_sha256": request.evidence.digest(),
        "agreement_sha256": request.evidence.agreement_sha256,
        "scope_sha256": request.evidence.scope_sha256,
        "agreement_gate_sha256": request.evidence.agreement_gate_sha256,
        "qualification_sha256": request.evidence.qualification_sha256,
        "partner_preflight_sha256": request.evidence.partner_preflight_sha256,
        "stripe_test_drill_sha256": request.evidence.stripe_test_drill_sha256,
        "delivery_manifest_sha256": request.evidence.delivery_manifest_sha256,
        "signed_at": request.evidence.signed_at,
        "delivery_acceptance_sha256": request.evidence.delivery_acceptance_sha256,
        "delivery_accepted_at": request.evidence.delivery_accepted_at,
        "deposit_invoice_id": request.evidence.deposit_invoice_id,
        "deposit_plan_sha256": request.evidence.deposit_plan_sha256,
        "negotiated_annual_amount_cents": (
            request.evidence.negotiated_annual_amount_cents
        ),
    }
    if release_binding is not None:
        bound.update(release_binding.plan_fields())
    plan_sha256 = hashlib.sha256(
        json.dumps(bound, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return {"mode": "read_only", **bound, "plan_sha256": plan_sha256}


def prepare_plan(
    request: BillingRequest,
    offer: dict[str, Any],
) -> tuple[dict[str, Any], ReleaseBindingV1 | None]:
    release_binding = validate_release_availability(request)
    return plan(request, offer, release_binding), release_binding


def contract_metadata(
    request: BillingRequest,
    milestone: str,
    plan_sha256: str,
    release_binding: ReleaseBindingV1 | None = None,
) -> dict[str, str]:
    metadata = {
        "tinyzkp_offer_id": request.offer_id,
        "tinyzkp_agreement_id": request.agreement_id,
        "tinyzkp_milestone": milestone,
        "tinyzkp_contract_evidence_sha256": request.evidence.digest(),
        "tinyzkp_agreement_sha256": request.evidence.agreement_sha256,
        "tinyzkp_scope_sha256": request.evidence.scope_sha256,
        "tinyzkp_signed_at": request.evidence.signed_at,
        "tinyzkp_plan_sha256": plan_sha256,
    }
    for field, metadata_key in (
        (request.evidence.agreement_gate_sha256, "tinyzkp_agreement_gate_sha256"),
        (request.evidence.qualification_sha256, "tinyzkp_qualification_sha256"),
        (request.evidence.partner_preflight_sha256, "tinyzkp_partner_preflight_sha256"),
        (request.evidence.stripe_test_drill_sha256, "tinyzkp_test_drill_sha256"),
        (request.evidence.delivery_manifest_sha256, "tinyzkp_delivery_manifest_sha256"),
    ):
        if field is not None:
            metadata[metadata_key] = field
    if request.evidence.delivery_acceptance_sha256:
        metadata["tinyzkp_delivery_acceptance_sha256"] = (
            request.evidence.delivery_acceptance_sha256
        )
        metadata["tinyzkp_delivery_accepted_at"] = (
            request.evidence.delivery_accepted_at or ""
        )
        metadata["tinyzkp_deposit_invoice_id"] = (
            request.evidence.deposit_invoice_id or ""
        )
        metadata["tinyzkp_deposit_plan_sha256"] = (
            request.evidence.deposit_plan_sha256 or ""
        )
    if request.evidence.negotiated_annual_amount_cents is not None:
        metadata["tinyzkp_negotiated_annual_amount_cents"] = str(
            request.evidence.negotiated_annual_amount_cents
        )
    if release_binding is not None:
        metadata.update(release_binding.stripe_metadata())
    return metadata


def validate_contract_customer(customer: Any, request: BillingRequest) -> None:
    metadata = value(customer, "metadata", {}) or {}
    name = value(customer, "name")
    address = value(customer, "address", {}) or {}
    if (
        value(customer, "id") != request.customer_id
        or value(customer, "deleted") is True
        or not isinstance(name, str)
        or not name.strip()
        or any(
            not str(value(address, field, "") or "").strip()
            for field in ("line1", "city", "postal_code", "country")
        )
        or value(metadata, "tinyzkp_contract_customer") != "true"
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
    ):
        raise ValueError(
            "Stripe customer is not an active, contract-tagged TinyZKP customer for this agreement"
        )


def create_stripe_client(api_key: str) -> Any:
    return stripe.StripeClient(
        api_key,
        stripe_version=STRIPE_API_VERSION,
        max_network_retries=2,
    )


def validate_annual_price(
    price: Any,
    offer: dict[str, Any],
    *,
    expected_price_id: str,
    expected_product_id: str,
    expected_amount_cents: int,
) -> None:
    recurring = value(price, "recurring", {}) or {}
    metadata = value(price, "metadata", {}) or {}
    product = value(price, "product", {}) or {}
    product_metadata = value(product, "metadata", {}) or {}
    if (
        value(price, "id") != expected_price_id
        or value(product, "id") != expected_product_id
    ):
        raise ValueError("annual Stripe price/product identity mismatch")
    if value(price, "active") is not True:
        raise ValueError("annual Stripe price is inactive")
    if (
        value(price, "currency") != "usd"
        or value(price, "unit_amount") != expected_amount_cents
    ):
        raise ValueError(
            "annual Stripe price amount/currency does not match the offer source"
        )
    if (
        value(recurring, "interval") != "year"
        or value(recurring, "interval_count", 1) != 1
    ):
        raise ValueError("annual Stripe price must recur exactly yearly")
    expected_lookup_key = f"{offer['id']}_annual_contract_v1"
    if (
        value(price, "lookup_key") != expected_lookup_key
        or value(metadata, "tinyzkp_offer_id") != offer["id"]
        or value(metadata, "tinyzkp_contract_price") != "true"
        or value(product, "active") is not True
        or value(product, "name") != offer["name"]
        or value(product_metadata, "tinyzkp_offer_id") != offer["id"]
        or value(product_metadata, "tinyzkp_contract_product") != "true"
    ):
        raise ValueError(
            "annual Stripe price/product provenance does not match the offer"
        )


def listed_invoices(client: Any, *, customer_id: str | None = None) -> list[Any]:
    params: dict[str, Any] = {"limit": 100}
    if customer_id:
        params["customer"] = customer_id
    page = client.v1.invoices.list(params)
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def stripe_object_id(item: Any) -> str:
    if isinstance(item, str):
        return item
    return str(value(item, "id", "") or "")


def hosted_invoice_url(invoice: Any) -> str:
    raw = value(invoice, "hosted_invoice_url")
    if not isinstance(raw, str):
        raise ValueError("Stripe invoice is missing its hosted invoice URL")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in raw):
        raise ValueError("Stripe invoice returned an untrusted hosted invoice URL")
    parsed = urlparse(raw)
    try:
        explicit_port = parsed.port
    except ValueError as error:
        raise ValueError(
            "Stripe invoice returned an untrusted hosted invoice URL"
        ) from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "invoice.stripe.com"
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or not parsed.path.startswith("/i/")
        or parsed.path == "/i/"
        or "#" in raw
    ):
        raise ValueError("Stripe invoice returned an untrusted hosted invoice URL")
    return raw


def billing_operation_key(request: BillingRequest) -> str:
    milestone = (
        "annual"
        if request.action == "annual-contract"
        else "deposit"
        if request.action == "evaluation-deposit"
        else "delivery"
    )
    material = "\0".join(
        (
            "tinyzkp-contract-billing-v1",
            request.customer_id,
            request.agreement_id,
            request.offer_id,
            milestone,
        )
    ).encode()
    return f"billing_{hashlib.sha256(material).hexdigest()}"


def open_billing_ledger(path: Path) -> sqlite3.Connection:
    parent = path.parent
    try:
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError("billing ledger parent must be a regular directory")
        parent_metadata = parent.stat()
        if parent_metadata.st_uid != os.geteuid() or parent_metadata.st_mode & 0o077:
            raise ValueError("billing ledger parent must be owner-only")
        if path.is_symlink():
            raise ValueError("billing ledger must not be a symlink")
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        os.close(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("billing ledger must be a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("billing ledger must be owner-only (0600 or stricter)")
        connection = sqlite3.connect(path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS billing_operations (
                    operation_key TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    customer_id TEXT NOT NULL,
                    agreement_id TEXT NOT NULL,
                    offer_id TEXT NOT NULL,
                    stripe_object_id TEXT,
                    phase TEXT NOT NULL DEFAULT 'reserved',
                    reserved_at TEXT NOT NULL,
                    bound_at TEXT
                ) STRICT
                """
            )
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(billing_operations)"
                ).fetchall()
            }
            if "phase" not in columns:
                connection.execute(
                    "ALTER TABLE billing_operations "
                    "ADD COLUMN phase TEXT NOT NULL DEFAULT 'reserved'"
                )
                connection.execute(
                    "UPDATE billing_operations SET phase = 'finalized' "
                    "WHERE stripe_object_id IS NOT NULL"
                )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        return connection
    except (OSError, sqlite3.Error) as error:
        raise ValueError("billing ledger is unavailable or unsafe") from error


def reserve_billing_operation(
    path: Path,
    request: BillingRequest,
    plan_sha256: str,
) -> BillingReservation:
    operation_key = billing_operation_key(request)
    connection = open_billing_ledger(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM billing_operations WHERE operation_key = ?",
            (operation_key,),
        ).fetchone()
        newly_reserved = row is None
        if row is None:
            connection.execute(
                """
                INSERT INTO billing_operations (
                    operation_key, plan_sha256, action, customer_id,
                    agreement_id, offer_id, stripe_object_id, phase,
                    reserved_at, bound_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, 'reserved', ?, NULL)
                """,
                (
                    operation_key,
                    plan_sha256,
                    request.action,
                    request.customer_id,
                    request.agreement_id,
                    request.offer_id,
                    datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                ),
            )
            stripe_id = None
            phase = "reserved"
        else:
            expected = (
                plan_sha256,
                request.action,
                request.customer_id,
                request.agreement_id,
                request.offer_id,
            )
            actual = tuple(
                row[field]
                for field in (
                    "plan_sha256",
                    "action",
                    "customer_id",
                    "agreement_id",
                    "offer_id",
                )
            )
            if actual != expected:
                raise ValueError(
                    "billing ledger operation is bound to a different contract plan"
                )
            stripe_id = row["stripe_object_id"]
            phase = row["phase"]
            if phase not in BILLING_PHASE_ORDER:
                raise ValueError("billing ledger contains an unsupported phase")
        connection.execute("COMMIT")
        return BillingReservation(
            operation_key=operation_key,
            plan_sha256=plan_sha256,
            action=request.action,
            customer_id=request.customer_id,
            stripe_object_id=stripe_id,
            phase=phase,
            newly_reserved=newly_reserved,
        )
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def advance_billing_operation(
    path: Path,
    reservation: BillingReservation,
    stripe_id: str,
    phase: str,
) -> None:
    if phase not in BILLING_PHASE_ORDER or phase == "reserved":
        raise ValueError("cannot advance to an invalid billing phase")
    expected_prefix = "sub_" if reservation.action == "annual-contract" else "in_"
    if not isinstance(stripe_id, str) or not stripe_id.startswith(expected_prefix):
        raise ValueError("cannot bind an invalid Stripe object ID")
    connection = open_billing_ledger(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM billing_operations WHERE operation_key = ?",
            (reservation.operation_key,),
        ).fetchone()
        if (
            row is None
            or row["plan_sha256"] != reservation.plan_sha256
            or row["action"] != reservation.action
            or row["customer_id"] != reservation.customer_id
        ):
            raise ValueError("billing ledger reservation identity changed")
        existing_id = row["stripe_object_id"]
        if existing_id is not None and existing_id != stripe_id:
            raise ValueError("billing ledger already binds a different Stripe object")
        existing_phase = row["phase"]
        if existing_phase not in BILLING_PHASE_ORDER:
            raise ValueError("billing ledger contains an unsupported phase")
        if BILLING_PHASE_ORDER[phase] < BILLING_PHASE_ORDER[existing_phase]:
            raise ValueError("billing ledger phase cannot move backward")
        connection.execute(
            """
            UPDATE billing_operations
            SET stripe_object_id = ?, phase = ?, bound_at = ?
            WHERE operation_key = ?
            """,
            (
                stripe_id,
                phase,
                datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                reservation.operation_key,
            ),
        )
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def bind_billing_operation(
    path: Path,
    reservation: BillingReservation,
    stripe_id: str,
) -> None:
    advance_billing_operation(
        path,
        reservation,
        stripe_id,
        "finalized",
    )


def validate_reusable_invoice(
    invoice: Any,
    request: BillingRequest,
    plan_sha256: str,
    milestone: str,
) -> None:
    metadata = value(invoice, "metadata", {}) or {}
    offer = load_offers()[request.offer_id]
    expected_amount = contract_amount_cents(request, offer)
    delivery_binding_matches = request.action != "evaluation-delivery" or (
        value(metadata, "tinyzkp_deposit_invoice_id")
        == request.evidence.deposit_invoice_id
        and value(metadata, "tinyzkp_deposit_plan_sha256")
        == request.evidence.deposit_plan_sha256
        and value(metadata, "tinyzkp_delivery_acceptance_sha256")
        == request.evidence.delivery_acceptance_sha256
        and value(metadata, "tinyzkp_delivery_manifest_sha256")
        == request.evidence.delivery_manifest_sha256
    )
    evaluation_binding_matches = request.action not in {
        "evaluation-deposit",
        "evaluation-delivery",
    } or (
        value(metadata, "tinyzkp_agreement_gate_sha256")
        == request.evidence.agreement_gate_sha256
        and value(metadata, "tinyzkp_qualification_sha256")
        == request.evidence.qualification_sha256
        and value(metadata, "tinyzkp_partner_preflight_sha256")
        == request.evidence.partner_preflight_sha256
        and value(metadata, "tinyzkp_test_drill_sha256")
        == request.evidence.stripe_test_drill_sha256
    )
    if (
        not stripe_object_id(invoice).startswith("in_")
        or stripe_object_id(value(invoice, "customer")) != request.customer_id
        or value(invoice, "status") not in {"open", "paid", "uncollectible"}
        or value(invoice, "currency") != "usd"
        or value(invoice, "collection_method") != "send_invoice"
        or value(invoice, "auto_advance") is not False
        or value(invoice, "total") != expected_amount
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_milestone") != milestone
        or value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        or value(metadata, "tinyzkp_contract_evidence_sha256")
        != request.evidence.digest()
        or value(metadata, "tinyzkp_scope_sha256") != request.evidence.scope_sha256
        or not evaluation_binding_matches
        or not delivery_binding_matches
    ):
        raise ValueError(
            "existing same-plan invoice is malformed or was edited; operator reconciliation is required"
        )


def validate_paid_deposit_for_delivery(
    invoice: Any,
    request: BillingRequest,
) -> None:
    """Bind a delivery invoice to the exact previously paid deposit object."""
    metadata = value(invoice, "metadata", {}) or {}
    expected_amount = evaluation_milestone_amount_cents(
        load_offers()[request.offer_id],
        "evaluation-deposit",
    )
    if (
        stripe_object_id(invoice) != request.evidence.deposit_invoice_id
        or stripe_object_id(value(invoice, "customer")) != request.customer_id
        or value(invoice, "status") != "paid"
        or value(invoice, "currency") != "usd"
        or value(invoice, "total") != expected_amount
        or value(invoice, "amount_paid") != expected_amount
        or value(invoice, "amount_remaining") != 0
        or value(invoice, "collection_method") != "send_invoice"
        or value(invoice, "auto_advance") is not False
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_milestone") != "deposit"
        or value(metadata, "tinyzkp_plan_sha256")
        != request.evidence.deposit_plan_sha256
        or value(metadata, "tinyzkp_agreement_sha256")
        != request.evidence.agreement_sha256
        or value(metadata, "tinyzkp_scope_sha256") != request.evidence.scope_sha256
        or value(metadata, "tinyzkp_signed_at") != request.evidence.signed_at
        or value(metadata, "tinyzkp_agreement_gate_sha256")
        != request.evidence.agreement_gate_sha256
        or value(metadata, "tinyzkp_qualification_sha256")
        != request.evidence.qualification_sha256
        or value(metadata, "tinyzkp_partner_preflight_sha256")
        != request.evidence.partner_preflight_sha256
        or value(metadata, "tinyzkp_test_drill_sha256")
        != request.evidence.stripe_test_drill_sha256
    ):
        raise ValueError(
            "delivery invoice requires the exact fully paid deposit bound in contract evidence"
        )


def validate_evaluation_history(
    request: BillingRequest, client: Any, plan_sha256: str
) -> Any | None:
    """Enforce founding slots and deposit-before-delivery from Stripe records."""
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    customer_invoices = listed_invoices(client, customer_id=request.customer_id)
    matching: list[Any] = []
    same_plan_claims = 0
    for invoice in customer_invoices:
        metadata = value(invoice, "metadata", {}) or {}
        same_milestone = (
            value(invoice, "status") != "void"
            and value(metadata, "tinyzkp_offer_id") == request.offer_id
            and value(metadata, "tinyzkp_agreement_id") == request.agreement_id
            and value(metadata, "tinyzkp_milestone") == milestone
        )
        if same_milestone:
            if value(metadata, "tinyzkp_plan_sha256") != plan_sha256:
                raise ValueError(
                    "an existing invoice for this agreement milestone has a different plan"
                )
            same_plan_claims += 1
            if value(invoice, "status") != "draft":
                matching.append(invoice)
    if request.action == "evaluation-delivery":
        deposits = [
            invoice
            for invoice in customer_invoices
            if stripe_object_id(invoice) == request.evidence.deposit_invoice_id
        ]
        if len(deposits) != 1:
            raise ValueError(
                "delivery invoice requires its exact paid deposit invoice"
            )
        validate_paid_deposit_for_delivery(deposits[0], request)
    if (
        request.action == "evaluation-deposit"
        and request.offer_id == "founding_evaluation"
    ):
        founding_offer = load_offers()["founding_evaluation"]
        customer_cap = founding_offer.get("customer_cap")
        if (
            not isinstance(customer_cap, int)
            or isinstance(customer_cap, bool)
            or customer_cap <= 0
        ):
            raise ValueError("Founding Evaluation customer cap is invalid")
        agreements = {
            str(value(metadata, "tinyzkp_agreement_id"))
            for invoice in listed_invoices(client)
            if value(invoice, "status") != "void"
            if (metadata := value(invoice, "metadata", {}) or {})
            if value(metadata, "tinyzkp_offer_id") == "founding_evaluation"
            and value(metadata, "tinyzkp_milestone") == "deposit"
            and value(metadata, "tinyzkp_agreement_id")
        }
        if (
            request.agreement_id not in agreements
            and len(agreements) >= customer_cap
        ):
            raise ValueError(
                f"the {customer_cap} Founding Evaluation slots are already allocated"
            )
    if same_plan_claims > 1:
        raise ValueError(
            "multiple existing invoices already claim this agreement milestone and plan"
        )
    if matching:
        validate_reusable_invoice(matching[0], request, plan_sha256, milestone)
        return matching[0]
    return None


def create_invoice(
    request: BillingRequest,
    offer: dict[str, Any],
    client: Any,
    plan_sha256: str,
) -> Any:
    amount_cents = evaluation_milestone_amount_cents(offer, request.action)
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    metadata = contract_metadata(request, milestone, plan_sha256)
    idempotency = f"tinyzkp-{request.agreement_id}-{milestone}-{plan_sha256[:24]}"
    invoice = client.v1.invoices.create(
        {
            "customer": request.customer_id,
            "collection_method": "send_invoice",
            "days_until_due": request.days_until_due,
            "auto_advance": False,
            "metadata": metadata,
            "description": f"TinyZKP agreement {request.agreement_id}",
        },
        {"idempotency_key": f"{idempotency}-invoice"},
    )
    invoice_id = value(invoice, "id")
    if not isinstance(invoice_id, str) or not invoice_id.startswith("in_"):
        raise ValueError("Stripe did not return a valid draft invoice ID")
    client.v1.invoice_items.create(
        {
            "customer": request.customer_id,
            "invoice": invoice_id,
            "amount": amount_cents,
            "currency": "usd",
            "description": f"{offer['name']} — {milestone}",
            "metadata": metadata,
        },
        {"idempotency_key": f"{idempotency}-item"},
    )
    return client.v1.invoices.finalize_invoice(
        invoice_id,
        {"auto_advance": False},
        {"idempotency_key": f"{idempotency}-finalize"},
    )


def listed_invoice_items(client: Any, invoice_id: str) -> list[Any]:
    page = client.v1.invoice_items.list({"invoice": invoice_id, "limit": 100})
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def validate_resumable_invoice(
    invoice: Any,
    request: BillingRequest,
    plan_sha256: str,
    milestone: str,
) -> str:
    metadata = value(invoice, "metadata", {}) or {}
    status = str(value(invoice, "status", "") or "")
    if (
        not stripe_object_id(invoice).startswith("in_")
        or stripe_object_id(value(invoice, "customer")) != request.customer_id
        or status not in {"draft", "open", "paid", "uncollectible"}
        or value(invoice, "currency") != "usd"
        or value(invoice, "collection_method") != "send_invoice"
        or value(invoice, "auto_advance") is not False
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_milestone") != milestone
        or value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        or value(metadata, "tinyzkp_contract_evidence_sha256")
        != request.evidence.digest()
        or value(metadata, "tinyzkp_agreement_sha256")
        != request.evidence.agreement_sha256
        or value(metadata, "tinyzkp_scope_sha256") != request.evidence.scope_sha256
        or value(metadata, "tinyzkp_signed_at") != request.evidence.signed_at
    ):
        raise ValueError(
            "resumable invoice is not exactly bound to this contract plan"
        )
    if status != "draft":
        validate_reusable_invoice(invoice, request, plan_sha256, milestone)
    return status


def validate_resumable_invoice_item(
    item: Any,
    *,
    invoice_id: str,
    request: BillingRequest,
    amount_cents: int,
    plan_sha256: str,
    milestone: str,
) -> None:
    metadata = value(item, "metadata", {}) or {}
    if (
        not stripe_object_id(item).startswith("ii_")
        or stripe_object_id(value(item, "invoice")) != invoice_id
        or stripe_object_id(value(item, "customer")) != request.customer_id
        or value(item, "amount") != amount_cents
        or value(item, "currency") != "usd"
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_milestone") != milestone
        or value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        or value(metadata, "tinyzkp_contract_evidence_sha256")
        != request.evidence.digest()
        or value(metadata, "tinyzkp_scope_sha256") != request.evidence.scope_sha256
    ):
        raise ValueError(
            "resumable invoice item is not exactly bound to this contract plan"
        )


def resumable_invoice_candidates(
    request: BillingRequest,
    client: Any,
    plan_sha256: str,
    milestone: str,
) -> list[Any]:
    candidates: list[Any] = []
    for invoice in listed_invoices(client, customer_id=request.customer_id):
        metadata = value(invoice, "metadata", {}) or {}
        if (
            value(invoice, "status") != "void"
            and value(metadata, "tinyzkp_offer_id") == request.offer_id
            and value(metadata, "tinyzkp_agreement_id") == request.agreement_id
            and value(metadata, "tinyzkp_milestone") == milestone
        ):
            if value(metadata, "tinyzkp_plan_sha256") != plan_sha256:
                raise ValueError(
                    "an existing invoice for this agreement milestone has a different plan"
                )
            validate_resumable_invoice(
                invoice,
                request,
                plan_sha256,
                milestone,
            )
            candidates.append(invoice)
    if len(candidates) > 1:
        raise ValueError(
            "multiple Stripe invoices claim the same resumable contract plan"
        )
    return candidates


def resume_evaluation_invoice(
    request: BillingRequest,
    offer: dict[str, Any],
    client: Any,
    plan_sha256: str,
    *,
    ledger_path: Path,
    reservation: BillingReservation,
) -> Any:
    """Create or deterministically resume the three-phase invoice workflow."""
    if not request.action.startswith("evaluation-"):
        raise ValueError("invoice resume is valid only for evaluation milestones")
    amount_cents = contract_amount_cents(request, offer)
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    metadata = contract_metadata(request, milestone, plan_sha256)
    idempotency = f"tinyzkp-{request.agreement_id}-{milestone}-{plan_sha256[:24]}"

    if reservation.stripe_object_id is not None:
        if reservation.phase == "reserved":
            raise ValueError(
                "billing ledger cannot bind an invoice while still reserved"
            )
        invoice = client.v1.invoices.retrieve(reservation.stripe_object_id)
        if stripe_object_id(invoice) != reservation.stripe_object_id:
            raise ValueError("Stripe returned the wrong ledger-bound invoice")
        status = validate_resumable_invoice(
            invoice,
            request,
            plan_sha256,
            milestone,
        )
        if reservation.phase == "finalized" and status == "draft":
            raise ValueError(
                "finalized billing ledger entry points to a draft invoice"
            )
    else:
        candidates = resumable_invoice_candidates(
            request,
            client,
            plan_sha256,
            milestone,
        )
        if candidates:
            invoice = candidates[0]
            status = str(value(invoice, "status"))
        else:
            invoice = client.v1.invoices.create(
                {
                    "customer": request.customer_id,
                    "collection_method": "send_invoice",
                    "days_until_due": request.days_until_due,
                    "auto_advance": False,
                    "metadata": metadata,
                    "description": f"TinyZKP agreement {request.agreement_id}",
                },
                {"idempotency_key": f"{idempotency}-invoice"},
            )
            status = validate_resumable_invoice(
                invoice,
                request,
                plan_sha256,
                milestone,
            )
        advance_billing_operation(
            ledger_path,
            reservation,
            stripe_object_id(invoice),
            "invoice_created" if status == "draft" else "finalized",
        )

    invoice_id = stripe_object_id(invoice)
    if status != "draft":
        bind_billing_operation(ledger_path, reservation, invoice_id)
        return invoice
    if reservation.phase == "finalized":
        raise ValueError("finalized billing ledger entry points to a draft invoice")

    items = listed_invoice_items(client, invoice_id)
    if len(items) > 1:
        raise ValueError("resumable invoice contains multiple invoice items")
    if items:
        validate_resumable_invoice_item(
            items[0],
            invoice_id=invoice_id,
            request=request,
            amount_cents=amount_cents,
            plan_sha256=plan_sha256,
            milestone=milestone,
        )
    else:
        if BILLING_PHASE_ORDER[reservation.phase] >= BILLING_PHASE_ORDER["item_created"]:
            raise ValueError("billing ledger item phase has no Stripe invoice item")
        item = client.v1.invoice_items.create(
            {
                "customer": request.customer_id,
                "invoice": invoice_id,
                "amount": amount_cents,
                "currency": "usd",
                "description": f"{offer['name']} — {milestone}",
                "metadata": metadata,
            },
            {"idempotency_key": f"{idempotency}-item"},
        )
        validate_resumable_invoice_item(
            item,
            invoice_id=invoice_id,
            request=request,
            amount_cents=amount_cents,
            plan_sha256=plan_sha256,
            milestone=milestone,
        )
    advance_billing_operation(
        ledger_path,
        reservation,
        invoice_id,
        "item_created",
    )
    finalized = client.v1.invoices.finalize_invoice(
        invoice_id,
        {"auto_advance": False},
        {"idempotency_key": f"{idempotency}-finalize"},
    )
    validate_reusable_invoice(
        finalized,
        request,
        plan_sha256,
        milestone,
    )
    bind_billing_operation(ledger_path, reservation, invoice_id)
    return finalized


def listed_subscriptions(client: Any, customer_id: str) -> list[Any]:
    page = client.v1.subscriptions.list(
        {"customer": customer_id, "status": "all", "limit": 100}
    )
    auto_paging_iter = getattr(page, "auto_paging_iter", None)
    if callable(auto_paging_iter):
        return list(auto_paging_iter())
    return list(value(page, "data", []) or [])


def validate_reusable_subscription(
    subscription: Any,
    request: BillingRequest,
    plan_sha256: str,
    release_binding: ReleaseBindingV1,
) -> None:
    metadata = value(subscription, "metadata", {}) or {}
    items = value(value(subscription, "items", {}) or {}, "data", []) or []
    expected_items = [
        item
        for item in items
        if stripe_object_id(value(item, "price")) == request.stripe_price_id
        and value(item, "quantity") == 1
    ]
    if (
        not stripe_object_id(subscription).startswith("sub_")
        or stripe_object_id(value(subscription, "customer")) != request.customer_id
        or value(subscription, "status") != "active"
        or value(subscription, "collection_method") != "send_invoice"
        or len(items) != 1
        or len(expected_items) != 1
        or value(metadata, "tinyzkp_offer_id") != request.offer_id
        or value(metadata, "tinyzkp_agreement_id") != request.agreement_id
        or value(metadata, "tinyzkp_milestone") != "annual"
        or value(metadata, "tinyzkp_plan_sha256") != plan_sha256
        or value(metadata, "tinyzkp_contract_evidence_sha256")
        != request.evidence.digest()
        or value(metadata, "tinyzkp_scope_sha256") != request.evidence.scope_sha256
        or value(metadata, "tinyzkp_negotiated_annual_amount_cents")
        != str(request.evidence.negotiated_annual_amount_cents)
        or value(metadata, "tinyzkp_backend_authorization_sha256")
        != release_binding.authorization_sha256
        or value(metadata, "tinyzkp_backend_authorization_bundle_sha256")
        != release_binding.authorization_bundle_sha256
        or value(metadata, "tinyzkp_backend_release_sha")
        != release_binding.release_sha
        or value(metadata, "tinyzkp_backend_source_tree_sha256")
        != release_binding.source_tree_sha256
    ):
        raise ValueError(
            "existing same-plan subscription is malformed or was edited; operator reconciliation is required"
        )


def validate_annual_history(
    request: BillingRequest,
    client: Any,
    plan_sha256: str,
    release_binding: ReleaseBindingV1,
) -> Any | None:
    matching: list[Any] = []
    for subscription in listed_subscriptions(client, request.customer_id):
        metadata = value(subscription, "metadata", {}) or {}
        same_agreement = (
            value(subscription, "status") not in {"canceled", "incomplete_expired"}
            and value(metadata, "tinyzkp_offer_id") == request.offer_id
            and value(metadata, "tinyzkp_agreement_id") == request.agreement_id
        )
        if same_agreement:
            if value(metadata, "tinyzkp_plan_sha256") != plan_sha256:
                raise ValueError(
                    "an existing annual subscription for this agreement has a different plan"
                )
            matching.append(subscription)
    if len(matching) > 1:
        raise ValueError(
            "multiple existing subscriptions already claim this agreement and plan"
        )
    if matching:
        validate_reusable_subscription(
            matching[0],
            request,
            plan_sha256,
            release_binding,
        )
        return matching[0]
    return None


def retrieve_and_validate_reserved_object(
    request: BillingRequest,
    client: Any,
    plan_sha256: str,
    stripe_id: str,
    release_binding: ReleaseBindingV1 | None = None,
) -> Any:
    if request.action == "annual-contract":
        if release_binding is None:
            raise ValueError("annual reconciliation requires its release binding")
        subscription = client.v1.subscriptions.retrieve(
            stripe_id,
            {"expand": ["items.data.price"]},
        )
        validate_reusable_subscription(
            subscription,
            request,
            plan_sha256,
            release_binding,
        )
        return subscription
    invoice = client.v1.invoices.retrieve(stripe_id)
    milestone = "deposit" if request.action == "evaluation-deposit" else "delivery"
    validate_reusable_invoice(invoice, request, plan_sha256, milestone)
    return invoice


def create_annual_contract(
    request: BillingRequest,
    offer: dict[str, Any],
    client: Any,
    plan_sha256: str,
    release_binding: ReleaseBindingV1,
) -> Any:
    price = client.v1.prices.retrieve(request.stripe_price_id, {"expand": ["product"]})
    validate_annual_price(
        price,
        offer,
        expected_price_id=request.stripe_price_id or "",
        expected_product_id=request.stripe_product_id or "",
        expected_amount_cents=contract_amount_cents(request, offer),
    )
    current_binding = validate_release_availability(request)
    if current_binding is None or current_binding != release_binding:
        raise ValueError(
            "backend release authorization changed after annual contract preview"
        )
    metadata = contract_metadata(
        request,
        "annual",
        plan_sha256,
        release_binding,
    )
    metadata["tinyzkp_support_hours_per_quarter"] = str(
        offer.get("included_support_hours_per_quarter", 0)
    )
    return client.v1.subscriptions.create(
        {
            "customer": request.customer_id,
            "items": [{"price": request.stripe_price_id, "quantity": 1}],
            "collection_method": "send_invoice",
            "days_until_due": request.days_until_due,
            "metadata": metadata,
        },
        {
            "idempotency_key": (
                f"tinyzkp-{request.agreement_id}-annual-{plan_sha256[:24]}-subscription"
            )
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=("evaluation-deposit", "evaluation-delivery", "annual-contract"),
    )
    parser.add_argument("--offer-id", required=True)
    parser.add_argument("--customer-id", required=True)
    parser.add_argument("--agreement-id", required=True)
    parser.add_argument("--days-until-due", type=int, default=15)
    parser.add_argument("--stripe-price-id")
    parser.add_argument("--stripe-product-id")
    parser.add_argument("--contract-evidence", type=Path, required=True)
    parser.add_argument("--agreement-document", type=Path, required=True)
    parser.add_argument("--scope-document", type=Path, required=True)
    parser.add_argument("--agreement-gate-document", type=Path)
    parser.add_argument("--qualification-document", type=Path)
    parser.add_argument("--partner-preflight-document", type=Path)
    parser.add_argument("--stripe-test-drill-document", type=Path)
    parser.add_argument("--delivery-acceptance-document", type=Path)
    parser.add_argument("--delivery-manifest-document", type=Path)
    parser.add_argument("--delivery-artifact-root", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument(
        "--billing-ledger",
        type=Path,
        default=os.environ.get("TINYZKP_CONTRACT_BILLING_LEDGER_PATH"),
        help="Owner-only SQLite ledger required for every Stripe write",
    )
    parser.add_argument(
        "--reconcile-stripe-object-id",
        help="Bind a prior reserved operation to an exact existing Stripe object",
    )
    parser.add_argument(
        "--expected-account-id", default=os.environ.get("STRIPE_EXPECTED_ACCOUNT_ID")
    )
    parser.add_argument(
        "--expected-display-name",
        default=os.environ.get("STRIPE_EXPECTED_DISPLAY_NAME"),
    )
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    evidence = load_contract_evidence(args.contract_evidence)
    verify_contract_documents(
        evidence,
        args.action,
        agreement_document=args.agreement_document,
        scope_document=args.scope_document,
        agreement_gate_document=getattr(args, "agreement_gate_document", None),
        qualification_document=getattr(args, "qualification_document", None),
        partner_preflight_document=getattr(args, "partner_preflight_document", None),
        stripe_test_drill_document=getattr(args, "stripe_test_drill_document", None),
        expected_stripe_account_id=args.expected_account_id,
        expected_stripe_display_name=args.expected_display_name,
        delivery_acceptance_document=args.delivery_acceptance_document,
        delivery_manifest_document=getattr(args, "delivery_manifest_document", None),
        delivery_artifact_root=getattr(args, "delivery_artifact_root", None),
        stripe_price_id=args.stripe_price_id,
        stripe_product_id=args.stripe_product_id,
    )
    request = BillingRequest(
        action=args.action,
        offer_id=args.offer_id,
        customer_id=args.customer_id,
        agreement_id=args.agreement_id,
        days_until_due=args.days_until_due,
        evidence=evidence,
        stripe_price_id=args.stripe_price_id,
        stripe_product_id=args.stripe_product_id,
    )
    offer = request.validate(load_offers())
    summary, release_binding = prepare_plan(request, offer)
    if not args.apply:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    if (
        not isinstance(args.expected_plan_sha256, str)
        or not HEX_SHA256.fullmatch(args.expected_plan_sha256)
        or args.expected_plan_sha256 != summary["plan_sha256"]
    ):
        raise SystemExit("refusing Stripe write without the exact preview plan SHA-256")
    if os.environ.get("TINYZKP_ALLOW_CONTRACT_BILLING_WRITE") != "1":
        raise SystemExit(
            "refusing Stripe write without TINYZKP_ALLOW_CONTRACT_BILLING_WRITE=1"
        )
    validate_sender_identity_gate()
    if not args.expected_account_id or not args.expected_display_name:
        raise SystemExit(
            "exact expected Stripe account ID and display name are required"
        )
    api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not api_key:
        raise SystemExit("STRIPE_SECRET_KEY is required")
    client = create_stripe_client(api_key)
    account = client.v1.accounts.retrieve_current()
    verify_account(
        account, args.expected_account_id or "", args.expected_display_name or ""
    )
    validate_customer_facing_sender_identity(account)
    customer = client.v1.customers.retrieve(request.customer_id)
    validate_contract_customer(customer, request)
    ledger_arg = getattr(args, "billing_ledger", None) or os.environ.get(
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH"
    )
    if not ledger_arg:
        raise SystemExit(
            "refusing Stripe write without TINYZKP_CONTRACT_BILLING_LEDGER_PATH"
        )
    ledger_path = Path(ledger_arg)
    reservation = reserve_billing_operation(
        ledger_path,
        request,
        summary["plan_sha256"],
    )
    reconcile_id = getattr(args, "reconcile_stripe_object_id", None)
    existing: Any | None = None
    if reservation.stripe_object_id is not None:
        if reconcile_id and reconcile_id != reservation.stripe_object_id:
            raise ValueError(
                "reconciliation ID differs from the Stripe object already bound in the ledger"
            )
        existing = retrieve_and_validate_reserved_object(
            request,
            client,
            summary["plan_sha256"],
            reservation.stripe_object_id,
            release_binding,
        )
    elif (
        not reservation.newly_reserved
        and not reconcile_id
        and not request.action.startswith("evaluation-")
    ):
        raise ValueError(
            "a prior Stripe write reservation has no bound object; rerun only with "
            "--reconcile-stripe-object-id after locating the original Stripe result"
        )
    elif reconcile_id:
        existing = retrieve_and_validate_reserved_object(
            request,
            client,
            summary["plan_sha256"],
            reconcile_id,
            release_binding,
        )
        bind_billing_operation(ledger_path, reservation, stripe_object_id(existing))
    elif reservation.stripe_object_id is None:
        existing = (
            validate_evaluation_history(request, client, summary["plan_sha256"])
            if request.action.startswith("evaluation-")
            else validate_annual_history(
                request,
                client,
                summary["plan_sha256"],
                release_binding,
            )
        )
        if existing is not None:
            bind_billing_operation(
                ledger_path,
                reservation,
                stripe_object_id(existing),
            )
    if existing is not None:
        summary.update(
            {
                "mode": "reconciled" if reconcile_id else "existing",
                "stripe_object_id": value(existing, "id"),
                "stripe_object_status": value(existing, "status"),
                "billing_operation_key": reservation.operation_key,
            }
        )
        if request.action.startswith("evaluation-"):
            summary["hosted_invoice_url"] = hosted_invoice_url(existing)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    created = (
        create_annual_contract(
            request,
            offer,
            client,
            summary["plan_sha256"],
            release_binding,
        )
        if request.action == "annual-contract"
        else resume_evaluation_invoice(
            request,
            offer,
            client,
            summary["plan_sha256"],
            ledger_path=ledger_path,
            reservation=reservation,
        )
    )
    if request.action == "annual-contract":
        if release_binding is None:
            raise ValueError("annual contract write lost its release binding")
        validate_reusable_subscription(
            created,
            request,
            summary["plan_sha256"],
            release_binding,
        )
    else:
        validate_reusable_invoice(
            created,
            request,
            summary["plan_sha256"],
            "deposit" if request.action == "evaluation-deposit" else "delivery",
        )
    bind_billing_operation(
        ledger_path,
        reservation,
        stripe_object_id(created),
    )
    summary.update(
        {
            "mode": "apply",
            "stripe_object_id": value(created, "id"),
            "billing_operation_key": reservation.operation_key,
        }
    )
    if request.action.startswith("evaluation-"):
        summary["hosted_invoice_url"] = hosted_invoice_url(created)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
