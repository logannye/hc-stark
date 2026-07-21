#!/usr/bin/env python3
"""Validate and aggregate the local new-profile demand gate.

This tool is deliberately file-only. It has no network, CRM, email, report
ingestion, or customer-data integration. The source ledger accepts only opaque
organization IDs and closed structured values; the generated status contains
aggregates and source hashes, never organization identifiers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import strict_json  # noqa: E402


SCHEMA_VERSION = 1
CURRENT_PROFILE = "tinyzkp-p3-goldilocks-v1"
GATE_ID = "new-compatibility-profile-demand-v1"
INPUT_SCHEMA_ID = "profile-expansion-demand-input-v1"
STANDARD_ANNUAL_PRICE_USD = 4_990
MINIMUM_QUALIFIED_ORGANIZATIONS = 5
MINIMUM_CONDITIONAL_PRICE_ACCEPTANCES = 3
MAX_RECORDS = 100
MAX_DOCUMENT_BYTES = 64 * 1024
SUPPORTED_REJECTION_REASONS = frozenset(
    {
        "unsupported_air_feature",
        "unsupported_platform",
        "unsupported_profile",
    }
)
ORGANIZATION_ID_PATTERN = r"org-[0-9a-f]{32}"
PROPOSED_PROFILE_PATTERN = r"tinyzkp-[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*"
ORGANIZATION_ID_RE = re.compile(rf"{ORGANIZATION_ID_PATTERN}\Z")
PROPOSED_PROFILE_RE = re.compile(rf"{PROPOSED_PROFILE_PATTERN}\Z")

DEFAULT_SCHEMA = ROOT / "release" / "profile-expansion-demand-input-v1.schema.json"
DEFAULT_INPUT = ROOT / "release" / "profile-expansion-demand-input-v1.json"
DEFAULT_STATUS = ROOT / "release" / "profile-expansion-demand-status-v1.json"

INPUT_KEYS = {"schema_version", "current_profile", "records"}
RECORD_KEYS = {
    "organization_id",
    "qualification",
    "proposed_profile_id",
    "rejection_reason",
    "conditional_annual_price_usd",
}


class GateError(ValueError):
    """A closed-contract or local-file validation failure."""


def expected_input_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:tinyzkp:internal:profile-expansion-demand-input-v1",
        "title": "TinyZKP new compatibility profile demand input v1",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "current_profile", "records"],
        "properties": {
            "schema_version": {"type": "integer", "const": SCHEMA_VERSION},
            "current_profile": {"type": "string", "const": CURRENT_PROFILE},
            "records": {
                "type": "array",
                "maxItems": MAX_RECORDS,
                "items": {"$ref": "#/$defs/record"},
            },
        },
        "$defs": {
            "record": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "organization_id",
                    "qualification",
                    "proposed_profile_id",
                    "rejection_reason",
                    "conditional_annual_price_usd",
                ],
                "properties": {
                    "organization_id": {
                        "type": "string",
                        "pattern": f"^{ORGANIZATION_ID_PATTERN}$",
                    },
                    "qualification": {
                        "type": "string",
                        "const": "technically_qualified",
                    },
                    "proposed_profile_id": {
                        "type": "string",
                        "pattern": f"^{PROPOSED_PROFILE_PATTERN}$",
                        "maxLength": 80,
                    },
                    "rejection_reason": {
                        "type": "string",
                        "enum": sorted(SUPPORTED_REJECTION_REASONS),
                    },
                    "conditional_annual_price_usd": {
                        "oneOf": [
                            {"type": "null"},
                            {
                                "type": "integer",
                                "const": STANDARD_ANNUAL_PRICE_USD,
                            },
                        ]
                    },
                },
            }
        },
    }


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        details = path.lstat()
    except OSError as error:
        raise GateError(f"cannot read {label}: {error}") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise GateError(f"{label} must be a regular non-symlink file")
    if details.st_size > MAX_DOCUMENT_BYTES:
        raise GateError(f"{label} exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GateError(f"cannot read {label}: {error}") from error
    if len(raw) != details.st_size:
        raise GateError(f"{label} changed while being read")
    return raw


def _decode_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = strict_json.loads(raw)
    except (TypeError, ValueError) as error:
        raise GateError(f"{label} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise GateError(f"{label} must be a JSON object")
    return value


def load_schema(path: Path = DEFAULT_SCHEMA) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, "input schema")
    schema = _decode_object(raw, "input schema")
    if schema != expected_input_schema():
        raise GateError("input schema differs from the locked v1 schema")
    return schema, raw


def load_input(path: Path = DEFAULT_INPUT) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, "demand input")
    return _decode_object(raw, "demand input"), raw


def load_status(path: Path = DEFAULT_STATUS) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular_file(path, "generated status")
    return _decode_object(raw, "generated status"), raw


def validate_input(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(value) != INPUT_KEYS:
        errors.append(
            "input must contain exactly schema_version, current_profile, and records"
        )
    if type(value.get("schema_version")) is not int or value.get(
        "schema_version"
    ) != SCHEMA_VERSION:
        errors.append("schema_version must be integer 1")
    if value.get("current_profile") != CURRENT_PROFILE:
        errors.append(f"current_profile must remain {CURRENT_PROFILE}")

    records = value.get("records")
    if not isinstance(records, list):
        errors.append("records must be an array")
        return errors
    if len(records) > MAX_RECORDS:
        errors.append(f"records may contain at most {MAX_RECORDS} entries")

    organization_ids: list[str] = []
    proposed_profiles: set[str] = set()
    rejection_reasons: set[str] = set()
    for index, record in enumerate(records):
        prefix = f"records[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if set(record) != RECORD_KEYS:
            errors.append(
                f"{prefix} must contain exactly the five privacy-minimal fields"
            )

        organization_id = record.get("organization_id")
        if (
            not isinstance(organization_id, str)
            or ORGANIZATION_ID_RE.fullmatch(organization_id) is None
        ):
            errors.append(f"{prefix}.organization_id must be an opaque org-<32 hex> ID")
        else:
            organization_ids.append(organization_id)

        if record.get("qualification") != "technically_qualified":
            errors.append(f"{prefix}.qualification must be technically_qualified")

        proposed_profile = record.get("proposed_profile_id")
        if (
            not isinstance(proposed_profile, str)
            or len(proposed_profile) > 80
            or PROPOSED_PROFILE_RE.fullmatch(proposed_profile) is None
            or proposed_profile == CURRENT_PROFILE
        ):
            errors.append(
                f"{prefix}.proposed_profile_id must be a non-v1 structured profile ID"
            )
        else:
            proposed_profiles.add(proposed_profile)

        reason = record.get("rejection_reason")
        if reason not in SUPPORTED_REJECTION_REASONS:
            errors.append(
                f"{prefix}.rejection_reason must use the existing incompatibility vocabulary"
            )
        else:
            rejection_reasons.add(str(reason))

        acceptance = record.get("conditional_annual_price_usd")
        if acceptance is not None and (
            type(acceptance) is not int or acceptance != STANDARD_ANNUAL_PRICE_USD
        ):
            errors.append(
                f"{prefix}.conditional_annual_price_usd must be null or "
                f"{STANDARD_ANNUAL_PRICE_USD}"
            )

    if len(organization_ids) != len(set(organization_ids)):
        errors.append("organization_id values must be distinct")
    if organization_ids != sorted(organization_ids):
        errors.append("records must be sorted by organization_id")
    if len(proposed_profiles) > 1:
        errors.append("all records must share one proposed_profile_id")
    if len(rejection_reasons) > 1:
        errors.append("all records must share one rejection_reason")
    return errors


def build_status(
    value: dict[str, Any],
    input_raw: bytes,
    schema_raw: bytes,
) -> dict[str, Any]:
    errors = validate_input(value)
    if errors:
        raise GateError("; ".join(errors))
    records = value["records"]
    organization_count = len(records)
    acceptance_count = sum(
        record["conditional_annual_price_usd"] == STANDARD_ANNUAL_PRICE_USD
        for record in records
    )
    eligible = (
        organization_count >= MINIMUM_QUALIFIED_ORGANIZATIONS
        and acceptance_count >= MINIMUM_CONDITIONAL_PRICE_ACCEPTANCES
    )
    proposed_profile = records[0]["proposed_profile_id"] if records else None
    rejection_reason = records[0]["rejection_reason"] if records else None
    return {
        "schema_version": SCHEMA_VERSION,
        "gate_id": GATE_ID,
        "current_profile": CURRENT_PROFILE,
        "status": "eligible" if eligible else "blocked",
        "qualification_window": "quarterly",
        "qualification_window_eligible": eligible,
        "minimum_distinct_qualified_organizations": (
            MINIMUM_QUALIFIED_ORGANIZATIONS
        ),
        "minimum_conditional_standard_annual_acceptances": (
            MINIMUM_CONDITIONAL_PRICE_ACCEPTANCES
        ),
        "standard_annual_price_usd": STANDARD_ANNUAL_PRICE_USD,
        "distinct_qualified_organizations": organization_count,
        "conditional_standard_annual_acceptances": acceptance_count,
        "proposed_profile_id": proposed_profile,
        "rejection_reason": rejection_reason,
        "organization_identifiers_included": False,
        "records_included": False,
        "source": {
            "schema_id": INPUT_SCHEMA_ID,
            "schema_sha256": hashlib.sha256(schema_raw).hexdigest(),
            "input_bytes": len(input_raw),
            "input_sha256": hashlib.sha256(input_raw).hexdigest(),
        },
    }


def validate_status(
    status: dict[str, Any],
    value: dict[str, Any],
    input_raw: bytes,
    schema_raw: bytes,
) -> list[str]:
    try:
        expected = build_status(value, input_raw, schema_raw)
    except GateError as error:
        return [str(error)]
    errors: list[str] = []
    if status.get("source") != expected["source"]:
        errors.append("generated status source/digest does not match input and schema")
    if status != expected:
        errors.append("generated status differs from the exact aggregate")
    return errors


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise GateError("generated status path must not be a symlink")
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".profile-expansion-demand-",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def evaluate_files(
    *,
    schema_path: Path = DEFAULT_SCHEMA,
    input_path: Path = DEFAULT_INPUT,
    status_path: Path = DEFAULT_STATUS,
) -> tuple[dict[str, Any], list[str]]:
    _, schema_raw = load_schema(schema_path)
    value, input_raw = load_input(input_path)
    input_errors = validate_input(value)
    if input_errors:
        return {}, input_errors
    status, _ = load_status(status_path)
    return status, validate_status(status, value, input_raw, schema_raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args(argv)

    try:
        _, schema_raw = load_schema(args.schema)
        value, input_raw = load_input(args.input)
        input_errors = validate_input(value)
        if input_errors:
            raise GateError("; ".join(input_errors))
        expected = build_status(value, input_raw, schema_raw)
        if args.generate:
            _write_json_atomic(args.status, expected)
        status, _ = load_status(args.status)
        status_errors = validate_status(status, value, input_raw, schema_raw)
        if status_errors:
            raise GateError("; ".join(status_errors))
        if args.require_eligible and not status["qualification_window_eligible"]:
            raise GateError("new compatibility profile demand gate remains blocked")
    except GateError as error:
        print(f"profile expansion demand gate: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "status": status["status"],
                "qualification_window_eligible": status[
                    "qualification_window_eligible"
                ],
                "distinct_qualified_organizations": status[
                    "distinct_qualified_organizations"
                ],
                "conditional_standard_annual_acceptances": status[
                    "conditional_standard_annual_acceptances"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
