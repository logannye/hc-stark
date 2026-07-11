#!/usr/bin/env python3
"""Capture and verify fresh read-only legacy Stripe containment status.

This tool never contacts or mutates Stripe.  ``capture`` consumes two private
inventory exports produced by ``billing/legacy_billing_containment.py``: the
reviewed baseline used to classify exact TinyZKP IDs, and a fresh read-only
inventory collected after containment.  The resulting artifact proves that no
selected legacy catalog, Payment Link, meter, subscription, or invoice remains
chargeable while every still-active object belongs to the explicitly reviewed
unrelated set.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any

from deploy_readiness_check import ProductionEnvError, load_private_env_file


ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXED_EVIDENCE = pathlib.Path(
    "/var/lib/tinyzkp-private/deploy/legacy-billing-containment-status.json"
)
SCHEMA = "tinyzkp-legacy-billing-containment-status-v1"
MAX_BYTES = 4 * 1024 * 1024
MAX_AGE = timedelta(minutes=15)
MAX_CAPTURE_INPUT_AGE = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(minutes=2)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ACCOUNT_RE = re.compile(r"^acct_[A-Za-z0-9]{16,32}$")
DEPLOYMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
ID_PREFIXES = {
    "product_ids": "prod_",
    "price_ids": "price_",
    "payment_link_ids": "plink_",
    "meter_ids": "mtr_",
    "subscription_ids": "sub_",
    "open_invoice_ids": "in_",
}
OBJECT_FIELDS = {
    "product_ids": "products",
    "price_ids": "prices",
    "payment_link_ids": "payment_links",
    "meter_ids": "meters",
    "subscription_ids": "subscriptions",
    "open_invoice_ids": "open_invoices",
}
OBJECT_KEYS = {
    "products": {"id", "name", "active", "metadata"},
    "prices": {"id", "product_id", "active", "currency", "lookup_key", "metadata"},
    "payment_links": {"id", "active", "product_ids"},
    "subscriptions": {
        "id",
        "customer_id",
        "status",
        "pause_collection_behavior",
        "product_ids",
    },
    "meters": {"id", "event_name", "status"},
    "open_invoices": {
        "id",
        "customer_id",
        "subscription_id",
        "status",
        "amount_remaining",
        "currency",
    },
}
CHARGEABLE_SUBSCRIPTION_STATES = {
    "active",
    "trialing",
    "past_due",
    "unpaid",
    "paused",
}
ALLOWED_RESOLUTIONS = {"refund", "credit", "none_due"}
ALLOWED_NOTIFICATION_CHANNELS = {
    "github",
    "linkedin",
    "signal",
    "discord",
    "telegram",
    "matrix",
    "phone",
    "certified_mail",
}
LEDGER_RECORD_KEYS = {
    "subscription_id",
    "customer_id",
    "notified_at",
    "notification_channel",
    "notification_evidence_sha256",
    "resolution",
    "resolution_object_id",
    "resolution_amount",
    "currency",
    "resolution_evidence_sha256",
    "approved_open_invoice_ids",
}
CHECK_KEYS = {
    "account_identity_exact",
    "catalog_inactive",
    "payment_links_inactive",
    "meters_inactive",
    "subscriptions_nonchargeable",
    "open_invoices_resolved",
    "notification_resolution_complete",
    "no_unreviewed_active_objects",
}


class EvidenceError(ValueError):
    """Legacy containment evidence is absent, unsafe, stale, or incomplete."""


def _canonical(value: object, *, newline: bool = True) -> bytes:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return encoded + (b"\n" if newline else b"")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"JSON object duplicates {key!r}")
        result[key] = value
    return result


def _parse_json(raw: bytes, *, label: str, canonical: bool = False) -> dict[str, Any]:
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
    if canonical and raw != _canonical(value):
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


def _read_file(
    path: pathlib.Path,
    *,
    label: str,
    limit: int = MAX_BYTES,
    exact_mode: int | None = None,
    required_uid: int | None = None,
) -> tuple[bytes, os.stat_result]:
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
        raw = b""
        while len(raw) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        if len(raw) > limit or (
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
            raise EvidenceError(f"{label} changed or exceeded its limit")
    finally:
        os.close(descriptor)
    return raw, before


def _inventory_digest(document: dict[str, Any]) -> str:
    return _sha256(_canonical(document, newline=False))


def _validate_metadata(value: object, *, label: str) -> None:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise EvidenceError(f"{label} metadata is invalid")


def _validate_id_list(value: object, *, prefix: str, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise EvidenceError(f"{label} must be a string array")
    if value != sorted(value) or len(value) != len(set(value)) or any(
        not item.startswith(prefix) for item in value
    ):
        raise EvidenceError(f"{label} is not sorted, unique, and prefix-safe")
    return value


def _validate_inventory(value: dict[str, Any], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    _exact_keys(
        value,
        {
            "schema_version",
            "stripe_account_id",
            "stripe_display_name",
            "objects",
            "inventory_sha256",
        },
        label=label,
    )
    account_id = value["stripe_account_id"]
    display_name = value["stripe_display_name"]
    if value["schema_version"] != 1 or not isinstance(account_id, str) or not account_id.startswith("acct_"):
        raise EvidenceError(f"{label} account/schema is invalid")
    if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 200:
        raise EvidenceError(f"{label} display name is invalid")
    objects = value["objects"]
    if not isinstance(objects, dict) or set(objects) != set(OBJECT_KEYS):
        raise EvidenceError(f"{label} object groups are incomplete")
    for group, keys in OBJECT_KEYS.items():
        records = objects[group]
        if not isinstance(records, list):
            raise EvidenceError(f"{label} {group} must be an array")
        seen: list[str] = []
        prefix = next(
            ID_PREFIXES[selection]
            for selection, object_group in OBJECT_FIELDS.items()
            if object_group == group
        )
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise EvidenceError(f"{label} {group} record {index} is invalid")
            _exact_keys(record, keys, label=f"{label} {group} record {index}")
            object_id = record["id"]
            if not isinstance(object_id, str) or not object_id.startswith(prefix) or object_id in seen:
                raise EvidenceError(f"{label} {group} ID is malformed or duplicate")
            seen.append(object_id)
            if "metadata" in record:
                _validate_metadata(record["metadata"], label=f"{label} {group}")
            for relation in ("product_ids",):
                if relation in record:
                    _validate_id_list(record[relation], prefix="prod_", label=f"{label} {group} {relation}")
            if group == "products":
                if type(record["active"]) is not bool or not isinstance(record["name"], str):
                    raise EvidenceError(f"{label} product state is invalid")
            elif group == "prices":
                if (
                    type(record["active"]) is not bool
                    or not isinstance(record["product_id"], str)
                    or not record["product_id"].startswith("prod_")
                    or not isinstance(record["lookup_key"], str)
                    or not isinstance(record["currency"], str)
                ):
                    raise EvidenceError(f"{label} price state is invalid")
            elif group == "payment_links":
                if type(record["active"]) is not bool:
                    raise EvidenceError(f"{label} Payment Link state is invalid")
            elif group == "subscriptions":
                if (
                    not isinstance(record["customer_id"], str)
                    or not record["customer_id"].startswith("cus_")
                    or not isinstance(record["status"], str)
                    or record["pause_collection_behavior"]
                    not in {"", "void", "keep_as_draft", "mark_uncollectible"}
                ):
                    raise EvidenceError(f"{label} subscription state is invalid")
            elif group == "meters":
                if not isinstance(record["event_name"], str) or not isinstance(record["status"], str):
                    raise EvidenceError(f"{label} meter state is invalid")
            elif group == "open_invoices":
                if (
                    not isinstance(record["customer_id"], str)
                    or not record["customer_id"].startswith("cus_")
                    or not isinstance(record["subscription_id"], str)
                    or not record["subscription_id"].startswith("sub_")
                    or not isinstance(record["status"], str)
                    or type(record["amount_remaining"]) is not int
                    or record["amount_remaining"] < 0
                    or not isinstance(record["currency"], str)
                ):
                    raise EvidenceError(f"{label} invoice state is invalid")
        if seen != sorted(seen):
            raise EvidenceError(f"{label} {group} records must be sorted by ID")
    document = {key: item for key, item in value.items() if key != "inventory_sha256"}
    digest = _inventory_digest(document)
    if value["inventory_sha256"] != digest:
        raise EvidenceError(f"{label} inventory digest is invalid")
    return value


def _load_scope(raw: bytes, *, baseline: dict[str, Any]) -> dict[str, list[str]]:
    scope = _parse_json(raw, label="legacy scope manifest")
    _exact_keys(
        scope,
        {
            "schema_version",
            "stripe_account_id",
            "stripe_display_name",
            "inventory_sha256",
            "selections",
        },
        label="legacy scope manifest",
    )
    if (
        scope["schema_version"] != 1
        or scope["stripe_account_id"] != baseline["stripe_account_id"]
        or str(scope["stripe_display_name"]).casefold()
        != str(baseline["stripe_display_name"]).casefold()
        or scope["inventory_sha256"] != baseline["inventory_sha256"]
    ):
        raise EvidenceError("legacy scope does not bind the baseline inventory")
    selections = scope["selections"]
    if not isinstance(selections, dict) or set(selections) != set(ID_PREFIXES):
        raise EvidenceError("legacy scope selections are incomplete")
    result: dict[str, list[str]] = {}
    available: dict[str, dict[str, dict[str, Any]]] = {}
    for selection, group in OBJECT_FIELDS.items():
        available[selection] = {
            record["id"]: record for record in baseline["objects"][group]
        }
        result[selection] = _validate_id_list(
            selections[selection],
            prefix=ID_PREFIXES[selection],
            label=f"legacy scope {selection}",
        )
        missing = sorted(set(result[selection]) - set(available[selection]))
        if missing:
            raise EvidenceError(f"legacy scope {selection} contains absent IDs")
    _validate_selection_relationships(baseline, result)
    return result


def _validate_selection_relationships(
    baseline: dict[str, Any], selections: dict[str, list[str]]
) -> None:
    available = {
        selection: {
            record["id"]: record for record in baseline["objects"][group]
        }
        for selection, group in OBJECT_FIELDS.items()
    }
    for field, selected in selections.items():
        if set(selected) - set(available[field]):
            raise EvidenceError(f"legacy selection {field} contains absent IDs")
    selected_products = set(selections["product_ids"])
    for price_id in selections["price_ids"]:
        if available["price_ids"][price_id]["product_id"] not in selected_products:
            raise EvidenceError("selected legacy price belongs to an unselected product")
    for field in ("payment_link_ids", "subscription_ids"):
        for object_id in selections[field]:
            if not set(available[field][object_id]["product_ids"]) <= selected_products:
                raise EvidenceError(f"selected legacy {field} references an unselected product")
    selected_subscriptions = set(selections["subscription_ids"])
    for invoice_id in selections["open_invoice_ids"]:
        if available["open_invoice_ids"][invoice_id]["subscription_id"] not in selected_subscriptions:
            raise EvidenceError("selected legacy invoice belongs to an unselected subscription")


def _validate_ledger(
    raw: bytes | None,
    *,
    baseline: dict[str, Any],
    selections: dict[str, list[str]],
) -> tuple[list[dict[str, Any]], str | None]:
    selected_subscriptions = selections["subscription_ids"]
    selected_invoices = set(selections["open_invoice_ids"])
    if raw is None:
        if selected_subscriptions or selected_invoices:
            raise EvidenceError("legacy subscription containment requires a notification-resolution ledger")
        return [], None
    ledger = _parse_json(raw, label="legacy notification ledger")
    _exact_keys(
        ledger,
        {"schema_version", "stripe_account_id", "inventory_sha256", "subscriptions"},
        label="legacy notification ledger",
    )
    if (
        ledger["schema_version"] != 2
        or ledger["stripe_account_id"] != baseline["stripe_account_id"]
        or ledger["inventory_sha256"] != baseline["inventory_sha256"]
        or not isinstance(ledger["subscriptions"], list)
    ):
        raise EvidenceError("legacy notification ledger does not bind the baseline")
    baseline_subscriptions = {
        record["id"]: record for record in baseline["objects"]["subscriptions"]
    }
    records: list[dict[str, Any]] = []
    approved_invoices: set[str] = set()
    for record in ledger["subscriptions"]:
        if not isinstance(record, dict):
            raise EvidenceError("legacy notification record is invalid")
        _exact_keys(record, LEDGER_RECORD_KEYS, label="legacy notification record")
        subscription_id = record["subscription_id"]
        if subscription_id not in baseline_subscriptions:
            raise EvidenceError("legacy notification record references an absent subscription")
        if record["customer_id"] != baseline_subscriptions[subscription_id]["customer_id"]:
            raise EvidenceError("legacy notification customer identity differs from baseline")
        _timestamp(record["notified_at"], label="legacy notification time")
        if record["notification_channel"] not in ALLOWED_NOTIFICATION_CHANNELS:
            raise EvidenceError("legacy notification channel is unsupported")
        _digest(record["notification_evidence_sha256"], label="legacy notification evidence")
        _digest(record["resolution_evidence_sha256"], label="legacy resolution evidence")
        resolution = record["resolution"]
        amount = record["resolution_amount"]
        if resolution not in ALLOWED_RESOLUTIONS or type(amount) is not int or amount < 0:
            raise EvidenceError("legacy resolution is invalid")
        if resolution == "none_due":
            if amount != 0 or record["resolution_object_id"] != "":
                raise EvidenceError("legacy none_due resolution is inconsistent")
        elif amount <= 0 or not isinstance(record["resolution_object_id"], str) or not record["resolution_object_id"]:
            raise EvidenceError("legacy refund/credit resolution is incomplete")
        if not isinstance(record["currency"], str) or re.fullmatch(r"[a-z]{3}", record["currency"]) is None:
            raise EvidenceError("legacy resolution currency is invalid")
        approved = _validate_id_list(
            record["approved_open_invoice_ids"],
            prefix="in_",
            label="legacy approved invoice IDs",
        )
        approved_invoices.update(approved)
        records.append(record)
    if [record["subscription_id"] for record in records] != selected_subscriptions:
        raise EvidenceError("legacy notification ledger does not exactly cover selected subscriptions")
    if approved_invoices != selected_invoices:
        raise EvidenceError("legacy notification ledger does not exactly approve selected invoices")
    return records, _sha256(raw)


def _current_ids(inventory: dict[str, Any]) -> dict[str, list[str]]:
    return {
        selection: [record["id"] for record in inventory["objects"][group]]
        for selection, group in OBJECT_FIELDS.items()
    }


def _current_chargeable_ids(inventory: dict[str, Any]) -> dict[str, list[str]]:
    result = _current_ids(inventory)
    result["subscription_ids"] = [
        record["id"]
        for record in inventory["objects"]["subscriptions"]
        if record["pause_collection_behavior"] != "void"
    ]
    return result


def _assert_current_is_chargeable_inventory(current: dict[str, Any]) -> None:
    objects = current["objects"]
    if any(record["active"] is not True for record in objects["products"]):
        raise EvidenceError("current product inventory contains inactive records")
    if any(record["active"] is not True for record in objects["prices"]):
        raise EvidenceError("current price inventory contains inactive records")
    if any(record["active"] is not True for record in objects["payment_links"]):
        raise EvidenceError("current Payment Link inventory contains inactive records")
    if any(record["status"] != "active" for record in objects["meters"]):
        raise EvidenceError("current meter inventory contains inactive records")
    if any(record["status"] not in CHARGEABLE_SUBSCRIPTION_STATES for record in objects["subscriptions"]):
        raise EvidenceError("current subscription inventory contains nonchargeable records")
    if any(record["status"] != "open" for record in objects["open_invoices"]):
        raise EvidenceError("current invoice inventory contains non-open records")


def source_identity(root: pathlib.Path = ROOT) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, relative in (
        ("legacy_billing_containment_tool_sha256", "billing/legacy_billing_containment.py"),
        ("status_tool_sha256", "scripts/ci/legacy_billing_containment_status.py"),
    ):
        raw, _metadata = _read_file(root / relative, label=relative, limit=8 * 1024 * 1024)
        result[key] = _sha256(raw)
    return result


def _subject(evidence: dict[str, Any]) -> bytes:
    return _canonical({key: value for key, value in evidence.items() if key != "subject_sha256"})


def capture_evidence(
    *,
    baseline_inventory_path: pathlib.Path,
    current_inventory_path: pathlib.Path,
    scope_manifest_path: pathlib.Path,
    notification_ledger_path: pathlib.Path | None,
    output: pathlib.Path,
    release_sha: str,
    deployment_id: str,
    expected_account_id: str,
    expected_display_name: str,
    observed_at: datetime,
    now: datetime | None = None,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    checked_at = now or datetime.now(timezone.utc)
    if SHA1_RE.fullmatch(release_sha) is None or DEPLOYMENT_RE.fullmatch(deployment_id) is None:
        raise EvidenceError("legacy capture release/deployment identity is invalid")
    if ACCOUNT_RE.fullmatch(expected_account_id) is None or not expected_display_name.strip():
        raise EvidenceError("legacy capture expected Stripe identity is invalid")
    baseline_raw, _baseline_metadata = _read_file(
        baseline_inventory_path, label="legacy baseline inventory"
    )
    current_raw, current_metadata = _read_file(
        current_inventory_path, label="fresh legacy current inventory"
    )
    scope_raw, _scope_metadata = _read_file(scope_manifest_path, label="legacy scope manifest")
    ledger_raw = None
    if notification_ledger_path is not None:
        ledger_raw, _ledger_metadata = _read_file(
            notification_ledger_path, label="legacy notification ledger"
        )
    file_time = datetime.fromtimestamp(current_metadata.st_mtime, tz=timezone.utc)
    if abs(checked_at - file_time) > MAX_CAPTURE_INPUT_AGE:
        raise EvidenceError("fresh legacy inventory file is too old for capture")
    if abs(observed_at - file_time) > MAX_CAPTURE_INPUT_AGE or observed_at > checked_at + MAX_CLOCK_SKEW:
        raise EvidenceError("legacy inventory observation time does not match the fresh export")
    baseline = _validate_inventory(
        _parse_json(baseline_raw, label="legacy baseline inventory"),
        label="legacy baseline inventory",
    )
    current = _validate_inventory(
        _parse_json(current_raw, label="legacy current inventory"),
        label="legacy current inventory",
    )
    if (
        baseline["stripe_account_id"] != expected_account_id
        or current["stripe_account_id"] != expected_account_id
        or str(baseline["stripe_display_name"]).casefold() != expected_display_name.casefold()
        or str(current["stripe_display_name"]).casefold() != expected_display_name.casefold()
    ):
        raise EvidenceError("legacy inventories do not match the exact Stripe account")
    _assert_current_is_chargeable_inventory(current)
    _assert_current_is_chargeable_inventory(baseline)
    selections = _load_scope(scope_raw, baseline=baseline)
    notification_records, ledger_sha256 = _validate_ledger(
        ledger_raw,
        baseline=baseline,
        selections=selections,
    )
    baseline_ids = _current_ids(baseline)
    current_present_ids = _current_ids(current)
    current_ids = _current_chargeable_ids(current)
    allowed_active = {
        field: sorted(set(baseline_ids[field]) - set(selections[field]))
        for field in ID_PREFIXES
    }
    for field in ID_PREFIXES:
        if not set(current_present_ids[field]) <= set(baseline_ids[field]):
            raise EvidenceError(f"current {field} contains an unreviewed active object")
        if set(current_ids[field]) & set(selections[field]):
            raise EvidenceError(f"selected legacy {field} remains active/chargeable")
        if not set(current_ids[field]) <= set(allowed_active[field]):
            raise EvidenceError(f"current {field} contains an unreviewed active object")
    checks = {key: True for key in sorted(CHECK_KEYS)}
    evidence: dict[str, Any] = {
        "schema_version": SCHEMA,
        "status": "contained",
        "observed_at": observed_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "release_sha": release_sha,
        "deployment_id": deployment_id,
        "stripe_account_id": expected_account_id,
        "stripe_display_name": expected_display_name,
        "source": {
            **source_identity(root),
            "baseline_inventory_file_sha256": _sha256(baseline_raw),
            "current_inventory_file_sha256": _sha256(current_raw),
            "scope_manifest_sha256": _sha256(scope_raw),
            "notification_ledger_sha256": ledger_sha256,
        },
        "baseline_inventory_sha256": baseline["inventory_sha256"],
        "current_inventory_sha256": current["inventory_sha256"],
        "baseline_inventory": baseline,
        "current_inventory": current,
        "selections": selections,
        "allowed_active_ids": allowed_active,
        "current_present_ids": current_present_ids,
        "current_active_ids": current_ids,
        "notification_resolutions": notification_records,
        "checks": checks,
    }
    evidence["subject_sha256"] = _sha256(_subject(evidence))
    encoded = _canonical(evidence)
    if len(encoded) > MAX_BYTES:
        raise EvidenceError("legacy containment status exceeds its size limit")
    if output.exists() or output.is_symlink():
        raise EvidenceError("legacy containment status output already exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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
        expected_release_sha=release_sha,
        expected_deployment_id=deployment_id,
        expected_account_id=expected_account_id,
        expected_display_name=expected_display_name,
        now=checked_at,
        enforce_fixed_path=False,
        required_uid=os.geteuid(),
        root=root,
    )


def validate_evidence(
    path: pathlib.Path,
    *,
    expected_release_sha: str,
    expected_deployment_id: str,
    expected_account_id: str,
    expected_display_name: str,
    now: datetime | None = None,
    enforce_fixed_path: bool = True,
    required_uid: int = 0,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    if SHA1_RE.fullmatch(expected_release_sha) is None or DEPLOYMENT_RE.fullmatch(expected_deployment_id) is None:
        raise EvidenceError("expected legacy release/deployment identity is invalid")
    if ACCOUNT_RE.fullmatch(expected_account_id) is None or not expected_display_name.strip():
        raise EvidenceError("expected Stripe account identity is invalid")
    if enforce_fixed_path and path != FIXED_EVIDENCE:
        raise EvidenceError("legacy containment status must use its fixed production path")
    raw, _metadata = _read_file(
        path,
        label="legacy containment status",
        exact_mode=0o600 if enforce_fixed_path else None,
        required_uid=required_uid if enforce_fixed_path else None,
    )
    evidence = _parse_json(raw, label="legacy containment status", canonical=True)
    _exact_keys(
        evidence,
        {
            "schema_version",
            "status",
            "observed_at",
            "release_sha",
            "deployment_id",
            "stripe_account_id",
            "stripe_display_name",
            "source",
            "baseline_inventory_sha256",
            "current_inventory_sha256",
            "baseline_inventory",
            "current_inventory",
            "selections",
            "allowed_active_ids",
            "current_present_ids",
            "current_active_ids",
            "notification_resolutions",
            "checks",
            "subject_sha256",
        },
        label="legacy containment status",
    )
    if evidence["schema_version"] != SCHEMA or evidence["status"] != "contained":
        raise EvidenceError("legacy containment status is not passing")
    if (
        evidence["release_sha"] != expected_release_sha
        or evidence["deployment_id"] != expected_deployment_id
        or evidence["stripe_account_id"] != expected_account_id
        or str(evidence["stripe_display_name"]).casefold() != expected_display_name.casefold()
    ):
        raise EvidenceError("legacy containment status identity mismatch")
    observed_at = _timestamp(evidence["observed_at"], label="legacy observation time")
    checked_at = now or datetime.now(timezone.utc)
    age = checked_at - observed_at
    if age < -MAX_CLOCK_SKEW or age > MAX_AGE:
        raise EvidenceError("legacy containment status is stale or future-dated")
    expected_source = source_identity(root)
    source = evidence["source"]
    if not isinstance(source, dict):
        raise EvidenceError("legacy containment source must be an object")
    _exact_keys(
        source,
        {
            *expected_source,
            "baseline_inventory_file_sha256",
            "current_inventory_file_sha256",
            "scope_manifest_sha256",
            "notification_ledger_sha256",
        },
        label="legacy containment source",
    )
    if any(source[key] != value for key, value in expected_source.items()):
        raise EvidenceError("legacy containment tool hashes differ from the release")
    for key in (
        "baseline_inventory_file_sha256",
        "current_inventory_file_sha256",
        "scope_manifest_sha256",
    ):
        _digest(source[key], label=f"legacy containment {key}")
    _digest(source["notification_ledger_sha256"], label="legacy notification ledger hash", optional=True)
    _digest(evidence["baseline_inventory_sha256"], label="legacy baseline inventory")
    _digest(evidence["current_inventory_sha256"], label="legacy current inventory")
    baseline = _validate_inventory(evidence["baseline_inventory"], label="embedded legacy baseline")
    current_inventory = _validate_inventory(
        evidence["current_inventory"], label="embedded legacy current inventory"
    )
    if (
        baseline["inventory_sha256"] != evidence["baseline_inventory_sha256"]
        or current_inventory["inventory_sha256"]
        != evidence["current_inventory_sha256"]
        or baseline["stripe_account_id"] != expected_account_id
        or current_inventory["stripe_account_id"] != expected_account_id
        or str(baseline["stripe_display_name"]).casefold()
        != expected_display_name.casefold()
        or str(current_inventory["stripe_display_name"]).casefold()
        != expected_display_name.casefold()
    ):
        raise EvidenceError("embedded legacy inventories differ from the evidence identity")
    _assert_current_is_chargeable_inventory(current_inventory)
    _assert_current_is_chargeable_inventory(baseline)
    for group_name in (
        "selections",
        "allowed_active_ids",
        "current_present_ids",
        "current_active_ids",
    ):
        group = evidence[group_name]
        if not isinstance(group, dict) or set(group) != set(ID_PREFIXES):
            raise EvidenceError(f"legacy containment {group_name} is incomplete")
        for field, prefix in ID_PREFIXES.items():
            _validate_id_list(group[field], prefix=prefix, label=f"legacy {group_name} {field}")
    for field in ID_PREFIXES:
        selected = set(evidence["selections"][field])
        allowed = set(evidence["allowed_active_ids"][field])
        current = set(evidence["current_active_ids"][field])
        if selected & current or selected & allowed or not current <= allowed:
            raise EvidenceError(f"legacy containment {field} set relationship is unsafe")
    _validate_selection_relationships(baseline, evidence["selections"])
    expected_baseline_ids = _current_ids(baseline)
    expected_present_ids = _current_ids(current_inventory)
    expected_current_ids = _current_chargeable_ids(current_inventory)
    expected_allowed = {
        field: sorted(
            set(expected_baseline_ids[field]) - set(evidence["selections"][field])
        )
        for field in ID_PREFIXES
    }
    if (
        evidence["current_present_ids"] != expected_present_ids
        or evidence["current_active_ids"] != expected_current_ids
        or evidence["allowed_active_ids"] != expected_allowed
    ):
        raise EvidenceError("legacy containment classifications differ from embedded inventories")
    checks = evidence["checks"]
    if not isinstance(checks, dict) or set(checks) != CHECK_KEYS or any(value is not True for value in checks.values()):
        raise EvidenceError("legacy containment checks are incomplete or non-passing")
    resolutions = evidence["notification_resolutions"]
    if not isinstance(resolutions, list):
        raise EvidenceError("legacy containment notification resolutions must be an array")
    selected_subscriptions = evidence["selections"]["subscription_ids"]
    approved_invoices: set[str] = set()
    for record in resolutions:
        if not isinstance(record, dict):
            raise EvidenceError("legacy containment resolution record is invalid")
        _exact_keys(record, LEDGER_RECORD_KEYS, label="legacy containment resolution")
        _timestamp(record["notified_at"], label="legacy containment notification time")
        if record["notification_channel"] not in ALLOWED_NOTIFICATION_CHANNELS:
            raise EvidenceError("legacy containment notification channel is unsupported")
        _digest(record["notification_evidence_sha256"], label="legacy notification evidence")
        _digest(record["resolution_evidence_sha256"], label="legacy resolution evidence")
        resolution = record["resolution"]
        amount = record["resolution_amount"]
        if resolution not in ALLOWED_RESOLUTIONS or type(amount) is not int or amount < 0:
            raise EvidenceError("legacy containment resolution is invalid")
        if resolution == "none_due":
            if amount != 0 or record["resolution_object_id"] != "":
                raise EvidenceError("legacy containment none_due resolution is inconsistent")
        elif amount <= 0 or not isinstance(record["resolution_object_id"], str) or not record["resolution_object_id"]:
            raise EvidenceError("legacy containment refund/credit resolution is incomplete")
        if not isinstance(record["currency"], str) or re.fullmatch(r"[a-z]{3}", record["currency"]) is None:
            raise EvidenceError("legacy containment resolution currency is invalid")
        approved_invoices.update(
            _validate_id_list(
                record["approved_open_invoice_ids"],
                prefix="in_",
                label="legacy containment approved invoices",
            )
        )
    if [record["subscription_id"] for record in resolutions] != selected_subscriptions:
        raise EvidenceError("legacy containment resolutions do not cover selected subscriptions")
    if approved_invoices != set(evidence["selections"]["open_invoice_ids"]):
        raise EvidenceError("legacy containment resolutions do not cover selected invoices")
    if bool(selected_subscriptions) != (source["notification_ledger_sha256"] is not None):
        raise EvidenceError("legacy containment ledger presence differs from subscription scope")
    _digest(evidence["subject_sha256"], label="legacy containment subject")
    if not hmac.compare_digest(evidence["subject_sha256"], _sha256(_subject(evidence))):
        raise EvidenceError("legacy containment subject hash is invalid")
    return {
        "schema_version": 1,
        "status": "contained",
        "observed_at": evidence["observed_at"],
        "current_inventory_sha256": evidence["current_inventory_sha256"],
        "subject_sha256": evidence["subject_sha256"],
        "evidence_identity_sha256": _sha256(raw),
    }


def _expected_identity_from_env(path: pathlib.Path) -> tuple[str, str]:
    try:
        configured = load_private_env_file(path)
    except ProductionEnvError as error:
        raise EvidenceError("Stripe identity environment is unavailable or unsafe") from error
    account_id = configured.get("STRIPE_EXPECTED_ACCOUNT_ID", "").strip()
    display_name = configured.get("STRIPE_EXPECTED_DISPLAY_NAME", "").strip()
    if ACCOUNT_RE.fullmatch(account_id) is None or not display_name:
        raise EvidenceError("Stripe expected account ID/display name is missing")
    return account_id, display_name


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--evidence", type=pathlib.Path, default=FIXED_EVIDENCE)
    verify.add_argument("--env-file", type=pathlib.Path, required=True)
    verify.add_argument("--expected-release-sha", required=True)
    verify.add_argument("--expected-deployment-id", required=True)
    verify.add_argument("--json", action="store_true")

    capture = subparsers.add_parser("capture")
    capture.add_argument("--baseline-inventory", type=pathlib.Path, required=True)
    capture.add_argument("--current-inventory", type=pathlib.Path, required=True)
    capture.add_argument("--scope-manifest", type=pathlib.Path, required=True)
    capture.add_argument("--notification-ledger", type=pathlib.Path)
    capture.add_argument("--output", type=pathlib.Path, default=FIXED_EVIDENCE)
    capture.add_argument("--env-file", type=pathlib.Path, required=True)
    capture.add_argument("--expected-release-sha", required=True)
    capture.add_argument("--expected-deployment-id", required=True)
    capture.add_argument("--observed-at", required=True)
    args = parser.parse_args(argv)
    try:
        account_id, display_name = _expected_identity_from_env(args.env_file)
        if args.command == "capture":
            report = capture_evidence(
                baseline_inventory_path=args.baseline_inventory,
                current_inventory_path=args.current_inventory,
                scope_manifest_path=args.scope_manifest,
                notification_ledger_path=args.notification_ledger,
                output=args.output,
                release_sha=args.expected_release_sha,
                deployment_id=args.expected_deployment_id,
                expected_account_id=account_id,
                expected_display_name=display_name,
                observed_at=_timestamp(args.observed_at, label="legacy observation time"),
            )
        else:
            report = validate_evidence(
                args.evidence,
                expected_release_sha=args.expected_release_sha,
                expected_deployment_id=args.expected_deployment_id,
                expected_account_id=account_id,
                expected_display_name=display_name,
            )
    except (EvidenceError, OSError) as error:
        print(f"FAIL legacy billing containment status - {error}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "PASS legacy billing containment status "
            f"(observed {report['observed_at']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
