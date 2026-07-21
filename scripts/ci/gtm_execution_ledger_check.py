#!/usr/bin/env python3
"""Validate the fail-closed TinyZKP Guard revenue-readiness ledger."""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = [
    "site/pricing.json",
    "site/commerce.json",
    "site/release.json",
    "release/guard-launch-state-v2.json",
]
CSV_COLUMNS = [
    "task_id",
    "category",
    "gate",
    "status",
    "owner",
    "reason_code",
    "public_status_url",
    "source_artifact",
    "evidence_count",
    "next_action",
]
EXPECTED_ROOT_KEYS = {
    "schema_version", "ledger_type", "generated_at", "generated_from", "operating_rules",
    "business_state", "offers", "summary", "tasks",
}
EXPECTED_BUSINESS_KEYS = {
    "launch_state", "sales_state", "checkout_enabled", "commerce_state", "portal_state",
    "merchant_provider", "merchant_of_record_status", "legal_status", "hosted_proving",
    "usage_metering", "revenue_evidence_claimed", "recorded_revenue_cents",
}
EXPECTED_SUMMARY_KEYS = {
    "total_gates", "blocking_gates", "passed_gates", "sales_open", "checkout_enabled",
    "revenue_evidence_claimed", "recorded_revenue_cents",
}
EXPECTED_OPERATING_RULES = [
    "Treat the canonical Guard launch state as the only source of gate completion.",
    "Keep sales and checkout closed until every launch gate passes and commerce is reviewed.",
    "Use Lemon Squeezy as the sole merchant of record for the Guard offer.",
    "Treat this as a readiness ledger, not a customer, payment, or booked-revenue ledger.",
    "Do not restore retired hosted-service or outbound-distribution paths.",
]
BANNED_ACTIVE_MARKERS = {
    "retired payment provider": re.compile(r"\bstripe\b", re.IGNORECASE),
    "retired one-off offer": re.compile(r"\bpilot\b", re.IGNORECASE),
    "retired account funnel": re.compile(r"\bsignup\b", re.IGNORECASE),
    "retired agent distribution": re.compile(r"\bmcp\b", re.IGNORECASE),
    "retired hosted API route": re.compile(r"(?:https://api\.tinyzkp\.com|https://mcp\.tinyzkp\.com|tinyzkp\.com/api/)", re.IGNORECASE),
    "retired site route": re.compile(r"tinyzkp\.com/(?:try|verify|contact|pilot|signup)(?:[?#/]|$)", re.IGNORECASE),
    "legacy completion state": re.compile(r"\b(?:completed|won|live_monitoring)\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def load_renderer():
    path = ROOT / "scripts" / "marketing" / "render_gtm_execution_ledger.py"
    spec = importlib.util.spec_from_file_location("render_gtm_execution_ledger_for_check", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Guard execution renderer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def banned_failures(label: str, text: str) -> list[str]:
    return [f"{label} contains {description}" for description, pattern in BANNED_ACTIVE_MARKERS.items() if pattern.search(text)]


def validate_json(root: Path) -> list[Check]:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.json"
    try:
        payload = load_json(path)
        pricing = load_json(root / "site" / "pricing.json")
        commerce = load_json(root / "site" / "commerce.json")
        release = load_json(root / "site" / "release.json")
        launch = load_json(root / "release" / "guard-launch-state-v2.json")
    except FileNotFoundError as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"missing file: {exc.filename}")]
    except (json.JSONDecodeError, ValueError) as exc:
        return [Check("FAIL", str(path.relative_to(root)), f"invalid JSON: {exc}")]

    failures = banned_failures("execution ledger", json.dumps(payload, sort_keys=True))
    if set(payload) != EXPECTED_ROOT_KEYS:
        failures.append("execution ledger root fields must exactly match the bounded Guard schema")
    if payload.get("schema_version") != 2:
        failures.append("schema_version must be 2")
    if payload.get("ledger_type") != "guard_revenue_readiness":
        failures.append("ledger_type must be guard_revenue_readiness")
    if payload.get("generated_from") != SOURCE_PATHS:
        failures.append("generated_from must contain only the four current Guard launch sources")
    if payload.get("operating_rules") != EXPECTED_OPERATING_RULES:
        failures.append("operating_rules must exactly match the bounded Guard contract")

    state = payload.get("business_state")
    if not isinstance(state, dict):
        failures.append("business_state must be an object")
        state = {}
    elif set(state) != EXPECTED_BUSINESS_KEYS:
        failures.append("business_state fields must exactly match the bounded Guard schema")
    expected_state = {
        "launch_state": launch.get("launch_state"),
        "sales_state": launch.get("sales_state"),
        "checkout_enabled": launch.get("checkout_enabled"),
        "commerce_state": launch.get("commerce_state"),
        "portal_state": launch.get("portal_state"),
        "merchant_provider": commerce.get("provider"),
        "merchant_of_record_status": launch.get("merchant_of_record_status"),
        "legal_status": launch.get("legal_status"),
        "hosted_proving": pricing.get("hosted_proving"),
        "usage_metering": pricing.get("usage_metering"),
        "revenue_evidence_claimed": False,
        "recorded_revenue_cents": 0,
    }
    if state != expected_state:
        failures.append("business_state must exactly match current Guard sources and claim no revenue evidence")
    if commerce.get("provider") != "lemon_squeezy":
        failures.append("current commerce provider must be lemon_squeezy")
    if state.get("recorded_revenue_cents") != 0 or state.get("revenue_evidence_claimed") is not False:
        failures.append("active ledger must not claim recorded revenue")

    offers = payload.get("offers")
    if not isinstance(offers, list):
        failures.append("offers must be a list")
        offers = []
    offers_by_id = {str(offer.get("id")): offer for offer in offers if isinstance(offer, dict)}
    products = {str(product.get("id")): product for product in pricing.get("products", []) if isinstance(product, dict)}
    if set(offers_by_id) != {"community", "guard"}:
        failures.append("offers must contain only Community and Guard")
    if "community" in offers_by_id and "community" in products:
        expected = products["community"]
        if set(offers_by_id["community"]) != {"id", "name", "availability", "license", "price_usd"}:
            failures.append("Community offer fields must exactly match the bounded schema")
        if any(offers_by_id["community"].get(field) != expected.get(field) for field in ("name", "availability", "license", "price_usd")):
            failures.append("Community offer must match pricing source")
    if "guard" in offers_by_id and "guard" in products:
        expected = products["guard"]
        prices = expected.get("prices") or {}
        actual = offers_by_id["guard"]
        if set(actual) != {"id", "name", "availability", "license", "monthly_usd", "annual_usd", "annual_recommended"}:
            failures.append("Guard offer fields must exactly match the bounded schema")
        if any(actual.get(field) != expected.get(field) for field in ("name", "availability", "license")):
            failures.append("Guard offer identity must match pricing source")
        if actual.get("monthly_usd") != prices.get("monthly_usd") or actual.get("annual_usd") != prices.get("annual_usd"):
            failures.append("Guard offer prices must match pricing source")

    tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        failures.append("tasks must be a list")
        tasks = []
    gate_status = launch.get("gate_status") if isinstance(launch.get("gate_status"), dict) else {}
    canonical_blocked = {gate for gate, status in gate_status.items() if isinstance(status, dict) and status.get("status") == "blocked"}
    listed_blocking = set(launch.get("blocking_gates") or [])
    if canonical_blocked != listed_blocking:
        failures.append("canonical blocking_gates must exactly match blocked gate statuses")
    if launch.get("launch_state") == "blocked" and (
        not canonical_blocked or launch.get("checkout_enabled") or launch.get("sales_state") == "live"
    ):
        failures.append("blocked launch must retain blockers with sales and checkout disabled")
    if launch.get("launch_state") == "qualified" and canonical_blocked:
        failures.append("qualified launch cannot retain blocking gates")
    if launch.get("sales_state") == "live" and (
        launch.get("launch_state") != "qualified"
        or launch.get("commerce_state") != "public_live"
        or launch.get("portal_state") != "live"
        or launch.get("legal_status") != "approved"
        or launch.get("merchant_of_record_status") != "approved"
        or launch.get("checkout_enabled") is not True
        or canonical_blocked
    ):
        failures.append("live sales require a qualified, public_live, blocker-free launch with checkout enabled")
    task_ids: set[str] = set()
    task_gates: set[str] = set()
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            failures.append(f"task {index} must be an object")
            continue
        if set(task) != set(CSV_COLUMNS):
            failures.append(f"task {index} fields must exactly match the bounded Guard gate schema")
        gate = str(task.get("gate") or "")
        task_id = str(task.get("task_id") or "")
        if task_id != f"guard_gate.{gate}":
            failures.append(f"{task_id or index} task id must be derived from gate")
        if task_id in task_ids or gate in task_gates:
            failures.append(f"duplicate gate task {task_id or gate}")
        task_ids.add(task_id)
        task_gates.add(gate)
        source = gate_status.get(gate)
        if not isinstance(source, dict):
            failures.append(f"{task_id} does not map to a canonical launch gate")
            continue
        if task.get("status") != source.get("status"):
            failures.append(f"{task_id} status must match canonical launch state")
        source_reason_code = source.get("reason_code")
        expected_reason_code = "" if source.get("status") == "passed" else source_reason_code
        if task.get("reason_code") != expected_reason_code:
            failures.append(f"{task_id} reason_code must match canonical launch state")
        evidence = source.get("evidence") if isinstance(source.get("evidence"), list) else []
        evidence_fingerprints: set[str] = set()
        for evidence_index, reference in enumerate(evidence):
            if not isinstance(reference, dict) or set(reference) != {
                "path", "sha256", "signature_path", "signature_sha256", "signer_id", "purpose"
            }:
                failures.append(f"{task_id} evidence reference {evidence_index} has invalid fields")
                continue
            fingerprint = json.dumps(reference, sort_keys=True)
            if fingerprint in evidence_fingerprints:
                failures.append(f"{task_id} evidence references must be unique")
            evidence_fingerprints.add(fingerprint)
            if not re.fullmatch(r"[0-9a-f]{64}", str(reference.get("sha256") or "")):
                failures.append(f"{task_id} evidence SHA-256 is malformed")
            if not re.fullmatch(r"[0-9a-f]{64}", str(reference.get("signature_sha256") or "")):
                failures.append(f"{task_id} evidence signature SHA-256 is malformed")
            if not str(reference.get("signature_path") or "").endswith(".sigstore.json"):
                failures.append(f"{task_id} evidence signature path is invalid")
            if not str(reference.get("signer_id") or "").strip() or not str(reference.get("purpose") or "").strip():
                failures.append(f"{task_id} evidence signer and purpose are required")
        if source.get("status") == "passed" and not evidence:
            failures.append(f"{task_id} passed status requires bound evidence")
        if source.get("status") == "passed" and source_reason_code is not None:
            failures.append(f"{task_id} passed status requires reason_code=null")
        if source.get("status") == "blocked" and evidence:
            failures.append(f"{task_id} blocked status cannot contain passing evidence")
        if source.get("status") == "blocked" and not (
            isinstance(source_reason_code, str) and bool(source_reason_code)
        ):
            failures.append(f"{task_id} blocked status requires a reason code")
        if task.get("evidence_count") != len(evidence):
            failures.append(f"{task_id} evidence count must match canonical launch state")
        expected_url = f"https://tinyzkp.com{source.get('reason_anchor')}"
        if task.get("public_status_url") != expected_url:
            failures.append(f"{task_id} public status URL must match canonical reason anchor")
        if task.get("source_artifact") != "release/guard-launch-state-v2.json":
            failures.append(f"{task_id} source artifact must be canonical launch state")
        if not str(task.get("next_action") or "").strip():
            failures.append(f"{task_id} next_action is required")
        if any(field in task for field in ("primary_cta", "secondary_cta", "submission_url", "completed_at", "actual_revenue_cents")):
            failures.append(f"{task_id} must not contain acquisition CTA, completion, or revenue fields")
    if task_gates != set(gate_status):
        failures.append("tasks must contain exactly one row for every canonical launch gate")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        failures.append("summary must be an object")
    else:
        if set(summary) != EXPECTED_SUMMARY_KEYS:
            failures.append("summary fields must exactly match the bounded Guard schema")
        blocked = sum(task.get("status") == "blocked" for task in tasks if isinstance(task, dict))
        expected_summary = {
            "total_gates": len(tasks),
            "blocking_gates": blocked,
            "passed_gates": len(tasks) - blocked,
            "sales_open": launch.get("sales_state") == "live",
            "checkout_enabled": launch.get("checkout_enabled"),
            "revenue_evidence_claimed": False,
            "recorded_revenue_cents": 0,
        }
        if summary != expected_summary:
            failures.append("summary must match canonical gate counts and claim no revenue evidence")

    if release.get("gate_status") != launch.get("gate_status"):
        failures.append("site release gates have drifted from canonical launch state")
    if pricing.get("price_policy") != commerce.get("price_policy"):
        failures.append("pricing and commerce price policies have drifted")
    try:
        expected_payload = load_renderer().render_ledger(
            pricing=pricing,
            commerce=commerce,
            release=release,
            launch_state=launch,
        )
        if payload != expected_payload:
            failures.append("execution ledger JSON must exactly match the four canonical Guard sources")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"canonical Guard sources cannot render safely: {exc}")
    if failures:
        return [Check("FAIL", str(path.relative_to(root)), "; ".join(failures[:30]))]
    return [Check("PASS", str(path.relative_to(root)), f"{len(tasks)} Guard gate tasks are canonical and fail closed")]


def validate_csv(root: Path, expected_count: int | None, expected_text: str | None = None) -> Check:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.csv"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing Guard revenue ledger CSV")
    text = path.read_text(encoding="utf-8")
    failures = banned_failures("execution ledger CSV", text)
    if expected_text is not None and text != expected_text:
        failures.append("CSV must exactly match the canonical JSON rendering")
    rows = list(csv.DictReader(text.splitlines()))
    actual_columns = list(rows[0].keys()) if rows else []
    if actual_columns != CSV_COLUMNS:
        failures.append("CSV columns must match the bounded Guard gate schema")
    if expected_count is not None and len(rows) != expected_count:
        failures.append(f"expected {expected_count} gate rows, found {len(rows)}")
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures))
    return Check("PASS", str(path.relative_to(root)), f"CSV contains {len(rows)} bounded Guard gate rows")


def validate_markdown(root: Path, expected_text: str | None = None) -> Check:
    path = root / "marketing" / "generated" / "gtm_execution_ledger.md"
    if not path.is_file():
        return Check("FAIL", str(path.relative_to(root)), "missing Guard revenue ledger markdown")
    text = path.read_text(encoding="utf-8")
    failures = banned_failures("execution ledger markdown", text)
    if expected_text is not None and text != expected_text:
        failures.append("markdown must exactly match the canonical JSON rendering")
    for marker in (
        "# TinyZKP Guard Revenue Readiness Ledger",
        "This is a fail-closed readiness ledger.",
        "Revenue evidence claimed: `false`",
        "Recorded revenue: `$0`",
        "## Guard Launch Gate Queue",
    ):
        if marker not in text:
            failures.append(f"markdown missing {marker!r}")
    if failures:
        return Check("FAIL", str(path.relative_to(root)), "; ".join(failures))
    return Check("PASS", str(path.relative_to(root)), "markdown reports only current Guard revenue readiness")


def validate(root: Path = ROOT) -> list[Check]:
    checks = validate_json(root)
    expected_count: int | None = None
    expected_outputs: dict[str, str] = {}
    if checks[0].status == "PASS":
        payload = load_json(root / "marketing" / "generated" / "gtm_execution_ledger.json")
        expected_count = len(payload.get("tasks") or [])
        expected_outputs = load_renderer().expected_outputs(payload)
    checks.append(validate_csv(root, expected_count, expected_outputs.get("csv")))
    checks.append(validate_markdown(root, expected_outputs.get("md")))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} Guard revenue ledger check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll Guard revenue-readiness ledger checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
