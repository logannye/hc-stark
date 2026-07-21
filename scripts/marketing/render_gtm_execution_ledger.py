#!/usr/bin/env python3
"""Render the fail-closed TinyZKP Guard revenue-readiness ledger.

The ledger is derived only from the public Community/Guard pricing, commerce,
release, and canonical Guard launch-state contracts. It does not send messages,
submit listings, create checkout sessions, or infer revenue from traffic.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRICING = ROOT / "site" / "pricing.json"
DEFAULT_COMMERCE = ROOT / "site" / "commerce.json"
DEFAULT_RELEASE = ROOT / "site" / "release.json"
DEFAULT_LAUNCH_STATE = ROOT / "release" / "guard-launch-state-v2.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "gtm_execution_ledger.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "gtm_execution_ledger.md"

SCHEMA_VERSION = 2
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EVIDENCE_KEYS = {"path", "sha256", "signature_path", "signature_sha256", "signer_id", "purpose"}
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
OPERATING_RULES = [
    "Treat the canonical Guard launch state as the only source of gate completion.",
    "Keep sales and checkout closed until every launch gate passes and commerce is reviewed.",
    "Use Lemon Squeezy as the sole merchant of record for the Guard offer.",
    "Treat this as a readiness ledger, not a customer, payment, or booked-revenue ledger.",
    "Do not restore retired hosted-service or outbound-distribution paths.",
]


GATE_METADATA = {
    "engine_release_ready": (
        "release",
        "engineering",
        "Publish digest-bound engine release evidence from the reviewed release commit.",
    ),
    "guard_release_ready": (
        "release",
        "engineering",
        "Publish the reviewed Guard release manifest and its bound source identity.",
    ),
    "guard_artifact_published": (
        "release",
        "engineering",
        "Publish the signed Guard artifact, checksum, provenance, and channel metadata.",
    ),
    "three_external_workloads": (
        "qualification",
        "founder",
        "Record three independent external workload qualification results in launch evidence.",
    ),
    "two_standard_annual_customers": (
        "qualification",
        "founder",
        "Record two standard annual-customer qualification outcomes without changing the public offer.",
    ),
    "five_unaided_installs": (
        "qualification",
        "engineering",
        "Record five clean-machine unaided install results without maintainer intervention.",
    ),
    "legal_terms_approved": (
        "legal",
        "owner_and_counsel",
        "Approve the commercial terms and publish the binding legal version.",
    ),
    "merchant_sandbox_lifecycle_passed": (
        "commerce",
        "founder",
        "Complete and record the Lemon Squeezy sandbox purchase, renewal, cancellation, and access lifecycle.",
    ),
    "merchant_live_owner_smoke_passed": (
        "commerce",
        "founder",
        "Complete and record the owner-controlled Lemon Squeezy production smoke test.",
    ),
    "release_rehearsal_within_budget": (
        "operations",
        "engineering",
        "Complete a release rehearsal and bind its measured support and maintenance budget evidence.",
    ),
    "legacy_obligations_resolved": (
        "operations",
        "founder",
        "Resolve and record every retained customer, billing, data, and service obligation.",
    ),
    "hosted_infrastructure_decommissioned": (
        "operations",
        "engineering",
        "Decommission retained hosted infrastructure only after the obligation inventory is complete.",
    ),
}


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
    _require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _guard_product(pricing: dict[str, Any]) -> dict[str, Any]:
    products = pricing.get("products")
    _require(isinstance(products, list), "pricing products must be a list")
    matches = [product for product in products if isinstance(product, dict) and product.get("id") == "guard"]
    _require(len(matches) == 1, "pricing must contain exactly one Guard product")
    return matches[0]


def _community_product(pricing: dict[str, Any]) -> dict[str, Any]:
    products = pricing.get("products") or []
    matches = [product for product in products if isinstance(product, dict) and product.get("id") == "community"]
    _require(len(matches) == 1, "pricing must contain exactly one Community product")
    return matches[0]


def validate_sources(
    *,
    pricing: dict[str, Any],
    commerce: dict[str, Any],
    release: dict[str, Any],
    launch_state: dict[str, Any],
) -> None:
    _require(launch_state.get("document_type") == "GuardLaunchStateV2", "launch state document type must be GuardLaunchStateV2")
    _require(commerce.get("provider") == "lemon_squeezy", "commerce provider must be lemon_squeezy")
    _require(isinstance(pricing.get("hosted_proving"), bool), "hosted_proving must be a boolean")
    _require(isinstance(pricing.get("usage_metering"), bool), "usage_metering must be a boolean")
    _require(pricing.get("hosted_proving") is False, "pricing must keep hosted proving disabled")
    _require(pricing.get("usage_metering") is False, "pricing must keep usage metering disabled")

    for field in ("launch_state", "sales_state", "commerce_state", "checkout_enabled", "portal_state"):
        values = [pricing.get(field), commerce.get(field), release.get(field), launch_state.get(field)]
        _require(len(set(values)) == 1, f"{field} must agree across all Guard launch sources")
    _require(
        not launch_state.get("checkout_enabled") or launch_state.get("sales_state") == "live",
        "checkout may be enabled only when Guard sales are live",
    )
    _require(
        launch_state.get("sales_state") != "live" or launch_state.get("checkout_enabled") is True,
        "live Guard sales require checkout to be enabled",
    )

    launch_gates = launch_state.get("gate_status")
    release_gates = release.get("gate_status")
    _require(isinstance(launch_gates, dict) and launch_gates, "launch state gate_status must be a non-empty object")
    _require(launch_gates == release_gates, "site release gate status must match canonical launch state")
    _require(launch_state.get("blocking_gates") == release.get("blocking_gates"), "release blocking gates must match canonical launch state")
    blocking_gates = set(launch_state.get("blocking_gates") or [])
    blocked_statuses = {gate for gate, status in launch_gates.items() if status.get("status") == "blocked"}
    _require(blocking_gates == blocked_statuses, "blocking_gates must exactly match blocked gate statuses")
    if launch_state.get("launch_state") == "blocked":
        _require(bool(blocking_gates), "blocked launch must retain at least one blocking gate")
        _require(not launch_state.get("checkout_enabled"), "blocked launch cannot enable checkout")
        _require(launch_state.get("sales_state") in {"closed", "frozen"}, "blocked launch cannot report live sales")
    if launch_state.get("launch_state") == "qualified":
        _require(not blocking_gates, "qualified launch cannot retain blocking gates")
    if launch_state.get("sales_state") == "live":
        _require(launch_state.get("launch_state") == "qualified", "live sales require a qualified launch")
        _require(launch_state.get("commerce_state") == "public_live", "live sales require public_live commerce")
        _require(launch_state.get("portal_state") == "live", "live sales require a live customer portal")
        _require(launch_state.get("legal_status") == "approved", "live sales require approved legal terms")
        _require(launch_state.get("merchant_of_record_status") == "approved", "live sales require an approved merchant of record")
        _require(not blocking_gates, "live sales require every launch gate to pass")

    price_policy = pricing.get("price_policy")
    _require(isinstance(price_policy, dict), "pricing price_policy must be an object")
    _require(price_policy == commerce.get("price_policy"), "pricing and commerce price policies must match")
    guard = _guard_product(pricing)
    prices = guard.get("prices")
    _require(isinstance(prices, dict), "Guard prices must be an object")
    _require(prices.get("monthly_usd") == price_policy.get("monthly_usd"), "Guard monthly price must match price policy")
    _require(prices.get("annual_usd") == price_policy.get("annual_usd"), "Guard annual price must match price policy")
    _require(isinstance(prices.get("annual_recommended"), bool), "Guard annual_recommended must be a boolean")


def _offer_summary(pricing: dict[str, Any]) -> list[dict[str, Any]]:
    community = _community_product(pricing)
    guard = _guard_product(pricing)
    prices = guard["prices"]
    return [
        {
            "id": "community",
            "name": str(community["name"]),
            "availability": str(community["availability"]),
            "license": str(community["license"]),
            "price_usd": int(community["price_usd"]),
        },
        {
            "id": "guard",
            "name": str(guard["name"]),
            "availability": str(guard["availability"]),
            "license": str(guard["license"]),
            "monthly_usd": int(prices["monthly_usd"]),
            "annual_usd": int(prices["annual_usd"]),
            "annual_recommended": prices["annual_recommended"],
        },
    ]


def _gate_order(launch_state: dict[str, Any]) -> list[str]:
    gate_status = launch_state["gate_status"]
    blocking = list(launch_state.get("blocking_gates") or [])
    return blocking + sorted(set(gate_status) - set(blocking))


def _validate_evidence_references(gate: str, evidence: list[Any]) -> None:
    serialized: set[str] = set()
    for index, reference in enumerate(evidence):
        _require(isinstance(reference, dict), f"{gate} evidence reference {index} must be an object")
        _require(set(reference) == EVIDENCE_KEYS, f"{gate} evidence reference {index} has invalid fields")
        fingerprint = json.dumps(reference, sort_keys=True)
        _require(fingerprint not in serialized, f"{gate} evidence references must be unique")
        serialized.add(fingerprint)
        path = str(reference["path"])
        signature_path = str(reference["signature_path"])
        _require(bool(path) and not path.startswith("/") and ".." not in Path(path).parts, f"{gate} evidence path is invalid")
        _require(
            bool(signature_path)
            and not signature_path.startswith("/")
            and ".." not in Path(signature_path).parts
            and signature_path.endswith(".sigstore.json"),
            f"{gate} evidence signature path is invalid",
        )
        _require(isinstance(reference["sha256"], str) and SHA256_RE.fullmatch(reference["sha256"]) is not None, f"{gate} evidence SHA-256 is malformed")
        _require(
            isinstance(reference["signature_sha256"], str)
            and SHA256_RE.fullmatch(reference["signature_sha256"]) is not None,
            f"{gate} evidence signature SHA-256 is malformed",
        )
        _require(isinstance(reference["signer_id"], str) and bool(reference["signer_id"].strip()), f"{gate} evidence signer_id is required")
        _require(isinstance(reference["purpose"], str) and bool(reference["purpose"].strip()), f"{gate} evidence purpose is required")


def gate_task(gate: str, launch_state: dict[str, Any]) -> dict[str, Any]:
    status = launch_state["gate_status"][gate]
    category, owner, next_action = GATE_METADATA.get(
        gate,
        ("launch", "founder", f"Add canonical evidence for {gate.replace('_', ' ')}."),
    )
    reason_anchor = str(status.get("reason_anchor") or launch_state.get("reason_anchors", {}).get(gate) or "")
    _require(reason_anchor.startswith("/"), f"{gate} reason anchor must be site-relative")
    evidence = status.get("evidence")
    _require(isinstance(evidence, list), f"{gate} evidence must be a list")
    _validate_evidence_references(gate, evidence)
    gate_status = str(status.get("status") or "")
    _require(gate_status in {"blocked", "passed"}, f"{gate} has unsupported status {gate_status!r}")
    source_reason_code = status.get("reason_code")
    if gate_status == "passed":
        _require(
            source_reason_code is None,
            f"{gate} passed status requires reason_code=null",
        )
        _require(bool(evidence), f"{gate} passed status requires bound evidence")
        reason_code = ""
    else:
        _require(not evidence, f"{gate} blocked status cannot contain passing evidence")
        _require(
            isinstance(source_reason_code, str) and bool(source_reason_code),
            f"{gate} blocked status requires a reason code",
        )
        reason_code = source_reason_code
    return {
        "task_id": f"guard_gate.{gate}",
        "category": category,
        "gate": gate,
        "status": gate_status,
        "owner": owner,
        "reason_code": reason_code,
        "public_status_url": f"https://tinyzkp.com{reason_anchor}",
        "source_artifact": "release/guard-launch-state-v2.json",
        "evidence_count": len(evidence),
        "next_action": "No action; retain the bound evidence." if gate_status == "passed" else next_action,
    }


def render_ledger(
    *,
    pricing: dict[str, Any],
    commerce: dict[str, Any],
    release: dict[str, Any],
    launch_state: dict[str, Any],
) -> dict[str, Any]:
    validate_sources(pricing=pricing, commerce=commerce, release=release, launch_state=launch_state)
    tasks = [gate_task(gate, launch_state) for gate in _gate_order(launch_state)]
    blocking_tasks = sum(task["status"] == "blocked" for task in tasks)
    evaluated_at = str(launch_state.get("evaluated_at") or "")
    _require(len(evaluated_at) >= 10, "launch state evaluated_at is required")
    return {
        "schema_version": SCHEMA_VERSION,
        "ledger_type": "guard_revenue_readiness",
        "generated_at": evaluated_at[:10],
        "generated_from": SOURCE_PATHS,
        "operating_rules": OPERATING_RULES,
        "business_state": {
            "launch_state": str(launch_state["launch_state"]),
            "sales_state": str(launch_state["sales_state"]),
            "checkout_enabled": bool(launch_state["checkout_enabled"]),
            "commerce_state": str(launch_state["commerce_state"]),
            "portal_state": str(launch_state["portal_state"]),
            "merchant_provider": str(commerce["provider"]),
            "merchant_of_record_status": str(launch_state["merchant_of_record_status"]),
            "legal_status": str(launch_state["legal_status"]),
            "hosted_proving": bool(pricing["hosted_proving"]),
            "usage_metering": bool(pricing["usage_metering"]),
            "revenue_evidence_claimed": False,
            "recorded_revenue_cents": 0,
        },
        "offers": _offer_summary(pricing),
        "summary": {
            "total_gates": len(tasks),
            "blocking_gates": blocking_tasks,
            "passed_gates": len(tasks) - blocking_tasks,
            "sales_open": launch_state["sales_state"] == "live",
            "checkout_enabled": bool(launch_state["checkout_enabled"]),
            "revenue_evidence_claimed": False,
            "recorded_revenue_cents": 0,
        },
        "tasks": tasks,
    }


def render_csv(payload: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(payload["tasks"])
    return buffer.getvalue()


def render_markdown(payload: dict[str, Any]) -> str:
    state = payload["business_state"]
    summary = payload["summary"]
    guard = next(offer for offer in payload["offers"] if offer["id"] == "guard")
    lines = [
        "# TinyZKP Guard Revenue Readiness Ledger",
        "",
        f"Generated from the canonical Community/Guard launch contracts dated `{payload['generated_at']}`.",
        "",
        "This is a fail-closed readiness ledger. It is not a customer, payment, or booked-revenue ledger.",
        "",
        "## Current Business State",
        "",
        f"- Launch: `{state['launch_state']}`",
        f"- Sales: `{state['sales_state']}`",
        f"- Checkout enabled: `{str(state['checkout_enabled']).lower()}`",
        f"- Merchant of record: `{state['merchant_provider']}` (`{state['merchant_of_record_status']}`)",
        f"- Legal: `{state['legal_status']}`",
        f"- Hosted proving: `{str(state['hosted_proving']).lower()}`",
        f"- Usage metering: `{str(state['usage_metering']).lower()}`",
        "- Revenue evidence claimed: `false`",
        "- Recorded revenue: `$0`",
        "",
        "## Guard Offer",
        "",
        f"- Availability: `{guard['availability']}`",
        f"- Monthly: `${guard['monthly_usd']:,}`",
        f"- Annual: `${guard['annual_usd']:,}`" + (" (recommended)" if guard["annual_recommended"] else ""),
        "",
        "## Gate Summary",
        "",
        f"- Total gates: {summary['total_gates']}",
        f"- Blocking gates: {summary['blocking_gates']}",
        f"- Passed gates: {summary['passed_gates']}",
        "",
        "## Guard Launch Gate Queue",
        "",
        "| Gate | Category | Status | Evidence | Next action |",
        "|---|---|---|---:|---|",
    ]
    for task in payload["tasks"]:
        lines.append(
            f"| [{task['gate']}]({task['public_status_url']}) | `{task['category']}` | "
            f"`{task['status']}` | {task['evidence_count']} | {task['next_action']} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def expected_outputs(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "json": json.dumps(payload, indent=2) + "\n",
        "csv": render_csv(payload),
        "md": render_markdown(payload),
    }


def check_outputs(expected: dict[str, str], paths: dict[str, Path]) -> list[str]:
    failures: list[str] = []
    for key, path in paths.items():
        if not path.is_file():
            failures.append(f"missing generated Guard revenue ledger file: {path}")
        elif path.read_text(encoding="utf-8") != expected[key]:
            failures.append(f"stale generated Guard revenue ledger file: {path}")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pricing", type=Path, default=DEFAULT_PRICING)
    parser.add_argument("--commerce", type=Path, default=DEFAULT_COMMERCE)
    parser.add_argument("--release", type=Path, default=DEFAULT_RELEASE)
    parser.add_argument("--launch-state", type=Path, default=DEFAULT_LAUNCH_STATE)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--check", action="store_true", help="Fail if generated ledger files are stale")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        payload = render_ledger(
            pricing=load_json(args.pricing),
            commerce=load_json(args.commerce),
            release=load_json(args.release),
            launch_state=load_json(args.launch_state),
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"FAIL cannot render Guard revenue ledger: {exc}", file=sys.stderr)
        return 1
    expected = expected_outputs(payload)
    paths = {"json": args.json_output, "csv": args.csv_output, "md": args.md_output}
    if args.check:
        failures = check_outputs(expected, paths)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        if failures:
            return 1
        print("PASS Guard revenue-readiness ledger is current")
        return 0
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in expected.items():
        paths[key].write_text(content, encoding="utf-8")
    print(f"Wrote Guard revenue-readiness ledger with {len(payload['tasks'])} gate task(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
