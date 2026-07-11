#!/usr/bin/env python3
"""Validate the exact 24-hour public-beta canary contract."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path


WORKLOADS = {"fibonacci", "poseidon2", "customer_cubic8"}
ZERO_FIELDS = {
    "verifier_failures",
    "unexplained_credit_differences",
    "stuck_leases",
    "unauthorized_artifact_accesses",
    "leaked_scratch_directories",
}


def validate(value: dict[str, object], release_sha: str) -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != 1 or value.get("release_channel") != "public_beta":
        failures.append("canary schema/channel mismatch")
    if value.get("release_sha") != release_sha:
        failures.append("canary release SHA mismatch")
    try:
        started = datetime.fromisoformat(str(value["started_at"]).replace("Z", "+00:00"))
        completed = datetime.fromisoformat(str(value["completed_at"]).replace("Z", "+00:00"))
        if (completed - started).total_seconds() < 24 * 60 * 60:
            failures.append("canary duration is below 24 hours")
    except (KeyError, ValueError):
        failures.append("canary timestamps are malformed")
    proofs = value.get("hourly_verified_proofs")
    if not isinstance(proofs, list) or len(proofs) < 24:
        failures.append("canary requires at least 24 hourly verified proofs")
    elif {item.get("workload") for item in proofs if isinstance(item, dict)} != WORKLOADS:
        failures.append("canary does not cover all three workloads")
    elif any(item.get("official_verification") is not True for item in proofs if isinstance(item, dict)):
        failures.append("canary contains an unverified proof")
    cancellations = value.get("cancellation_refund_exercises")
    if not isinstance(cancellations, list) or len(cancellations) < 4 or any(
        not isinstance(item, dict) or item.get("full_reservation_released") is not True
        for item in cancellations
    ):
        failures.append("canary requires four successful cancellation/refund exercises")
    billing = value.get("live_billing_canaries")
    kinds = {item.get("kind") for item in billing if isinstance(item, dict)} if isinstance(billing, list) else set()
    if kinds != {"topup", "subscription"} or any(
        item.get("synthetic") is not True
        or item.get("refunded") is not True
        or item.get("excluded_from_revenue") is not True
        or (item.get("kind") == "subscription" and item.get("cancelled") is not True)
        for item in billing if isinstance(item, dict)
    ):
        failures.append("live billing canaries are incomplete")
    for field in ZERO_FIELDS:
        if value.get(field) != 0:
            failures.append(f"{field} must be zero")
    if value.get("status") != "passed":
        failures.append("canary status is not passed")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    args = parser.parse_args()
    failures = validate(json.loads(args.evidence.read_text(encoding="utf-8")), args.release_sha)
    if failures:
        raise SystemExit("public-beta canary failed:\n- " + "\n- ".join(failures))
    print("PASS public-beta 24-hour canary")


if __name__ == "__main__":
    main()
