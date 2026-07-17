#!/usr/bin/env python3
"""Validate the immutable starting point and containment release contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "release" / "evaluation-revenue-launch-baseline-v1.json"
EXPECTED_REMOTE = "https://github.com/logannye/hc-stark.git"
EXPECTED_BRANCH = "codex/evaluation-revenue-launch"
RELEASE_FLAGS = {
    "site_api_mcp_same_sha": True,
    "proving_worker_deployed": False,
    "hosted_proving_enabled": False,
    "hosted_verification_enabled": False,
    "account_creation_enabled": False,
    "public_checkout_enabled": False,
    "customer_email_enabled": False,
}
COMMERCIAL_CONTRACT = {
    "pricing_source_sha256": "affa95a4c1bb7ec056e9b3ff89cf8e23f894d67f57b5b3eb5ee733679b8ab920",
    "founding_offer_sha256": "61e4b33400d667ece3463d0ea62c47477fb01877f5bc09eb67a1555ee6350f46",
    "offer_id": "founding_evaluation",
    "price_usd": 15_000,
    "deposit_usd": 7_500,
    "delivery_usd": 7_500,
    "customer_cap": 3,
    "duration": "2_weeks",
    "engineering_day_cap": 8,
}
EXPECTED_INPUTS = {
    "/opt/hc-stark/.env",
    "/var/lib/tinyzkp-private/deploy/pages-bindings.env",
    "/var/lib/tinyzkp-private/deploy/internal-secret",
    "/var/lib/tinyzkp-private/deploy/legacy-billing-containment-status.json",
    "/var/lib/tinyzkp-private/deploy/production-preflight.json",
    "/var/lib/tinyzkp-private/deploy/installer-drill-evidence.json",
    "/var/lib/tinyzkp-private/backup/fixed-host-evidence",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(payload: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(payload, dict):
        return ["revenue launch baseline must be a JSON object"]
    if payload.get("schema_version") != 1 or payload.get("status") != "recorded":
        failures.append("revenue launch baseline must be a recorded v1 manifest")
    if payload.get("canonical_remote") != EXPECTED_REMOTE:
        failures.append("revenue launch baseline canonical remote is incorrect")
    if payload.get("implementation_branch") != EXPECTED_BRANCH:
        failures.append("revenue launch baseline implementation branch is incorrect")
    if GIT_SHA.fullmatch(str(payload.get("starting_commit_sha", ""))) is None:
        failures.append("revenue launch baseline starting commit is malformed")
    locks = payload.get("dependency_locks")
    if not isinstance(locks, dict) or not locks:
        failures.append("revenue launch baseline dependency locks are missing")
    else:
        for relative, expected in locks.items():
            path = ROOT / relative
            if (
                not isinstance(relative, str)
                or not isinstance(expected, str)
                or SHA256.fullmatch(expected) is None
                or not path.is_file()
            ):
                failures.append(f"revenue launch dependency lock is invalid: {relative!r}")
            elif digest(path) != expected:
                failures.append(f"revenue launch dependency lock changed: {relative}")
    if set(payload.get("deployment_inputs", [])) != EXPECTED_INPUTS:
        failures.append("revenue launch deployment input inventory is incomplete or unknown")
    commercial = payload.get("commercial_contract")
    if commercial != COMMERCIAL_CONTRACT:
        failures.append("revenue launch commercial contract is incomplete or changed")
    else:
        pricing_path = ROOT / "site" / "pricing.json"
        if digest(pricing_path) != commercial["pricing_source_sha256"]:
            failures.append("revenue launch pricing source changed after baseline capture")
        pricing = json.loads(pricing_path.read_text(encoding="utf-8"))
        matches = [
            offer
            for offer in pricing.get("offers", [])
            if isinstance(offer, dict) and offer.get("id") == commercial["offer_id"]
        ]
        if len(matches) != 1:
            failures.append("revenue launch founding offer is missing or duplicated")
        else:
            offer_sha256 = hashlib.sha256(
                json.dumps(
                    matches[0],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ).hexdigest()
            if offer_sha256 != commercial["founding_offer_sha256"]:
                failures.append("revenue launch founding offer changed after baseline capture")
    if payload.get("release_contract") != RELEASE_FLAGS:
        failures.append("revenue launch containment flags are incomplete or unsafe")
    return failures


def main() -> int:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"FAIL  revenue launch baseline is unreadable: {error}", file=sys.stderr)
        return 1
    failures = validate(payload)
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print("PASS  evaluation revenue launch baseline is complete and immutable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
