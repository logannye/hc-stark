#!/usr/bin/env python3
"""Validate the fail-closed TinyZKP Guard commercial launch gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / "release" / "guard-launch-gates-v1.json"
REQUIRED_GATES = {
    "engine_release_ready",
    "guard_release_ready",
    "three_external_workloads",
    "two_standard_annual_customers",
    "five_unaided_installs",
    "legal_terms_approved",
    "merchant_sandbox_lifecycle_passed",
    "merchant_live_owner_smoke_passed",
    "legacy_obligations_resolved",
    "hosted_infrastructure_decommissioned",
}


def load_config(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read strict launch-gate JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("launch-gate document must be an object")
    return value


def validate(config: dict, *, require_ready: bool = False) -> list[str]:
    errors: list[str] = []
    if config.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if config.get("release") != "tinyzkp-guard-v1":
        errors.append("release must be tinyzkp-guard-v1")

    status = config.get("status")
    if status not in {"blocked", "ready"}:
        errors.append("status must be blocked or ready")

    checkout_enabled = config.get("checkout_enabled")
    if not isinstance(checkout_enabled, bool):
        errors.append("checkout_enabled must be a boolean")

    gates = config.get("blocking_gates")
    if not isinstance(gates, list) or any(not isinstance(item, str) for item in gates):
        errors.append("blocking_gates must be a string array")
    else:
        actual = set(gates)
        extra = actual - REQUIRED_GATES
        if extra:
            errors.append(f"unknown blocking gates: {', '.join(sorted(extra))}")
        if len(gates) != len(actual):
            errors.append("blocking_gates contains duplicates")

    gate_status = config.get("gate_status")
    calculated_blocking: set[str] = set()
    if not isinstance(gate_status, dict):
        errors.append("gate_status must be an object")
    else:
        missing = REQUIRED_GATES - set(gate_status)
        extra = set(gate_status) - REQUIRED_GATES
        if missing:
            errors.append(f"missing gate status: {', '.join(sorted(missing))}")
        if extra:
            errors.append(f"unknown gate status: {', '.join(sorted(extra))}")
        for gate_name in sorted(REQUIRED_GATES & set(gate_status)):
            record = gate_status[gate_name]
            if not isinstance(record, dict) or set(record) != {"status", "evidence"}:
                errors.append(
                    f"gate_status.{gate_name} must contain exactly status and evidence"
                )
                continue
            gate_state = record.get("status")
            evidence = record.get("evidence")
            if gate_state not in {"blocked", "passed"}:
                errors.append(f"gate_status.{gate_name}.status must be blocked or passed")
            if (
                not isinstance(evidence, list)
                or any(not isinstance(item, str) or not item.strip() for item in evidence)
                or len(evidence) != len(set(evidence))
            ):
                errors.append(
                    f"gate_status.{gate_name}.evidence must be a unique non-empty string array"
                )
            if gate_state == "passed" and evidence == []:
                errors.append(f"passed gate {gate_name} requires reviewed evidence")
            if gate_state != "passed":
                calculated_blocking.add(gate_name)

    if isinstance(gates, list) and all(isinstance(item, str) for item in gates):
        if set(gates) != calculated_blocking:
            errors.append("blocking_gates must exactly match non-passed gate_status entries")

    if status == "blocked":
        if checkout_enabled is True:
            errors.append("checkout cannot be enabled while launch status is blocked")
        if not calculated_blocking:
            errors.append("blocked status requires at least one non-passed gate")
    if status == "ready":
        if checkout_enabled is not True:
            errors.append("ready status requires checkout_enabled=true")
        if calculated_blocking:
            errors.append("ready status requires every gate to pass")
    if require_ready and (status != "ready" or checkout_enabled is not True):
        errors.append("TinyZKP Guard commercial launch is not ready")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ValueError as exc:
        print(f"guard launch gate: FAIL: {exc}", file=sys.stderr)
        return 2

    errors = validate(config, require_ready=args.require_ready)
    if errors:
        for error in errors:
            print(f"guard launch gate: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "schema_version": 1,
                "status": config["status"],
                "checkout_enabled": config["checkout_enabled"],
                "ready": config["status"] == "ready" and config["checkout_enabled"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
