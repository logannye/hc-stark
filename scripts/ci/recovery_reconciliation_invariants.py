#!/usr/bin/env python3
"""Recovery-era replacement for legacy agent-SaaS reconciliation checks."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
FAILURES: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> int:
    gates = json.loads(text("release/backend-v1-gates.json"))
    require(gates["status"] == "blocked", "backend release must remain blocked")

    server = tomllib.loads(text("crates/hc-server/Cargo.toml"))
    require(server["lib"]["path"] == "src/maintenance.rs", "server production lib is not maintenance-only")
    require(
        server["package"].get("autobins") is False,
        "server still auto-discovers legacy workers",
    )
    for dependency in (
        "hc-core",
        "hc-prover",
        "hc-recursion",
        "hc-sdk",
        "hc-verifier",
        "hc-vm",
        "hc-workloads",
    ):
        require(
            server["dependencies"][dependency].get("optional") is True,
            f"server legacy dependency is not optional: {dependency}",
        )

    cli = tomllib.loads(text("crates/hc-cli/Cargo.toml"))
    require(cli["features"].get("default") == [], "CLI default features are not empty")
    require("legacy-research" in cli["features"], "CLI lacks explicit legacy-research quarantine")

    dockerfile = text("Dockerfile")
    compose = text("docker-compose.yml")
    deploy = text("deploy/hetzner/deploy.sh")
    setup = text("deploy/hetzner/setup.sh")
    require("hc-worker" not in dockerfile, "production image copies hc-worker")
    require("hc-job-worker" not in dockerfile, "production image copies hc-job-worker")
    require("hc-job-worker:" not in compose, "Compose still defines a proving worker")
    require("billing-cron:" not in compose, "Compose still emits legacy meter events")
    require("billing/sync_usage.py" not in deploy, "deploy reinstalls the usage meter cron")
    require("billing/checkout_recovery.py" not in deploy, "deploy reinstalls checkout recovery")
    require("billing/sync_usage.py" not in setup, "host setup reinstalls the usage meter cron")
    require("billing/checkout_recovery.py" not in setup, "host setup reinstalls checkout recovery")

    workflow = text(".github/workflows/ci.yml")
    for marker in (
        "backend_recovery_gate.py",
        "plonky3_compatibility_gate.py",
        "cargo test -p hc-plonky3",
        "backup restore checks",
        "billing python checks",
        "Python SDK checks",
        "TypeScript SDK checks",
        "compose_config_check.py",
        "cargo audit",
    ):
        require(marker in workflow, f"CI lost retained gate: {marker}")

    require((ROOT / "crates/hc-server/src/lib.rs").is_file(), "historical server source was deleted")
    require((ROOT / "crates/hc-server/src/bin/hc-worker.rs").is_file(), "legacy worker research source was deleted")
    require((ROOT / "crates/hc-server/src/bin/hc-job-worker.rs").is_file(), "legacy queue-worker research source was deleted")

    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL recovery reconciliation: {failure}", file=sys.stderr)
        return 1
    print("PASS recovery reconciliation invariants (legacy SaaS checks quarantined)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
