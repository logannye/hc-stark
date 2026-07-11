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
        "render_offers.py --check",
        "Python SDK checks",
        "TypeScript SDK checks",
        "compose_config_check.py",
        "cargo audit",
        "billing/tests/test_runtime_lock.py",
        "billing/runtime_lock.py",
        "scripts/ci/test_fixed_host_backup_evidence.py",
    ):
        require(marker in workflow, f"CI lost retained gate: {marker}")

    runtime_files = (
        "billing/RUNTIME.md",
        "billing/host-runtime-provenance.json",
        "billing/requirements-bootstrap.lock",
        "billing/requirements.lock",
        "billing/runtime-profile.json",
        "billing/runtime_lock.py",
        "billing/tests/test_runtime_lock.py",
        "billing/wheelhouse-manifest.json",
    )
    for relative in runtime_files:
        require((ROOT / relative).is_file(), f"billing runtime artifact is missing: {relative}")
    for relative in (
        "scripts/ci/fixed_host_backup_evidence.py",
        "scripts/ci/test_fixed_host_backup_evidence.py",
    ):
        require(
            (ROOT / relative).is_file(),
            f"fixed-host backup evidence gate is missing: {relative}",
        )
    runtime_profile = json.loads(text("billing/runtime-profile.json"))
    require(
        runtime_profile.get("profile_id")
        == "tinyzkp-billing-debian12-x86_64-cpython311-v1",
        "billing runtime profile target drifted",
    )
    host_provenance = json.loads(text("billing/host-runtime-provenance.json"))
    require(
        host_provenance.get("status") == "unconfigured",
        "unreviewed recovery source must keep host runtime provenance blocked",
    )
    installer = text("deploy/hetzner/install_billing_runtime.sh")
    for marker in (
        "verify-host-provenance",
        "--production-permissions",
        "--copies --without-pip \"$STAGING\"",
        "PYTHONPATH=\"$BOOTSTRAP_WHEEL\"",
        "cleanup_runtime_install",
    ):
        require(marker in installer, f"billing runtime installer lost control: {marker}")

    cloudflare_profile = json.loads(
        text("release/cloudflare-production-toolchain-v1.json")
    )
    runtime_lock_source = text("billing/runtime_lock.py")
    for value in (
        cloudflare_profile["node"]["production_path"],
        cloudflare_profile["node"]["binary_sha256"],
    ):
        require(
            value in runtime_lock_source,
            "production runtime identity drifted from the pinned Node profile",
        )

    production_preflight = text("scripts/ci/production_launch_preflight.py")
    for marker in (
        'EVIDENCE_SCHEMA = "tinyzkp-production-preflight-evidence-v7"',
        '"backup_loader_token_sha256"',
        '"backup_transport_secret_sha256"',
        "_backup_private_input_identity",
        "_cloudflare_evidence_identity",
        "_production_runtime_evidence_identity",
        "_fixed_host_backup_evidence_identity",
        "_private_gate_input_snapshot",
        '"cloudflare_materialization_sha256"',
    ):
        require(
            marker in production_preflight,
            f"production evidence lost private/runtime binding: {marker}",
        )
    require(
        "production backup evidence requires exactly one encrypted rclone credential"
        in production_preflight,
        "production preflight no longer matches the rclone fixed-host drill",
    )
    env_example = text("deploy/hetzner/.env.example")
    require(
        "HC_BACKUP_REMOTE=tinyzkp-backups-crypt:prod-sqlite" in env_example,
        "production example does not select the reviewed encrypted rclone path",
    )
    require(
        "HC_BACKUP_HTTP_URL=" not in env_example,
        "production example still advertises unreviewed HTTP backup ingest",
    )
    require(
        "unexpected recovery secrets" in text("scripts/ci/cloudflare_pages_secret_check.py"),
        "Cloudflare live inventory no longer rejects arbitrary secrets",
    )
    require(
        "scripts/ci/run_production_preflight.sh --production" in deploy,
        "deploy handoff bypasses the clean production-preflight wrapper",
    )

    release_workflow = text(".github/workflows/release-backend.yml")
    for marker in (
        "backend_release_ready.py",
        "cargo build --locked",
        "tinyzkp-backend.spdx.json",
        "cosign sign-blob",
        "actions/attest@v4",
    ):
        require(marker in release_workflow, f"release workflow lost integrity control: {marker}")

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
