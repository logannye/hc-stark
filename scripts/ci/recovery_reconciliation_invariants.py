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
    require(
        server["lib"]["path"] == "src/maintenance.rs",
        "server production lib is not maintenance-only",
    )
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
    require(
        "legacy-research" in cli["features"],
        "CLI lacks explicit legacy-research quarantine",
    )

    dockerfile = text("Dockerfile")
    compose = text("docker-compose.yml")
    deploy = text("deploy/hetzner/deploy.sh")
    setup = text("deploy/hetzner/setup.sh")
    transaction = text("deploy/hetzner/deployment_transaction.py")
    require("hc-worker" not in dockerfile, "production image copies hc-worker")
    require("hc-job-worker" not in dockerfile, "production image copies hc-job-worker")
    require("hc-job-worker:" not in compose, "Compose still defines a proving worker")
    require("billing-cron:" not in compose, "Compose still emits legacy meter events")
    require(
        "billing/sync_usage.py" not in deploy, "deploy reinstalls the usage meter cron"
    )
    require(
        "billing/checkout_recovery.py" not in deploy,
        "deploy reinstalls checkout recovery",
    )
    require(
        "billing/sync_usage.py" not in setup,
        "host setup reinstalls the usage meter cron",
    )
    require(
        "billing/checkout_recovery.py" not in setup,
        "host setup reinstalls checkout recovery",
    )
    archived_marketing = {
        "marketing/README.md": (
            "Archived recovery-era material — do not execute, publish, submit, or use",
            "no email outreach",
            "commercial/no-email-evaluation-runbook.md",
        ),
        "marketing/GTM_DISTRIBUTION_PLAN.md": (
            "Archived recovery-era material — do not execute, publish, submit, or use",
            "prohibit email outreach and public checkout",
            "commercial/no-email-evaluation-runbook.md",
        ),
        "marketing/USER_INTERVIEWS.md": (
            "Archived recovery-era material — do not execute.",
            "no-email commercial policy",
            "commercial/no-email-evaluation-runbook.md",
        ),
        "marketing/MCP_DIRECTORY.md": (
            "Archived recovery-era material — do not submit or use for outreach.",
            "HTTPS/no-email",
            "applicant-selected non-email reply channel",
        ),
    }
    for relative, markers in archived_marketing.items():
        content = text(relative)
        for marker in markers:
            require(
                marker in content,
                f"archived marketing warning drifted: {relative}: {marker}",
            )
        lowered = content.lower()
        require(
            "logan@tinyzkp.com" not in lowered, f"founder email remains in {relative}"
        )
        require(
            "galenhealth" not in lowered,
            f"other-business identity remains in {relative}",
        )
    retired_growth_artifacts = (
        "scripts/ci/badge_embed_check.py",
        "scripts/ci/openai_chatgpt_app_check.py",
        "scripts/ci/package_distribution_check.py",
        "scripts/ci/receipt_share_contract_check.py",
        "scripts/ci/seo_conversion_check.py",
        "scripts/monitoring/daily_growth_decision.py",
        "scripts/monitoring/daily_growth_decision_cron.sh",
        "scripts/monitoring/gtm_growth_monitor.py",
        "scripts/monitoring/verify_growth_data_wiring.sh",
    )
    for relative in retired_growth_artifacts:
        require(
            not (ROOT / relative).exists(),
            f"retired self-serve growth artifact was restored: {relative}",
        )
    require(
        "tinyzkp/hc-server:${HC_IMAGE_TAG:-local}" in compose
        and "tinyzkp/hc-mcp:${HC_IMAGE_TAG:-local}" in compose,
        "Compose images are not explicit immutable-tag inputs",
    )
    require(":latest" not in deploy, "production deploy uses a mutable latest image")
    for marker in (
        "deployment.lock",
        "trap rollback_on_exit EXIT",
        'export HC_IMAGE_TAG="$RELEASE_SHA"',
        "deployment_transaction.py",
        "install-configs",
        "--transaction-id",
    ):
        require(marker in deploy, f"transactional deployment lost control: {marker}")
    for marker in (
        "known-containment.json",
        "verify_local_containment",
        "candidate_images",
        "prior_known_containment",
        "_durable_unlink",
        "_emergency_stop",
    ):
        require(marker in transaction, f"deployment transaction lost control: {marker}")
    for relative in (
        "deploy/hetzner/deployment_transaction.py",
        "deploy/hetzner/test_deployment_transaction.py",
        "deploy/hetzner/rollback.sh",
        "deploy/hetzner/hc-billing-webhook.service",
        "deploy/hetzner/hc-billing.cron",
        "scripts/deploy/cloudflare_pages_release.py",
        "scripts/deploy/test_cloudflare_pages_release.py",
        "docs/runbooks/cloudflare_pages_release.md",
    ):
        require(
            (ROOT / relative).is_file(),
            f"transactional deploy artifact is missing: {relative}",
        )
    require("RELEASE AUTHORITY: NONE" in setup, "setup is not marked bootstrap-only")
    for forbidden in (
        "apt-get ",
        "systemctl start",
        "systemctl restart",
        "systemctl reload",
        "systemctl enable",
        "docker compose",
        "ufw --force enable",
        "Installing Caddyfile",
    ):
        require(
            forbidden not in setup,
            f"bootstrap setup retains release authority: {forbidden}",
        )

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
        "scripts/ci/test_installer_drill_evidence.py",
        "scripts/ci/test_legacy_billing_containment_status.py",
        "billing/tests/test_agreement_gate.py",
        "billing/tests/test_evaluation_delivery_manifest.py",
        "billing/tests/test_stripe_test_drill.py",
        "scripts/ci/test_billing_service_hardening.py",
        "deploy/hetzner/test_deployment_transaction.py",
        "deploy/hetzner/deployment_transaction.py",
        "deploy/hetzner/rollback.sh",
        "scripts/deploy/test_cloudflare_pages_release.py",
        "scripts/deploy/cloudflare_pages_release.py",
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
        require(
            (ROOT / relative).is_file(),
            f"billing runtime artifact is missing: {relative}",
        )
    for relative in (
        "scripts/ci/fixed_host_backup_evidence.py",
        "scripts/ci/test_fixed_host_backup_evidence.py",
        "scripts/ci/installer_drill_evidence.py",
        "scripts/ci/test_installer_drill_evidence.py",
        "scripts/ci/legacy_billing_containment_status.py",
        "scripts/ci/test_legacy_billing_containment_status.py",
        "billing/agreement_gate.py",
        "billing/evaluation_delivery_manifest.py",
        "billing/stripe_test_drill.py",
        "commercial/agreement-form-profile.template.json",
        "commercial/annual-contract-evidence.template.json",
        "commercial/evaluation-delivery-manifest.template.json",
        "scripts/deploy/cloudflare_pages_release.py",
        "scripts/deploy/test_cloudflare_pages_release.py",
        "docs/runbooks/cloudflare_pages_release.md",
    ):
        require(
            (ROOT / relative).is_file(),
            f"recovery evidence gate is missing: {relative}",
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
        '--copies --without-pip "$STAGING"',
        'PYTHONPATH="$BOOTSTRAP_WHEEL"',
        "cleanup_runtime_install",
    ):
        require(
            marker in installer, f"billing runtime installer lost control: {marker}"
        )

    cloudflare_profile = json.loads(
        text("release/cloudflare-production-toolchain-v1.json")
    )
    runtime_lock_source = text("billing/runtime_lock.py")
    for value in (
        cloudflare_profile["node"]["production_path"],
        cloudflare_profile["node"]["binary_sha256"],
        "/usr/bin/openssl",
    ):
        require(
            value in runtime_lock_source,
            "production runtime identity drifted from the pinned Node profile",
        )

    production_preflight = text("scripts/ci/production_launch_preflight.py")
    for marker in (
        'EVIDENCE_SCHEMA = "tinyzkp-production-preflight-evidence-v8"',
        '"backup_loader_token_sha256"',
        '"backup_transport_secret_sha256"',
        "_backup_private_input_identity",
        "_cloudflare_evidence_identity",
        "_production_runtime_evidence_identity",
        "_fixed_host_backup_evidence_identity",
        "_installer_drill_evidence_identity",
        "_legacy_billing_containment_evidence_identity",
        "_private_gate_input_snapshot",
        '"cloudflare_materialization_sha256"',
        '"Cloudflare Pages release transaction adversarial tests"',
        '"scripts/deploy/test_cloudflare_pages_release.py"',
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
    pages_release = text("scripts/deploy/cloudflare_pages_release.py")
    for marker in (
        "DEPLOY_FAILURE_RECORD_SCHEMA",
        "_attempt_exact_rollback",
        "deploy_failed_rollback_failed",
        "failed_rollback_failed",
        "deploy_failure_path",
    ):
        require(
            marker in pages_release,
            f"Cloudflare Pages transaction lost fail-closed rollback: {marker}",
        )
    pages_runbook = text("docs/runbooks/cloudflare_pages_release.md")
    for marker in (
        "Wrangler invocation is the transaction boundary",
        "automatic rollback FAILED",
        "failed_rollback_failed",
        "TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1",
    ):
        require(
            marker in pages_runbook,
            f"Cloudflare Pages rollback runbook drifted: {marker}",
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
        "unexpected recovery secrets"
        in text("scripts/ci/cloudflare_pages_secret_check.py"),
        "Cloudflare live inventory no longer rejects arbitrary secrets",
    )
    require(
        "scripts/ci/run_production_preflight.sh" in deploy and "--production" in deploy,
        "deploy handoff bypasses the clean production-preflight wrapper",
    )
    require(
        "--require-legacy" in deploy,
        "production deploy no longer requires fresh legacy billing containment evidence",
    )

    release_workflow = text(".github/workflows/release-backend.yml")
    for marker in (
        "backend_release_ready.py",
        "cargo build --locked",
        "tinyzkp-backend.spdx.json",
        "cosign sign-blob",
        "actions/attest@v4",
    ):
        require(
            marker in release_workflow,
            f"release workflow lost integrity control: {marker}",
        )

    require(
        (ROOT / "crates/hc-server/src/lib.rs").is_file(),
        "historical server source was deleted",
    )
    require(
        (ROOT / "crates/hc-server/src/bin/hc-worker.rs").is_file(),
        "legacy worker research source was deleted",
    )
    require(
        (ROOT / "crates/hc-server/src/bin/hc-job-worker.rs").is_file(),
        "legacy queue-worker research source was deleted",
    )

    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL recovery reconciliation: {failure}", file=sys.stderr)
        return 1
    print("PASS recovery reconciliation invariants (legacy SaaS checks quarantined)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
