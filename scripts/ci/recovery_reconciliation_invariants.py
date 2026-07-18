#!/usr/bin/env python3
"""Recovery-era replacement for legacy agent-SaaS reconciliation checks."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tomllib

import check_pinned_actions


ROOT = Path(__file__).resolve().parents[2]
FAILURES: list[str] = []


def reviewed_action_count(
    workflow: str, repository: str, revision: str, version_comment: str
) -> int:
    """Count exact SHA-pinned action uses with the reviewed major-version comment."""

    reference = re.compile(
        rf"(?m)^\s*(?:-\s*)?uses:\s*{re.escape(repository)}@"
        rf"{re.escape(revision)}\s+#\s*{re.escape(version_comment)}\s*$"
    )
    return len(reference.findall(workflow))


def require(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def fixed_host_workflow_failures(workflow: str) -> list[str]:
    failures: list[str] = []
    expected_counts = {
        "--require-fixed-host": 3,
        "trap reclaim_reports EXIT": 4,
        "--expected-release-sha": 2,
        "scripts/benchmark/run_fixed_host_release_matrix.py": 1,
        "if: github.event_name == 'workflow_dispatch' && inputs.release_matrix": 1,
    }
    for marker, expected in expected_counts.items():
        if workflow.count(marker) != expected:
            failures.append(
                f"fixed-host workflow must contain {expected} exact occurrence(s): {marker}"
            )
    for marker in (
        "release_matrix:",
        "HC_RELEASE_SHA: ${{ github.sha }}",
        "plonky3-backend-release-matrix-${{ github.sha }}",
        "raw-reports/fixed-host-release-matrix/",
    ):
        if marker not in workflow:
            failures.append(f"fixed-host release matrix lost control: {marker}")
    if workflow.count("!inputs.release_matrix") != 3:
        failures.append(
            "fragmented telemetry/exploratory jobs are not suppressed during the release matrix"
        )
    return failures


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
        "scripts/ci/test_fixed_host_evidence_workspace.py",
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
        "scripts/ci/fixed_host_evidence_workspace.py",
        "scripts/ci/test_fixed_host_evidence_workspace.py",
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
        '"scripts/ci/test_fixed_host_evidence_workspace.py"',
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
        "unexpected static-site secrets"
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
        "group: backend-release-${{ github.ref }}",
        "cancel-in-progress: false",
        "fetch-depth: 0",
        "finalize_signed_evidence.py",
        "build_engine_identity_report.py",
        "engine-identity.json",
        "cargo build --locked",
        "tinyzkp-engine.spdx.json",
        "cosign sign-blob",
    ):
        require(marker in release_workflow, f"release workflow lost integrity control: {marker}")
    for retired in (
        "build_commercial_authorization.py",
        "backend-v1-commercial-authorization",
        "backend-v1-release-ready-report",
    ):
        require(
            retired not in release_workflow,
            f"release workflow reactivated retired billing authorization: {retired}",
        )
    require(
        reviewed_action_count(
            release_workflow,
            "actions/attest",
            check_pinned_actions.ACTION_ALLOWLIST["actions/attest"],
            "v4",
        )
        == 2,
        "release workflow must retain both reviewed SHA-pinned actions/attest v4 steps",
    )

    require(
        "test_build_external_records.py" in workflow,
        "CI does not validate hash-bound external evidence record generation",
    )
    finalizer = text("scripts/release/finalize_signed_evidence.py")
    for marker in (
        "REQUIRED_CHECKSUM_ENTRIES",
        "--certificate-identity-regexp",
        "--certificate-oidc-issuer",
        "verify_spdx_sbom",
    ):
        require(marker in finalizer, f"signed finalization lost policy control: {marker}")

    evidence_builder = text("scripts/release/build_candidate_evidence.py")
    release_validator = text("scripts/ci/backend_release_ready.py")
    prerelease_validator = text("scripts/ci/backend_prerelease_ready.py")
    fuzz_runner = text("scripts/release/run_fuzz_smoke.py")
    fuzz_anchor = text("scripts/release/fuzz_tool_anchor.py")
    gate_tool_anchor = text("scripts/release/gate_tool_anchor.py")
    require(
        '"crash_resume_and_corruption_suite": [' in evidence_builder
        and '"crash_matrix"' in evidence_builder
        and '"fuzz_smoke"' in evidence_builder
        and '"crash_tool_identity"' in evidence_builder
        and '"fuzz_tool_identity"' in evidence_builder
        and 'f"crash_log_{name}"' in evidence_builder
        and 'f"fuzz_log_{name}"' in evidence_builder,
        "candidate evidence no longer requires crash/fuzz reports, tool provenance, and logs",
    )
    require(
        'RESOURCE_MATRIX_ROLE = "matrix_manifest"' in evidence_builder
        and "fixed-host-release-matrix-v1.json" in evidence_builder
        and "validate_resource_matrix_binding" in release_validator
        and "validate_resource_matrix_binding" in prerelease_validator,
        "first-party resource evidence no longer requires one authority-limited matrix manifest",
    )
    for marker in (
        "validate_fuzz_smoke",
        "FUZZ_TARGETS",
        "FUZZ_SMOKE_SEED_LIMIT",
        "parse_fuzz_summary",
        "validate_tool_identity_artifact",
        "read_bounded_file",
        "canonical_device_identity",
        "verify_evidence_only_transition",
        "expected_crash_command",
    ):
        require(marker in release_validator, f"release fuzz gate lost control: {marker}")
    for marker in (
        "SMOKE_SEED_LIMIT",
        'CARGO_FUZZ_VERSION = "cargo-fuzz 0.13.2"',
        'FUZZ_TOOLCHAIN = "nightly-2026-04-15"',
        "WORKLOAD_FIXTURES",
        "seed_payloads",
        "prepare_smoke_corpus",
        "smoke_corpus_sha256",
        "target_marker",
        "TOOL_IDENTITY_FILE",
        "execution-corpus",
        "-artifact_prefix=",
        "harden_tree",
    ):
        require(marker in fuzz_runner, f"bounded fuzz smoke lost control: {marker}")
    for marker in (
        '"status": "unreviewed"',
        '"review_required": True',
        "cargo_fuzz_anchor",
        "require_trusted_digest",
        "write_json_atomic",
    ):
        require(marker in fuzz_anchor, f"cargo-fuzz anchor workflow lost control: {marker}")
    for marker in (
        '"status": "unreviewed"',
        '"review_required": True',
        "expected_tool_names",
        "require_trusted_mapping",
        "write_json_atomic",
    ):
        require(
            marker in gate_tool_anchor,
            f"generic gate-tool anchor workflow lost control: {marker}",
        )
    nightly_workflow = text(".github/workflows/nightly-backend.yml")
    require(
        "cargo install cargo-fuzz --version 0.13.2 --locked" in nightly_workflow,
        "cargo-fuzz release tool is not version-pinned",
    )
    for marker in (
        'toolchain: "nightly-2026-04-15"',
        "cargo +nightly-2026-04-15 fetch",
        "--manifest-path fuzz/Cargo.toml",
        "run_crash_matrix_disk_full.sh",
        "fuzz_tool_anchor.py capture",
        "fuzz_tool_anchor.py verify",
    ):
        require(marker in nightly_workflow, f"nightly evidence workflow lost control: {marker}")
    try:
        capture_position = nightly_workflow.index("fuzz_tool_anchor.py capture")
        verify_position = nightly_workflow.index("fuzz_tool_anchor.py verify")
        expensive_position = nightly_workflow.index(
            "Randomized proof equality through 2^18"
        )
    except ValueError:
        pass
    else:
        require(
            capture_position < verify_position < expensive_position,
            "nightly does not fail closed on cargo-fuzz trust before expensive evidence",
        )

    preliminary_sbom = text("scripts/release/build_preliminary_sbom.py")
    review_bundle = text("scripts/release/build_review_bundle.py")
    for source, label in (
        (preliminary_sbom, "preliminary SBOM"),
        (review_bundle, "review bundle"),
    ):
        for marker in ("0o600", "os.fsync"):
            require(marker in source, f"{label} lost private atomic output: {marker}")

    benches_workflow = text(".github/workflows/benches.yml")
    for failure in fixed_host_workflow_failures(benches_workflow):
        require(False, failure)

    for workflow_path in (".github/workflows/publish-backend-crates.yml",):
        publish_workflow = text(workflow_path)
        for marker in (
            "fetch-depth: 0",
            "tinyzkp-engine.spdx.json",
            "--certificate-identity-regexp",
            "--certificate-oidc-issuer",
            "gh attestation verify release-artifacts/backend-v1-final-evidence.json",
            "gh attestation verify release-artifacts/backend-v1-final-gates.json",
            '--signer-workflow "github.com/$GITHUB_REPOSITORY/.github/workflows/release-backend.yml"',
            '--source-digest "$evidenced_sha"',
            '--source-ref "refs/tags/$BACKEND_TAG"',
            "--deny-self-hosted-runners",
            'test "$(git rev-parse HEAD)" = "$evidenced_sha"',
            'test "$(git rev-list -n 1 "$BACKEND_TAG")" = "$evidenced_sha"',
            "sha256sum --check SHA256SUMS",
        ):
            require(
                marker in publish_workflow,
                f"publish release identity gate lost control in {workflow_path}: {marker}",
            )
        require(
            "--ignore-missing" not in publish_workflow,
            f"publish checksum verification became partial in {workflow_path}",
        )
        require(
            "cancel-in-progress: false" in publish_workflow,
            f"publish workflow can race or cancel an in-flight release in {workflow_path}",
        )
    sdk_publish_workflow = text(".github/workflows/publish-sdks.yml")
    require(
        sdk_publish_workflow.count("needs.release-gate.outputs.backend_sha") == 2,
        "SDK WASM/MCP jobs are not pinned to the evidenced backend commit",
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
