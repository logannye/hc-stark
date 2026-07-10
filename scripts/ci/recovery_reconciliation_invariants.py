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
    ):
        require(marker in workflow, f"CI lost retained gate: {marker}")

    release_workflow = text(".github/workflows/release-backend.yml")
    for marker in (
        "backend_release_ready.py",
        "group: backend-release-${{ github.ref }}",
        "cancel-in-progress: false",
        "fetch-depth: 0",
        "finalize_signed_evidence.py",
        "build_commercial_authorization.py",
        "backend-v1-commercial-authorization.json",
        "backend-v1-commercial-authorization.sigstore.json",
        "backend-v1-release-ready-report.json",
        "cargo build --locked",
        "tinyzkp-backend.spdx.json",
        "cosign sign-blob",
        "actions/attest@v4",
    ):
        require(marker in release_workflow, f"release workflow lost integrity control: {marker}")

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
    fuzz_runner = text("scripts/release/run_fuzz_smoke.py")
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
    ):
        require(marker in nightly_workflow, f"nightly evidence workflow lost control: {marker}")

    preliminary_sbom = text("scripts/release/build_preliminary_sbom.py")
    review_bundle = text("scripts/release/build_review_bundle.py")
    for source, label in (
        (preliminary_sbom, "preliminary SBOM"),
        (review_bundle, "review bundle"),
    ):
        for marker in ("0o600", "os.fsync"):
            require(marker in source, f"{label} lost private atomic output: {marker}")

    benches_workflow = text(".github/workflows/benches.yml")
    require(
        benches_workflow.count("--require-fixed-host") == 3,
        "fixed-host workflows do not fail closed on machine/storage class",
    )
    require(
        benches_workflow.count("trap reclaim_reports EXIT") == 3,
        "root-run fixed-host reports are not returned to the workflow owner",
    )
    require(
        benches_workflow.count("--expected-release-sha") == 2,
        "blocking fixed-host validators do not bind reports to the workflow SHA",
    )

    for workflow_path in (
        ".github/workflows/publish-backend-crates.yml",
        ".github/workflows/publish-sdks.yml",
    ):
        publish_workflow = text(workflow_path)
        for marker in (
            "fetch-depth: 0",
            "tinyzkp-backend.spdx.json",
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
