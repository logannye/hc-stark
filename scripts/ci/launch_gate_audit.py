#!/usr/bin/env python3
"""Audit local evidence for TinyZKP reconciliation and launch gates.

This does not certify that production is deployed. It proves that the branch
contains the artifacts needed for a coordinated release, and it reports the
remaining deploy/observation actions separately so the company cannot silently
turn local readiness into an overbroad production claim.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from dataclasses import dataclass, field


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_LEGACY_ROOT = ROOT.parent / "space-efficient-zero-knowledge-proofs"


@dataclass(frozen=True)
class Evidence:
    path: str
    markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Gate:
    phase: str
    name: str
    required: tuple[Evidence, ...]
    deploy_action: str | None = None
    optional_legacy: bool = False


@dataclass
class GateResult:
    phase: str
    name: str
    status: str
    details: list[str] = field(default_factory=list)
    deploy_action: str | None = None


PHASE_MARKERS = tuple(f"## Phase {i}:" for i in range(0, 11))

GATES: tuple[Gate, ...] = (
    Gate(
        "Phase 0",
        "Canonical company taxonomy",
        (
            Evidence("docs/strategy/reconciliation_roadmap.md", ("## Launch gate matrix", *PHASE_MARKERS)),
            Evidence("site/research.html", ("One company, one thesis: space-efficient proving.", "space-efficient-zero-knowledge-proofs", "not the hosted production engine")),
            Evidence("README.md", ("Research lineage:", "space-efficient-zero-knowledge-proofs")),
            Evidence("BUSINESS_GUIDE.md", ("Legacy research repo:", "tinyzkp.com/research")),
        ),
        "Merge product and legacy positioning branches, then deploy the website.",
    ),
    Gate(
        "Phase 1",
        "Legacy repo hygiene",
        (
            Evidence("README.md", ("Legacy research repo.", "not be treated as the hosted TinyZKP engine", "current opening code still contains full-vector")),
            Evidence(".gitignore", ("proof.bin", "target/")),
            Evidence("LICENSE", ("MIT License",)),
            Evidence("scripts/test_sszkp.sh", ("research prototype", "dev-srs")),
        ),
        "Merge the legacy repo update and verify proof.bin is no longer tracked.",
        optional_legacy=True,
    ),
    Gate(
        "Phase 2",
        "Product repo positioning",
        (
            Evidence("README.md", ("Get an API key", "accumulator_step", "transparent STARK", "HC_SERVER_PROVE_DISPATCH")),
            Evidence("site/docs.html", ("Research Lineage", "When Not to Use TinyZKP", "Security &amp; Audit Status")),
            Evidence("clients/python/README.md", ("accumulator_step", "lifecycle")),
            Evidence("clients/typescript/README.md", ("accumulator_step", "lifecycle")),
            Evidence("clients/rust/src/lib.rs", ("accumulator_step", "pub lifecycle: String")),
        ),
        "Publish package/docs updates only with the API/MCP lifecycle release.",
    ),
    Gate(
        "Phase 3",
        "Website usability and public funnel",
        (
            Evidence("site/index.html", ('href="/research">Research</a>', 'href="/security">Security</a>', 'src="/analytics.js"')),
            Evidence("site/docs.html", ("<h1>Documentation</h1>", "docs-intro")),
            Evidence("site/try.html", ("playground_prove_succeeded",)),
            Evidence("site/verify.html", ("client_verify_succeeded",)),
            Evidence("site/signup.html", ("checkout_started",)),
            Evidence("site/contact.html", ("Project fit", "Do not paste API keys")),
            Evidence("site/account.html", (".login-view::before{width:320px;height:320px;top:-120px}",)),
            Evidence("site/_worker.js", ("SECURITY_HEADERS", "X-Frame-Options", "Referrer-Policy")),
            Evidence("scripts/ci/site_route_check.py", (
                "worker_api_routes",
                "parse_literal_script_routes",
                "exactly one primary <h1>",
                "expected_canonical_url",
            )),
            Evidence("scripts/ci/site_worker_dispatch_test.mjs", ("extensionless", "/api/events", "registeredPostRoutes", "assertSecurityHeaders")),
        ),
        "Deploy Cloudflare Pages from the same main revision as the API/MCP release and run live canaries.",
    ),
    Gate(
        "Phase 4",
        "Production service hardening",
        (
            Evidence("billing/usage_pg_tools.py", ("compare", "backfill", "ON CONFLICT")),
            Evidence("billing/tenant_pg_tools.py", ("compare", "backfill", "tenant_store.sqlite")),
            Evidence("billing/tenant_store.py", ("HC_TENANT_PG_REQUIRED", "HC_TENANT_PG_URL")),
            Evidence("crates/hc-server/src/shared_rate_limit.rs", ("Postgres", "prove")),
            Evidence("crates/hc-server/src/job_index.rs", ("claim_next", "postgres_job_schema_stores_completed_proof_status")),
            Evidence("crates/hc-server/src/bin/hc-job-worker.rs", ("--check-config", "--once", "renew")),
            Evidence("scripts/monitoring/shared_dispatch_smoke.sh", ("poll/download", "inspect, verify", "TINYZKP_SMOKE_PUBLIC_ONLY")),
            Evidence("scripts/ci/deploy_readiness_check.py", ("HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres",)),
            Evidence("scripts/ci/compose_config_check.py", ("production-shared-workers",)),
        ),
        "Provision Postgres, run parity, flip shared state sources, deploy shared workers, and observe authenticated smoke.",
    ),
    Gate(
        "Phase 5",
        "Security, audit, and trust",
        (
            Evidence("site/security.html", ("Responsible disclosure", "Template discovery uses three lifecycle values", "Do not treat default TinyZKP receipts as input privacy")),
            Evidence("docs/security/threat_model.md", ("Threat Model",)),
            Evidence("docs/security/auditor_guide.md", ("Auditor",)),
            Evidence("docs/security/soundness_proof.md", ("accumulator_step",)),
            Evidence("docs/governance/release_policy.md", ("Release surfaces", "Compatibility")),
            Evidence("docs/runbooks/release_provenance.md", ("gh attestation verify", "npm publish --provenance")),
            Evidence(".github/workflows/publish-sdks.yml", ("actions/attest@v4", "npm publish --provenance --access public", "twine check dist/*")),
        ),
        "Commission external cryptography/implementation review before expanding security claims.",
    ),
    Gate(
        "Phase 6",
        "Developer experience",
        (
            Evidence("site/docs.html", ("data-copy-code", "Local Development &amp; Self-Hosting", "SDK &amp; Verifier Compatibility")),
            Evidence("clients/python/tests/test_client.py", ("accumulator_step", "lifecycle")),
            Evidence("clients/typescript/tests/client.test.mjs", ("accumulator_step", "lifecycle")),
            Evidence("crates/hc-workloads/tests/template_examples.rs", ("accumulator_step_doc_example_builds",)),
            Evidence(".github/workflows/ci.yml", ("clients/python[test]", "npm run build", "cargo test --manifest-path clients/rust/Cargo.toml")),
        ),
        "Keep docs examples tied to tested SDK/template examples before future template expansion.",
    ),
    Gate(
        "Phase 7",
        "Commercial packaging",
        (
            Evidence("pricing.json", ("trace_step_usage", "proof_usage")),
            Evidence("billing/STRIPE_PRODUCT_IDS.md", ("Compute", "Developer", "Pro", "Scale")),
            Evidence("billing/sync_usage.py", ("STRIPE_METER_EVENT_NAME", "PostgresUsageSource", "DISCOUNT_FACTORS")),
            Evidence("billing/tests/test_site_pricing_parity.py", ("pricing",)),
            Evidence("scripts/ci/site_worker_dispatch_test.mjs", ("line_items[1][price]", "Stripe should not be called when a paid plan price binding is missing")),
            Evidence("site/compute.html", ("What is live now on Compute", "Design-partner", "$0.50")),
            Evidence("site/contact.html", ("trace_length", "proof_frequency", "current_alternative")),
        ),
        "Run Stripe production smoke and billing sync dry run before launch announcement.",
    ),
    Gate(
        "Phase 8",
        "Governance and release process",
        (
            Evidence(".github/CODEOWNERS", ("/crates/hc-server/", "/site/", "/billing/")),
            Evidence("CHANGELOG.md", ("Reconciliation and positioning", "Operations")),
            Evidence("docs/governance/release_policy.md", ("Release trains", "Release surfaces")),
            Evidence("docs/runbooks/2026-06-23-reconciliation-deploy.md", ("Merge order", "Post-deploy canaries")),
            Evidence("docs/runbooks/incident_response.md", ("SEV1", "rollback")),
        ),
        "Use release ownership and canaries for every production rollout.",
    ),
    Gate(
        "Phase 9",
        "Metrics and learning loop",
        (
            Evidence("site/functions/api/events.js", ("ALLOWED_EVENTS", "ALLOWED_PROPS")),
            Evidence("site/analytics.js", ("navigator.sendBeacon", "page_view")),
            Evidence("site/privacy.html", ("Product analytics", "do not include proof bytes, API keys, email addresses, or form contents")),
            Evidence("billing/tests/test_provision_free.py", ("account already exists", "unique-test@example.com")),
            Evidence("site/research.html", ("research_outbound_click",)),
            Evidence("site/docs.html", ("docs_copy",)),
            Evidence("site/try.html", ("playground_prove_succeeded",)),
        ),
        "Review activation/contact data before choosing the next product wedge.",
    ),
    Gate(
        "Phase 10",
        "Full production-grade company posture",
        (
            Evidence("site/status.html", ("Incident categories and response targets", "Billing and account", "Security disclosure")),
            Evidence("site/contact.html", ("Support expectations", "Direct fallback email", "Compute and enterprise inquiries")),
            Evidence("site/docs.html", ("API Versioning &amp; Deprecation", "GET https://api.tinyzkp.com/version", "Deprecated routes or fields")),
            Evidence("site/terms.html", ("API key", "billing", "support expectations")),
            Evidence("site/privacy.html", ("Product analytics", "Client-side verification")),
            Evidence("docs/runbooks/restore.md", ("HC_BACKUP_REMOTE", "api_health_audit.sh", "/usage")),
            Evidence("billing/backup.sh", ("HC_BACKUP_REMOTE", "rclone", "umask 077")),
            Evidence("billing/tests/test_backup_script.py", ("recoverable_snapshots", "dated_rclone_target")),
            Evidence("billing/tests/test_session_endpoints.py", ("session_token", "api_key", "stripe_customer_id")),
            Evidence("scripts/ci/site_worker_dispatch_test.mjs", (
                "/provision-free",
                "free@example.com",
                "cus_server_123",
                "session/reveal-key",
                "tzk_client_should_not_win",
                "tzk_currentabcdef",
            )),
            Evidence("site/functions/api/verify-magic-link.js", ("explicit allowlist", "api_key")),
            Evidence("scripts/ci/production_launch_preflight.py", ("live reconciliation canary", "authenticated prove/verify smoke")),
            Evidence("docs/operations.md", ("deploy_readiness_check.py", "compose_config_check.py", "shared_dispatch_smoke.sh")),
            Evidence("scripts/monitoring/api_health_audit.sh", ("Production Health Audit", "MCP", "billing webhook")),
        ),
        "Run restore drill, production canaries, and authenticated smoke after deploy; observe Postgres/shared-worker cutovers.",
    ),
)


def read_text(root: pathlib.Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8", errors="replace")


def check_evidence(root: pathlib.Path, evidence: Evidence) -> list[str]:
    failures: list[str] = []
    path = root / evidence.path
    if not path.is_file():
        return [f"missing {evidence.path}"]
    text = read_text(root, evidence.path)
    for marker in evidence.markers:
        if marker not in text:
            failures.append(f"{evidence.path} missing marker: {marker}")
    return failures


def legacy_proof_bin_tracked(legacy_root: pathlib.Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "ls-files", "proof.bin"],
            cwd=legacy_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return bool(result.stdout.strip()) and (legacy_root / "proof.bin").exists()


def audit_gates(root: pathlib.Path, legacy_root: pathlib.Path | None, require_legacy: bool) -> list[GateResult]:
    results: list[GateResult] = []
    for gate in GATES:
        gate_root = root
        status = "PASS"
        details: list[str] = []

        if gate.optional_legacy:
            if legacy_root is None or not legacy_root.is_dir():
                status = "FAIL" if require_legacy else "SKIP"
                details.append("legacy checkout not available; pass --legacy-root or --require-legacy for full local audit")
                results.append(GateResult(gate.phase, gate.name, status, details, gate.deploy_action))
                continue
            gate_root = legacy_root

        for evidence in gate.required:
            details.extend(check_evidence(gate_root, evidence))

        if gate.optional_legacy and legacy_root is not None and legacy_root.is_dir():
            if legacy_proof_bin_tracked(legacy_root):
                details.append("proof.bin is still tracked in the legacy repo")

        if details:
            status = "FAIL"
        results.append(GateResult(gate.phase, gate.name, status, details, gate.deploy_action))
    return results


def print_text(results: list[GateResult]) -> None:
    for result in results:
        print(f"{result.status:<4} {result.phase}: {result.name}")
        for detail in result.details:
            print(f"     - {detail}")
        if result.deploy_action and result.status == "PASS":
            print(f"     deploy/observe: {result.deploy_action}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT, help="Product repo root")
    parser.add_argument(
        "--legacy-root",
        type=pathlib.Path,
        default=DEFAULT_LEGACY_ROOT if DEFAULT_LEGACY_ROOT.exists() else None,
        help="Optional space-efficient-zero-knowledge-proofs checkout",
    )
    parser.add_argument(
        "--require-legacy",
        action="store_true",
        help="Fail if the legacy checkout is unavailable or incomplete",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)

    results = audit_gates(args.root.resolve(), args.legacy_root.resolve() if args.legacy_root else None, args.require_legacy)
    failures = [result for result in results if result.status == "FAIL"]

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "phase": result.phase,
                        "name": result.name,
                        "status": result.status,
                        "details": result.details,
                        "deploy_action": result.deploy_action,
                    }
                    for result in results
                ],
                indent=2,
            )
        )
    else:
        print_text(results)
        passed = sum(1 for result in results if result.status == "PASS")
        skipped = sum(1 for result in results if result.status == "SKIP")
        print(f"\nLaunch gate audit: {passed} passed, {skipped} skipped, {len(failures)} failed")
        if not failures:
            print("Local launch-gate evidence is present. Production deploy/observation gates remain separate.")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
