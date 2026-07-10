#!/usr/bin/env python3
"""Fail closed if a recovery build exposes retired proving or billing claims."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
FAILURES: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def check_public_contract() -> None:
    pricing = json.loads(text("site/pricing.json"))
    require(pricing["service_status"] == "backend_recovery", "site pricing must report backend_recovery")
    for field in ("hosted_proving_available", "hosted_verification_available", "account_creation_enabled", "checkout_enabled"):
        require(pricing[field] is False, f"site pricing must keep {field}=false")
    require(pricing["stripe_policy"]["api_version"] == "2026-02-25.clover", "Stripe API version must be pinned")

    indexed = ["index.html", "engine.html", "benchmarks.html", "plonky3.html", "security.html", "docs.html", "pricing.html", "status.html"]
    forbidden = ("proof.version", "Protocol v9", "StatementV1", "ReceiptV2", "$20K", "$36K", "$75K", "$5,000/month", "at least 70%")
    for page in indexed:
        body = text(f"site/{page}")
        require("/status" in body and "/contact" in body, f"{page} must expose Status and Contact navigation")
        for claim in forbidden:
            require(claim not in body, f"{page} contains retired claim {claim!r}")

    worker = text("site/_worker.js")
    for route in ("/compute", "/receipts", "/try", "/signup", "/pilot", "/platform-rollout"):
        require(route in worker, f"worker is missing retired-route handling for {route}")
    for route in ("/api/create-checkout", "/api/create-free-account", "/api/create-pilot-checkout", "/api/demo-prove"):
        require(route in worker, f"worker is missing maintenance denial for {route}")

    openapi = json.loads(text("site/openapi.json"))
    require(set(openapi["paths"]) == {"/healthz", "/version", "/v1/capabilities"}, "maintenance OpenAPI exposes unsupported paths")


def check_server_and_mcp() -> None:
    server = text("crates/hc-server/src/maintenance.rs")
    server_cargo = text("crates/hc-server/Cargo.toml")
    require("maintenance_mode: true" in server, "server maintenance must be compile-time default on")
    require('route("/v1/capabilities", get(capabilities))' in server, "capabilities route is missing")
    for route in ('route("/v1/inputs"', 'route("/v1/quotes"', 'route("/v1/proofs"', 'route("/v1/verify"'):
        require(route not in server, f"production router exposes retired route marker {route}")
    require('service_status: "backend_recovery"' in server, "server capabilities do not report backend recovery")
    require('plonky3_version: "0.6.1"' in server, "server capabilities do not pin Plonky3")
    require("legacy_statement_unbound" in server, "legacy hosted verification must fail closed")
    require('path = "src/maintenance.rs"' in server_cargo, "production server library is not maintenance-only")
    require("autobins = false" in server_cargo, "legacy worker binaries can still be auto-discovered")
    require("hc-worker" not in text("Dockerfile"), "production image still contains a legacy proving worker")
    require("hc-job-worker" not in text("Dockerfile"), "production image still contains a legacy queue worker")
    workspace = tomllib.loads(text("Cargo.toml"))
    package_version = workspace["workspace"]["package"]["version"]
    require(
        f'package_version: "{package_version}"' in text("site/_worker.js"),
        "site package version differs from the Rust workspace",
    )

    mcp = text("crates/hc-mcp/src/lib.rs")
    discovery = text("crates/hc-mcp/src/tools/discovery.rs")
    require('PRODUCTION_TOOL_NAMES: &[&str] = &["get_capabilities"]' in mcp, "MCP production discovery is not capability-only")
    require('"service_status": "backend_recovery"' in discovery, "MCP capabilities do not report backend recovery")
    require('"proving": false' in discovery and '"verification": false' in discovery, "MCP execution features must be false")


def check_billing_and_release() -> None:
    worker = text("site/_worker.js")
    for retired_function in (
        "create-checkout.js",
        "create-pilot-checkout.js",
        "create-free-account.js",
        "demo-prove.js",
    ):
        require(
            not (ROOT / "site/functions/api" / retired_function).exists(),
            f"retired Pages function still deploys: {retired_function}",
        )
    require("MAINTENANCE_DISABLED_API_ROUTES" in worker, "worker lacks maintenance route denials")
    require('const ROUTES = { "/api/contact": contact };' in worker, "worker deploys more than evaluation intake")
    require("TINYZKP_ALLOW_LEGACY_BILLING_WRITE" in text("billing/setup_stripe_products.sh"), "legacy Stripe catalog writes are not fail-closed")
    require("TINYZKP_ALLOW_LEGACY_METER_EVENTS" in text("billing/sync_usage.py"), "legacy meter events are not fail-closed")
    require('os.environ.get("CONTACT_TO_EMAIL", "hello@tinyzkp.com")' in text("billing/provision_tenant.py"), "contact recipient is not environment-configured")
    require('os.environ.get("TINYZKP_MAINTENANCE_MODE", "1")' in text("billing/provision_tenant.py"), "billing webhook maintenance mode is not fail-closed")
    caddy = text("deploy/hetzner/Caddyfile")
    for route in ("@stripe_webhook path /webhook", "@contact_intake path /send-contact", "@webhook_health path /health"):
        require(route in caddy, f"webhook proxy is missing allowlisted route: {route}")
    for retired_route in ("/provision-free", "/rotate", "/send-magic-link", "/verify-magic-link"):
        require(retired_route not in caddy, f"webhook proxy exposes retired account route: {retired_route}")
    require("respond 404" in caddy, "webhook proxy does not fail closed for unknown routes")

    release = json.loads(text("release/backend-v1-gates.json"))
    require(release["status"] == "blocked", "backend v1 must remain blocked during recovery")
    for gate_name in (
        "one_million_row_resource_gate",
        "ten_million_row_resource_gate",
        "deterministic_cross_mode_proofs",
        "crash_resume_and_corruption_suite",
        "plonky3_specialist_review",
        "implementation_review_no_high_findings",
        "external_design_partner_integration",
        "replacement_sdk_contracts",
        "signed_release_sbom_and_checksums",
        "api_mcp_site_cli_identity_match",
    ):
        require(not release["gates"][gate_name]["passed"], f"unearned release gate is marked passed: {gate_name}")


def main() -> int:
    check_public_contract()
    check_server_and_mcp()
    check_billing_and_release()
    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print("TinyZKP backend recovery gate: PASS (maintenance mode, no production claim)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
