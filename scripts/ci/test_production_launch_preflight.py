import argparse
import pathlib

import pytest

import production_launch_preflight as preflight


def args(**overrides):
    defaults = {
        "require_legacy": False,
        "env_file": ".env",
        "production": False,
        "pages_bindings_file": None,
        "check_host_python": False,
        "host_python": None,
        "live": False,
        "site_url": "https://tinyzkp.com",
        "api_url": "https://api.tinyzkp.com",
        "mcp_url": "https://mcp.tinyzkp.com",
        "webhook_url": "https://webhook.tinyzkp.com",
        "contact_readiness_secret_file": "/secure/internal-secret",
        "expected_release_sha": None,
        "authenticated_smoke": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def commands(steps):
    return [step.command for step in steps]


def test_local_preflight_builds_fast_static_gate_sequence():
    built = preflight.build_steps(args(), python="python", node="node")

    assert commands(built) == [
        ("python", "scripts/ci/recovery_reconciliation_invariants.py"),
        ("python", "scripts/ci/backend_recovery_gate.py"),
        ("python", "scripts/ci/server_card_check.py"),
        ("python", "scripts/ci/plonky3_compatibility_gate.py"),
        ("python", "scripts/ci/launch_gate_audit.py"),
        ("python", "scripts/ci/backup_restore_check.py"),
        ("python", "scripts/ci/site_route_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_site_route_check.py"),
        (
            "python",
            "-m",
            "pytest",
            "scripts/ci/test_release_identity_check.py",
            "scripts/ci/test_site_asset_manifest.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "billing/tests/test_legacy_billing_containment.py",
            "billing/tests/test_legacy_write_quarantine.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "billing/tests/test_contact_intake.py",
            "billing/tests/test_evaluation_store.py",
            "scripts/monitoring/test_contact_intake_readiness.py",
        ),
        ("python", "-m", "pytest", "billing/tests/test_site_pricing_parity.py"),
        ("python", "scripts/commercial/render_offers.py", "--check"),
        (
            "python",
            "-m",
            "pytest",
            "billing/tests/test_contract_billing.py",
            "billing/tests/test_configure_contract_portal.py",
            "billing/tests/test_evaluation_start_ready.py",
        ),
        ("python", "-m", "pytest", "scripts/commercial/test_validate_scorecard.py"),
        ("python", "scripts/ci/site_deploy_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_cloudflare_pages_secret_check.py"),
        ("node", "scripts/ci/site_worker_dispatch_test.mjs"),
        ("python", "scripts/ci/compose_config_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_billing_service_hardening.py"),
        ("python", "scripts/ci/deploy_readiness_check.py", "--env-file", ".env"),
    ]


def test_production_adds_stricter_deploy_gates():
    built = preflight.build_steps(
        args(
            production=True,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            check_host_python=True,
            host_python="/opt/hc-stark/.venv/bin/python",
        ),
        python="python",
        node="node",
    )

    assert ("python", "scripts/ci/launch_gate_audit.py") in commands(built)
    assert (
        "python",
        "scripts/ci/deploy_readiness_check.py",
        "--env-file",
        "/opt/hc-stark/.env",
        "--production",
        "--check-host-python",
        "--host-python",
        "/opt/hc-stark/.venv/bin/python",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/site_deploy_check.py",
        "--production",
        "--bindings-file",
        "/secure/pages.env",
    ) in commands(built)


def test_live_steps_are_opt_in_and_use_recovery_canary():
    built = preflight.build_steps(args(live=True), python="python", node="node")

    canary = next(step for step in built if step.name == "live backend recovery canary")
    assert canary.command == (
        "python",
        "scripts/monitoring/backend_recovery_canary.py",
        "--site-url",
        "https://tinyzkp.com",
        "--api-url",
        "https://api.tinyzkp.com",
        "--mcp-url",
        "https://mcp.tinyzkp.com",
    )
    assert ("python", "scripts/ci/cloudflare_pages_secret_check.py") in commands(built)
    assert (
        "python",
        "scripts/monitoring/contact_intake_readiness.py",
        "--site-url",
        "https://tinyzkp.com",
        "--webhook-url",
        "https://webhook.tinyzkp.com",
        "--internal-secret-file",
        "/secure/internal-secret",
    ) in commands(built)


def test_expected_release_sha_adds_live_release_identity_check():
    built = preflight.build_steps(
        args(
            live=True,
            expected_release_sha="abc123",
            site_url="https://site.example",
            api_url="https://api.example",
            mcp_url="https://mcp.example",
        ),
        python="python",
        node="node",
    )

    assert (
        "python",
        "scripts/ci/release_identity_check.py",
        "--expected-sha",
        "abc123",
        "--site-url",
        "https://site.example",
        "--api-url",
        "https://api.example",
        "--mcp-url",
        "https://mcp.example",
    ) in commands(built)


def test_authenticated_smoke_is_separate_from_public_live_canary():
    try:
        preflight.build_steps(args(authenticated_smoke=True), python="python", node="node")
    except ValueError as exc:
        assert "unavailable while backend v1 is blocked" in str(exc)
    else:
        raise AssertionError("authenticated proving smoke must fail closed during recovery")


def test_run_step_captures_success(tmp_path):
    script = tmp_path / "ok.py"
    script.write_text("print('hello')\n", encoding="utf-8")

    result = preflight.run_step(
        preflight.Step("ok", ("python3", str(script))),
        root=pathlib.Path("/"),
    )

    assert result.status == "PASS"
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_run_step_captures_failure(tmp_path):
    script = tmp_path / "fail.py"
    script.write_text("import sys\nprint('bad', file=sys.stderr)\nsys.exit(7)\n", encoding="utf-8")

    result = preflight.run_step(
        preflight.Step("fail", ("python3", str(script))),
        root=pathlib.Path("/"),
    )

    assert result.status == "FAIL"
    assert result.returncode == 7
    assert result.stderr.strip() == "bad"


def test_run_step_reports_missing_command():
    result = preflight.run_step(
        preflight.Step("missing", ("definitely-not-a-real-tinyzkp-command",)),
        root=pathlib.Path("/"),
    )

    assert result.status == "FAIL"
    assert result.returncode is None
    assert result.error


def test_live_cli_requires_expected_release_sha(monkeypatch):
    monkeypatch.delenv("TINYZKP_EXPECT_RELEASE_SHA", raising=False)
    with pytest.raises(SystemExit) as exc:
        preflight.main(["--live"])
    assert exc.value.code == 2
