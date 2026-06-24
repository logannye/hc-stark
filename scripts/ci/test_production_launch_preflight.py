import argparse
import pathlib

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
        ("bash", "./scripts/ci/reconciliation_invariants.sh"),
        ("python", "scripts/ci/launch_gate_audit.py"),
        ("python", "scripts/ci/backup_restore_check.py"),
        ("python", "scripts/ci/site_route_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_site_route_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_release_identity_check.py"),
        ("python", "scripts/ci/server_card_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_server_card_check.py"),
        ("python", "scripts/ci/site_deploy_check.py"),
        ("node", "scripts/ci/site_worker_dispatch_test.mjs"),
        ("python", "scripts/ci/compose_config_check.py"),
        ("python", "scripts/ci/deploy_readiness_check.py", "--env-file", ".env"),
    ]


def test_require_legacy_and_production_add_stricter_deploy_gates():
    built = preflight.build_steps(
        args(
            require_legacy=True,
            production=True,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            check_host_python=True,
            host_python="/opt/hc-stark/.venv/bin/python",
        ),
        python="python",
        node="node",
    )

    assert ("python", "scripts/ci/launch_gate_audit.py", "--require-legacy") in commands(built)
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


def test_live_steps_are_opt_in_and_public_smoke_sets_public_only_env():
    built = preflight.build_steps(args(live=True), python="python", node="node")

    public_smoke = next(step for step in built if step.name == "live public smoke")
    assert public_smoke.command == ("bash", "scripts/monitoring/shared_dispatch_smoke.sh")
    assert public_smoke.env == {"TINYZKP_SMOKE_PUBLIC_ONLY": "1"}
    assert ("bash", "./scripts/ci/reconciliation_invariants.sh", "--live") in commands(built)


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
    built = preflight.build_steps(args(authenticated_smoke=True), python="python", node="node")

    smoke = built[-1]
    assert smoke.name == "live authenticated prove/verify smoke"
    assert smoke.command == ("bash", "scripts/monitoring/shared_dispatch_smoke.sh")
    assert smoke.env == {}


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
