import argparse
from datetime import datetime, timedelta, timezone
import json
import pathlib
import shutil
import stat
import subprocess
import sys

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
        "node_executable": "/reviewed/node",
        "wrangler_entrypoint": "/reviewed/cloudflare/node_modules/wrangler/bin/wrangler.js",
        "git_executable": None,
        "deployment_id": preflight.DEFAULT_DEPLOYMENT_ID,
        "live": False,
        "site_url": "https://tinyzkp.com",
        "api_url": "https://api.tinyzkp.com",
        "mcp_url": "https://mcp.tinyzkp.com",
        "webhook_url": "https://webhook.tinyzkp.com",
        "contact_readiness_secret_file": "/secure/internal-secret",
        "expected_release_sha": None,
        "authenticated_smoke": False,
        "evidence_output": None,
        "verify_evidence": None,
        "consume_evidence": False,
        "json": False,
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
        ("python", "billing/runtime_lock.py", "verify-metadata"),
        ("python", "scripts/ci/backup_restore_check.py"),
        ("python", "-m", "pytest", "billing/tests/test_backup_script.py"),
        (
            "python",
            "-m",
            "pytest",
            "scripts/ci/test_fixed_host_backup_evidence.py",
            "scripts/ci/test_fixed_host_evidence_workspace.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "scripts/ci/test_installer_drill_evidence.py",
            "scripts/ci/test_legacy_billing_containment_status.py",
        ),
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
            "billing/tests/test_stripe_production_identity_check.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "scripts/commercial/test_validate_scorecard.py",
            "scripts/commercial/test_evaluation_qualification.py",
            "scripts/commercial/test_partner_preflight.py",
        ),
        ("python", "scripts/ci/site_deploy_check.py"),
        (
            "python",
            "-m",
            "pytest",
            "scripts/ci/test_site_deploy_check.py",
            "scripts/ci/test_production_secret_parity_check.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "scripts/ci/test_cloudflare_pages_secret_check.py",
            "scripts/ci/test_cloudflare_toolchain_check.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "scripts/deploy/test_cloudflare_pages_release.py",
        ),
        ("python", "scripts/ci/cloudflare_toolchain_check.py"),
        ("node", "scripts/ci/site_worker_dispatch_test.mjs"),
        ("node", "scripts/release/test_public_beta_site_worker.mjs"),
        ("python", "scripts/ci/compose_config_check.py"),
        ("python", "-m", "pytest", "scripts/ci/test_billing_service_hardening.py"),
        ("python", "-m", "pytest", "deploy/hetzner/test_deployment_transaction.py"),
        ("python", "scripts/ci/deploy_readiness_check.py", "--env-file", ".env"),
    ]


def test_production_adds_stricter_deploy_gates():
    built = preflight.build_steps(
        args(
            production=True,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            check_host_python=True,
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
        ),
        python="python",
        node="node",
    )

    assert ("python", "scripts/ci/launch_gate_audit.py") in commands(built)
    assert (
        "/usr/bin/python3",
        "billing/runtime_lock.py",
        "verify-production-runtime",
        "--venv-root",
        "/var/lib/tinyzkp-runtime/billing-venv",
        "--node-binary",
        "/reviewed/node",
    ) in commands(built)
    assert (
        "/usr/bin/python3",
        "billing/runtime_lock.py",
        "verify-wheelhouse",
        "--wheelhouse",
        "/var/lib/tinyzkp-runtime/wheelhouse",
        "--production-permissions",
    ) in commands(built)
    assert (
        "/var/lib/tinyzkp-runtime/billing-venv/bin/python",
        "billing/runtime_lock.py",
        "verify-installed",
    ) in commands(built)
    assert (
        "/usr/bin/python3",
        "scripts/ci/fixed_host_backup_evidence.py",
        "--expected-release-sha",
        "0" * 40,
        "--expected-deployment-id",
        preflight.DEFAULT_DEPLOYMENT_ID,
        "--machine-id-file",
        "/etc/machine-id",
    ) in commands(built)
    assert (
        "/usr/bin/python3",
        "scripts/ci/installer_drill_evidence.py",
        "verify",
        "--expected-release-sha",
        "0" * 40,
        "--expected-deployment-id",
        preflight.DEFAULT_DEPLOYMENT_ID,
        "--machine-id-file",
        "/etc/machine-id",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/deploy_readiness_check.py",
        "--env-file",
        "/opt/hc-stark/.env",
        "--production",
        "--check-host-python",
        "--host-python",
        "/var/lib/tinyzkp-runtime/billing-venv/bin/python",
    ) in commands(built)
    assert (
        "/var/lib/tinyzkp-runtime/billing-venv/bin/python",
        "billing/stripe_production_identity_check.py",
        "--env-file",
        "/opt/hc-stark/.env",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/site_deploy_check.py",
        "--production",
        "--bindings-file",
        "/secure/pages.env",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/production_secret_parity_check.py",
        "--host-env-file",
        "/opt/hc-stark/.env",
        "--pages-bindings-file",
        "/secure/pages.env",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/cloudflare_toolchain_check.py",
        "--runtime",
        "--node-executable",
        "/reviewed/node",
        "--wrangler-entrypoint",
        "/reviewed/cloudflare/node_modules/wrangler/bin/wrangler.js",
    ) in commands(built)


def test_production_build_always_enables_host_checks():
    built = preflight.build_steps(
        args(
            production=True,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            check_host_python=False,
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
        ),
        python="python",
        node="node",
    )

    assert (
        "python",
        "scripts/ci/deploy_readiness_check.py",
        "--env-file",
        "/opt/hc-stark/.env",
        "--production",
        "--check-host-python",
        "--host-python",
        "/var/lib/tinyzkp-runtime/billing-venv/bin/python",
    ) in commands(built)


def test_require_legacy_adds_fresh_live_containment_artifact_gate():
    built = preflight.build_steps(
        args(
            production=True,
            require_legacy=True,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
            expected_release_sha="a" * 40,
        ),
        python="python",
        node="node",
    )

    assert (
        "/usr/bin/python3",
        "scripts/ci/legacy_billing_containment_status.py",
        "verify",
        "--env-file",
        "/opt/hc-stark/.env",
        "--expected-release-sha",
        "a" * 40,
        "--expected-deployment-id",
        preflight.DEFAULT_DEPLOYMENT_ID,
    ) in commands(built)

    without = preflight.build_steps(
        args(
            production=True,
            require_legacy=False,
            pages_bindings_file="/secure/pages.env",
            env_file="/opt/hc-stark/.env",
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
            expected_release_sha="a" * 40,
        ),
        python="python",
        node="node",
    )
    assert not any(
        "legacy_billing_containment_status.py" in command
        for command in commands(without)
    )


def test_production_build_rejects_omitted_host_python():
    with pytest.raises(ValueError, match="production host Python"):
        preflight.build_steps(
            args(
                production=True,
                pages_bindings_file="/secure/pages.env",
                host_python=None,
            ),
            python="python",
            node="node",
        )


def test_live_steps_are_opt_in_and_use_recovery_canary():
    built = preflight.build_steps(
        args(
            live=True,
            production=True,
            pages_bindings_file="/secure/pages.env",
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
        ),
        python="python",
        node="node",
    )

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
    assert (
        "python",
        "scripts/ci/cloudflare_pages_secret_check.py",
        "--node-executable",
        "/reviewed/node",
        "--wrangler-entrypoint",
        "/reviewed/cloudflare/node_modules/wrangler/bin/wrangler.js",
    ) in commands(built)
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
            production=True,
            pages_bindings_file="/secure/pages.env",
            host_python="/var/lib/tinyzkp-runtime/billing-venv/bin/python",
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


def test_live_build_rejects_partial_nonproduction_preflight():
    with pytest.raises(ValueError, match="complete production preflight"):
        preflight.build_steps(args(live=True), python="python", node="node")


def test_authenticated_smoke_is_separate_from_public_live_canary():
    try:
        preflight.build_steps(
            args(authenticated_smoke=True), python="python", node="node"
        )
    except ValueError as exc:
        assert "unavailable while backend v1 is blocked" in str(exc)
    else:
        raise AssertionError(
            "authenticated proving smoke must fail closed during recovery"
        )


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
    script.write_text(
        "import sys\nprint('bad', file=sys.stderr)\nsys.exit(7)\n", encoding="utf-8"
    )

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


def test_production_step_environment_drops_language_and_loader_injection(
    tmp_path, monkeypatch
):
    script = tmp_path / "environment.py"
    script.write_text(
        "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", "/attacker")
    monkeypatch.setenv("PYTHONHOME", "/attacker")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/attacker")
    monkeypatch.setenv("LD_PRELOAD", "/attacker.so")

    result = preflight.run_step(
        preflight.Step("env", (sys.executable, str(script))),
        root=tmp_path,
        production=True,
    )
    environment = json.loads(result.stdout)
    assert result.status == "PASS"
    assert environment["PATH"] == preflight.TRUSTED_SYSTEM_PATH
    for forbidden in ("PYTHONPATH", "PYTHONHOME", "NODE_OPTIONS", "LD_PRELOAD"):
        assert forbidden not in environment
    with pytest.raises(preflight.EvidenceError, match="forbidden environment"):
        preflight.production_subprocess_environment({"NODE_OPTIONS": "--inspect"})


def test_live_cli_requires_expected_release_sha(monkeypatch):
    monkeypatch.delenv("TINYZKP_EXPECT_RELEASE_SHA", raising=False)
    with pytest.raises(SystemExit) as exc:
        preflight.main(["--live"])
    assert exc.value.code == 2


def test_require_legacy_cli_requires_complete_production_mode():
    with pytest.raises(SystemExit) as exc:
        preflight.main(["--require-legacy"])
    assert exc.value.code == 2


def test_production_cli_requires_explicit_existing_host_python(tmp_path):
    bindings = tmp_path / "pages.env"
    bindings.write_text("placeholder\n", encoding="utf-8")

    with pytest.raises(SystemExit) as omitted:
        preflight.main(["--production", "--pages-bindings-file", str(bindings)])
    assert omitted.value.code == 2

    with pytest.raises(SystemExit) as missing:
        preflight.main(
            [
                "--production",
                "--pages-bindings-file",
                str(bindings),
                "--host-python",
                str(tmp_path / "missing-python"),
            ]
        )
    assert missing.value.code == 2


def _production_evidence_fixture(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    env_file = tmp_path / "host.env"
    pages_file = tmp_path / "pages.env"
    internal_secret = "TinyZKP-Internal-Secret-0123456789"
    env_file.write_text(f"INTERNAL_SECRET={internal_secret}\n", encoding="utf-8")
    pages_file.write_text(f"INTERNAL_SECRET={internal_secret}\n", encoding="utf-8")
    env_file.chmod(0o600)
    pages_file.chmod(0o600)
    release_sha = "a" * 40
    configured = args(
        production=True,
        env_file=str(env_file),
        pages_bindings_file=str(pages_file),
        host_python=sys.executable,
        node_executable=sys.executable,
        wrangler_entrypoint=str(pathlib.Path(sys.executable).resolve()),
        git_executable=sys.executable,
        expected_release_sha=release_sha,
        contact_readiness_secret_file=None,
    )
    monkeypatch.setattr(
        preflight,
        "source_identity",
        lambda _root, _git, _remote=preflight.EXPECTED_REMOTE_URL: (
            release_sha,
            "main",
            True,
            True,
            preflight.EXPECTED_REMOTE_URL,
            release_sha,
        ),
    )
    monkeypatch.setattr(
        preflight, "validate_immutable_source_materialization", lambda *_args: None
    )
    monkeypatch.setattr(
        preflight,
        "_regular_file_digest",
        lambda path, **_kwargs: (str(pathlib.Path(path).resolve()), "b" * 64),
    )
    monkeypatch.setattr(
        preflight,
        "venv_identity",
        lambda _path: {
            "venv_root": "/reviewed/venv",
            "venv_identity_sha256": "c" * 64,
            "venv_file_count": 10,
            "venv_package_count": 4,
        },
    )
    monkeypatch.setattr(preflight, "stable_host_identity", lambda *_args: "d" * 64)
    monkeypatch.setattr(
        preflight,
        "_backup_private_input_identity_from_config",
        lambda _configured: {
            "backup_loader_token_sha256": "6" * 64,
            "backup_transport_kind": "rclone",
            "backup_transport_secret_path": "/secure/rclone.conf",
            "backup_transport_secret_sha256": "7" * 64,
        },
    )
    monkeypatch.setattr(
        preflight,
        "_production_runtime_evidence_identity",
        lambda _args: {
            "production_runtime_identity_sha256": "0" * 64,
            "production_runtime_file_count": 250,
            "production_runtime_byte_count": 12_500_000,
        },
    )
    monkeypatch.setattr(
        preflight,
        "_fixed_host_backup_evidence_identity",
        lambda _args, **_kwargs: {
            "fixed_host_backup_evidence_identity_sha256": "1" * 64,
            "fixed_host_backup_subject_sha256": "2" * 64,
            "fixed_host_backup_run_id": "3" * 32,
        },
    )
    monkeypatch.setattr(
        preflight,
        "_installer_drill_evidence_identity",
        lambda _args, **_kwargs: {
            "installer_drill_evidence_identity_sha256": "4" * 64,
            "installer_drill_subject_sha256": "5" * 64,
            "installer_drill_run_id": "6" * 32,
            "installer_drill_review_status": "unreviewed",
        },
    )
    monkeypatch.setattr(
        preflight,
        "_legacy_billing_containment_evidence_identity",
        lambda _args: {
            "legacy_billing_containment_required": False,
            "legacy_billing_status_identity_sha256": "",
            "legacy_billing_status_subject_sha256": "",
            "legacy_billing_current_inventory_sha256": "",
            "legacy_billing_status_observed_at": "",
        },
    )
    monkeypatch.setattr(
        preflight,
        "cloudflare_toolchain_identity",
        lambda _node, _wrangler: {
            "profile_id": "tinyzkp-cloudflare-production-v1",
            "profile_sha256": "1" * 64,
            "package_lock_sha256": "2" * 64,
            "materialization_sha256": "a" * 64,
            "node_version": "v24.18.0",
            "wrangler_version": "4.85.0",
            "node_realpath": "/reviewed/node",
            "node_sha256": "3" * 64,
            "wrangler_install_root": "/reviewed/cloudflare/node_modules",
            "wrangler_entrypoint_realpath": "/reviewed/cloudflare/node_modules/wrangler/bin/wrangler.js",
            "wrangler_entrypoint_sha256": "4" * 64,
            "wrangler_tree_sha256": "5" * 64,
            "wrangler_file_count": 100,
            "wrangler_total_bytes": 1000,
        },
    )
    monkeypatch.setattr(
        preflight,
        "container_image_identity",
        lambda _release_sha: (
            {
                f"tinyzkp/hc-server:{release_sha}": "sha256:" + "e" * 64,
                f"tinyzkp/hc-mcp:{release_sha}": "sha256:" + "f" * 64,
            },
            "9" * 64,
        ),
    )
    steps = preflight.build_steps(configured, python=sys.executable, node="node")
    results = [
        preflight.StepResult(
            step.name,
            "PASS",
            step.command,
            returncode=0,
        )
        for step in steps
    ]
    now = datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc)
    return configured, results, now


def test_complete_production_evidence_round_trip(tmp_path, monkeypatch):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    assert "TinyZKP-Internal-Secret-0123456789" not in json.dumps(payload)
    preflight.atomic_write_evidence(evidence, payload)

    report = preflight.verify_evidence(evidence, configured, now=now)

    assert report == {
        "schema_version": 1,
        "status": "pass",
        "release_sha": "a" * 40,
        "fresh": True,
        "inputs_unchanged": True,
        "complete_gate_set": True,
        "container_images_sha256": "9" * 64,
        "container_image_ids": {
            "tinyzkp/hc-server:" + "a" * 40: "sha256:" + "e" * 64,
            "tinyzkp/hc-mcp:" + "a" * 40: "sha256:" + "f" * 64,
        },
    }
    assert evidence.stat().st_mode & 0o777 == 0o600

    payload["gate_results"][0]["returncode"] = False
    preflight.atomic_write_evidence(evidence, payload)
    with pytest.raises(preflight.EvidenceError, match="non-passing gate"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_changed_wrangler_tree(tmp_path, monkeypatch):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    original = preflight.cloudflare_toolchain_identity(
        pathlib.Path(configured.node_executable),
        pathlib.Path(configured.wrangler_entrypoint),
    )
    changed = {**original, "wrangler_tree_sha256": "8" * 64}
    monkeypatch.setattr(
        preflight, "cloudflare_toolchain_identity", lambda _node, _wrangler: changed
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_changed_cloudflare_materialization(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    original = preflight.cloudflare_toolchain_identity(
        pathlib.Path(configured.node_executable),
        pathlib.Path(configured.wrangler_entrypoint),
    )
    changed = {**original, "materialization_sha256": "b" * 64}
    monkeypatch.setattr(
        preflight, "cloudflare_toolchain_identity", lambda _node, _wrangler: changed
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_changed_backup_credential(tmp_path, monkeypatch):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    monkeypatch.setattr(
        preflight,
        "_backup_private_input_identity_from_config",
        lambda _configured: {
            "backup_loader_token_sha256": "6" * 64,
            "backup_transport_kind": "rclone",
            "backup_transport_secret_path": "/secure/rclone.conf",
            "backup_transport_secret_sha256": "8" * 64,
        },
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_evidence_rejects_private_input_rotation_while_gates_run(tmp_path, monkeypatch):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    initial = preflight._private_gate_input_snapshot(configured)
    monkeypatch.setattr(
        preflight,
        "_backup_private_input_identity_from_config",
        lambda _configured: {
            "backup_loader_token_sha256": "6" * 64,
            "backup_transport_kind": "rclone",
            "backup_transport_secret_path": "/secure/rclone.conf",
            "backup_transport_secret_sha256": "8" * 64,
        },
    )

    with pytest.raises(preflight.EvidenceError, match="changed while aggregate gates"):
        preflight.build_pass_evidence(
            configured,
            results,
            now=now,
            issuance_input_snapshot=initial,
        )


def test_production_evidence_rejects_changed_host_runtime_identity(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    monkeypatch.setattr(
        preflight,
        "_production_runtime_evidence_identity",
        lambda _args: {
            "production_runtime_identity_sha256": "f" * 64,
            "production_runtime_file_count": 250,
            "production_runtime_byte_count": 12_500_000,
        },
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_changed_fixed_host_backup_evidence(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    monkeypatch.setattr(
        preflight,
        "_fixed_host_backup_evidence_identity",
        lambda _args, **_kwargs: {
            "fixed_host_backup_evidence_identity_sha256": "4" * 64,
            "fixed_host_backup_subject_sha256": "2" * 64,
            "fixed_host_backup_run_id": "3" * 32,
        },
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_changed_installer_drill_evidence(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)
    monkeypatch.setattr(
        preflight,
        "_installer_drill_evidence_identity",
        lambda _args, **_kwargs: {
            "installer_drill_evidence_identity_sha256": "7" * 64,
            "installer_drill_subject_sha256": "5" * 64,
            "installer_drill_run_id": "6" * 32,
            "installer_drill_review_status": "unreviewed",
        },
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_binds_required_legacy_containment_status(
    tmp_path, monkeypatch
):
    configured, _results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    configured.require_legacy = True
    current = {
        "legacy_billing_containment_required": True,
        "legacy_billing_status_identity_sha256": "8" * 64,
        "legacy_billing_status_subject_sha256": "9" * 64,
        "legacy_billing_current_inventory_sha256": "a" * 64,
        "legacy_billing_status_observed_at": "2026-07-10T20:00:00Z",
    }
    monkeypatch.setattr(
        preflight,
        "_legacy_billing_containment_evidence_identity",
        lambda _args: current,
    )
    steps = preflight.build_steps(configured, python=sys.executable, node="node")
    results = [
        preflight.StepResult(step.name, "PASS", step.command, returncode=0)
        for step in steps
    ]
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    assert payload["legacy_billing_containment_required"] is True
    preflight.atomic_write_evidence(evidence, payload)
    monkeypatch.setattr(
        preflight,
        "_legacy_billing_containment_evidence_identity",
        lambda _args: {
            **current,
            "legacy_billing_status_identity_sha256": "b" * 64,
        },
    )

    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_backup_private_input_identity_binds_rclone_and_rejects_http(
    tmp_path, monkeypatch
):
    tmp_path.chmod(0o700)
    env_file = tmp_path / "host.env"
    loader = tmp_path / "loader-token"
    rclone = tmp_path / "rclone.conf"
    http_token = tmp_path / "http-ingest-token"
    for path, content in (
        (loader, "a" * 64 + "\n"),
        (rclone, "[offbox]\ntype = s3\n"),
        (http_token, "b" * 64 + "\n"),
    ):
        path.write_text(content, encoding="ascii")
        path.chmod(0o600)
    monkeypatch.setattr(preflight.backup_env_exec, "FIXED_LOADER_TOKEN", loader)
    monkeypatch.setattr(preflight.backup_env_exec, "FIXED_RCLONE_CONFIG", rclone)
    monkeypatch.setattr(preflight.backup_env_exec, "FIXED_HTTP_TOKEN", http_token)

    env_file.write_text("HC_BACKUP_REMOTE=offbox:tinyzkp\n", encoding="utf-8")
    env_file.chmod(0o600)
    rclone_identity = preflight._backup_private_input_identity(env_file)
    assert rclone_identity == {
        "backup_loader_token_sha256": preflight._sha256(loader.read_bytes()),
        "backup_transport_kind": "rclone",
        "backup_transport_secret_path": str(rclone),
        "backup_transport_secret_sha256": preflight._sha256(rclone.read_bytes()),
    }

    pages = tmp_path / "pages.env"
    pages.write_text("INTERNAL_SECRET=fixture\n", encoding="utf-8")
    pages.chmod(0o600)
    original_loader = preflight.load_private_env_file
    monkeypatch.setattr(
        preflight,
        "load_private_env_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("snapshot must parse the already-read env bytes")
        ),
    )
    snapshot = preflight._private_gate_input_snapshot(
        argparse.Namespace(env_file=str(env_file), pages_bindings_file=str(pages))
    )
    assert snapshot["backup_transport_kind"] == "rclone"
    monkeypatch.setattr(preflight, "load_private_env_file", original_loader)

    env_file.write_text(
        "HC_BACKUP_HTTP_URL=https://backup.example/tinyzkp\n"
        f"HC_BACKUP_HTTP_TOKEN_FILE={http_token}\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    with pytest.raises(preflight.EvidenceError, match="encrypted rclone"):
        preflight._backup_private_input_identity(env_file)


def test_production_evidence_rejects_stale_changed_and_incomplete_inputs(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)

    with pytest.raises(preflight.EvidenceError, match="stale"):
        preflight.verify_evidence(
            evidence,
            configured,
            now=now + preflight.EVIDENCE_MAX_AGE + timedelta(seconds=1),
        )

    pages = pathlib.Path(configured.pages_bindings_file)
    pages.write_text("INTERNAL_SECRET=" + "b" * 32 + "\n", encoding="utf-8")
    pages.chmod(0o600)
    with pytest.raises(preflight.EvidenceError, match="inputs changed"):
        preflight.verify_evidence(evidence, configured, now=now)

    pages.write_text(
        "INTERNAL_SECRET=TinyZKP-Internal-Secret-0123456789\n",
        encoding="utf-8",
    )
    pages.chmod(0o600)
    payload["gate_results"] = payload["gate_results"][:-1]
    preflight.atomic_write_evidence(evidence, payload)
    with pytest.raises(preflight.EvidenceError, match="complete gate set"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_production_evidence_rejects_duplicate_json_symlink_and_bad_mode(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)

    encoded = json.dumps(payload, separators=(",", ":"))
    evidence.write_text(
        encoded[:-1] + ',"status":"pass"}',
        encoding="utf-8",
    )
    evidence.chmod(0o600)
    with pytest.raises(preflight.EvidenceError, match="duplicates"):
        preflight.verify_evidence(evidence, configured, now=now)

    evidence.unlink()
    target = tmp_path / "target.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    target.chmod(0o600)
    evidence.symlink_to(target)
    with pytest.raises(preflight.EvidenceError, match="unavailable or unsafe"):
        preflight.verify_evidence(evidence, configured, now=now)

    evidence.unlink()
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    evidence.chmod(0o400)
    with pytest.raises(preflight.EvidenceError, match="mode 0600"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_atomic_evidence_requires_owner_only_parent(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(
        preflight.EvidenceError, match="parent must be current-owner-only"
    ):
        preflight.atomic_write_evidence(
            tmp_path / "preflight.json",
            preflight.placeholder_evidence("in_progress", "a" * 40),
        )


def test_evidence_requires_published_main_and_rejects_in_progress_artifact(
    tmp_path, monkeypatch
):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        preflight,
        "source_identity",
        lambda _root, _git, _remote=preflight.EXPECTED_REMOTE_URL: (
            "a" * 40,
            "main",
            True,
            False,
            preflight.EXPECTED_REMOTE_URL,
            "a" * 40,
        ),
    )
    with pytest.raises(preflight.EvidenceError, match="origin/main"):
        preflight.build_pass_evidence(configured, results, now=now)

    evidence = tmp_path / "preflight.json"
    preflight.atomic_write_evidence(
        evidence,
        preflight.placeholder_evidence("in_progress", "a" * 40),
    )
    with pytest.raises(preflight.EvidenceError, match="completed passing"):
        preflight.verify_evidence(evidence, configured, now=now)


def test_source_identity_requires_clean_published_main(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@invalid.example"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "TinyZKP test"],
        cwd=repository,
        check=True,
    )
    (repository / "tracked").write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "test"], cwd=repository, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", str(repository)], cwd=repository, check=True
    )

    git_executable = pathlib.Path(
        subprocess.run(
            ["which", "git"], text=True, capture_output=True, check=True
        ).stdout.strip()
    )
    release_sha, branch, clean, published, remote_url, remote_sha = (
        preflight.source_identity(repository, git_executable, str(repository))
    )
    assert preflight.RELEASE_SHA.fullmatch(release_sha)
    assert (branch, clean, published) == ("main", True, True)
    assert (remote_url, remote_sha) == (str(repository), release_sha)

    (repository / "tracked").write_text("changed\n", encoding="utf-8")
    assert (
        preflight.source_identity(repository, git_executable, str(repository))[2]
        is False
    )


def test_source_identity_ignores_repo_local_remote_rewrites(tmp_path):
    repository = tmp_path / "repo"
    fake = tmp_path / "fake"
    for path, value in ((repository, "reviewed\n"), (fake, "fake\n")):
        path.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@invalid.example"],
            cwd=path,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "TinyZKP test"],
            cwd=path,
            check=True,
        )
        (path / "tracked").write_text(value, encoding="utf-8")
        subprocess.run(["git", "add", "tracked"], cwd=path, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "test"], cwd=path, check=True)

    expected_remote = str(repository)
    subprocess.run(
        ["git", "remote", "add", "origin", expected_remote],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", f"url.{fake}.insteadOf", expected_remote],
        cwd=repository,
        check=True,
    )
    git_executable = pathlib.Path(shutil.which("git") or "/usr/bin/git")

    release_sha, _branch, _clean, published, remote_url, remote_sha = (
        preflight.source_identity(repository, git_executable, expected_remote)
    )
    assert published is True
    assert remote_url == expected_remote
    assert remote_sha == release_sha


def test_git_metadata_rejects_group_writable_config(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
    config = repository / ".git" / "config"
    original_mode = stat.S_IMODE(config.stat().st_mode)
    config.chmod(0o664)
    try:
        with pytest.raises(preflight.EvidenceError, match="unsafe entry"):
            preflight.validate_git_metadata(repository)
    finally:
        config.chmod(original_mode)


def test_venv_identity_hashes_all_files_and_rejects_symlinks(tmp_path):
    venv = tmp_path / ".venv"
    (venv / "bin").mkdir(parents=True)
    site = venv / "lib" / "python3.12" / "site-packages"
    dist = site / "demo-1.0.dist-info"
    dist.mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_bytes(
        pathlib.Path(shutil.which("true") or "/usr/bin/true").read_bytes()
    )
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    metadata = dist / "METADATA"
    record = dist / "RECORD"
    metadata.write_text("Name: demo\nVersion: 1.0\n", encoding="utf-8")
    record.write_text(
        "demo-1.0.dist-info/METADATA,,\ndemo-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    for directory in (venv, venv / "bin", venv / "lib", site.parent, site, dist):
        directory.chmod(0o555)
    python.chmod(0o555)
    for path in (venv / "pyvenv.cfg", metadata, record):
        path.chmod(0o444)

    identity = preflight.venv_identity(python)
    assert identity["venv_package_count"] == 1
    assert identity["venv_file_count"] == 4

    python.chmod(0o755)
    with pytest.raises(preflight.EvidenceError, match="immutable private copy"):
        preflight.venv_identity(python)
    for directory in (dist, site, site.parent, venv / "lib", venv / "bin", venv):
        directory.chmod(0o755)


def test_evidence_consumption_is_one_time(tmp_path, monkeypatch):
    configured, results, now = _production_evidence_fixture(tmp_path, monkeypatch)
    evidence = tmp_path / "preflight.json"
    consumed = tmp_path / "consumed"
    consumed.mkdir(mode=0o700)
    payload = preflight.build_pass_evidence(configured, results, now=now)
    preflight.atomic_write_evidence(evidence, payload)

    report = preflight.consume_evidence(
        evidence,
        configured,
        now=now,
        consumption_dir=consumed,
    )
    assert report["consumed"] is True
    assert not evidence.exists()
    assert (consumed / f"{payload['nonce']}.claim").is_file()
    with pytest.raises((preflight.EvidenceError, preflight.ProductionEnvError)):
        preflight.consume_evidence(
            evidence,
            configured,
            now=now,
            consumption_dir=consumed,
        )
