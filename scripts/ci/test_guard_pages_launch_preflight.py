import argparse
import json
from pathlib import Path
import sys

import pytest

import guard_pages_launch_preflight as preflight


def args(**overrides):
    defaults = {
        "production": False,
        "live": False,
        "site_url": "https://tinyzkp.com",
        "source_guard_trust_sha256": None,
        "source_signing_trust_sha256": None,
        "source_market_trust_sha256": None,
        "node_executable": None,
        "wrangler_entrypoint": None,
        "require_decommissioned_hosts": False,
        "json": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def commands(steps):
    return [step.command for step in steps]


def write_guard_state(
    root: Path,
    *,
    commerce_state: str = "unconfigured",
    authorization_state: str = "blocked",
    passed: tuple[str, ...] = (),
) -> None:
    release = root / "release"
    release.mkdir(parents=True, exist_ok=True)
    gates = {
        "engine_release_ready": {
            "status": "passed" if "engine_release_ready" in passed else "blocked"
        },
        "hosted_infrastructure_decommissioned": {
            "status": (
                "passed"
                if "hosted_infrastructure_decommissioned" in passed
                else "blocked"
            )
        },
    }
    (release / "guard-launch-state-v2.json").write_text(
        json.dumps({"commerce_state": commerce_state, "gate_status": gates}),
        encoding="utf-8",
    )
    (release / "guard-candidate-build-authorization-v1.json").write_text(
        json.dumps({"authorization_state": authorization_state}),
        encoding="utf-8",
    )


def test_local_preflight_is_only_guard_and_static_pages_business():
    built = preflight.build_steps(args(), python="python", node="node")

    assert commands(built) == [
        ("python", "scripts/ci/guard_launch_gate.py", "--check"),
        ("python", "scripts/ci/guard_market_clock.py", "--check"),
        ("python", "scripts/ci/passive_operations_scorecard.py", "--check"),
        ("python", "scripts/ci/claim_containment_scan.py"),
        ("python", "scripts/ci/site_route_check.py"),
        ("python", "scripts/ci/site_deploy_check.py"),
        ("python", "scripts/commercial/render_offers.py", "--check"),
        (
            "python",
            "scripts/marketing/render_gtm_execution_ledger.py",
            "--check",
        ),
        ("python", "scripts/ci/gtm_execution_ledger_check.py"),
        (
            "python",
            "scripts/marketing/render_gtm_pipeline_ledger.py",
            "--check",
        ),
        ("python", "scripts/ci/gtm_pipeline_ledger_check.py"),
        (
            "python",
            "-m",
            "pytest",
            "-q",
            "scripts/ci/test_guard_launch_gate.py",
            "scripts/ci/test_guard_market_clock.py",
            "scripts/ci/test_guard_site_contract.py",
            "scripts/ci/test_gtm_execution_ledger.py",
            "scripts/ci/test_gtm_pipeline_ledger.py",
            "scripts/ci/test_passive_operations_scorecard.py",
            "scripts/ci/test_claim_containment_scan.py",
            "scripts/ci/test_site_route_check.py",
            "scripts/ci/test_site_deploy_check.py",
            "scripts/ci/test_cloudflare_pages_secret_check.py",
            "scripts/ci/test_cloudflare_toolchain_check.py",
            "scripts/deploy/test_static_site_canary.py",
        ),
        (
            "python",
            "-m",
            "pytest",
            "-q",
            "scripts/deploy/test_cloudflare_pages_release.py",
        ),
        ("python", "scripts/ci/cloudflare_toolchain_check.py"),
        ("node", "--check", "site/_worker.js"),
        ("node", "scripts/ci/site_worker_dispatch_test.mjs"),
        ("node", "scripts/ci/site_shared_checkout_test.mjs"),
    ]
    joined = "\n".join(" ".join(command).lower() for command in commands(built))
    for retired in (
        "backend_recovery",
        "server_card",
        "billing/",
        "stripe",
        "evaluation",
        "sdk",
        "api.tinyzkp",
        "mcp.tinyzkp",
        "contact_intake",
        "docker compose",
    ):
        assert retired not in joined


def test_production_adds_exact_cloudflare_runtime_and_empty_secret_inventory(
    monkeypatch,
):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "scoped-token")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "scoped-account")
    monkeypatch.setenv("TINYZKP_GUARD_TRUST_POLICY_SHA256", "a" * 64)
    monkeypatch.setenv("TINYZKP_GUARD_SIGNING_TRUST_POLICY_SHA256", "b" * 64)
    monkeypatch.setenv("TINYZKP_GUARD_MARKET_TRUST_POLICY_SHA256", "c" * 64)
    monkeypatch.setenv("TINYZKP_COSIGN", "/reviewed/cosign")
    built = preflight.build_steps(
        args(
            production=True,
            node_executable="/reviewed/node",
            wrangler_entrypoint="/reviewed/wrangler.js",
        ),
        python="python",
        node="/reviewed/node",
    )

    assert (
        "python",
        "scripts/ci/cloudflare_toolchain_check.py",
        "--runtime",
        "--node-executable",
        "/reviewed/node",
        "--wrangler-entrypoint",
        "/reviewed/wrangler.js",
    ) in commands(built)
    assert (
        "python",
        "scripts/ci/cloudflare_pages_secret_check.py",
        "--node-executable",
        "/reviewed/node",
        "--wrangler-entrypoint",
        "/reviewed/wrangler.js",
    ) in commands(built)
    assert ("/reviewed/node", "--check", "site/_worker.js") in commands(built)
    assert set(built[0].env) == set(preflight.GUARD_TRUST_ENV)
    assert set(built[1].env) == set(preflight.MARKET_TRUST_ENV)
    assert built[1].env["TINYZKP_COSIGN"] == "/reviewed/cosign"
    assert built[-1].name == "Cloudflare Pages live secret inventory check"
    assert set(built[-1].env) == set(preflight.CLOUDFLARE_ENV)
    assert all(
        not (set(step.env) & set(preflight.CLOUDFLARE_ENV))
        for step in built[:-1]
    )


@pytest.mark.parametrize("missing", ["node_executable", "wrangler_entrypoint"])
def test_production_requires_only_the_reviewed_cloudflare_runtime(missing):
    configured = args(
        production=True,
        node_executable="/reviewed/node",
        wrangler_entrypoint="/reviewed/wrangler.js",
    )
    setattr(configured, missing, None)
    with pytest.raises(preflight.PreflightError, match="production preflight requires"):
        preflight.build_steps(configured, python="python", node="node")


def test_source_derived_trust_is_explicit_complete_and_non_production(tmp_path):
    write_guard_state(
        tmp_path,
        authorization_state="published",
        passed=("engine_release_ready",),
    )
    guard_digest = "a" * 64
    signing_digest = "b" * 64
    market_digest = "c" * 64
    configured = args(
        source_guard_trust_sha256=guard_digest,
        source_signing_trust_sha256=signing_digest,
        source_market_trust_sha256=market_digest,
    )
    built = preflight.build_steps(configured, python="python", node="node", root=tmp_path)

    assert built[0].command == (
        "python",
        "scripts/ci/guard_launch_gate.py",
        "--check",
        "--require-current-evaluation",
        "--trusted-policy-sha256",
        guard_digest,
        "--trusted-signing-policy-sha256",
        signing_digest,
    )
    assert built[1].command == (
        "python",
        "scripts/ci/guard_market_clock.py",
        "--check",
        "--trusted-policy-sha256",
        market_digest,
    )

    with pytest.raises(preflight.PreflightError, match="supplied together"):
        preflight.build_steps(
            args(source_guard_trust_sha256=guard_digest), root=tmp_path
        )
    with pytest.raises(preflight.PreflightError, match="refuses source-derived"):
        preflight.build_steps(
            args(
                production=True,
                node_executable="/reviewed/node",
                wrangler_entrypoint="/reviewed/wrangler.js",
                source_guard_trust_sha256=guard_digest,
                source_signing_trust_sha256=signing_digest,
                source_market_trust_sha256=market_digest,
            ),
            root=tmp_path,
        )


def test_live_mode_uses_static_contracts_and_containment_routes_without_backend():
    built = preflight.build_steps(
        args(live=True, site_url="https://tinyzkp.com"),
        python="python",
        node="node",
    )

    assert (
        "python",
        "scripts/deploy/static_site_canary.py",
        "--base-url",
        "https://tinyzkp.com",
        "--mode",
        "contracts",
    ) in commands(built)
    assert (
        "python",
        "scripts/deploy/static_site_canary.py",
        "--base-url",
        "https://tinyzkp.com",
        "--mode",
        "routes",
    ) in commands(built)
    assert not any("backend_recovery_canary.py" in command for command in commands(built))
    assert not any("release_identity_check.py" in command for command in commands(built))


def test_retired_hosts_are_checked_when_decommission_is_claimed_or_required(tmp_path):
    write_guard_state(
        tmp_path,
        passed=("hosted_infrastructure_decommissioned",),
    )
    built = preflight.build_steps(
        args(live=True), python="python", node="node", root=tmp_path
    )
    assert (
        "python",
        "scripts/deploy/static_site_canary.py",
        "--mode",
        "retired-hosts",
    ) in commands(built)

    write_guard_state(tmp_path)
    forced = preflight.build_steps(
        args(live=True, require_decommissioned_hosts=True),
        python="python",
        node="node",
        root=tmp_path,
    )
    assert any("retired-hosts" in command for command in commands(forced))


def test_retired_host_requirement_is_live_only():
    with pytest.raises(preflight.PreflightError, match="live post-deploy"):
        preflight.build_steps(
            args(require_decommissioned_hosts=True), python="python", node="node"
        )


@pytest.mark.parametrize(
    ("commerce", "authorization", "passed", "expected"),
    [
        ("unconfigured", "blocked", (), None),
        (
            "unconfigured",
            "blocked",
            ("engine_release_ready",),
            "--require-current-evaluation",
        ),
        (
            "unconfigured",
            "authorized",
            (),
            "--require-candidate-build-ready",
        ),
        (
            "unconfigured",
            "candidate_prepared",
            (),
            "--require-promotion-ready",
        ),
        ("live_hidden", "published", (), "--require-current-evaluation"),
        ("public_live", "published", (), "--require-ready"),
    ],
)
def test_guard_readiness_escalates_fail_closed(
    tmp_path, commerce, authorization, passed, expected
):
    write_guard_state(
        tmp_path,
        commerce_state=commerce,
        authorization_state=authorization,
        passed=passed,
    )
    mode = preflight.guard_mode(tmp_path)
    assert mode.readiness_argument == expected
    built = preflight.build_steps(args(), root=tmp_path)
    command = built[0].command
    assert (command[-1] if len(command) == 4 else None) == expected


def test_guard_mode_rejects_duplicate_or_unknown_state(tmp_path):
    write_guard_state(tmp_path)
    state = tmp_path / preflight.GUARD_STATE
    state.write_text(
        '{"commerce_state":"unconfigured","commerce_state":"public_live",'
        '"gate_status":{"one":{"status":"blocked"}}}',
        encoding="utf-8",
    )
    with pytest.raises(preflight.PreflightError, match="duplicate JSON key"):
        preflight.guard_mode(tmp_path)

    write_guard_state(tmp_path, commerce_state="retired-backend")
    with pytest.raises(preflight.PreflightError, match="commerce state"):
        preflight.guard_mode(tmp_path)


def test_run_step_captures_success_failure_and_missing_command(tmp_path):
    ok = tmp_path / "ok.py"
    fail = tmp_path / "fail.py"
    ok.write_text("print('hello')\n", encoding="utf-8")
    fail.write_text(
        "import sys\nprint('bad', file=sys.stderr)\nsys.exit(7)\n",
        encoding="utf-8",
    )

    success = preflight.run_step(
        preflight.Step("ok", (sys.executable, str(ok))), root=tmp_path
    )
    failure = preflight.run_step(
        preflight.Step("fail", (sys.executable, str(fail))), root=tmp_path
    )
    missing = preflight.run_step(
        preflight.Step("missing", ("definitely-not-a-tinyzkp-command",)),
        root=tmp_path,
    )

    assert (success.status, success.returncode, success.stdout.strip()) == (
        "PASS",
        0,
        "hello",
    )
    assert (failure.status, failure.returncode, failure.stderr.strip()) == (
        "FAIL",
        7,
        "bad",
    )
    assert missing.status == "FAIL"
    assert missing.returncode is None
    assert missing.error


def test_production_stops_before_later_credentialed_step_after_failure(tmp_path):
    fail = tmp_path / "fail.py"
    credentialed = tmp_path / "credentialed.py"
    marker = tmp_path / "credentialed-ran"
    fail.write_text("raise SystemExit(9)\n", encoding="utf-8")
    credentialed.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
        encoding="utf-8",
    )
    steps = [
        preflight.Step("runtime validator", (sys.executable, str(fail))),
        preflight.Step(
            "credentialed inventory",
            (sys.executable, str(credentialed)),
            env={"CLOUDFLARE_API_TOKEN": "must-not-be-exposed"},
        ),
    ]

    results = preflight.run_steps(steps, root=tmp_path, production=True)

    assert [result.name for result in results] == ["runtime validator"]
    assert results[0].status == "FAIL"
    assert not marker.exists()


def test_production_environment_drops_inherited_injection_and_passes_step_env(
    tmp_path, monkeypatch
):
    script = tmp_path / "environment.py"
    script.write_text(
        "import json, os; print(json.dumps(dict(os.environ), sort_keys=True))\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", "/attacker")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/attacker")
    monkeypatch.setenv("LD_PRELOAD", "/attacker.so")
    result = preflight.run_step(
        preflight.Step(
            "env",
            (sys.executable, str(script)),
            env={"TINYZKP_GUARD_TRUST_POLICY_SHA256": "a" * 64},
        ),
        root=tmp_path,
        production=True,
    )
    environment = json.loads(result.stdout)

    assert result.status == "PASS"
    assert environment["PATH"] == preflight.TRUSTED_SYSTEM_PATH
    assert environment["TINYZKP_GUARD_TRUST_POLICY_SHA256"] == "a" * 64
    for forbidden in ("PYTHONPATH", "NODE_OPTIONS", "LD_PRELOAD"):
        assert forbidden not in environment
    with pytest.raises(preflight.PreflightError, match="forbidden environment"):
        preflight.production_subprocess_environment({"NODE_OPTIONS": "--inspect"})


def test_nonproduction_environment_strips_operator_and_merchant_credentials(
    tmp_path, monkeypatch
):
    secrets = {
        "CLOUDFLARE_API_TOKEN": "cloudflare-token",
        "CLOUDFLARE_ACCOUNT_ID": "cloudflare-account",
        "STRIPE_SECRET_KEY": "stripe-secret",
        "LEMON_SQUEEZY_API_KEY": "merchant-secret",
        "GITHUB_TOKEN": "github-token",
        "UNRELATED_API_TOKEN": "other-token",
        "merchant_secret": "lowercase-secret",
    }
    script = tmp_path / "environment.py"
    script.write_text(
        "import json, os\n"
        f"forbidden = {tuple(secrets)!r}\n"
        "print(json.dumps({\n"
        "    'guard_trust': os.environ.get('TINYZKP_GUARD_TRUST_POLICY_SHA256'),\n"
        "    'safe_test_value': os.environ.get('TINYZKP_SAFE_TEST_VALUE'),\n"
        "    'forbidden_present': [key for key in forbidden if key in os.environ],\n"
        "}, sort_keys=True))\n",
        encoding="utf-8",
    )
    for key, value in secrets.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("TINYZKP_GUARD_TRUST_POLICY_SHA256", "a" * 64)
    monkeypatch.setenv("TINYZKP_SAFE_TEST_VALUE", "retained")

    result = preflight.run_step(
        preflight.Step("env", (sys.executable, str(script))), root=tmp_path
    )
    observed = json.loads(result.stdout)

    assert result.status == "PASS"
    assert observed["guard_trust"] == "a" * 64
    assert observed["safe_test_value"] == "retained"
    assert observed["forbidden_present"] == []
    with pytest.raises(preflight.PreflightError, match="credential environment"):
        preflight.nonproduction_subprocess_environment(
            {"CLOUDFLARE_API_TOKEN": "explicit-but-forbidden"}
        )


def test_live_cli_no_longer_requires_backend_production_arguments(monkeypatch, capsys):
    monkeypatch.setattr(preflight, "build_steps", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(preflight, "run_steps", lambda *_args, **_kwargs: [])

    assert preflight.main(["--live", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "pass"
    assert output["live"] is True


def test_production_cli_requires_cloudflare_paths_not_host_python(
    tmp_path, monkeypatch
):
    node = tmp_path / "node"
    wrangler = tmp_path / "wrangler.js"
    node.write_text("#!/bin/sh\n", encoding="utf-8")
    wrangler.write_text("// reviewed\n", encoding="utf-8")
    node.chmod(0o755)

    with pytest.raises(SystemExit) as omitted:
        preflight.main(["--production"])
    assert omitted.value.code == 2

    monkeypatch.setattr(preflight, "build_steps", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(preflight, "run_steps", lambda *_args, **_kwargs: [])
    parser_args = [
        "--production",
        "--node-executable",
        str(node),
        "--wrangler-entrypoint",
        str(wrangler),
    ]
    assert preflight.main(parser_args) == 0


def test_workflows_bind_source_only_and_protected_production_preflights():
    ci = (preflight.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    deploy = (preflight.ROOT / ".github/workflows/deploy-site.yml").read_text(
        encoding="utf-8"
    )
    source_flags = (
        "--source-guard-trust-sha256",
        "--source-signing-trust-sha256",
        "--source-market-trust-sha256",
    )
    for workflow in (ci, deploy):
        assert "scripts/ci/guard_pages_launch_preflight.py" in workflow
        assert all(flag in workflow for flag in source_flags)

    release_step = ci.split("- name: Release evidence and launch-gate tests", 1)[1]
    release_step = release_step.split("- name: Static site contracts", 1)[0]
    assert "python3 scripts/ci/guard_launch_gate.py" in release_step
    assert "python3 scripts/ci/guard_market_clock.py" in release_step
    assert "release/guard-launch-trust-v1.json" in release_step
    assert "release/guard-signing-trust-v1.json" in release_step
    assert "release/guard-market-trust-v1.json" in release_step
    assert release_step.count("--trusted-policy-sha256") == 2
    assert release_step.count("--trusted-signing-policy-sha256") == 1

    assert deploy.count(
        "sigstore/cosign-installer@f713795cb21599bc4e5c4b58cbad1da852d7eeb9"
    ) == 2
    for path_filter in (
        '".gitattributes"',
        '"BUSINESS_GUIDE.md"',
        '"README.md"',
        '"commercial/**"',
        '"docs/**"',
        '"marketing/**"',
        '"release/**"',
        '"site/**"',
        '"scripts/ci/**"',
        '"scripts/commercial/**"',
        '"scripts/deploy/**"',
        '"scripts/marketing/**"',
        '"toolchains/cloudflare/**"',
        '".github/workflows/ci.yml"',
        '".github/workflows/deploy-site.yml"',
    ):
        assert deploy.count(path_filter) == 2

    production = deploy.split("\n  production:\n", 1)[1]
    production_preflight = production.index(
        "python3 scripts/ci/guard_pages_launch_preflight.py"
    )
    assert production.index("git archive --format=tar \"$GITHUB_SHA\"") < production_preflight
    assert 'git show "$GITHUB_SHA:$toolchain_input"' in production
    assert production.index("materialize_cloudflare_toolchain.py\"") < production_preflight
    assert "--production" in production[production_preflight:]
    assert "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}" in production
    assert "CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}" in production
    for archived_input in (
        "scripts/ci/materialize_cloudflare_toolchain.py",
        "scripts/ci/cloudflare_toolchain_check.py",
        "release/cloudflare-production-toolchain-v1.json",
        "toolchains/cloudflare/package.json",
        "toolchains/cloudflare/package-lock.json",
    ):
        assert archived_input in production
