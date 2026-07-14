import importlib.util
import argparse
import json
import os
from pathlib import Path
import subprocess

import pytest


PATH = Path(__file__).with_name("activate_public_beta.py")
SPEC = importlib.util.spec_from_file_location("activate_public_beta", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize(
    "release_sha",
    [
        "04e8af8ed0be29433adc60730ab5e3eef13b13aa",
        "8ecaa4845a5b921f0c8b038c44d949a4a6d1670b",
        "1876ecf57b5d9945fa56b9c7ab154447d2363a56",
    ],
)
def test_abandoned_candidate_is_rejected_before_any_external_action(
    tmp_path: Path, release_sha: str
):
    args = argparse.Namespace(release_sha=release_sha)
    with pytest.raises(SystemExit, match="permanently abandoned"):
        MODULE.activate(args)


def test_smoke_command_must_be_operator_owned_and_nonwritable(tmp_path: Path):
    command = tmp_path / "smoke"
    command.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(command, 0o755)
    assert MODULE.require_executable(command) == command.resolve()
    os.chmod(command, 0o777)
    with pytest.raises(ValueError, match="non-writable"):
        MODULE.require_executable(command)


def test_private_activation_evidence_is_owner_only(tmp_path: Path):
    output = tmp_path / "private" / "activation.json"
    MODULE.write_private(output, {"status": "passed"})
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="already exists"):
        MODULE.write_private(output, {"status": "passed"})


def test_post_write_smoke_failure_restores_caddy_pages_probe_and_containment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_sha = "a" * 40
    staged = tmp_path / "site"
    staged.mkdir()
    (staged / "discovery.json").write_text(
        json.dumps({"service_status": "public_beta", "release_sha": release_sha}),
        encoding="utf-8",
    )
    smoke = tmp_path / "smoke"
    smoke.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    smoke.chmod(0o700)
    commands: list[list[str]] = []
    page_rollbacks: list[str] = []
    discovery_calls = 0
    deployments = iter(({"id": "previous"}, {"id": "candidate"}))

    def fake_run(command, *, cwd=None, env=None):
        del cwd, env
        commands.append(command)
        if command == [str(smoke.resolve())]:
            raise subprocess.CalledProcessError(1, command)

    def fake_fetch_json(url: str):
        nonlocal discovery_calls
        discovery_calls += 1
        if discovery_calls <= 2:
            return {"service_status": "public_beta", "release_sha": release_sha}
        assert url == "https://tinyzkp.com/discovery.json"
        return {"service_status": "backend_recovery"}

    monkeypatch.setenv("TEST_CF_TOKEN", "test-token")
    monkeypatch.setattr(MODULE, "run", fake_run)
    monkeypatch.setattr(MODULE, "production_deployment", lambda *args: next(deployments))
    monkeypatch.setattr(MODULE, "fetch_json", fake_fetch_json)
    monkeypatch.setattr(
        MODULE,
        "rollback_pages",
        lambda token, account, project, deployment: page_rollbacks.append(deployment),
    )
    args = argparse.Namespace(
        release_sha=release_sha,
        staged_site=staged,
        api_ssh="root@api",
        account_id="account",
        project="tinyzkp",
        cloudflare_token_env="TEST_CF_TOKEN",
        wrangler="wrangler",
        smoke_command=smoke,
        evidence=tmp_path / "evidence.json",
        confirmation="ACTIVATE_PUBLIC_BETA",
    )

    with pytest.raises(subprocess.CalledProcessError):
        MODULE.activate(args)

    joined = [" ".join(command) for command in commands]
    assert sum("set-beta-writes.sh 0" in command for command in joined) == 2
    assert any("switch-beta-route.sh rollback" in command for command in joined)
    assert any("AUDIT_MODE:containment" in command for command in joined)
    assert page_rollbacks == ["previous"]
    assert discovery_calls == 3
    assert not args.evidence.exists()
