from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

import cloudflare_pages_release as pages


ACCOUNT = "c" * 32
NEW_SHA = "a" * 40
PRIOR_SHA = "b" * 40
PRIOR_ID = "11111111-1111-1111-1111-111111111111"
NEW_ID = "22222222-2222-2222-2222-222222222222"


def deployment(identifier, release, label):
    return {
        "id": identifier,
        "url": f"https://{label}.tinyzkp.pages.dev",
        "project_name": pages.PROJECT_NAME,
        "environment": "production",
        "deployment_trigger": {
            "metadata": {
                "commit_hash": release,
                "branch": pages.PRODUCTION_BRANCH,
                "commit_dirty": False,
            }
        },
        "latest_stage": {"status": "success"},
        "created_on": "2026-07-10T20:00:00Z"
        if identifier == PRIOR_ID
        else "2026-07-10T21:00:00Z",
    }


class FakeApi:
    def __init__(self):
        self.deployments = {
            PRIOR_ID: deployment(PRIOR_ID, PRIOR_SHA, "prior"),
            NEW_ID: deployment(NEW_ID, NEW_SHA, "new"),
        }
        self.current = PRIOR_ID
        self.rollback_calls = []

    def get_project(self):
        return {
            "id": "project-identity",
            "name": pages.PROJECT_NAME,
            "production_branch": pages.PRODUCTION_BRANCH,
            "canonical_deployment": copy.deepcopy(self.deployments[self.current]),
        }

    def get_deployment(self, identifier):
        return copy.deepcopy(self.deployments[identifier])

    def rollback(self, identifier):
        self.rollback_calls.append(identifier)
        self.current = identifier
        return copy.deepcopy(self.deployments[identifier])


class RollbackFailureApi(FakeApi):
    def rollback(self, identifier):
        self.rollback_calls.append(identifier)
        raise pages.ReleaseError("simulated rollback outage")


def source_identity(release=NEW_SHA):
    return {
        "release_sha": release,
        "site_git_tree_oid": "d" * 40,
        "site_archive_sha256": "1" * 64,
        "site_manifest_sha256": "2" * 64,
        "site_file_count": 40,
        "site_total_bytes": 100_000,
    }


def toolchain_identity():
    return {
        "profile_id": "tinyzkp-cloudflare-production-v1",
        "profile_sha256": "3" * 64,
        "package_lock_sha256": "4" * 64,
        "node_version": "v24.18.0",
        "wrangler_version": "4.85.0",
        "node_realpath": str(pages.PINNED_NODE),
        "node_sha256": "5" * 64,
        "wrangler_install_root": "/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules",
        "wrangler_entrypoint_realpath": str(pages.PINNED_WRANGLER),
        "wrangler_entrypoint_sha256": "6" * 64,
        "materialization_sha256": "7" * 64,
        "wrangler_tree_sha256": "8" * 64,
        "wrangler_file_count": 123,
        "wrangler_total_bytes": 456_789,
    }


def source_provider(_root, release):
    return source_identity(release)


def toolchain_provider(_node, _wrangler):
    return toolchain_identity()


@contextmanager
def source_materializer(_root, release, expected):
    assert expected == source_identity(release)
    temporary = (
        Path(os.environ.get("TMPDIR", "/tmp")) / f"tinyzkp-source-test-{os.getpid()}"
    )
    if temporary.exists():
        shutil.rmtree(temporary)
    source = temporary / "site"
    home = temporary / "home"
    source.mkdir(parents=True, mode=0o700)
    home.mkdir(mode=0o700)
    (source / "wrangler.toml").write_text('name = "tinyzkp"\n')
    try:
        yield source, home
    finally:
        shutil.rmtree(temporary)


def private_path(tmp_path, name):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700, exist_ok=True)
    parent.chmod(0o700)
    return parent / name


def write_environment():
    return {
        pages.WRITE_ENV: "1",
        "CLOUDFLARE_API_TOKEN": "test-token-value-1234567890",
        "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
    }


def plan(api):
    return pages.deploy_plan(
        reviewed_sha=NEW_SHA,
        expected_account_id=ACCOUNT,
        api=api,
        source_provider=source_provider,
        toolchain_provider=toolchain_provider,
    )


def deploy_record(tmp_path, api):
    preview = plan(api)

    def runner(command, **kwargs):
        assert command[0] == str(pages.PINNED_NODE)
        assert command[1] == str(pages.PINNED_WRANGLER)
        assert command[2:4] == ("pages", "deploy")
        assert command[command.index("--project-name") + 1] == pages.PROJECT_NAME
        assert command[command.index("--branch") + 1] == pages.PRODUCTION_BRANCH
        assert command[command.index("--commit-hash") + 1] == NEW_SHA
        assert "--commit-dirty=false" in command
        assert kwargs["env"] == {
            "PATH": pages.TRUSTED_PATH,
            "HOME": kwargs["env"]["HOME"],
            "TMPDIR": kwargs["env"]["HOME"],
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
            "WRANGLER_SEND_METRICS": "false",
            "CLOUDFLARE_API_TOKEN": "test-token-value-1234567890",
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
        }
        api.current = NEW_ID
        return subprocess.CompletedProcess(command, 0, "deployed\n", "")

    output = private_path(tmp_path, "deployment.json")
    result = pages.apply_deploy(
        reviewed_sha=NEW_SHA,
        expected_account_id=ACCOUNT,
        expected_plan_sha256=preview["plan_sha256"],
        output=output,
        api=api,
        source_provider=source_provider,
        source_materializer=source_materializer,
        toolchain_provider=toolchain_provider,
        runner=runner,
        environment={
            **write_environment(),
            "UNRELATED_SECRET": "must-not-be-forwarded",
        },
        now=lambda: "2026-07-10T22:00:00Z",
    )
    return output, result


def test_deploy_plan_is_read_only_deterministic_and_binds_prior_source_toolchain():
    api = FakeApi()
    first = plan(api)
    second = plan(api)
    assert first == second
    assert first["plan_sha256"] == pages.canonical_sha256(first["plan"])
    assert first["plan"]["account_id"] == ACCOUNT
    assert first["plan"]["project_name"] == pages.PROJECT_NAME
    assert first["plan"]["release_sha"] == NEW_SHA
    assert first["plan"]["prior_production_deployment"]["deployment_id"] == PRIOR_ID
    assert first["plan"]["source"] == source_identity()
    assert first["plan"]["toolchain"] == toolchain_identity()
    assert api.current == PRIOR_ID


def test_cli_deploy_and_rollback_default_to_plan_mode():
    deploy = pages.parse_args(
        ["deploy", "--release-sha", NEW_SHA, "--expected-account-id", ACCOUNT]
    )
    rollback = pages.parse_args(
        [
            "rollback",
            "--deployment-record",
            "/secure/deployment.json",
            "--expected-record-sha256",
            "0" * 64,
            "--expected-account-id",
            ACCOUNT,
        ]
    )
    assert deploy.apply is False
    assert rollback.apply is False


def test_deploy_plan_rejects_wrong_project_source_or_toolchain():
    class WrongProject(FakeApi):
        def get_project(self):
            value = super().get_project()
            value["name"] = "not-tinyzkp"
            return value

    with pytest.raises(pages.ReleaseError, match="exact tinyzkp/main"):
        plan(WrongProject())

    with pytest.raises(pages.ReleaseError, match="reviewed release"):
        pages.deploy_plan(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            api=FakeApi(),
            source_provider=lambda _root, _sha: source_identity(PRIOR_SHA),
            toolchain_provider=toolchain_provider,
        )

    changed = toolchain_identity()
    changed["wrangler_version"] = "4.86.0"
    with pytest.raises(pages.ReleaseError, match="pinned runtime"):
        pages.deploy_plan(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            api=FakeApi(),
            source_provider=source_provider,
            toolchain_provider=lambda _node, _wrangler: changed,
        )


def test_apply_uses_only_pinned_wrangler_and_writes_canonical_owner_only_record(
    tmp_path,
):
    api = FakeApi()
    output, result = deploy_record(tmp_path, api)
    raw = output.read_bytes()
    payload = json.loads(raw)
    assert raw == pages.canonical_bytes(payload)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert result["deployment_record_sha256"] == pages.sha256_bytes(raw)
    assert payload["new_deployment"]["deployment_id"] == NEW_ID
    assert payload["prior_production_deployment"]["deployment_id"] == PRIOR_ID
    assert payload["release_sha"] == NEW_SHA
    assert payload["source"] == source_identity()
    assert payload["toolchain"] == toolchain_identity()
    pages.validate_deployment_record(payload)


@pytest.mark.parametrize(
    "environment",
    [
        {
            "CLOUDFLARE_API_TOKEN": "test-token-value-1234567890",
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
        },
        {
            pages.WRITE_ENV: "1",
            "CLOUDFLARE_API_TOKEN": "test-token-value-1234567890",
            "CLOUDFLARE_ACCOUNT_ID": "d" * 32,
        },
    ],
)
def test_apply_requires_write_flag_exact_account_and_plan_before_runner(
    tmp_path, environment
):
    api = FakeApi()
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    with pytest.raises(pages.ReleaseError):
        pages.apply_deploy(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            expected_plan_sha256="0" * 64,
            output=private_path(tmp_path, "blocked.json"),
            api=api,
            source_provider=source_provider,
            source_materializer=source_materializer,
            toolchain_provider=toolchain_provider,
            runner=runner,
            environment=environment,
        )
    assert called is False
    assert api.current == PRIOR_ID


def test_apply_fails_closed_when_cloudflare_does_not_publish_exact_new_sha(tmp_path):
    api = FakeApi()
    preview = plan(api)

    def runner(command, **_kwargs):
        api.current = NEW_ID
        api.deployments[NEW_ID]["deployment_trigger"]["metadata"]["commit_hash"] = (
            "e" * 40
        )
        return subprocess.CompletedProcess(command, 0, "ok", "")

    output = private_path(tmp_path, "bad.json")
    with pytest.raises(pages.ReleaseError, match="automatic rollback verified"):
        pages.apply_deploy(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            expected_plan_sha256=preview["plan_sha256"],
            output=output,
            api=api,
            source_provider=source_provider,
            source_materializer=source_materializer,
            toolchain_provider=toolchain_provider,
            runner=runner,
            environment=write_environment(),
        )
    assert not output.exists()
    assert api.current == PRIOR_ID
    assert api.rollback_calls == [PRIOR_ID]
    failure_path = pages.deploy_failure_path(output)
    failure = json.loads(failure_path.read_text())
    pages.validate_deploy_failure_record(failure)
    assert failure["status"] == "deploy_failed_rolled_back"
    assert failure["failure_stage"] == "deployment_validation"
    assert failure["rollback"]["canonical_deployment"]["deployment_id"] == PRIOR_ID
    assert "test-token" not in failure_path.read_text()
    assert stat.S_IMODE(failure_path.stat().st_mode) == 0o600


def test_wrangler_failure_after_possible_mutation_rolls_back_and_records(tmp_path):
    api = FakeApi()
    preview = plan(api)

    def runner(command, **_kwargs):
        api.current = NEW_ID
        return subprocess.CompletedProcess(command, 1, "", "failed")

    output = private_path(tmp_path, "wrangler-failed.json")
    with pytest.raises(pages.ReleaseError, match="automatic rollback verified"):
        pages.apply_deploy(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            expected_plan_sha256=preview["plan_sha256"],
            output=output,
            api=api,
            source_provider=source_provider,
            source_materializer=source_materializer,
            toolchain_provider=toolchain_provider,
            runner=runner,
            environment=write_environment(),
            now=lambda: "2026-07-10T22:01:00Z",
        )
    failure = json.loads(pages.deploy_failure_path(output).read_text())
    assert failure["failure_stage"] == "wrangler_invocation"
    assert failure["status"] == "deploy_failed_rolled_back"
    assert api.current == PRIOR_ID


def test_deploy_failure_records_critical_unverified_state_when_rollback_fails(
    tmp_path,
):
    api = RollbackFailureApi()
    preview = plan(api)

    def runner(command, **_kwargs):
        api.current = NEW_ID
        api.deployments[NEW_ID]["deployment_trigger"]["metadata"]["commit_hash"] = (
            "e" * 40
        )
        return subprocess.CompletedProcess(command, 0, "ok", "")

    output = private_path(tmp_path, "rollback-failed.json")
    with pytest.raises(pages.ReleaseError, match="automatic rollback FAILED"):
        pages.apply_deploy(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            expected_plan_sha256=preview["plan_sha256"],
            output=output,
            api=api,
            source_provider=source_provider,
            source_materializer=source_materializer,
            toolchain_provider=toolchain_provider,
            runner=runner,
            environment=write_environment(),
            now=lambda: "2026-07-10T22:02:00Z",
        )
    assert api.current == NEW_ID
    assert api.rollback_calls == [PRIOR_ID]
    failure_path = pages.deploy_failure_path(output)
    failure = json.loads(failure_path.read_text())
    pages.validate_deploy_failure_record(failure)
    assert failure["status"] == "deploy_failed_rollback_failed"
    assert failure["rollback"]["status"] == "failed"
    assert (
        failure["rollback"]["failure_code"]
        == "rollback_request_and_verification_failed"
    )
    assert failure_path.read_bytes() == pages.canonical_bytes(failure)
    assert "simulated rollback outage" not in failure_path.read_text()


def test_deployment_record_publish_failure_still_rolls_back_and_preserves_evidence(
    tmp_path, monkeypatch
):
    api = FakeApi()
    preview = plan(api)

    def runner(command, **_kwargs):
        api.current = NEW_ID
        return subprocess.CompletedProcess(command, 0, "ok", "")

    output = private_path(tmp_path, "record-write-failed.json")
    original_writer = pages.write_canonical_exclusive

    def fail_deployment_record(path, value):
        if path == output:
            raise pages.ReleaseError("simulated deployment record write failure")
        return original_writer(path, value)

    monkeypatch.setattr(pages, "write_canonical_exclusive", fail_deployment_record)
    with pytest.raises(pages.ReleaseError, match="automatic rollback verified"):
        pages.apply_deploy(
            reviewed_sha=NEW_SHA,
            expected_account_id=ACCOUNT,
            expected_plan_sha256=preview["plan_sha256"],
            output=output,
            api=api,
            source_provider=source_provider,
            source_materializer=source_materializer,
            toolchain_provider=toolchain_provider,
            runner=runner,
            environment=write_environment(),
            now=lambda: "2026-07-10T22:03:00Z",
        )
    assert not output.exists()
    assert api.current == PRIOR_ID
    failure = json.loads(pages.deploy_failure_path(output).read_text())
    assert failure["failure_stage"] == "deployment_record_write"
    assert failure["deployment_record_published"] is False
    assert failure["status"] == "deploy_failed_rolled_back"


def test_canary_consumes_exact_record_and_runs_identity_then_containment(tmp_path):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    commands = []

    def runner(command, **kwargs):
        commands.append(command)
        assert kwargs["env"] == pages._public_canary_environment()
        return subprocess.CompletedProcess(command, 0, "PASS\n", "")

    output = private_path(tmp_path, "canary.json")
    result = pages.run_post_deploy_canary(
        deployment_record_path=record_path,
        expected_record_sha256=deployed["deployment_record_sha256"],
        expected_account_id=ACCOUNT,
        output=output,
        api=api,
        runner=runner,
        environment=write_environment(),
        now=lambda: "2026-07-10T22:05:00Z",
    )
    assert result["status"] == "passed"
    assert len(commands) == 2
    assert commands[0][1].endswith("scripts/ci/release_identity_check.py")
    assert commands[0][-2:] == ("--expected-sha", NEW_SHA)
    assert commands[1][1].endswith("scripts/monitoring/backend_recovery_canary.py")
    canary = json.loads(output.read_text())
    assert canary["deployment_record_sha256"] == deployed["deployment_record_sha256"]
    assert canary["deployment_id"] == NEW_ID
    assert output.read_bytes() == pages.canonical_bytes(canary)


def test_canary_rejects_record_hash_or_stale_canonical_deployment_before_commands(
    tmp_path,
):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not execute")

    with pytest.raises(pages.ReleaseError, match="reviewed canary input"):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256="0" * 64,
            expected_account_id=ACCOUNT,
            output=private_path(tmp_path, "wrong-hash.json"),
            api=api,
            runner=runner,
            environment=write_environment(),
        )
    assert called is False

    api.current = PRIOR_ID
    with pytest.raises(pages.ReleaseError, match="no longer the canonical"):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            output=private_path(tmp_path, "stale.json"),
            api=api,
            runner=runner,
            environment=write_environment(),
        )
    assert called is False


def test_failed_canary_writes_failure_evidence_then_fails(tmp_path):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    calls = 0

    def runner(command, **_kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            command, 1 if calls == 1 else 0, "", "failed"
        )

    output = private_path(tmp_path, "failed-canary.json")
    with pytest.raises(pages.ReleaseError, match="post-deploy canary failed"):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            output=output,
            api=api,
            runner=runner,
            environment=write_environment(),
        )
    evidence = json.loads(output.read_text())
    assert evidence["status"] == "failed_rolled_back"
    assert [check["exit_code"] for check in evidence["checks"]] == [1, 0]
    assert evidence["rollback"]["target_deployment"]["deployment_id"] == PRIOR_ID
    assert evidence["rollback"]["canonical_deployment"]["deployment_id"] == PRIOR_ID
    assert api.rollback_calls == [PRIOR_ID]
    assert api.current == PRIOR_ID


def test_canary_execution_error_is_evidence_and_triggers_rollback(tmp_path):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    calls = 0

    def runner(command, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated execution failure")
        return subprocess.CompletedProcess(command, 0, "PASS", "")

    output = private_path(tmp_path, "canary-execution-error.json")
    with pytest.raises(pages.ReleaseError, match="automatic rollback verified"):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            output=output,
            api=api,
            runner=runner,
            environment=write_environment(),
            now=lambda: "2026-07-10T22:06:00Z",
        )
    evidence = json.loads(output.read_text())
    assert [check["exit_code"] for check in evidence["checks"]] == [-1000, 0]
    assert evidence["status"] == "failed_rolled_back"
    assert api.current == PRIOR_ID


def test_canary_rollback_failure_is_critical_canonical_evidence(tmp_path):
    api = RollbackFailureApi()
    record_path, deployed = deploy_record(tmp_path, api)

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 1, "", "failed")

    output = private_path(tmp_path, "canary-rollback-failed.json")
    with pytest.raises(pages.ReleaseError, match="automatic rollback FAILED"):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            output=output,
            api=api,
            runner=runner,
            environment=write_environment(),
            now=lambda: "2026-07-10T22:07:00Z",
        )
    assert api.current == NEW_ID
    assert api.rollback_calls == [PRIOR_ID]
    evidence = json.loads(output.read_text())
    pages.validate_canary_record(evidence)
    assert evidence["status"] == "failed_rollback_failed"
    assert evidence["rollback"]["status"] == "failed"
    assert output.read_bytes() == pages.canonical_bytes(evidence)
    assert "simulated rollback outage" not in output.read_text()


@pytest.mark.parametrize(
    ("expected_account", "environment", "message"),
    [
        (ACCOUNT, {}, pages.WRITE_ENV),
        ("d" * 32, {pages.WRITE_ENV: "1"}, "another Cloudflare account"),
    ],
)
def test_canary_requires_exact_account_and_rollback_write_authorization(
    tmp_path, expected_account, environment, message
):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("must not run")

    with pytest.raises(pages.ReleaseError, match=message):
        pages.run_post_deploy_canary(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=expected_account,
            output=private_path(tmp_path, f"blocked-{expected_account[0]}.json"),
            api=api,
            runner=runner,
            environment=environment,
        )
    assert called is False
    assert api.rollback_calls == []
    assert api.current == NEW_ID


def test_rollback_preview_and_apply_target_only_recorded_prior_deployment(tmp_path):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    preview = pages.rollback_plan(
        deployment_record_path=record_path,
        expected_record_sha256=deployed["deployment_record_sha256"],
        expected_account_id=ACCOUNT,
        api=api,
    )
    assert preview["plan"]["from_deployment"]["deployment_id"] == NEW_ID
    assert preview["plan"]["target_deployment"]["deployment_id"] == PRIOR_ID
    assert preview["plan_sha256"] == pages.canonical_sha256(preview["plan"])
    assert api.rollback_calls == []

    output = private_path(tmp_path, "rollback.json")
    result = pages.apply_rollback(
        deployment_record_path=record_path,
        expected_record_sha256=deployed["deployment_record_sha256"],
        expected_account_id=ACCOUNT,
        expected_plan_sha256=preview["plan_sha256"],
        output=output,
        api=api,
        environment={pages.WRITE_ENV: "1"},
        now=lambda: "2026-07-10T22:10:00Z",
    )
    assert api.rollback_calls == [PRIOR_ID]
    assert api.current == PRIOR_ID
    assert result["target_deployment_id"] == PRIOR_ID
    rollback = json.loads(output.read_text())
    pages.validate_rollback_record(rollback)
    assert rollback["target_deployment"] == rollback["api_result_deployment"]
    assert output.read_bytes() == pages.canonical_bytes(rollback)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_rollback_requires_current_recorded_deployment_write_env_and_exact_preview(
    tmp_path,
):
    api = FakeApi()
    record_path, deployed = deploy_record(tmp_path, api)
    preview = pages.rollback_plan(
        deployment_record_path=record_path,
        expected_record_sha256=deployed["deployment_record_sha256"],
        expected_account_id=ACCOUNT,
        api=api,
    )
    with pytest.raises(pages.ReleaseError, match=pages.WRITE_ENV):
        pages.apply_rollback(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            expected_plan_sha256=preview["plan_sha256"],
            output=private_path(tmp_path, "no-write.json"),
            api=api,
            environment={},
        )
    assert api.rollback_calls == []

    with pytest.raises(pages.ReleaseError, match="exact preview"):
        pages.apply_rollback(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            expected_plan_sha256="0" * 64,
            output=private_path(tmp_path, "wrong-plan.json"),
            api=api,
            environment={pages.WRITE_ENV: "1"},
        )
    assert api.rollback_calls == []

    api.current = PRIOR_ID
    with pytest.raises(pages.ReleaseError, match="no longer the canonical"):
        pages.rollback_plan(
            deployment_record_path=record_path,
            expected_record_sha256=deployed["deployment_record_sha256"],
            expected_account_id=ACCOUNT,
            api=api,
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda record: record.update(account_id="d" * 32), ""),
        (
            lambda record: record["new_deployment"].update(release_sha=PRIOR_SHA),
            "inconsistent",
        ),
        (
            lambda record: record["new_deployment"].update(commit_dirty=True),
            "clean production",
        ),
        (lambda record: record["source"].update(site_archive_sha256="bad"), "SHA-256"),
        (
            lambda record: record["toolchain"].update(wrangler_version="latest"),
            "pinned runtime",
        ),
        (lambda record: record.update(post_deploy_canary="passed"), "state/project"),
    ],
)
def test_deployment_record_validator_rejects_nested_mutations(
    tmp_path, mutator, message
):
    api = FakeApi()
    record_path, _deployed = deploy_record(tmp_path, api)
    record = json.loads(record_path.read_text())
    mutator(record)
    if message:
        with pytest.raises(pages.ReleaseError, match=message):
            pages.validate_deployment_record(record)
    else:
        # A different well-formed account remains structurally valid; the live
        # canary/rollback exact-account comparison rejects it.
        assert pages.validate_deployment_record(record)["account_id"] == "d" * 32


def test_record_reader_rejects_group_readable_noncanonical_and_symlink(tmp_path):
    api = FakeApi()
    record_path, _deployed = deploy_record(tmp_path, api)
    record_path.chmod(0o640)
    with pytest.raises(pages.ReleaseError, match="owner-only"):
        pages.read_canonical_record(record_path, "deployment record")
    record_path.chmod(0o600)
    payload = json.loads(record_path.read_text())
    record_path.write_text(json.dumps(payload, indent=2))
    with pytest.raises(pages.ReleaseError, match="not canonical"):
        pages.read_canonical_record(record_path, "deployment record")
    record_path.write_bytes(pages.canonical_bytes(payload))
    linked = private_path(tmp_path, "linked.json")
    linked.symlink_to(record_path)
    with pytest.raises(pages.ReleaseError, match="unavailable or unsafe"):
        pages.read_canonical_record(linked, "deployment record")


class FakeResponse:
    def __init__(self, payload):
        self.status = 200
        self._raw = json.dumps(
            {"success": True, "errors": [], "result": payload}
        ).encode()

    def read(self, _limit):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_minimal_api_client_uses_only_exact_project_deployment_and_rollback_paths():
    requests = []
    payloads = [
        {"name": pages.PROJECT_NAME},
        deployment(PRIOR_ID, PRIOR_SHA, "prior"),
        deployment(PRIOR_ID, PRIOR_SHA, "prior"),
    ]

    def opener(request, timeout):
        requests.append((request, timeout))
        return FakeResponse(payloads.pop(0))

    client = pages.CloudflareApi(ACCOUNT, "test-token-value-1234567890", opener=opener)
    client.get_project()
    client.get_deployment(PRIOR_ID)
    client.rollback(PRIOR_ID)

    assert [request.get_method() for request, _timeout in requests] == [
        "GET",
        "GET",
        "POST",
    ]
    assert requests[0][0].full_url == (
        f"{pages.API_ORIGIN}/accounts/{ACCOUNT}/pages/projects/{pages.PROJECT_NAME}"
    )
    deployment_url = (
        f"{pages.API_ORIGIN}/accounts/{ACCOUNT}/pages/projects/{pages.PROJECT_NAME}"
        f"/deployments/{PRIOR_ID}"
    )
    assert requests[1][0].full_url == deployment_url
    assert requests[2][0].full_url == deployment_url + "/rollback"
    assert requests[2][0].data == b"{}"
    assert all(
        request.headers["Authorization"] == "Bearer test-token-value-1234567890"
        for request, _timeout in requests
    )


def git(repo, *arguments, env=None):
    command = [shutil.which("git") or "git", "-C", str(repo), *arguments]
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def source_repo(tmp_path):
    repo = tmp_path / "repo"
    site = repo / "site"
    site.mkdir(parents=True)
    (site / "wrangler.toml").write_text(
        'name = "tinyzkp"\ncompatibility_date = "2025-12-01"\npages_build_output_dir = "."\n'
    )
    (site / "_worker.js").write_text(
        "export default { fetch() { return new Response('ok'); } };\n"
    )
    (site / "index.html").write_text("<!doctype html><title>TinyZKP</title>\n")
    git(repo, "init")
    git(repo, "config", "user.email", "test@invalid.example")
    git(repo, "config", "user.name", "Test")
    git(repo, "add", "site")
    commit_env = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-07-10T20:00:00Z",
        "GIT_COMMITTER_DATE": "2026-07-10T20:00:00Z",
    }
    git(repo, "commit", "-m", "site", env=commit_env)
    return repo, git(repo, "rev-parse", "HEAD")


def test_git_source_inspector_binds_clean_reviewed_sha_and_sealed_materialization(
    tmp_path,
):
    repo, release = source_repo(tmp_path)
    git_path = Path(shutil.which("git") or "/usr/bin/git")
    identity = pages.inspect_site_source(repo, release, git=git_path)
    assert identity["release_sha"] == release
    assert identity["site_file_count"] == 3
    assert pages.SHA256.fullmatch(identity["site_archive_sha256"])
    with pages.materialized_site_source(repo, release, identity, git=git_path) as (
        source,
        home,
    ):
        assert (source / "index.html").read_text().startswith("<!doctype")
        assert stat.S_IMODE(source.stat().st_mode) == 0o500
        assert stat.S_IMODE((source / "index.html").stat().st_mode) == 0o400
        assert stat.S_IMODE(home.stat().st_mode) == 0o700


def test_git_source_inspector_rejects_wrong_head_dirty_untracked_and_symlink(tmp_path):
    repo, release = source_repo(tmp_path)
    git_path = Path(shutil.which("git") or "/usr/bin/git")
    (repo / "README").write_text("new head\n")
    git(repo, "add", "README")
    git(repo, "commit", "-m", "new head")
    with pytest.raises(pages.ReleaseError, match="Git HEAD"):
        pages.inspect_site_source(repo, release, git=git_path)
    git(repo, "reset", "--hard", release)

    (repo / "site" / "index.html").write_text("dirty")
    with pytest.raises(pages.ReleaseError, match="site source has"):
        pages.inspect_site_source(repo, release, git=git_path)
    git(repo, "restore", "site/index.html")
    (repo / "site" / "untracked.txt").write_text("untracked")
    with pytest.raises(pages.ReleaseError, match="site source has"):
        pages.inspect_site_source(repo, release, git=git_path)
    (repo / "site" / "untracked.txt").unlink()

    (repo / "site" / "linked").symlink_to("index.html")
    git(repo, "add", "site/linked")
    git(repo, "commit", "-m", "link")
    linked_release = git(repo, "rev-parse", "HEAD")
    with pytest.raises(pages.ReleaseError, match="link or special"):
        pages.inspect_site_source(repo, linked_release, git=git_path)
