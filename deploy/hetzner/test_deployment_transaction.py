from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "hetzner" / "deployment_transaction.py"
SPEC = importlib.util.spec_from_file_location("deployment_transaction", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
transaction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transaction)


class FakeRunner:
    def __init__(self) -> None:
        self.images: dict[str, str] = {}
        self.containers = {"hc-server": "", "hc-mcp": ""}
        self.container_ids = {"hc-server": "1" * 12, "hc-mcp": "2" * 12}
        self.services: dict[str, dict[str, object]] = {
            "caddy.service": {"active": "active", "enabled": True},
            "hc-billing-webhook.service": {"active": "active", "enabled": True},
            "hc-stark.service": {"active": "inactive", "enabled": False},
        }
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.fail_caddy_validation = False
        self.fail_systemd_validation = False

    def add_release(self, release_sha: str, marker: str) -> None:
        for service, name in transaction.image_names(release_sha).items():
            suffix = "1" if service == "hc-server" else "2"
            self.images[name] = "sha256:" + (marker + suffix)[:1] * 64

    def run(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd
        environment = env or {}
        self.calls.append((command, environment))
        output = ""
        error = ""
        code = 0
        if command[:4] == ("/usr/bin/docker", "image", "inspect", "--format"):
            name = command[-1]
            if name in self.images:
                output = self.images[name] + "\n"
            else:
                code, error = 1, "missing image"
        elif "compose" in command and command[-3:-1] == ("ps", "-q"):
            service = command[-1]
            if self.containers[service]:
                output = self.container_ids[service] + "\n"
        elif command[:3] == ("/usr/bin/docker", "inspect", "--format"):
            container_id = command[-1]
            service = next(
                key for key, value in self.container_ids.items() if value == container_id
            )
            output = self.containers[service] + "\n"
        elif command[:2] == ("/usr/bin/systemctl", "is-active"):
            state = self.services[command[-1]]["active"]
            output = str(state) + "\n"
            code = 0 if state == "active" else 3
        elif command[:2] == ("/usr/bin/systemctl", "is-enabled"):
            enabled = bool(self.services[command[-1]]["enabled"])
            output = ("enabled" if enabled else "disabled") + "\n"
            code = 0 if enabled else 1
        elif command[:2] == ("/usr/bin/caddy", "validate"):
            if self.fail_caddy_validation:
                code, error = 1, "invalid Caddyfile"
        elif command[:2] == ("/usr/bin/systemd-analyze", "verify"):
            if self.fail_systemd_validation:
                code, error = 1, "invalid unit"
        elif "compose" in command and "up" in command:
            release_sha = environment["HC_IMAGE_TAG"]
            for service, name in transaction.image_names(release_sha).items():
                self.containers[service] = self.images[name]
        elif "compose" in command and "stop" in command:
            self.containers = {"hc-server": "", "hc-mcp": ""}
        elif command[:2] == ("/usr/bin/systemctl", "enable"):
            self.services[command[-1]]["enabled"] = True
        elif command[:2] == ("/usr/bin/systemctl", "disable"):
            self.services[command[-1]]["enabled"] = False
        elif command[:2] == ("/usr/bin/systemctl", "start"):
            self.services[command[-1]]["active"] = "active"
        elif command[:2] == ("/usr/bin/systemctl", "restart"):
            self.services[command[-1]]["active"] = "active"
        elif command[:2] == ("/usr/bin/systemctl", "reload"):
            self.services[command[-1]]["active"] = "active"
        elif command[:2] == ("/usr/bin/systemctl", "stop"):
            self.services[command[-1]]["active"] = "inactive"
        elif command == ("/usr/bin/systemctl", "daemon-reload"):
            pass
        else:  # pragma: no cover - makes new production commands explicit
            raise AssertionError(f"unhandled command: {command}")
        return subprocess.CompletedProcess(command, code, output, error)


def _source_bytes(marker: str) -> dict[str, bytes]:
    return {
        "caddy": (
            "# "
            + marker
            + "\napi.tinyzkp.com { reverse_proxy 127.0.0.1:8080 }\n"
            + "mcp.tinyzkp.com { reverse_proxy 127.0.0.1:3001 }\n"
            + "webhook.tinyzkp.com { reverse_proxy 127.0.0.1:5001 }\n"
        ).encode(),
        "systemd": (
            "# "
            + marker
            + "\nUser=tinyzkp-billing\nGroup=tinyzkp-billing\n"
            + "ExecStart=/var/lib/tinyzkp-runtime/billing-venv/bin/gunicorn\n"
            + "NoNewPrivileges=true\nProtectSystem=strict\n"
            + "ReadWritePaths=/opt/hc-stark/data\n"
        ).encode(),
        "cron": (
            "# "
            + marker
            + "\n0 2 * * * root /opt/hc-stark/billing/backup.sh\n"
            + "17 3 * * * tinyzkp-billing /bin/sh -c 'purge-expired --apply'\n"
        ).encode(),
    }


@pytest.fixture
def sandbox(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    sources_root = repo / "configs"
    targets_root = tmp_path / "etc"
    sources_root.mkdir()
    targets_root.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    sources = {key: sources_root / key for key in transaction.CONFIG_SOURCES}
    targets = {key: targets_root / key for key in transaction.CONFIG_TARGETS}
    for key, raw in _source_bytes("release-a").items():
        sources[key].write_bytes(raw)
        targets[key].write_bytes(("old-" + key + "\n").encode())
    return repo, state_root, sources, targets


def _install(
    record: dict[str, object],
    runner: FakeRunner,
    sandbox,
) -> dict[str, object]:
    repo, state_root, sources, targets = sandbox
    return transaction.install_configs(
        str(record["transaction_id"]),
        runner=runner.run,
        repo=repo,
        state_root=state_root,
        config_sources=sources,
        config_targets=targets,
    )


def _begin(release_sha: str, runner: FakeRunner, sandbox) -> dict[str, object]:
    repo, state_root, _sources, targets = sandbox
    return transaction.begin_transaction(
        release_sha,
        "tinyzkp-production-primary",
        runner=runner.run,
        repo=repo,
        state_root=state_root,
        config_targets=targets,
    )


def _commit(
    record: dict[str, object],
    runner: FakeRunner,
    sandbox,
    *,
    health_checker=lambda: None,
):
    repo, state_root, _sources, targets = sandbox
    return transaction.commit_transaction(
        str(record["transaction_id"]),
        runner=runner.run,
        repo=repo,
        state_root=state_root,
        config_targets=targets,
        health_checker=health_checker,
    )


def test_commit_records_immutable_images_configs_services_and_removes_active(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    record = _begin(release_sha, runner, sandbox)
    _install(record, runner, sandbox)
    runner.run(
        (*transaction.COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
        env={"HC_IMAGE_TAG": release_sha},
    )

    known = _commit(record, runner, sandbox)

    _repo, state_root, _sources, targets = sandbox
    assert known["release_sha"] == release_sha
    assert known["services"]["hc-stark.service"] == {
        "active": "inactive",
        "enabled": False,
    }
    assert set(known["configs"]) == set(targets)
    assert not (state_root / transaction.ACTIVE.name).exists()
    on_disk = json.loads((state_root / transaction.KNOWN.name).read_text())
    assert on_disk == known
    assert (state_root / transaction.KNOWN.name).stat().st_mode & 0o777 == 0o600


def test_validation_happens_before_first_config_replacement(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    record = _begin(release_sha, runner, sandbox)
    _repo, _state_root, _sources, targets = sandbox
    before = {key: path.read_bytes() for key, path in targets.items()}
    runner.fail_systemd_validation = True

    with pytest.raises(transaction.TransactionError, match="validation failed"):
        _install(record, runner, sandbox)

    assert {key: path.read_bytes() for key, path in targets.items()} == before


def test_first_failed_deploy_restores_configs_but_stops_all_backend_surfaces(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    record = _begin(release_sha, runner, sandbox)
    _repo, state_root, _sources, targets = sandbox
    before = {key: path.read_bytes() for key, path in targets.items()}
    _install(record, runner, sandbox)
    runner.run(
        (*transaction.COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
        env={"HC_IMAGE_TAG": release_sha},
    )

    rolled_back = transaction.rollback_transaction(
        target_release_sha=None,
        runner=runner.run,
        repo=sandbox[0],
        state_root=state_root,
        config_targets=targets,
    )

    assert rolled_back["rollback_disposition"] == "failed_closed_no_prior"
    assert {key: path.read_bytes() for key, path in targets.items()} == before
    assert runner.containers == {"hc-server": "", "hc-mcp": ""}
    assert runner.services["hc-billing-webhook.service"]["active"] == "inactive"
    assert not (state_root / transaction.ACTIVE.name).exists()


def test_rollback_accepts_only_exact_recorded_prior_known_release(sandbox):
    release_a = "a" * 40
    release_b = "b" * 40
    runner = FakeRunner()
    runner.add_release(release_a, "a")
    runner.add_release(release_b, "b")
    first = _begin(release_a, runner, sandbox)
    _install(first, runner, sandbox)
    runner.run(
        (*transaction.COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
        env={"HC_IMAGE_TAG": release_a},
    )
    _commit(first, runner, sandbox)
    _repo, state_root, sources, targets = sandbox
    prior_configs = {key: path.read_bytes() for key, path in targets.items()}
    for key, raw in _source_bytes("release-b").items():
        sources[key].write_bytes(raw)
    second = _begin(release_b, runner, sandbox)
    _install(second, runner, sandbox)
    runner.run(
        (*transaction.COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
        env={"HC_IMAGE_TAG": release_b},
    )
    # Simulate power loss after commit atomically replaced known-containment but
    # before it durably removed the active transaction marker.
    interrupted_candidate = {
        "schema_version": transaction.SCHEMA_KNOWN,
        "status": "known_containment",
        "release_sha": release_b,
        "deployment_id": "tinyzkp-production-primary",
        "committed_at": "2026-07-10T20:00:00Z",
        "transaction_id": second["transaction_id"],
        "images": second["candidate_images"],
        "configs": transaction._current_config_hashes(targets),
        "services": runner.services,
    }
    transaction._atomic_write(state_root / transaction.KNOWN.name, interrupted_candidate)

    with pytest.raises(transaction.TransactionError, match="not the recorded prior"):
        transaction.rollback_transaction(
            target_release_sha="c" * 40,
            runner=runner.run,
            repo=sandbox[0],
            state_root=state_root,
            config_targets=targets,
        )
    rolled_back = transaction.rollback_transaction(
        target_release_sha=release_a,
        runner=runner.run,
        repo=sandbox[0],
        state_root=state_root,
        config_targets=targets,
    )

    assert rolled_back["rollback_release_sha"] == release_a
    assert {key: path.read_bytes() for key, path in targets.items()} == prior_configs
    assert runner.containers["hc-server"] == runner.images[
        f"tinyzkp/hc-server:{release_a}"
    ]
    assert json.loads((state_root / transaction.KNOWN.name).read_text())["release_sha"] == release_a
    assert not (state_root / transaction.ACTIVE.name).exists()


def test_tampered_active_ledger_is_rejected(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    _begin(release_sha, runner, sandbox)
    _repo, state_root, _sources, targets = sandbox
    active = state_root / transaction.ACTIVE.name
    value = json.loads(active.read_text())
    value["candidate_images"]["hc-server"]["name"] = "tinyzkp/hc-server:latest"
    transaction._atomic_write(active, value)

    with pytest.raises(transaction.TransactionError, match="candidate image identity"):
        transaction.rollback_transaction(
            target_release_sha=None,
            runner=runner.run,
            repo=sandbox[0],
            state_root=state_root,
            config_targets=targets,
        )


def test_commit_cannot_bypass_health_checker(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    record = _begin(release_sha, runner, sandbox)
    _install(record, runner, sandbox)
    runner.run(
        (*transaction.COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
        env={"HC_IMAGE_TAG": release_sha},
    )

    def unhealthy() -> None:
        raise transaction.TransactionError("capabilities are open")

    with pytest.raises(transaction.TransactionError, match="capabilities are open"):
        _commit(record, runner, sandbox, health_checker=unhealthy)
    assert (sandbox[1] / transaction.ACTIVE.name).exists()


def test_group_writable_config_parent_is_rejected_before_snapshot(sandbox):
    release_sha = "a" * 40
    runner = FakeRunner()
    runner.add_release(release_sha, "a")
    sandbox[3]["caddy"].parent.chmod(0o775)

    with pytest.raises(transaction.TransactionError, match="target parent is unsafe"):
        _begin(release_sha, runner, sandbox)


def test_local_containment_requires_exact_error_codes(monkeypatch):
    def request(port, method, path, *, body=None):
        del port, method, body
        if path == "/prove":
            return 503, b'{"code":"wrong"}'
        if path == "/verify":
            return 422, b'{"code":"legacy_statement_unbound"}'
        if path == "/v1/capabilities":
            return 200, (
                b'{"account_creation_enabled":false,"checkout_enabled":false,'
                b'"proving_available":false,"verification_available":false}'
            )
        if path in {"/send-contact", "/contact-readiness"}:
            return 403, b"{}"
        return 200, b"{}"

    monkeypatch.setattr(transaction, "_local_request", request)
    with pytest.raises(transaction.TransactionError, match="code=protocol_upgrade"):
        transaction.verify_local_containment()


def test_local_containment_accepts_strict_fail_closed_contract(monkeypatch):
    def request(port, method, path, *, body=None):
        del port, method, body
        if path == "/prove":
            return 503, b'{"code":"protocol_upgrade"}'
        if path == "/verify":
            return 422, b'{"code":"legacy_statement_unbound"}'
        if path == "/v1/capabilities":
            return 200, (
                b'{"account_creation_enabled":false,"checkout_enabled":false,'
                b'"proving_available":false,"verification_available":false}'
            )
        if path in {"/send-contact", "/contact-readiness"}:
            return 403, b"{}"
        return 200, b"{}"

    monkeypatch.setattr(transaction, "_local_request", request)
    transaction.verify_local_containment()
