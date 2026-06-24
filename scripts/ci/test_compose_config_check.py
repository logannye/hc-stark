import subprocess

import compose_config_check as compose


def test_compose_command_layers_files_before_args():
    assert compose.compose_command(("docker-compose.yml", "deploy/hetzner/docker-compose.prod.yml"), "config") == [
        "docker",
        "compose",
        "-f",
        "docker-compose.yml",
        "-f",
        "deploy/hetzner/docker-compose.prod.yml",
        "config",
    ]


def test_validate_services_rejects_missing_required_service():
    failures = compose.validate_services(compose.SCENARIOS[0], {"hc-server"})
    assert "local: missing services:" in "\n".join(failures)
    assert "hc-mcp" in "\n".join(failures)


def test_validate_services_rejects_profile_worker_without_shared_profile():
    failures = compose.validate_services(compose.SCENARIOS[0], set(compose.BASE_SERVICES) | {"hc-job-worker"})
    assert "local: unexpected services: hc-job-worker" in failures


def test_shared_worker_scenario_requires_worker_service():
    failures = compose.validate_services(compose.SCENARIOS[2], set(compose.BASE_SERVICES))
    assert "production-shared-workers: missing services: hc-job-worker" in failures


def test_check_scenario_runs_render_and_service_commands(monkeypatch):
    calls = []

    def fake_run(command, cwd, env, text, stdout, stderr, check):
        calls.append((command, env))
        if command[-1] == "--services":
            return subprocess.CompletedProcess(command, 0, stdout="\n".join(sorted(compose.BASE_SERVICES)), stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="rendered: true\n", stderr="")

    monkeypatch.setattr(compose.subprocess, "run", fake_run)
    failures, warnings = compose.check_scenario(compose.SCENARIOS[1])

    assert failures == []
    assert warnings == []
    assert calls[0][0] == compose.compose_command(compose.SCENARIOS[1].files, "config")
    assert calls[1][0] == compose.compose_command(compose.SCENARIOS[1].files, "config", "--services")
    assert calls[0][1]["HC_SERVER_API_KEYS"] == "tenant:tzk_dummy_key"
    assert calls[0][1]["HC_METRICS_TOKEN"] == "dummy-metrics-token"


def test_check_scenario_surfaces_compose_failure(monkeypatch):
    def fake_run(command, cwd, env, text, stdout, stderr, check):
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="bad compose")

    monkeypatch.setattr(compose.subprocess, "run", fake_run)
    failures, _warnings = compose.check_scenario(compose.SCENARIOS[0])

    assert failures == ["local: docker compose config failed\nbad compose"]
