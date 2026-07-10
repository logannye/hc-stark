#!/usr/bin/env python3
"""Validate TinyZKP Docker Compose render paths used by operators and CI."""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class ComposeScenario:
    name: str
    files: tuple[str, ...]
    env: dict[str, str]
    required_services: frozenset[str]
    forbidden_services: frozenset[str] = frozenset()


BASE_ENV: dict[str, str] = {}

PROD_ENV = BASE_ENV

BASE_SERVICES = frozenset(
    {
        "hc-server",
        "hc-mcp",
    }
)

SCENARIOS = (
    ComposeScenario(
        name="local",
        files=("docker-compose.yml",),
        env=BASE_ENV,
        required_services=BASE_SERVICES,
        forbidden_services=frozenset({"hc-job-worker", "prometheus", "grafana", "alertmanager"}),
    ),
    ComposeScenario(
        name="production",
        files=("docker-compose.yml", "deploy/hetzner/docker-compose.prod.yml"),
        env=PROD_ENV,
        required_services=BASE_SERVICES,
        forbidden_services=frozenset({"hc-job-worker", "prometheus", "grafana", "alertmanager"}),
    ),
)


def compose_command(files: tuple[str, ...], *args: str) -> list[str]:
    command = ["docker", "compose"]
    for file in files:
        command.extend(["-f", file])
    command.extend(args)
    return command


def scenario_env(scenario: ComposeScenario) -> dict[str, str]:
    env = os.environ.copy()
    env.update(scenario.env)
    return env


def run_compose(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def validate_services(scenario: ComposeScenario, services: set[str]) -> list[str]:
    failures: list[str] = []
    missing = sorted(scenario.required_services - services)
    unexpected = sorted(scenario.forbidden_services & services)
    if missing:
        failures.append(f"{scenario.name}: missing services: {', '.join(missing)}")
    if unexpected:
        failures.append(f"{scenario.name}: unexpected services: {', '.join(unexpected)}")
    return failures


def check_scenario(scenario: ComposeScenario) -> tuple[list[str], list[str]]:
    env = scenario_env(scenario)
    failures: list[str] = []
    warnings: list[str] = []

    render = run_compose(compose_command(scenario.files, "config"), env)
    if render.returncode != 0:
        failures.append(f"{scenario.name}: docker compose config failed\n{render.stderr.strip()}")
        return failures, warnings
    if render.stderr.strip():
        warnings.append(f"{scenario.name}: docker compose config stderr: {render.stderr.strip()}")

    services_result = run_compose(compose_command(scenario.files, "config", "--services"), env)
    if services_result.returncode != 0:
        failures.append(f"{scenario.name}: docker compose config --services failed\n{services_result.stderr.strip()}")
        return failures, warnings
    if services_result.stderr.strip():
        warnings.append(f"{scenario.name}: docker compose config --services stderr: {services_result.stderr.strip()}")

    services = {line.strip() for line in services_result.stdout.splitlines() if line.strip()}
    failures.extend(validate_services(scenario, services))
    return failures, warnings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=[scenario.name for scenario in SCENARIOS],
        action="append",
        help="Scenario to check. Defaults to all scenarios.",
    )
    args = parser.parse_args(argv)

    selected = [scenario for scenario in SCENARIOS if not args.scenario or scenario.name in args.scenario]
    failures: list[str] = []
    warnings: list[str] = []
    for scenario in selected:
        scenario_failures, scenario_warnings = check_scenario(scenario)
        failures.extend(scenario_failures)
        warnings.extend(scenario_warnings)
        if not scenario_failures:
            print(f"PASS  compose config: {scenario.name}")

    for warning in warnings:
        print(f"WARN  {warning}")
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
