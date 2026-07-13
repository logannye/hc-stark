from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path(__file__).with_name("switch-beta-route.sh")
SHA = "a" * 40


def executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def route_environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
    route = tmp_path / "tinyzkp-beta-route.caddy"
    caddyfile = tmp_path / "Caddyfile"
    containment = tmp_path / "Caddyfile.tinyzkp-containment"
    route.write_text("previous route\n", encoding="utf-8")
    caddyfile.write_text("previous caddy\n", encoding="utf-8")
    containment.write_text("containment caddy\n", encoding="utf-8")
    tools = tmp_path / "bin"
    tools.mkdir()
    executable(tools / "flock", "#!/bin/sh\nexit 0\n")
    executable(
        tools / "caddy",
        """#!/bin/sh
set -eu
count_file="$TINYZKP_ROUTE_TEST_ROOT/caddy-count"
count=0
test ! -f "$count_file" || count=$(cat "$count_file")
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"
test "${FAIL_CADDY_VALIDATE_ON_CALL:-0}" != "$count"
""",
    )
    executable(
        tools / "systemctl",
        """#!/bin/sh
set -eu
count_file="$TINYZKP_ROUTE_TEST_ROOT/reload-count"
count=0
test ! -f "$count_file" || count=$(cat "$count_file")
count=$((count + 1))
printf '%s\n' "$count" >"$count_file"
test "${FAIL_RELOAD_ON_CALL:-0}" != "$count"
""",
    )
    executable(
        tools / "curl",
        """#!/bin/sh
set -eu
url=''
for argument in "$@"; do
  case "$argument" in http://*|https://*) url="$argument" ;; esac
done
if test "${FAIL_EXTERNAL_HEALTH:-0}" = 1 && test "$url" = https://api.tinyzkp.com/healthz; then
  exit 22
fi
case "$*" in
  *--write-out*) printf '503' ;;
  *) printf '{"release_sha":"%s","service_status":"public_beta"}' "$EXPECTED_TEST_SHA" ;;
esac
""",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{tools}:{environment['PATH']}",
            "TMPDIR": str(tmp_path),
            "TINYZKP_ROUTE_TEST_MODE": "1",
            "TINYZKP_ROUTE_TEST_ROOT": str(tmp_path),
            "TINYZKP_ROUTE_TARGET_ROUTE": str(route),
            "TINYZKP_ROUTE_TARGET_CADDY": str(caddyfile),
            "TINYZKP_ROUTE_CONTAINMENT_CADDY": str(containment),
            "TINYZKP_ROUTE_LOCK": str(tmp_path / "route.lock"),
            "EXPECTED_TEST_SHA": SHA,
        }
    )
    return environment, route, caddyfile


def invoke(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), "public", SHA, "public_beta"],
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    ("failure", "value"),
    (
        ("FAIL_CADDY_VALIDATE_ON_CALL", "1"),
        ("FAIL_RELOAD_ON_CALL", "1"),
        ("FAIL_EXTERNAL_HEALTH", "1"),
    ),
)
def test_route_transaction_restores_both_files_after_failure(
    route_environment: tuple[dict[str, str], Path, Path], failure: str, value: str
) -> None:
    environment, route, caddyfile = route_environment
    before = (route.read_bytes(), caddyfile.read_bytes())
    environment[failure] = value

    result = invoke(environment)

    assert result.returncode != 0
    assert (route.read_bytes(), caddyfile.read_bytes()) == before
    assert "restoring the previous configuration" in result.stderr


def test_route_transaction_commits_only_after_external_checks(
    route_environment: tuple[dict[str, str], Path, Path]
) -> None:
    environment, route, caddyfile = route_environment

    result = invoke(environment)

    assert result.returncode == 0, result.stderr
    assert "tinyzkp_beta_write_backend" in route.read_text(encoding="utf-8")
    assert "tinyzkp-beta-route.caddy" in caddyfile.read_text(encoding="utf-8")
    assert "transaction committed" in result.stdout
