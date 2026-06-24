#!/usr/bin/env python3
"""Validate production env coherence before a TinyZKP deploy.

This is intentionally stricter than individual binaries. A binary can support a
partial switch for staging, but production deploys should refuse incoherent
state-cutover combinations before containers restart.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import subprocess
import sys


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_env_file(path: pathlib.Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        env[key] = _strip_quotes(value)
    return env


def merged_env(path: pathlib.Path) -> dict[str, str]:
    env = load_env_file(path)
    for key, value in os.environ.items():
        if (
            key.startswith("HC_")
            or key.startswith("TINYZKP_")
            or key in {"COMPOSE_PROFILES", "STRIPE_SECRET_KEY", "INTERNAL_SECRET"}
        ):
            env[key] = value
    return env


def _value(env: dict[str, str], key: str) -> str:
    return env.get(key, "").strip()


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_set(env: dict[str, str], key: str) -> bool:
    return bool(_value(env, key))


def _mode(env: dict[str, str], key: str, default: str) -> str:
    return (_value(env, key) or default).lower()


def _placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered == ""
        or "changeme" in lowered
        or "change_me" in lowered
        or "xxx" in lowered
    )


def check_env(
    env: dict[str, str],
    *,
    check_host_python: bool = False,
    host_python: str | None = None,
    production: bool = False,
) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    warnings: list[str] = []

    server_pg = _value(env, "HC_SERVER_PG_URL")
    tenant_pg = _value(env, "HC_TENANT_PG_URL") or _value(env, "HC_SERVER_AUTH_PG_URL")
    shared_dispatch = _mode(env, "HC_SERVER_PROVE_DISPATCH", "local") == "shared"
    job_index_source = _mode(env, "HC_SERVER_JOB_INDEX_SOURCE", "sqlite")
    usage_read_source = _mode(env, "HC_SERVER_USAGE_READ_FROM", "sqlite")
    usage_source = _mode(env, "HC_USAGE_SOURCE", "sqlite")
    auth_pg_enabled = _is_set(env, "HC_SERVER_AUTH_PG_URL")
    tenant_pg_required = _truthy(_value(env, "HC_TENANT_PG_REQUIRED"))
    compose_profiles = {
        part.strip()
        for part in _value(env, "COMPOSE_PROFILES").split(",")
        if part.strip()
    }

    if usage_read_source == "postgres" and not server_pg:
        failures.append("HC_SERVER_USAGE_READ_FROM=postgres requires HC_SERVER_PG_URL")
    if usage_source == "postgres" and not server_pg:
        failures.append("HC_USAGE_SOURCE=postgres requires HC_SERVER_PG_URL")
    if usage_read_source not in {"sqlite", "postgres"}:
        failures.append("HC_SERVER_USAGE_READ_FROM must be sqlite or postgres")
    if usage_source not in {"sqlite", "postgres"}:
        failures.append("HC_USAGE_SOURCE must be sqlite or postgres")

    if job_index_source == "postgres" and not (_is_set(env, "HC_JOB_INDEX_PG_URL") or server_pg):
        failures.append("HC_SERVER_JOB_INDEX_SOURCE=postgres requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL")
    if job_index_source not in {"sqlite", "postgres", "disabled"}:
        failures.append("HC_SERVER_JOB_INDEX_SOURCE must be sqlite, postgres, or disabled")

    if shared_dispatch:
        if job_index_source != "postgres":
            failures.append("HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres")
        if not (_is_set(env, "HC_JOB_INDEX_PG_URL") or server_pg):
            failures.append("HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL")
        if not (_is_set(env, "HC_JOB_WORKER_USAGE_PG_URL") or server_pg):
            failures.append("HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_WORKER_USAGE_PG_URL or HC_SERVER_PG_URL")
    elif "shared-workers" in compose_profiles:
        warnings.append("COMPOSE_PROFILES includes shared-workers while HC_SERVER_PROVE_DISPATCH is not shared")

    if tenant_pg_required and not tenant_pg:
        failures.append("HC_TENANT_PG_REQUIRED=1 requires HC_TENANT_PG_URL or HC_SERVER_AUTH_PG_URL")
    if auth_pg_enabled:
        if not tenant_pg:
            failures.append("HC_SERVER_AUTH_PG_URL requires HC_TENANT_PG_URL or shared fallback")
        if not tenant_pg_required and not _truthy(_value(env, "TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN")):
            failures.append(
                "HC_SERVER_AUTH_PG_URL requires HC_TENANT_PG_REQUIRED=1 "
                "(or TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN=1 for a staging observation deploy)"
            )

    if _is_set(env, "HC_RATE_LIMIT_PG_URL") and not server_pg:
        warnings.append("HC_RATE_LIMIT_PG_URL is set without HC_SERVER_PG_URL; confirm this is a separate Postgres DSN")

    if production:
        required = {
            "STRIPE_SECRET_KEY": "Stripe webhook and billing sync require a live secret key",
            "STRIPE_WEBHOOK_SECRET": "Stripe webhook signature verification requires a webhook secret",
            "INTERNAL_SECRET": "Cloudflare Pages functions and billing webhook must share INTERNAL_SECRET",
            "GRAFANA_ADMIN_PASSWORD": "Grafana must not deploy with a blank/default admin password",
        }
        if (
            _placeholder(_value(env, "HC_SERVER_API_KEYS"))
            and _placeholder(_value(env, "HC_SERVER_API_KEYS_FILE"))
            and _placeholder(_value(env, "HC_API_KEYS_FILE"))
        ):
            failures.append(
                "HC_SERVER_API_KEYS or an API key file path is missing or still a placeholder: "
                "API tenants need at least one configured key source"
            )
        for key, reason in required.items():
            if _placeholder(_value(env, key)):
                failures.append(f"{key} is missing or still a placeholder: {reason}")

    if (tenant_pg or tenant_pg_required) and check_host_python:
        if host_python:
            try:
                result = subprocess.run(
                    [host_python, "-c", "import psycopg"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except OSError:
                failures.append(f"HC_TENANT_PG_URL mirroring requires psycopg in {host_python}")
            else:
                if result.returncode != 0:
                    failures.append(f"HC_TENANT_PG_URL mirroring requires psycopg in {host_python}")
        elif importlib.util.find_spec("psycopg") is None:
            failures.append("HC_TENANT_PG_URL mirroring requires the host Python package psycopg")

    return failures, warnings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=".env", help="Path to production .env file")
    parser.add_argument(
        "--check-host-python",
        action="store_true",
        help="Also verify host Python has packages required for enabled host-level services",
    )
    parser.add_argument(
        "--host-python",
        help="Python interpreter used by the host billing webhook; checked when --check-host-python is set",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Require production-only secrets and non-placeholder values",
    )
    args = parser.parse_args(argv)

    env_file = pathlib.Path(args.env_file)
    env = merged_env(env_file)
    failures, warnings = check_env(
        env,
        check_host_python=args.check_host_python,
        host_python=args.host_python,
        production=args.production,
    )

    for warning in warnings:
        print(f"WARN  {warning}")
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print(f"PASS  deploy readiness ({env_file})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
