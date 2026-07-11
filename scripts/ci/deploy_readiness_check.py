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
import pwd
import re
import shutil
import stat
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))

import backup_env_exec  # noqa: E402


MAX_ENV_BYTES = 64 * 1024
DATA_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
RCLONE_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*:.*$")
STRIPE_LIVE_SECRET = re.compile(r"^sk_live_[A-Za-z0-9]{24,128}$")
STRIPE_WEBHOOK_SECRET = re.compile(r"^whsec_[A-Za-z0-9]{24,128}$")
STRIPE_ACCOUNT_ID = re.compile(r"^acct_[A-Za-z0-9]{16,32}$")
EXECUTION_SCOPED_RELEASE_IDENTITY_KEYS = frozenset(
    {"HC_RELEASE_SHA", "HC_RELEASE_REF", "HC_RELEASE_BUILD_URL"}
)
RELEASE_AUTHORIZATION_KEYS = (
    "TINYZKP_BACKEND_RELEASE_AUTHORIZATION",
    "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256",
    "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE",
    "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256",
)


class ProductionEnvError(ValueError):
    """A production environment file is missing, unsafe, or not data-only."""


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
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        env[key] = _strip_quotes(value)
    return env


def read_private_file(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int,
    exact_mode_0600: bool = False,
) -> bytes:
    """Read one current-owner private regular file through an O_NOFOLLOW fd."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    absolute = path.absolute()
    parent = absolute.parent
    try:
        parent_metadata = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise ProductionEnvError(f"{label} parent is unavailable or unsafe") from error
    if (
        parent.is_symlink()
        or (os.geteuid() == 0 and resolved_parent != parent)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise ProductionEnvError(
            f"{label} parent must be a current-owner, non-writable, symlink-free directory"
        )
    if not hasattr(os, "O_NOFOLLOW"):
        raise ProductionEnvError(f"{label} loading requires O_NOFOLLOW support")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProductionEnvError(
            f"{label} file is unavailable or unsafe: {path}"
        ) from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProductionEnvError(f"{label} file must be a regular non-symlink file")
        if metadata.st_nlink != 1:
            raise ProductionEnvError(f"{label} file must have exactly one hard link")
        if metadata.st_uid != os.geteuid():
            raise ProductionEnvError(f"{label} file must be owned by the current operator")
        mode = stat.S_IMODE(metadata.st_mode)
        if exact_mode_0600 and mode != 0o600:
            raise ProductionEnvError(f"{label} file must have mode 0600")
        if not exact_mode_0600 and mode & 0o077:
            raise ProductionEnvError(f"{label} file must be owner-only (0600 or stricter)")

        content = bytearray()
        while len(content) <= max_bytes:
            chunk = os.read(
                descriptor,
                min(8192, max_bytes + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
    finally:
        os.close(descriptor)

    if not content:
        raise ProductionEnvError(f"{label} file is empty")
    if len(content) > max_bytes:
        limit = "64 KiB" if max_bytes == 64 * 1024 else f"{max_bytes} bytes"
        raise ProductionEnvError(f"{label} file exceeds {limit}")
    return bytes(content)


def load_private_env_file(
    path: pathlib.Path, *, exact_mode_0600: bool = False
) -> dict[str, str]:
    """Read a production env without following links or evaluating shell code."""

    content = read_private_file(
        path,
        label="production env",
        max_bytes=MAX_ENV_BYTES,
        exact_mode_0600=exact_mode_0600,
    )
    return parse_private_env_bytes(content)


def parse_private_env_bytes(content: bytes) -> dict[str, str]:
    """Parse bytes already read from one trusted production-env descriptor."""

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProductionEnvError("production env file must be UTF-8") from error
    if "\x00" in text:
        raise ProductionEnvError("production env file contains a NUL byte")

    env: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = DATA_ASSIGNMENT.fullmatch(line)
        if match is None:
            raise ProductionEnvError(
                f"production env line {line_number} is not a data-only KEY=value assignment"
            )
        key, raw_value = match.groups()
        if key in env:
            raise ProductionEnvError(f"production env key is duplicated: {key}")
        value = raw_value.strip()
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ProductionEnvError(
                    f"production env line {line_number} has an unterminated quoted value"
                )
            value = value[1:-1]
        elif value[-1:] in {"'", '"'}:
            raise ProductionEnvError(
                f"production env line {line_number} has a stray quote"
            )
        if any(ord(character) < 0x20 for character in value):
            raise ProductionEnvError(
                f"production env line {line_number} contains a control character"
            )
        env[key] = value
    return env


def _managed_environment_key(key: str) -> bool:
    return (
        key.startswith("HC_")
        or key.startswith("TINYZKP_")
        or key.startswith("STRIPE_")
        or key.startswith("SMTP_")
        or key.startswith("CONTACT_")
        or key in {"COMPOSE_PROFILES", "INTERNAL_SECRET", "ALERT_WEBHOOK_URL"}
    )


def reject_conflicting_inherited_environment(
    configured: dict[str, str],
    inherited: dict[str, str],
    *,
    keys: set[str] | None = None,
) -> None:
    conflicts = sorted(
        key
        for key, value in inherited.items()
        if _managed_environment_key(key)
        and key not in EXECUTION_SCOPED_RELEASE_IDENTITY_KEYS
        and key in configured
        and (keys is None or key in keys)
        and value != configured[key]
    )
    if conflicts:
        raise ProductionEnvError(
            "inherited environment conflicts with owner-only production env: "
            + ", ".join(conflicts)
        )


def merged_env(path: pathlib.Path, *, production: bool = False) -> dict[str, str]:
    if production:
        env = load_private_env_file(path)
        reject_conflicting_inherited_environment(env, dict(os.environ))
        return env

    env = load_env_file(path)
    for key, value in os.environ.items():
        if _managed_environment_key(key):
            env[key] = value
    return env


def _validate_rclone_remote(remote: str) -> str | None:
    """Verify a configured off-host destination with a read-only directory probe."""

    if RCLONE_REMOTE.fullmatch(remote) is None:
        return "HC_BACKUP_REMOTE must name a configured rclone remote (name:path)"
    executable = shutil.which("rclone")
    if executable is None:
        return "HC_BACKUP_REMOTE requires rclone on the production host"
    try:
        read_private_file(
            backup_env_exec.FIXED_RCLONE_CONFIG,
            label="rclone config",
            max_bytes=64 * 1024,
            exact_mode_0600=True,
        )
    except ProductionEnvError as error:
        return f"fixed rclone config is unsafe: {error}"
    probe_environment = {
        "PATH": backup_env_exec.FIXED_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "RCLONE_CONFIG": str(backup_env_exec.FIXED_RCLONE_CONFIG),
    }
    try:
        result = subprocess.run(
            [executable, "lsd", "--max-depth", "1", remote],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env=probe_environment,
        )
    except subprocess.TimeoutExpired:
        return "HC_BACKUP_REMOTE read-only rclone probe timed out"
    except OSError:
        return "HC_BACKUP_REMOTE read-only rclone probe could not run"
    if result.returncode != 0:
        return "HC_BACKUP_REMOTE is not configured, reachable, and readable by rclone"
    return None


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


def _strong_internal_secret(value: str) -> bool:
    return (
        32 <= len(value) <= 256
        and not any(character.isspace() for character in value)
        and len(set(value)) >= 12
    )


def _allowed_private_owner_ids() -> set[int]:
    owners = {os.geteuid()}
    if os.geteuid() == 0:
        try:
            owners.add(pwd.getpwnam("tinyzkp-billing").pw_uid)
        except KeyError:
            pass
    return owners


def _expected_store_owner_ids(key: str) -> set[int]:
    """Match each durable path to the process that actually opens it."""

    current = os.geteuid()
    if current != 0:
        return {current}
    if key == "TINYZKP_CONTRACT_BILLING_LEDGER_PATH":
        return {0}
    if key == "HC_EVALUATION_STORE_PATH":
        try:
            return {pwd.getpwnam("tinyzkp-billing").pw_uid}
        except KeyError:
            return set()
    return {current}


def _validate_private_store_path(raw: str, key: str) -> list[str]:
    """Validate an absolute private file target and its durable parent.

    The billing ledger may not exist until the first reserved operation, so a
    missing leaf is accepted only when its real containing directory already
    exists with owner-only permissions. Existing leaves must be regular,
    non-symlink, owner-only files.
    """

    path = pathlib.Path(raw)
    failures: list[str] = []
    if not path.is_absolute():
        return [f"{key} must be an absolute durable path"]
    parent = path.parent
    try:
        parent_metadata = parent.lstat()
    except OSError:
        return [f"{key} parent directory does not exist: {parent}"]
    owners = _expected_store_owner_ids(key)
    if not owners:
        failures.append(
            f"{key} cannot be validated because tinyzkp-billing does not exist"
        )
    if parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        failures.append(f"{key} parent must be a real non-symlink directory")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        failures.append(f"{key} parent directory must be owner-only (0700 or stricter)")
    if not parent_metadata.st_mode & stat.S_IWUSR:
        failures.append(f"{key} parent directory must be owner-writable")
    if not owners or parent_metadata.st_uid not in owners:
        failures.append(f"{key} parent directory has an unexpected owner")

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return failures
    except OSError:
        failures.append(f"{key} is unavailable or unsafe")
        return failures
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        failures.append(f"{key} must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        failures.append(f"{key} must be owner-only (0600 or stricter)")
    if not metadata.st_mode & stat.S_IWUSR:
        failures.append(f"{key} must be owner-writable")
    if not owners or metadata.st_uid not in owners:
        failures.append(f"{key} has an unexpected owner")
    return failures


def _validate_required_backup_source(path: pathlib.Path, label: str) -> list[str]:
    failures: list[str] = []
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError:
        return [f"required backup source is missing: {label}"]
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        failures.append(f"required backup source parent is unsafe: {label}")
    if parent_metadata.st_uid not in _allowed_private_owner_ids():
        failures.append(f"required backup source parent has an unexpected owner: {label}")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        failures.append(f"required backup source parent must be owner-only: {label}")
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        failures.append(f"required backup source is not a regular file: {label}")
    if metadata.st_nlink != 1:
        failures.append(f"required backup source must have one hard link: {label}")
    if metadata.st_uid not in _allowed_private_owner_ids():
        failures.append(f"required backup source has an unexpected owner: {label}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        failures.append(f"required backup source must be owner-only: {label}")
    return failures


def _validate_backup_source_semantics(
    path: pathlib.Path, label: str, profile: str
) -> list[str]:
    try:
        owner = path.lstat().st_uid
        if profile == "api-keys":
            helper_args = ("validate-api-keys", "--path", str(path))
        else:
            helper_args = (
                "validate-sqlite",
                "--path",
                str(path),
                "--profile",
                profile,
            )
        if os.geteuid() == 0 and owner != 0:
            result = subprocess.run(
                (
                    "/usr/sbin/runuser",
                    "--user",
                    "tinyzkp-billing",
                    "--",
                    "/usr/bin/env",
                    "-i",
                    f"PATH={backup_env_exec.FIXED_PATH}",
                    "LANG=C",
                    "LC_ALL=C",
                    "TZ=UTC",
                    "/usr/bin/python3",
                    str(ROOT / "billing" / "backup_env_exec.py"),
                    *helper_args,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                detail = result.stderr.strip()[-500:]
                return [
                    f"required backup source failed semantic validation: {label}"
                    + (f" ({detail})" if detail else "")
                ]
        else:
            if profile == "api-keys":
                backup_env_exec.validate_api_key_source(path)
            else:
                backup_env_exec.validate_sqlite_source(path, profile)
    except (OSError, subprocess.TimeoutExpired, backup_env_exec.BackupEnvError) as error:
        return [f"required backup source failed semantic validation: {label} ({error})"]
    return []


def _validate_release_authorization(
    env: dict[str, str], *, host_python: str | None
) -> str | None:
    """Run contract_billing's authoritative payload and Sigstore validator."""

    interpreter = host_python or sys.executable
    command = (
        interpreter,
        "-c",
        (
            "import sys; from types import SimpleNamespace; "
            f"sys.path.insert(0, {str(ROOT / 'billing')!r}); "
            "import contract_billing; "
            "binding = contract_billing.validate_release_availability("
            "SimpleNamespace(action='annual-contract')); "
            "assert binding is not None"
        ),
    )
    validator_env = os.environ.copy()
    validator_env.update({key: _value(env, key) for key in RELEASE_AUTHORIZATION_KEYS})
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=validator_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"configured backend release authorization validator failed: {error}"
    if result.returncode != 0:
        detail = result.stdout.strip()[-1200:]
        return (
            "configured backend release authorization failed contract_billing validation"
            + (f": {detail}" if detail else "")
        )
    return None


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

    if job_index_source == "postgres" and not (
        _is_set(env, "HC_JOB_INDEX_PG_URL") or server_pg
    ):
        failures.append(
            "HC_SERVER_JOB_INDEX_SOURCE=postgres requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL"
        )
    if job_index_source not in {"sqlite", "postgres", "disabled"}:
        failures.append(
            "HC_SERVER_JOB_INDEX_SOURCE must be sqlite, postgres, or disabled"
        )

    if shared_dispatch:
        if job_index_source != "postgres":
            failures.append(
                "HC_SERVER_PROVE_DISPATCH=shared requires HC_SERVER_JOB_INDEX_SOURCE=postgres"
            )
        if not (_is_set(env, "HC_JOB_INDEX_PG_URL") or server_pg):
            failures.append(
                "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_INDEX_PG_URL or HC_SERVER_PG_URL"
            )
        if not (_is_set(env, "HC_JOB_WORKER_USAGE_PG_URL") or server_pg):
            failures.append(
                "HC_SERVER_PROVE_DISPATCH=shared requires HC_JOB_WORKER_USAGE_PG_URL or HC_SERVER_PG_URL"
            )
    elif "shared-workers" in compose_profiles:
        warnings.append(
            "COMPOSE_PROFILES includes shared-workers while HC_SERVER_PROVE_DISPATCH is not shared"
        )

    if tenant_pg_required and not tenant_pg:
        failures.append(
            "HC_TENANT_PG_REQUIRED=1 requires HC_TENANT_PG_URL or HC_SERVER_AUTH_PG_URL"
        )
    if auth_pg_enabled:
        if not tenant_pg:
            failures.append(
                "HC_SERVER_AUTH_PG_URL requires HC_TENANT_PG_URL or shared fallback"
            )
        if not tenant_pg_required and not _truthy(
            _value(env, "TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN")
        ):
            failures.append(
                "HC_SERVER_AUTH_PG_URL requires HC_TENANT_PG_REQUIRED=1 "
                "(or TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN=1 for a staging observation deploy)"
            )

    if _is_set(env, "HC_RATE_LIMIT_PG_URL") and not server_pg:
        warnings.append(
            "HC_RATE_LIMIT_PG_URL is set without HC_SERVER_PG_URL; confirm this is a separate Postgres DSN"
        )

    if production:
        required = {
            "STRIPE_SECRET_KEY": "existing-customer webhooks and contract billing require a live secret key",
            "STRIPE_WEBHOOK_SECRET": "Stripe webhook signature verification requires a webhook secret",
            "INTERNAL_SECRET": "Cloudflare Pages functions and billing webhook must share INTERNAL_SECRET",
            "STRIPE_EXPECTED_ACCOUNT_ID": "contract and containment tools require exact account identity",
            "STRIPE_EXPECTED_DISPLAY_NAME": "contract and containment tools require exact account identity",
            "HC_EVALUATION_STORE_PATH": "evaluation applications require a durable owner-only ledger",
            "TINYZKP_CONTRACT_BILLING_LEDGER_PATH": "contract billing requires a durable owner-only operation ledger",
        }
        for key, reason in required.items():
            if _placeholder(_value(env, key)):
                failures.append(f"{key} is missing or still a placeholder: {reason}")
        if STRIPE_LIVE_SECRET.fullmatch(_value(env, "STRIPE_SECRET_KEY")) is None:
            failures.append("STRIPE_SECRET_KEY must be a canonical sk_live_ secret")
        if (
            STRIPE_WEBHOOK_SECRET.fullmatch(_value(env, "STRIPE_WEBHOOK_SECRET"))
            is None
        ):
            failures.append("STRIPE_WEBHOOK_SECRET must be a canonical whsec_ secret")
        if (
            STRIPE_ACCOUNT_ID.fullmatch(_value(env, "STRIPE_EXPECTED_ACCOUNT_ID"))
            is None
        ):
            failures.append("STRIPE_EXPECTED_ACCOUNT_ID must be a canonical acct_ ID")
        if not _strong_internal_secret(_value(env, "INTERNAL_SECRET")):
            failures.append(
                "INTERNAL_SECRET must be 32-256 non-whitespace characters with at least 12 unique characters"
            )
        if _truthy(_value(env, "TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN")):
            failures.append("production forbids TINYZKP_DEPLOY_ALLOW_AUTH_PG_FAIL_OPEN")
        for key in (
            "HC_EVALUATION_STORE_PATH",
            "TINYZKP_CONTRACT_BILLING_LEDGER_PATH",
        ):
            if _is_set(env, key):
                failures.extend(_validate_private_store_path(_value(env, key), key))
        if _value(env, "HC_EVALUATION_STORE_PATH") == _value(
            env, "TINYZKP_CONTRACT_BILLING_LEDGER_PATH"
        ) and _is_set(env, "HC_EVALUATION_STORE_PATH"):
            failures.append(
                "evaluation and contract billing ledgers must use distinct paths"
            )
        backup_data = pathlib.Path(
            _value(env, "HC_BACKUP_DATA_DIR") or backup_env_exec.FIXED_DATA_ROOT
        )
        expected_evaluation = backup_data / "evaluation_applications.sqlite"
        if pathlib.Path(_value(env, "HC_EVALUATION_STORE_PATH")) != expected_evaluation:
            failures.append(
                "HC_EVALUATION_STORE_PATH must match the required backup data store"
            )
        required_backup_sources = {
            "tenant store": (backup_data / "tenant_store.sqlite", "tenant"),
            "usage store": (backup_data / "usage.sqlite", "usage"),
            "evaluation store": (expected_evaluation, "evaluation"),
            "API key store": (backup_data / "api_keys.txt", "api-keys"),
            "contract billing ledger": (
                pathlib.Path(_value(env, "TINYZKP_CONTRACT_BILLING_LEDGER_PATH")),
                "contract",
            ),
        }
        for label, (path, profile) in required_backup_sources.items():
            metadata_failures = _validate_required_backup_source(path, label)
            failures.extend(metadata_failures)
            if not metadata_failures:
                failures.extend(
                    _validate_backup_source_semantics(path, label, profile)
                )

        annual_release_keys = RELEASE_AUTHORIZATION_KEYS
        configured_release_keys = {
            key for key in annual_release_keys if _is_set(env, key)
        }
        if configured_release_keys and configured_release_keys != set(
            annual_release_keys
        ):
            failures.append(
                "annual backend release authorization requires all four path/digest settings"
            )
        elif configured_release_keys:
            release_precheck_failed = False
            for key in (
                "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_SHA256",
                "TINYZKP_BACKEND_RELEASE_AUTHORIZATION_BUNDLE_SHA256",
            ):
                if re.fullmatch(r"[0-9a-f]{64}", _value(env, key)) is None:
                    failures.append(f"{key} must be a lowercase SHA-256 digest")
                    release_precheck_failed = True
            if not release_precheck_failed:
                release_failure = _validate_release_authorization(
                    env, host_python=host_python
                )
                if release_failure:
                    failures.append(release_failure)
        backup_remote = _value(env, "HC_BACKUP_REMOTE")
        backup_http_url = _value(env, "HC_BACKUP_HTTP_URL")
        backup_http_token_file = _value(env, "HC_BACKUP_HTTP_TOKEN_FILE")
        backup_settings = {
            key: env[key]
            for key in backup_env_exec.BACKUP_KEYS
            if key in env and env[key].strip()
        }
        try:
            backup_env_exec.validate_backup_values(backup_settings, production=True)
        except backup_env_exec.BackupEnvError as error:
            failures.append(f"backup configuration is unsafe: {error}")
        if not backup_remote and not (backup_http_url and backup_http_token_file):
            failures.append(
                "off-host backups require HC_BACKUP_REMOTE or both "
                "HC_BACKUP_HTTP_URL and HC_BACKUP_HTTP_TOKEN_FILE"
            )
        if backup_http_url or backup_http_token_file:
            failures.append(
                "production backup evidence currently requires encrypted rclone; "
                "HTTP backup ingest is not release-authorized"
            )
        if bool(backup_http_url) != bool(backup_http_token_file):
            failures.append(
                "HC_BACKUP_HTTP_URL and HC_BACKUP_HTTP_TOKEN_FILE must be configured together"
            )
        if backup_http_url and not backup_http_url.startswith("https://"):
            failures.append("HC_BACKUP_HTTP_URL must use https")
        if backup_http_url and not _truthy(
            _value(env, "HC_BACKUP_HTTP_RETENTION_CONFIRMED")
        ):
            failures.append(
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED=1 is required for HTTP backups"
            )
        if backup_remote and check_host_python:
            remote_failure = _validate_rclone_remote(backup_remote)
            if remote_failure:
                failures.append(remote_failure)
        if check_host_python and os.geteuid() == 0:
            try:
                backup_env_exec.read_loader_token(
                    backup_env_exec.FIXED_LOADER_TOKEN
                )
            except backup_env_exec.BackupEnvError as error:
                failures.append(f"backup loader token is unsafe: {error}")
            try:
                staging = backup_env_exec.FIXED_STAGING_ROOT.lstat()
                service_gid = pwd.getpwnam("tinyzkp-billing").pw_gid
                if (
                    backup_env_exec.FIXED_STAGING_ROOT.is_symlink()
                    or not stat.S_ISDIR(staging.st_mode)
                    or staging.st_uid != 0
                    or staging.st_gid != service_gid
                    or stat.S_IMODE(staging.st_mode) != 0o710
                ):
                    failures.append(
                        "backup staging root must be root:tinyzkp-billing mode 0710"
                    )
            except (KeyError, OSError):
                failures.append("backup staging root is unavailable or unsafe")
        if backup_http_token_file and check_host_python:
            token_path = pathlib.Path(backup_http_token_file)
            try:
                raw_token = read_private_file(
                    token_path,
                    label="HTTP backup token",
                    max_bytes=1024,
                    exact_mode_0600=True,
                )
                token = raw_token.decode("ascii").strip()
                if (
                    not 32 <= len(token) <= 512
                    or re.fullmatch(r"[A-Za-z0-9._~-]+", token) is None
                ):
                    failures.append(
                        "HC_BACKUP_HTTP_TOKEN_FILE has invalid length or characters"
                    )
            except (OSError, UnicodeDecodeError, ProductionEnvError):
                failures.append("HC_BACKUP_HTTP_TOKEN_FILE is unavailable or unsafe")
        if not _truthy(_value(env, "TINYZKP_MAINTENANCE_MODE")):
            failures.append(
                "TINYZKP_MAINTENANCE_MODE=1 is required during backend recovery"
            )
        outbound_email_configuration = sorted(
            key
            for key, value in env.items()
            if value.strip()
            and (
                key.startswith("SMTP_")
                or key == "CONTACT_TO_EMAIL"
                or (
                    key
                    in {
                        "TINYZKP_OUTBOUND_EMAIL_ENABLED",
                        "TINYZKP_CUSTOMER_EMAILS_ENABLED",
                    }
                    and _truthy(value)
                )
            )
        )
        if outbound_email_configuration:
            failures.append(
                "backend recovery forbids outbound email configuration: "
                + ", ".join(outbound_email_configuration)
            )
        forbidden = sorted(
            key
            for key, value in env.items()
            if value.strip()
            and (
                key.startswith("STRIPE_PRICE_ID")
                or key == "STRIPE_METER_EVENT_NAME"
                or (key.startswith("TINYZKP_ALLOW_LEGACY_") and _truthy(value))
            )
        )
        if forbidden:
            failures.append(
                "backend recovery forbids legacy billing configuration: "
                + ", ".join(forbidden)
            )
        if shared_dispatch or "shared-workers" in compose_profiles:
            failures.append(
                "backend recovery forbids shared proving dispatch and worker profiles"
            )

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
                failures.append(
                    f"HC_TENANT_PG_URL mirroring requires psycopg in {host_python}"
                )
            else:
                if result.returncode != 0:
                    failures.append(
                        f"HC_TENANT_PG_URL mirroring requires psycopg in {host_python}"
                    )
        elif importlib.util.find_spec("psycopg") is None:
            failures.append(
                "HC_TENANT_PG_URL mirroring requires the host Python package psycopg"
            )

    if production and check_host_python and host_python:
        try:
            result = subprocess.run(
                [host_python, "-c", "import flask, gunicorn, stripe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            failures.append(f"billing webhook runtime is unavailable in {host_python}")
        else:
            if result.returncode != 0:
                failures.append(
                    f"billing webhook runtime is incomplete in {host_python}"
                )

    return failures, warnings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file", default=".env", help="Path to production .env file"
    )
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
    try:
        env = merged_env(env_file, production=args.production)
    except ProductionEnvError as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
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
