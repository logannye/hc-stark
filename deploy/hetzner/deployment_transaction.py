#!/usr/bin/env python3
"""Transactional state and rollback helper for TinyZKP containment deploys.

All production paths are fixed.  The shell deploy wrapper holds the exclusive
process lock; this helper records immutable candidate images, snapshots the
complete mutable pre-state, validates all staged configuration before the first
atomic replacement, commits a known-containment record only after health
checks, and rolls back only to the recorded prior known-containment release.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable


REPO = pathlib.Path("/opt/hc-stark")
STATE_ROOT = pathlib.Path("/var/lib/tinyzkp-private/deploy")
TRANSACTIONS = STATE_ROOT / "transactions"
ACTIVE = STATE_ROOT / "active-deployment-transaction.json"
KNOWN = STATE_ROOT / "known-containment.json"
SCHEMA_TRANSACTION = "tinyzkp-deployment-transaction-v1"
SCHEMA_KNOWN = "tinyzkp-known-containment-v1"
RELEASE_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TX_RE = re.compile(r"^[0-9a-f]{32}$")
DEPLOYMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
MAX_JSON = 512 * 1024
MAX_CONFIG = 2 * 1024 * 1024
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
COMPOSE = (
    "/usr/bin/docker",
    "compose",
    "-f",
    "docker-compose.yml",
    "-f",
    "deploy/hetzner/docker-compose.prod.yml",
)
CONFIG_SOURCES = {
    "caddy": REPO / "deploy/hetzner/Caddyfile",
    "systemd": REPO / "deploy/hetzner/hc-billing-webhook.service",
    "cron": REPO / "deploy/hetzner/hc-billing.cron",
}
CONFIG_TARGETS = {
    "caddy": pathlib.Path("/etc/caddy/Caddyfile"),
    "systemd": pathlib.Path("/etc/systemd/system/hc-billing-webhook.service"),
    "cron": pathlib.Path("/etc/cron.d/hc-billing"),
}
CONFIG_MODES = {"caddy": 0o644, "systemd": 0o644, "cron": 0o644}
SERVICES = (
    "caddy.service",
    "hc-billing-webhook.service",
    "hc-stark.service",
)


class TransactionError(RuntimeError):
    """Deployment transaction state is absent, unsafe, or inconsistent."""


Runner = Callable[..., subprocess.CompletedProcess[str]]
HealthChecker = Callable[[], None]


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise TransactionError("durable deployment write made no progress")
        offset += written


def _fsync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_unlink(path: pathlib.Path) -> None:
    path.unlink()
    _fsync_directory(path.parent)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransactionError(f"deployment JSON duplicates {key!r}")
        result[key] = value
    return result


def _parse(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                TransactionError(f"{label} contains invalid number {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError(f"{label} must be strict UTF-8 JSON") from error
    if not isinstance(value, dict) or raw != _canonical(value):
        raise TransactionError(f"{label} must be one canonical JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        raise TransactionError(f"{label} fields are incomplete or unexpected")


def _safe_file(
    path: pathlib.Path,
    *,
    label: str,
    limit: int,
    exact_mode: int | None = None,
    owner: int | None = None,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise TransactionError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 <= before.st_size <= limit
        or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
        or (owner is not None and before.st_uid != owner)
    ):
        raise TransactionError(f"{label} is not a safe regular file")
    if not hasattr(os, "O_NOFOLLOW"):
        raise TransactionError(f"{label} requires O_NOFOLLOW")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise TransactionError(f"{label} changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise TransactionError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise TransactionError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    return b"".join(chunks), before


def _ensure_private_directory(path: pathlib.Path, *, create: bool = True) -> None:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise TransactionError(f"deployment state directory is unsafe: {path}")


def _atomic_write(path: pathlib.Path, value: object, *, mode: int = 0o600) -> None:
    _ensure_private_directory(path.parent)
    encoded = _canonical(value)
    if len(encoded) > MAX_JSON:
        raise TransactionError("deployment state exceeds its size limit")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _atomic_bytes(
    target: pathlib.Path,
    raw: bytes,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
) -> None:
    parent = target.parent
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise TransactionError(f"configuration target parent is unsafe: {parent}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        _fsync_directory(parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _default_runner(
    command: tuple[str, ...],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )


def _clean_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    result = {
        "PATH": TRUSTED_PATH,
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    if extra:
        result.update(extra)
    return result


def image_names(release_sha: str) -> dict[str, str]:
    if RELEASE_RE.fullmatch(release_sha) is None:
        raise TransactionError("deployment image release SHA is invalid")
    return {
        "hc-server": f"tinyzkp/hc-server:{release_sha}",
        "hc-mcp": f"tinyzkp/hc-mcp:{release_sha}",
    }


def _image_id(name: str, runner: Runner) -> str:
    completed = runner(
        ("/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", name),
        env=_clean_env(),
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or IMAGE_ID_RE.fullmatch(value) is None:
        raise TransactionError(f"immutable deployment image is unavailable: {name}")
    return value


def _candidate_images(release_sha: str, runner: Runner) -> dict[str, dict[str, str]]:
    return {
        service: {"name": name, "image_id": _image_id(name, runner)}
        for service, name in image_names(release_sha).items()
    }


def _service_state(name: str, runner: Runner) -> dict[str, object]:
    completed = runner(
        ("/usr/bin/systemctl", "is-active", name),
        env=_clean_env(),
    )
    value = completed.stdout.strip()
    allowed = {"active", "inactive", "failed", "activating", "deactivating"}
    if value not in allowed:
        if completed.returncode != 0 and not value:
            value = "inactive"
        else:
            raise TransactionError(f"cannot establish service state for {name}")
    enabled_check = runner(
        ("/usr/bin/systemctl", "is-enabled", name),
        env=_clean_env(),
    )
    enabled_value = enabled_check.stdout.strip()
    enabled_states = {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}
    disabled_states = {
        "disabled",
        "static",
        "indirect",
        "masked",
        "generated",
        "transient",
        "not-found",
        "",
    }
    if enabled_value in enabled_states and enabled_check.returncode == 0:
        enabled = True
    elif enabled_value in disabled_states and enabled_check.returncode != 0:
        enabled = False
    else:
        raise TransactionError(f"cannot establish enablement state for {name}")
    return {"active": value, "enabled": enabled}


def _running_container_image(service: str, runner: Runner, repo: pathlib.Path) -> str:
    completed = runner(
        (*COMPOSE, "ps", "-q", service),
        cwd=repo,
        env=_clean_env({"HC_IMAGE_TAG": "state-inspection"}),
    )
    container_id = completed.stdout.strip()
    if completed.returncode != 0:
        raise TransactionError(f"cannot inspect current container for {service}")
    if not container_id:
        return ""
    if re.fullmatch(r"[0-9a-f]{12,64}", container_id) is None:
        raise TransactionError(f"container ID for {service} is malformed")
    inspected = runner(
        ("/usr/bin/docker", "inspect", "--format", "{{.Image}}", container_id),
        env=_clean_env(),
    )
    image_id = inspected.stdout.strip()
    if inspected.returncode != 0 or IMAGE_ID_RE.fullmatch(image_id) is None:
        raise TransactionError(f"running container image for {service} is unavailable")
    return image_id


def _snapshot_configs(
    transaction_root: pathlib.Path,
    config_targets: dict[str, pathlib.Path],
) -> dict[str, dict[str, object]]:
    snapshot_root = transaction_root / "pre-state"
    _ensure_private_directory(snapshot_root)
    result: dict[str, dict[str, object]] = {}
    for key, target in config_targets.items():
        parent = target.parent.lstat()
        if (
            target.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise TransactionError(f"configuration target parent is unsafe: {target.parent}")
        try:
            raw, metadata = _safe_file(target, label=f"pre-state {key}", limit=MAX_CONFIG)
        except TransactionError:
            if target.exists() or target.is_symlink():
                raise
            result[key] = {
                "target": str(target),
                "present": False,
                "sha256": "",
                "mode": 0,
                "uid": 0,
                "gid": 0,
                "snapshot": "",
            }
            continue
        snapshot = snapshot_root / f"{key}.snapshot"
        descriptor = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        result[key] = {
            "target": str(target),
            "present": True,
            "sha256": _sha256(raw),
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "snapshot": snapshot.relative_to(transaction_root).as_posix(),
        }
    return result


def _valid_timestamp(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ) is not None


def _validate_service_record(value: object, *, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"active", "enabled"}
        or value["active"]
        not in {"active", "inactive", "failed", "activating", "deactivating"}
        or type(value["enabled"]) is not bool
    ):
        raise TransactionError(f"{label} service state is invalid")


def _validate_known(
    value: dict[str, Any],
    *,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "status",
            "release_sha",
            "deployment_id",
            "committed_at",
            "transaction_id",
            "images",
            "configs",
            "services",
        },
        label="known containment",
    )
    if (
        value["schema_version"] != SCHEMA_KNOWN
        or value["status"] != "known_containment"
        or not isinstance(value["release_sha"], str)
        or RELEASE_RE.fullmatch(value["release_sha"]) is None
        or not isinstance(value["transaction_id"], str)
        or TX_RE.fullmatch(value["transaction_id"]) is None
        or DEPLOYMENT_RE.fullmatch(str(value["deployment_id"])) is None
        or not _valid_timestamp(value["committed_at"])
    ):
        raise TransactionError("known containment identity is invalid")
    if not isinstance(value["images"], dict) or set(value["images"]) != {"hc-server", "hc-mcp"}:
        raise TransactionError("known containment images are incomplete")
    for service, record in value["images"].items():
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "image_id"}
            or record["name"] != image_names(value["release_sha"])[service]
            or IMAGE_ID_RE.fullmatch(str(record["image_id"])) is None
        ):
            raise TransactionError("known containment image identity is invalid")
    if not isinstance(value["configs"], dict) or set(value["configs"]) != set(config_targets):
        raise TransactionError("known containment configs are incomplete")
    for key, record in value["configs"].items():
        if (
            not isinstance(record, dict)
            or set(record) != {"target", "sha256"}
            or record["target"] != str(config_targets[key])
            or DIGEST_RE.fullmatch(str(record["sha256"])) is None
        ):
            raise TransactionError("known containment config identity is invalid")
    if not isinstance(value["services"], dict) or set(value["services"]) != set(SERVICES):
        raise TransactionError("known containment service state is incomplete")
    for service, record in value["services"].items():
        _validate_service_record(record, label=f"known containment {service}")
    if (
        value["services"]["caddy.service"] != {"active": "active", "enabled": True}
        or value["services"]["hc-billing-webhook.service"]
        != {"active": "active", "enabled": True}
        or value["services"]["hc-stark.service"]["active"] not in {"inactive", "failed"}
        or value["services"]["hc-stark.service"]["enabled"] is not False
    ):
        raise TransactionError("known containment service state is not fail-closed")


def _load_optional_known(
    path: pathlib.Path,
    *,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    raw, _metadata = _safe_file(
        path,
        label="known containment",
        limit=MAX_JSON,
        exact_mode=0o600,
        owner=os.geteuid(),
    )
    value = _parse(raw, label="known containment")
    _validate_known(value, config_targets=config_targets)
    return value


def _validate_transaction(
    value: dict[str, Any],
    *,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "status",
            "transaction_id",
            "started_at",
            "deployment_id",
            "candidate_release_sha",
            "candidate_images",
            "prior_known_containment",
            "pre_state",
            "staged_config_sha256",
            "configs_installed",
        },
        label="deployment transaction",
    )
    release_sha = value["candidate_release_sha"]
    if (
        value["schema_version"] != SCHEMA_TRANSACTION
        or value["status"] != "active"
        or not isinstance(value["transaction_id"], str)
        or TX_RE.fullmatch(value["transaction_id"]) is None
        or not _valid_timestamp(value["started_at"])
        or not isinstance(value["deployment_id"], str)
        or DEPLOYMENT_RE.fullmatch(value["deployment_id"]) is None
        or not isinstance(release_sha, str)
        or RELEASE_RE.fullmatch(release_sha) is None
        or type(value["configs_installed"]) is not bool
    ):
        raise TransactionError("deployment transaction identity is invalid")
    candidates = value["candidate_images"]
    if not isinstance(candidates, dict) or set(candidates) != {"hc-server", "hc-mcp"}:
        raise TransactionError("deployment candidate images are incomplete")
    for service, record in candidates.items():
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "image_id"}
            or record["name"] != image_names(release_sha)[service]
            or IMAGE_ID_RE.fullmatch(str(record["image_id"])) is None
        ):
            raise TransactionError("deployment candidate image identity is invalid")
    prior = value["prior_known_containment"]
    if prior is not None:
        if not isinstance(prior, dict):
            raise TransactionError("prior known containment is malformed")
        _validate_known(prior, config_targets=config_targets)
        if prior["deployment_id"] != value["deployment_id"]:
            raise TransactionError("prior containment deployment identity differs")
    pre_state = value["pre_state"]
    if not isinstance(pre_state, dict) or set(pre_state) != {
        "configs",
        "services",
        "container_image_ids",
    }:
        raise TransactionError("deployment pre-state is incomplete")
    configs = pre_state["configs"]
    if not isinstance(configs, dict) or set(configs) != set(config_targets):
        raise TransactionError("deployment config pre-state is incomplete")
    for key, record in configs.items():
        if not isinstance(record, dict) or set(record) != {
            "target",
            "present",
            "sha256",
            "mode",
            "uid",
            "gid",
            "snapshot",
        }:
            raise TransactionError("deployment config pre-state is malformed")
        present = record["present"]
        if (
            type(present) is not bool
            or record["target"] != str(config_targets[key])
            or type(record["mode"]) is not int
            or type(record["uid"]) is not int
            or type(record["gid"]) is not int
        ):
            raise TransactionError("deployment config pre-state identity is invalid")
        if present:
            if (
                DIGEST_RE.fullmatch(str(record["sha256"])) is None
                or not 0 <= record["mode"] <= 0o7777
                or record["uid"] < 0
                or record["gid"] < 0
                or record["snapshot"] != f"pre-state/{key}.snapshot"
            ):
                raise TransactionError("deployment config snapshot is invalid")
        elif any(
            (
                record["sha256"] != "",
                record["mode"] != 0,
                record["uid"] != 0,
                record["gid"] != 0,
                record["snapshot"] != "",
            )
        ):
            raise TransactionError("absent deployment config pre-state is invalid")
    services = pre_state["services"]
    if not isinstance(services, dict) or set(services) != set(SERVICES):
        raise TransactionError("deployment service pre-state is incomplete")
    for service, record in services.items():
        _validate_service_record(record, label=f"pre-state {service}")
    containers = pre_state["container_image_ids"]
    if not isinstance(containers, dict) or set(containers) != {"hc-server", "hc-mcp"}:
        raise TransactionError("deployment container pre-state is incomplete")
    if any(
        image_id != "" and IMAGE_ID_RE.fullmatch(str(image_id)) is None
        for image_id in containers.values()
    ):
        raise TransactionError("deployment container pre-state is malformed")
    staged = value["staged_config_sha256"]
    if not isinstance(staged, dict):
        raise TransactionError("staged config identity is malformed")
    if value["configs_installed"]:
        if set(staged) != set(config_targets) or any(
            DIGEST_RE.fullmatch(str(digest)) is None for digest in staged.values()
        ):
            raise TransactionError("installed config identity is incomplete")
    elif staged:
        raise TransactionError("uninstalled transaction records staged config identity")


def _load_active(
    path: pathlib.Path = ACTIVE,
    *,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> dict[str, Any]:
    raw, _metadata = _safe_file(
        path,
        label="active deployment transaction",
        limit=MAX_JSON,
        exact_mode=0o600,
        owner=os.geteuid(),
    )
    value = _parse(raw, label="active deployment transaction")
    _validate_transaction(value, config_targets=config_targets)
    return value


def _write_transaction(
    record: dict[str, Any],
    *,
    active_path: pathlib.Path,
    transactions_root: pathlib.Path,
) -> None:
    transaction_id = record["transaction_id"]
    root = transactions_root / transaction_id
    _atomic_write(root / "record.json", record)
    _atomic_write(active_path, record)


def begin_transaction(
    release_sha: str,
    deployment_id: str,
    *,
    runner: Runner = _default_runner,
    repo: pathlib.Path = REPO,
    state_root: pathlib.Path = STATE_ROOT,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> dict[str, Any]:
    if RELEASE_RE.fullmatch(release_sha) is None or DEPLOYMENT_RE.fullmatch(deployment_id) is None:
        raise TransactionError("candidate deployment identity is invalid")
    _ensure_private_directory(state_root)
    transactions_root = state_root / "transactions"
    _ensure_private_directory(transactions_root)
    active_path = state_root / ACTIVE.name
    known_path = state_root / KNOWN.name
    if active_path.exists() or active_path.is_symlink():
        raise TransactionError("an unresolved deployment transaction is already active")
    transaction_id = secrets.token_hex(16)
    transaction_root = transactions_root / transaction_id
    transaction_root.mkdir(mode=0o700)
    try:
        candidates = _candidate_images(release_sha, runner)
        configs = _snapshot_configs(transaction_root, config_targets)
        services = {service: _service_state(service, runner) for service in SERVICES}
        containers = {
            service: _running_container_image(service, runner, repo)
            for service in ("hc-server", "hc-mcp")
        }
        prior = _load_optional_known(known_path, config_targets=config_targets)
        if prior is not None:
            if prior["deployment_id"] != deployment_id:
                raise TransactionError("prior known containment belongs to another deployment")
            for service, image in prior["images"].items():
                if _image_id(image["name"], runner) != image["image_id"]:
                    raise TransactionError("prior known containment image is unavailable or changed")
                if containers[service] != image["image_id"]:
                    raise TransactionError("running container differs from prior known containment")
            for key, config in prior["configs"].items():
                if not configs[key]["present"] or configs[key]["sha256"] != config["sha256"]:
                    raise TransactionError("live config differs from prior known containment")
            if services != prior["services"]:
                raise TransactionError("live services differ from prior known containment")
        record: dict[str, Any] = {
            "schema_version": SCHEMA_TRANSACTION,
            "status": "active",
            "transaction_id": transaction_id,
            "started_at": _now(),
            "deployment_id": deployment_id,
            "candidate_release_sha": release_sha,
            "candidate_images": candidates,
            "prior_known_containment": prior,
            "pre_state": {
                "configs": configs,
                "services": services,
                "container_image_ids": containers,
            },
            "staged_config_sha256": {},
            "configs_installed": False,
        }
        _write_transaction(
            record,
            active_path=active_path,
            transactions_root=transactions_root,
        )
        return record
    except Exception:
        shutil.rmtree(transaction_root, ignore_errors=True)
        active_path.unlink(missing_ok=True)
        raise


def _validate_cron(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransactionError("staged cron is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text or "sync_usage.py" in text or "checkout_recovery.py" in text:
        raise TransactionError("staged cron has unsafe encoding or legacy jobs")
    jobs = [line for line in text.splitlines() if line and not line.startswith("#")]
    if len(jobs) != 2:
        raise TransactionError("staged cron must contain exactly two recovery jobs")
    expected = (
        ("0", "2", "*", "*", "*", "root", "/opt/hc-stark/billing/backup.sh"),
        ("17", "3", "*", "*", "*", "tinyzkp-billing", "/bin/sh"),
    )
    for line, prefix in zip(jobs, expected):
        fields = line.split(maxsplit=6)
        if len(fields) != 7 or tuple(fields[:6]) != prefix[:6] or not fields[6].startswith(prefix[6]):
            raise TransactionError("staged cron schedule or executable is invalid")


def _validate_systemd_source(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransactionError("staged systemd unit is not UTF-8") from error
    required = (
        "User=tinyzkp-billing",
        "Group=tinyzkp-billing",
        "ExecStart=/var/lib/tinyzkp-runtime/billing-venv/bin/gunicorn",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/opt/hc-stark/data",
    )
    if not text.endswith("\n") or any(marker not in text for marker in required):
        raise TransactionError("staged systemd unit lacks recovery hardening")


def _validate_caddy_source(raw: bytes) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TransactionError("staged Caddyfile is not UTF-8") from error
    for marker in (
        "api.tinyzkp.com",
        "mcp.tinyzkp.com",
        "webhook.tinyzkp.com",
        "reverse_proxy 127.0.0.1:8080",
        "reverse_proxy 127.0.0.1:3001",
        "reverse_proxy 127.0.0.1:5001",
    ):
        if marker not in text:
            raise TransactionError("staged Caddyfile is incomplete")


def install_configs(
    transaction_id: str,
    *,
    runner: Runner = _default_runner,
    repo: pathlib.Path = REPO,
    state_root: pathlib.Path = STATE_ROOT,
    config_sources: dict[str, pathlib.Path] = CONFIG_SOURCES,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> dict[str, Any]:
    active_path = state_root / ACTIVE.name
    transactions_root = state_root / "transactions"
    record = _load_active(active_path, config_targets=config_targets)
    if record["transaction_id"] != transaction_id or TX_RE.fullmatch(transaction_id) is None:
        raise TransactionError("installer transaction ID does not match active state")
    if record["configs_installed"]:
        raise TransactionError("deployment configs were already installed")
    transaction_root = transactions_root / transaction_id
    staged_root = transaction_root / "staged"
    _ensure_private_directory(staged_root)
    staged: dict[str, tuple[pathlib.Path, bytes]] = {}
    for key, source in config_sources.items():
        raw, metadata = _safe_file(source, label=f"source config {key}", limit=MAX_CONFIG)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TransactionError(f"source config {key} is mutable or has the wrong owner")
        if key == "cron":
            _validate_cron(raw)
        elif key == "systemd":
            _validate_systemd_source(raw)
        elif key == "caddy":
            _validate_caddy_source(raw)
        path = staged_root / key
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        staged[key] = (path, raw)

    caddy_check = runner(
        (
            "/usr/bin/caddy",
            "validate",
            "--config",
            str(staged["caddy"][0]),
            "--adapter",
            "caddyfile",
        ),
        env=_clean_env(),
    )
    systemd_check = runner(
        ("/usr/bin/systemd-analyze", "verify", str(staged["systemd"][0])),
        env=_clean_env(),
    )
    if caddy_check.returncode != 0 or systemd_check.returncode != 0:
        raise TransactionError("staged Caddy/systemd validation failed")

    # Every staged input has passed before the first target replacement.
    for key in ("cron", "systemd", "caddy"):
        _atomic_bytes(
            config_targets[key],
            staged[key][1],
            mode=CONFIG_MODES[key],
        )
    record["staged_config_sha256"] = {
        key: _sha256(raw) for key, (_path, raw) in staged.items()
    }
    record["configs_installed"] = True
    _write_transaction(
        record,
        active_path=active_path,
        transactions_root=transactions_root,
    )
    return record


def _run_required(
    runner: Runner,
    command: tuple[str, ...],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
    label: str,
) -> None:
    completed = runner(command, cwd=cwd, env=env or _clean_env())
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-1000:]
        raise TransactionError(f"{label} failed: {detail}")


def _restore_configs(
    record: dict[str, Any],
    transaction_root: pathlib.Path,
) -> None:
    for key, item in record["pre_state"]["configs"].items():
        target = pathlib.Path(item["target"])
        if item["present"]:
            snapshot = transaction_root / item["snapshot"]
            raw, _metadata = _safe_file(
                snapshot,
                label=f"rollback snapshot {key}",
                limit=MAX_CONFIG,
                exact_mode=0o600,
                owner=os.geteuid(),
            )
            if _sha256(raw) != item["sha256"]:
                raise TransactionError(f"rollback snapshot hash changed: {key}")
            _atomic_bytes(
                target,
                raw,
                mode=item["mode"],
                uid=item["uid"],
                gid=item["gid"],
            )
        else:
            try:
                target.lstat()
            except FileNotFoundError:
                continue
            target.unlink()


def _restore_service_state(name: str, state: dict[str, object], runner: Runner) -> None:
    _validate_service_record(state, label=f"rollback {name}")
    enable_action = "enable" if state["enabled"] else "disable"
    enable_result = runner(
        ("/usr/bin/systemctl", enable_action, name),
        env=_clean_env(),
    )
    if enable_result.returncode != 0:
        observed = _service_state(name, runner)
        if observed["enabled"] != state["enabled"]:
            detail = (enable_result.stderr or enable_result.stdout).strip()[-1000:]
            raise TransactionError(f"restore {name} {enable_action} failed: {detail}")
    action = (
        "reload"
        if name == "caddy.service" and state["active"] in {"active", "activating"}
        else "start"
        if state["active"] in {"active", "activating"}
        else "stop"
    )
    active_result = runner(
        ("/usr/bin/systemctl", action, name),
        env=_clean_env(),
    )
    if active_result.returncode != 0:
        observed = _service_state(name, runner)
        desired_active = state["active"] in {"active", "activating"}
        if (observed["active"] == "active") != desired_active:
            detail = (active_result.stderr or active_result.stdout).strip()[-1000:]
            raise TransactionError(f"restore {name} {action} failed: {detail}")


def _emergency_stop(
    runner: Runner,
    *,
    repo: pathlib.Path,
    image_tag: str,
) -> list[str]:
    """Best-effort stop of every backend surface after rollback trouble."""

    failures: list[str] = []
    commands = (
        (
            (*COMPOSE, "stop", "hc-server", "hc-mcp"),
            repo,
            _clean_env({"HC_IMAGE_TAG": image_tag}),
            "container stop",
        ),
        (
            ("/usr/bin/systemctl", "stop", "hc-billing-webhook.service"),
            None,
            _clean_env(),
            "webhook stop",
        ),
        (
            ("/usr/bin/systemctl", "stop", "hc-stark.service"),
            None,
            _clean_env(),
            "legacy compose service stop",
        ),
    )
    for command, cwd, env, label in commands:
        try:
            completed = runner(command, cwd=cwd, env=env)
        except Exception as error:  # pragma: no cover - defensive production path
            failures.append(f"{label}: {error}")
            continue
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[-500:]
            failures.append(f"{label}: {detail or completed.returncode}")
    return failures


def _reconcile_known_after_rollback(
    record: dict[str, Any],
    *,
    state_root: pathlib.Path,
    config_targets: dict[str, pathlib.Path],
) -> None:
    """Repair a known record written just before a commit-time interruption."""

    known_path = state_root / KNOWN.name
    current = _load_optional_known(known_path, config_targets=config_targets)
    prior = record["prior_known_containment"]
    if current is not None and current != prior:
        if (
            current["transaction_id"] != record["transaction_id"]
            or current["release_sha"] != record["candidate_release_sha"]
            or current["deployment_id"] != record["deployment_id"]
        ):
            raise TransactionError("known containment changed outside the active transaction")
    if prior is None:
        if current is not None:
            _durable_unlink(known_path)
    else:
        _atomic_write(known_path, prior)


def rollback_transaction(
    *,
    target_release_sha: str | None,
    expected_transaction_id: str | None = None,
    require_no_prior: bool = False,
    runner: Runner = _default_runner,
    repo: pathlib.Path = REPO,
    state_root: pathlib.Path = STATE_ROOT,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
) -> dict[str, Any]:
    active_path = state_root / ACTIVE.name
    transactions_root = state_root / "transactions"
    record = _load_active(active_path, config_targets=config_targets)
    if expected_transaction_id is not None and record["transaction_id"] != expected_transaction_id:
        raise TransactionError("rollback transaction ID does not match active state")
    transaction_root = transactions_root / record["transaction_id"]
    prior = record["prior_known_containment"]
    if require_no_prior and prior is not None:
        raise TransactionError("fail-closed no-prior rollback cannot replace known containment")
    if target_release_sha is not None:
        if RELEASE_RE.fullmatch(target_release_sha) is None:
            raise TransactionError("requested rollback release SHA is invalid")
        if prior is None or prior["release_sha"] != target_release_sha:
            raise TransactionError("rollback target is not the recorded prior known containment")

    # On a first containment attempt there is no authorized legacy rollback.
    # Stop surfaces *before* touching restored configuration and keep stopping
    # all remaining surfaces even when one stop command fails.
    initial_stop_failures: list[str] = []
    if prior is None:
        initial_stop_failures = _emergency_stop(
            runner,
            repo=repo,
            image_tag=record["candidate_release_sha"],
        )
    try:
        _restore_configs(record, transaction_root)
        _run_required(
            runner,
            ("/usr/bin/systemctl", "daemon-reload"),
            label="systemd rollback reload",
        )
        if pathlib.Path(config_targets["caddy"]).exists():
            _run_required(
                runner,
                (
                    "/usr/bin/caddy",
                    "validate",
                    "--config",
                    str(config_targets["caddy"]),
                    "--adapter",
                    "caddyfile",
                ),
                label="restored Caddy validation",
            )

        if prior is None:
            if initial_stop_failures:
                raise TransactionError(
                    "fail-closed stop was incomplete: " + "; ".join(initial_stop_failures)
                )
            disposition = "failed_closed_no_prior"
        else:
            _validate_known(prior, config_targets=config_targets)
            for image in prior["images"].values():
                if _image_id(image["name"], runner) != image["image_id"]:
                    raise TransactionError("recorded rollback image changed or disappeared")
            rollback_env = _clean_env(
                {
                    "HC_IMAGE_TAG": prior["release_sha"],
                    "HC_RELEASE_SHA": prior["release_sha"],
                    "HC_RELEASE_REF": f"rollback/{prior['release_sha']}",
                    "HC_RELEASE_BUILD_URL": "",
                }
            )
            _run_required(
                runner,
                (*COMPOSE, "up", "-d", "--no-build", "hc-server", "hc-mcp"),
                cwd=repo,
                env=rollback_env,
                label="known-containment container rollback",
            )
            for service, state in record["pre_state"]["services"].items():
                _restore_service_state(service, state, runner)
            disposition = "rolled_back_known_containment"
        _reconcile_known_after_rollback(
            record,
            state_root=state_root,
            config_targets=config_targets,
        )
    except Exception as error:
        failures = _emergency_stop(
            runner,
            repo=repo,
            image_tag=record["candidate_release_sha"],
        )
        detail = f"; emergency stop failures: {'; '.join(failures)}" if failures else ""
        raise TransactionError(f"rollback failed closed: {error}{detail}") from error

    rollback_record = {
        **record,
        "status": "rolled_back",
        "rolled_back_at": _now(),
        "rollback_disposition": disposition,
        "rollback_release_sha": prior["release_sha"] if prior else "",
    }
    _atomic_write(transaction_root / "rolled-back.json", rollback_record)
    _durable_unlink(active_path)
    return rollback_record


def _current_config_hashes(config_targets: dict[str, pathlib.Path]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for key, target in config_targets.items():
        raw, _metadata = _safe_file(target, label=f"committed config {key}", limit=MAX_CONFIG)
        result[key] = {"target": str(target), "sha256": _sha256(raw)}
    return result


def _local_request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise TransactionError(f"local containment request failed: {port}{path}") from error
    finally:
        connection.close()
    if len(raw) > 1024 * 1024:
        raise TransactionError(f"local containment response is oversized: {port}{path}")
    return response.status, raw


def verify_local_containment() -> None:
    expected = (
        (8080, "GET", "/healthz", None, 200),
        (8080, "GET", "/version", None, 200),
        (3001, "GET", "/version", None, 200),
        (5001, "GET", "/health", None, 200),
        (5001, "POST", "/send-contact", b"{}", 403),
        (5001, "POST", "/contact-readiness", b"{}", 403),
    )
    for port, method, path, body, expected_status in expected:
        status, _raw = _local_request(port, method, path, body=body)
        if status != expected_status:
            raise TransactionError(
                f"local containment {port}{path} returned {status}, expected {expected_status}"
            )
    error_checks = (
        ("/prove", b"{}", 503, "protocol_upgrade"),
        ("/verify", b'{"proof":{"version":7}}', 422, "legacy_statement_unbound"),
    )
    for path, body, expected_status, expected_code in error_checks:
        status, raw = _local_request(8080, "POST", path, body=body)
        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicates,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    TransactionError(f"local {path} response contains invalid number {token}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TransactionError(f"local {path} response is malformed") from error
        if (
            status != expected_status
            or not isinstance(payload, dict)
            or payload.get("code") != expected_code
        ):
            raise TransactionError(
                f"local {path} did not return HTTP {expected_status} code={expected_code}"
            )
    status, raw = _local_request(8080, "GET", "/v1/capabilities")
    if status != 200:
        raise TransactionError("local capabilities endpoint is unavailable")
    try:
        capabilities = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransactionError("local capabilities response is malformed") from error
    if not isinstance(capabilities, dict) or any(
        capabilities.get(key) is not False
        for key in (
            "proving_available",
            "verification_available",
            "checkout_enabled",
            "account_creation_enabled",
        )
    ):
        raise TransactionError("local capabilities are not fail-closed")


def commit_transaction(
    transaction_id: str,
    *,
    runner: Runner = _default_runner,
    repo: pathlib.Path = REPO,
    state_root: pathlib.Path = STATE_ROOT,
    config_targets: dict[str, pathlib.Path] = CONFIG_TARGETS,
    health_checker: HealthChecker = verify_local_containment,
) -> dict[str, Any]:
    active_path = state_root / ACTIVE.name
    known_path = state_root / KNOWN.name
    transactions_root = state_root / "transactions"
    record = _load_active(active_path, config_targets=config_targets)
    if record["transaction_id"] != transaction_id or not record["configs_installed"]:
        raise TransactionError("deployment transaction is not ready to commit")
    candidates = _candidate_images(record["candidate_release_sha"], runner)
    if candidates != record["candidate_images"]:
        raise TransactionError("candidate images changed before commit")
    for service, candidate in candidates.items():
        if _running_container_image(service, runner, repo) != candidate["image_id"]:
            raise TransactionError("running container does not use the candidate image")
    services = {service: _service_state(service, runner) for service in SERVICES}
    if (
        services["caddy.service"] != {"active": "active", "enabled": True}
        or services["hc-billing-webhook.service"]
        != {"active": "active", "enabled": True}
        or services["hc-stark.service"]["active"] not in {"inactive", "failed"}
        or services["hc-stark.service"]["enabled"] is not False
    ):
        raise TransactionError("cannot commit while host services are not fail-closed")
    configs = _current_config_hashes(config_targets)
    for key, digest in record["staged_config_sha256"].items():
        if configs[key]["sha256"] != digest:
            raise TransactionError("installed config changed before commit")
    # This check is deliberately inside the transaction helper. Invoking
    # `deployment_transaction.py commit` directly cannot bypass containment
    # health/capability enforcement performed by the shell wrapper.
    health_checker()
    known = {
        "schema_version": SCHEMA_KNOWN,
        "status": "known_containment",
        "release_sha": record["candidate_release_sha"],
        "deployment_id": record["deployment_id"],
        "committed_at": _now(),
        "transaction_id": transaction_id,
        "images": candidates,
        "configs": configs,
        "services": services,
    }
    _validate_known(known, config_targets=config_targets)
    _atomic_write(known_path, known)
    committed = {**record, "status": "committed", "committed_at": known["committed_at"]}
    _atomic_write(transactions_root / transaction_id / "committed.json", committed)
    _durable_unlink(active_path)
    return known


def _require_production_operator() -> None:
    if os.geteuid() != 0 or sys.platform != "linux":
        raise TransactionError("deployment transactions require root on Linux")
    if pathlib.Path.cwd().resolve() != REPO:
        raise TransactionError(f"deployment transaction must run from {REPO}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    begin = subparsers.add_parser("begin")
    begin.add_argument("--candidate-release-sha", required=True)
    begin.add_argument("--deployment-id", required=True)
    begin.add_argument("--id-only", action="store_true")
    install = subparsers.add_parser("install-configs")
    install.add_argument("--transaction-id", required=True)
    commit = subparsers.add_parser("commit")
    commit.add_argument("--transaction-id", required=True)
    rollback = subparsers.add_parser("rollback")
    rollback_mode = rollback.add_mutually_exclusive_group(required=True)
    rollback_mode.add_argument("--target-release-sha")
    rollback_mode.add_argument("--fail-closed-no-prior", action="store_true")
    rollback_mode.add_argument("--automatic-recorded", action="store_true")
    rollback.add_argument("--transaction-id")
    subparsers.add_parser("status")
    args = parser.parse_args(argv)
    try:
        _require_production_operator()
        if args.command == "begin":
            result = begin_transaction(args.candidate_release_sha, args.deployment_id)
        elif args.command == "install-configs":
            result = install_configs(args.transaction_id)
        elif args.command == "commit":
            result = commit_transaction(args.transaction_id)
        elif args.command == "rollback":
            if args.automatic_recorded:
                if args.transaction_id is None or TX_RE.fullmatch(args.transaction_id) is None:
                    raise TransactionError("automatic rollback requires the exact transaction ID")
            elif args.transaction_id is not None:
                raise TransactionError("transaction ID is accepted only for automatic rollback")
            result = rollback_transaction(
                target_release_sha=args.target_release_sha,
                expected_transaction_id=args.transaction_id,
                require_no_prior=args.fail_closed_no_prior,
            )
        else:
            result = _load_active() if ACTIVE.exists() else (_load_optional_known(KNOWN) or {"status": "empty"})
    except (OSError, subprocess.TimeoutExpired, TransactionError) as error:
        print(f"FAIL deployment transaction - {error}", file=sys.stderr)
        return 1
    if args.command == "begin" and args.id_only:
        print(result["transaction_id"])
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
