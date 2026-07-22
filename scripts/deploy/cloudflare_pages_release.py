#!/usr/bin/env python3
"""Plan, deploy, verify, or roll back TinyZKP Cloudflare Pages safely.

The default deploy/rollback behavior is a read-only plan. Writes require both
an exact preview hash and ``TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE=1``. Cloudflare
credentials are used only by the fixed Pages API paths and pinned Wrangler
runtime; they are never serialized into plans or records.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, Iterator
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

from cloudflare_toolchain_check import ToolchainError, validate_runtime  # noqa: E402


PROJECT_NAME = "tinyzkp"
PRODUCTION_BRANCH = "main"
API_ORIGIN = "https://api.cloudflare.com/client/v4"
WRITE_ENV = "TINYZKP_ALLOW_CLOUDFLARE_PAGES_WRITE"
DEPLOY_PLAN_SCHEMA = "tinyzkp-cloudflare-pages-deploy-plan-v1"
DEPLOYMENT_RECORD_SCHEMA = "tinyzkp-cloudflare-pages-deployment-v1"
CANARY_RECORD_SCHEMA = "tinyzkp-cloudflare-pages-canary-v3"
DEPLOY_FAILURE_RECORD_SCHEMA = "tinyzkp-cloudflare-pages-deploy-failure-v1"
ROLLBACK_PLAN_SCHEMA = "tinyzkp-cloudflare-pages-rollback-plan-v1"
ROLLBACK_RECORD_SCHEMA = "tinyzkp-cloudflare-pages-rollback-v1"
ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
RELEASE_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DEPLOYMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
PINNED_NODE = Path("/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node")
PINNED_WRANGLER = Path(
    "/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js"
)
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class ReleaseError(ValueError):
    """The requested Pages operation failed a fail-closed invariant."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ReleaseError(f"value is not canonical JSON: {error}") from error


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant_rejector(value: str) -> None:
    raise ReleaseError(f"non-finite JSON number is forbidden: {value}")


def strict_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_duplicate_rejector,
            parse_constant=_constant_rejector,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{label} is not strict UTF-8 JSON") from error


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} must be an object")
    if set(value) != keys:
        raise ReleaseError(
            f"{label} fields differ; missing={sorted(keys - set(value))}, "
            f"extra={sorted(set(value) - keys)}"
        )
    return value


def _owner_only_regular(path: Path, label: str, *, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ReleaseError(f"{label} validation requires O_NOFOLLOW")
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseError(f"{label} is unavailable or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ReleaseError(
                f"{label} must be current-owner, owner-only, single-link, and regular"
            )
        raw = bytearray()
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ReleaseError(f"{label} exceeds {max_bytes} bytes")
        if not raw:
            raise ReleaseError(f"{label} is empty")
        return bytes(raw)
    finally:
        os.close(descriptor)


def read_canonical_record(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _owner_only_regular(path, label, max_bytes=MAX_JSON_BYTES)
    value = strict_json(raw, label)
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ReleaseError(f"{label} is not canonical JSON")
    return value, raw


def _private_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReleaseError("record directory must be current-owner mode 0700")


def write_canonical_exclusive(path: Path, value: dict[str, Any]) -> str:
    _private_parent(path)
    if path.exists() or path.is_symlink():
        raise ReleaseError("record output already exists")
    raw = canonical_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except OSError as error:
            raise ReleaseError(
                "record output could not be published exclusively"
            ) from error
        os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return sha256_bytes(raw)


@contextmanager
def operation_lock(parent: Path) -> Iterator[None]:
    _private_parent(parent / "record.json")
    lock = parent / ".cloudflare-pages-release.lock"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock, flags, 0o600)
    except OSError as error:
        raise ReleaseError("another Pages release operation is active") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)


def release_sha(value: Any, label: str = "release SHA") -> str:
    if not isinstance(value, str) or RELEASE_SHA.fullmatch(value) is None:
        raise ReleaseError(
            f"{label} must be exactly 40 lowercase hexadecimal characters"
        )
    return value


def sha256_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ReleaseError(f"{label} must be a lowercase SHA-256")
    return value


def account_id(value: Any) -> str:
    if not isinstance(value, str) or ACCOUNT_ID.fullmatch(value) is None:
        raise ReleaseError(
            "Cloudflare account ID must be exactly 32 lowercase hexadecimal characters"
        )
    return value


def deployment_id(value: Any, label: str = "deployment ID") -> str:
    if not isinstance(value, str) or DEPLOYMENT_ID.fullmatch(value) is None:
        raise ReleaseError(f"{label} is malformed")
    return value


def canonical_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReleaseError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ReleaseError(f"{label} must use YYYY-MM-DDTHH:MM:SSZ") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ReleaseError(f"{label} must be canonical")
    return value


def api_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReleaseError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ReleaseError(f"{label} must be an RFC 3339 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReleaseError(f"{label} must be UTC")
    return (
        parsed.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def utc_now() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


class CloudflareApi:
    """Minimal fixed-surface Cloudflare Pages v4 client."""

    def __init__(
        self,
        account: str,
        token: str,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        self.account = account_id(account)
        if (
            not isinstance(token, str)
            or not 20 <= len(token) <= 512
            or token != token.strip()
            or any(character.isspace() for character in token)
        ):
            raise ReleaseError("Cloudflare API token is missing or malformed")
        self._token = token
        self._opener = opener

    def _request(
        self, method: str, suffix: str, body: bytes | None = None
    ) -> dict[str, Any]:
        if not suffix.startswith("/") or ".." in PurePosixPath(suffix).parts:
            raise ReleaseError("Cloudflare API path is unsafe")
        request = urllib.request.Request(
            API_ORIGIN + suffix,
            data=body,
            method=method,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "TinyZKP-Pages-Release/1",
            },
        )
        try:
            with self._opener(request, timeout=30) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
                status_code = response.status
        except urllib.error.HTTPError as error:
            error.read(MAX_JSON_BYTES + 1)
            raise ReleaseError(f"Cloudflare API returned HTTP {error.code}") from error
        except (OSError, urllib.error.URLError) as error:
            raise ReleaseError("Cloudflare API request failed") from error
        if status_code != 200 or len(raw) > MAX_JSON_BYTES:
            raise ReleaseError("Cloudflare API response status or size is invalid")
        envelope = strict_json(raw, "Cloudflare API response")
        if not isinstance(envelope, dict):
            raise ReleaseError("Cloudflare API response must be an object")
        if envelope.get("success") is not True or envelope.get("errors") not in (
            [],
            None,
        ):
            raise ReleaseError("Cloudflare API reported failure")
        result = envelope.get("result")
        if not isinstance(result, dict):
            raise ReleaseError("Cloudflare API result must be an object")
        return result

    def get_project(self) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/accounts/{self.account}/pages/projects/{PROJECT_NAME}",
        )

    def get_deployment(self, target: str) -> dict[str, Any]:
        target = deployment_id(target)
        return self._request(
            "GET",
            f"/accounts/{self.account}/pages/projects/{PROJECT_NAME}/deployments/{quote(target, safe='')}",
        )

    def rollback(self, target: str) -> dict[str, Any]:
        target = deployment_id(target, "rollback target deployment ID")
        return self._request(
            "POST",
            f"/accounts/{self.account}/pages/projects/{PROJECT_NAME}/deployments/{quote(target, safe='')}/rollback",
            b"{}",
        )


def _run_git(
    git: Path,
    root: Path,
    arguments: tuple[str, ...],
    *,
    binary: bool = False,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> bytes | str:
    command = (str(git), "-C", str(root), *arguments)
    try:
        completed = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
            text=not binary,
            env={"PATH": TRUSTED_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError("Git source inspection failed") from error
    stderr = (
        completed.stderr
        if isinstance(completed.stderr, str)
        else completed.stderr.decode("utf-8", errors="replace")
    )
    if completed.returncode != 0 or stderr:
        raise ReleaseError("Git source inspection failed or emitted diagnostics")
    output = completed.stdout
    if binary:
        if not isinstance(output, bytes) or len(output) > MAX_ARCHIVE_BYTES:
            raise ReleaseError("Git site archive is malformed or oversized")
        return output
    if not isinstance(output, str):
        raise ReleaseError("Git returned unexpected output")
    return output


def _archive_identity(
    raw: bytes,
) -> tuple[dict[str, Any], list[tuple[str, bool, bytes]]]:
    records: list[dict[str, Any]] = []
    members: list[tuple[str, bool, bytes]] = []
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                if len(members) >= MAX_SOURCE_FILES:
                    raise ReleaseError("site archive contains too many entries")
                archived_path = PurePosixPath(member.name)
                if (
                    archived_path.is_absolute()
                    or not archived_path.parts
                    or archived_path.parts[0] != "site"
                    or any(part in {"", ".", ".."} for part in archived_path.parts)
                ):
                    raise ReleaseError("site archive contains an unsafe path")
                if len(archived_path.parts) == 1:
                    if not member.isdir():
                        raise ReleaseError("site archive root must be a directory")
                    continue
                path = PurePosixPath(*archived_path.parts[1:])
                normalized_name = path.as_posix()
                if path.parts[0] in {".git", ".wrangler"} or normalized_name in seen:
                    raise ReleaseError(
                        "site archive contains an unsafe or duplicate path"
                    )
                seen.add(normalized_name)
                if member.isdir():
                    records.append({"kind": "directory", "path": normalized_name})
                    members.append((normalized_name, True, b""))
                    continue
                if not member.isreg() or member.issym() or member.islnk():
                    raise ReleaseError("site archive contains a link or special file")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseError("site archive file is unreadable")
                content = stream.read(MAX_ARCHIVE_BYTES + 1)
                total += len(content)
                if len(content) != member.size or total > MAX_ARCHIVE_BYTES:
                    raise ReleaseError("site archive content is truncated or oversized")
                records.append(
                    {
                        "kind": "file",
                        "path": normalized_name,
                        "size": len(content),
                        "sha256": sha256_bytes(content),
                    }
                )
                members.append((normalized_name, False, content))
    except (tarfile.TarError, OSError) as error:
        raise ReleaseError("Git site archive is unreadable") from error
    file_paths = {record["path"] for record in records if record["kind"] == "file"}
    if not {"wrangler.toml", "_worker.js"} <= file_paths:
        raise ReleaseError("site archive omits wrangler.toml or _worker.js")
    manifest = sorted(records, key=lambda item: (str(item["path"]), str(item["kind"])))
    return {
        "site_archive_sha256": sha256_bytes(raw),
        "site_manifest_sha256": canonical_sha256(manifest),
        "site_file_count": len(file_paths),
        "site_total_bytes": total,
    }, members


def inspect_site_source(
    root: Path,
    reviewed_sha: str,
    *,
    git: Path = Path("/usr/bin/git"),
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> dict[str, Any]:
    reviewed_sha = release_sha(reviewed_sha, "reviewed release SHA")
    root = root.resolve(strict=True)

    def snapshot() -> tuple[str, str, str, bytes]:
        top = str(
            _run_git(git, root, ("rev-parse", "--show-toplevel"), runner=runner)
        ).strip()
        head = str(_run_git(git, root, ("rev-parse", "HEAD"), runner=runner)).strip()
        dirty = str(
            _run_git(
                git,
                root,
                ("status", "--porcelain=v1", "--untracked-files=all", "--", "site"),
                runner=runner,
            )
        )
        tree = str(
            _run_git(git, root, ("rev-parse", f"{reviewed_sha}:site"), runner=runner)
        ).strip()
        archive = _run_git(
            git,
            root,
            ("archive", "--format=tar", reviewed_sha, "site"),
            binary=True,
            runner=runner,
        )
        assert isinstance(archive, bytes)
        if Path(top).resolve(strict=True) != root:
            raise ReleaseError("source root is not the exact Git top-level")
        if head != reviewed_sha:
            raise ReleaseError("reviewed release SHA differs from Git HEAD")
        if dirty:
            raise ReleaseError("site source has tracked, staged, or untracked changes")
        if GIT_OBJECT.fullmatch(tree) is None:
            raise ReleaseError("site Git tree object is malformed")
        return head, dirty, tree, archive

    first = snapshot()
    archive_identity, _members = _archive_identity(first[3])
    second = snapshot()
    if (
        first[:3] != second[:3]
        or sha256_bytes(first[3]) != sha256_bytes(second[3])
        or sha256_bytes(second[3]) != archive_identity["site_archive_sha256"]
    ):
        raise ReleaseError("site source changed during inspection")
    return {
        "release_sha": reviewed_sha,
        "site_git_tree_oid": first[2],
        **archive_identity,
    }


@contextmanager
def materialized_site_source(
    root: Path,
    reviewed_sha: str,
    expected_identity: dict[str, Any],
    *,
    git: Path = Path("/usr/bin/git"),
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> Iterator[tuple[Path, Path]]:
    current = inspect_site_source(root, reviewed_sha, git=git, runner=runner)
    if current != expected_identity:
        raise ReleaseError("site source identity differs from the reviewed deploy plan")
    raw = _run_git(
        git,
        root,
        ("archive", "--format=tar", reviewed_sha, "site"),
        binary=True,
        runner=runner,
    )
    assert isinstance(raw, bytes)
    identity, members = _archive_identity(raw)
    if any(identity[key] != expected_identity[key] for key in identity):
        raise ReleaseError("materialized site archive differs from the deploy plan")
    temporary = Path(tempfile.mkdtemp(prefix="tinyzkp-pages-source-"))
    temporary.chmod(0o700)
    source = temporary / "site"
    home = temporary / "home"
    source.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    try:
        for member_name, is_directory, content in members:
            relative = PurePosixPath(member_name)
            target = source.joinpath(*relative.parts)
            if is_directory:
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
        reviewed_config = (source / "wrangler.toml").read_bytes()
        scratch_config = home / "wrangler.toml"
        descriptor = os.open(
            scratch_config,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(reviewed_config)
            output.flush()
            os.fsync(output.fileno())
        scratch_config.chmod(0o400)
        for path in sorted(source.rglob("*"), reverse=True):
            path.chmod(0o500 if path.is_dir() else 0o400)
        source.chmod(0o500)
        yield source, home
    finally:
        for path in source.rglob("*") if source.exists() else []:
            try:
                path.chmod(0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        if source.exists():
            source.chmod(0o700)
        shutil.rmtree(temporary, ignore_errors=False)


TOOLCHAIN_KEYS = {
    "profile_id",
    "profile_sha256",
    "package_lock_sha256",
    "node_version",
    "wrangler_version",
    "node_realpath",
    "node_sha256",
    "wrangler_install_root",
    "wrangler_entrypoint_realpath",
    "wrangler_entrypoint_sha256",
    "materialization_sha256",
    "wrangler_tree_sha256",
    "wrangler_file_count",
    "wrangler_total_bytes",
}


def toolchain_identity(
    node: Path,
    wrangler: Path,
    *,
    validator: Callable[..., dict[str, object]] = validate_runtime,
) -> dict[str, Any]:
    try:
        identity = validator(
            node,
            wrangler,
            enforce_profile_paths=True,
            expected_owner_uid=0,
            require_root_parent_chain=True,
        )
    except ToolchainError as error:
        raise ReleaseError(
            "pinned Cloudflare toolchain provenance is invalid"
        ) from error
    if not isinstance(identity, dict) or set(identity) != TOOLCHAIN_KEYS:
        raise ReleaseError("Cloudflare toolchain identity fields differ")
    for field in (
        "profile_sha256",
        "package_lock_sha256",
        "node_sha256",
        "wrangler_entrypoint_sha256",
        "materialization_sha256",
        "wrangler_tree_sha256",
    ):
        sha256_hex(identity.get(field), f"toolchain {field}")
    if (
        identity.get("profile_id") != "tinyzkp-cloudflare-production-v1"
        or identity.get("node_version") != "v24.18.0"
        or identity.get("wrangler_version") != "4.85.0"
        or identity.get("node_realpath") != str(PINNED_NODE)
        or identity.get("wrangler_entrypoint_realpath") != str(PINNED_WRANGLER)
    ):
        raise ReleaseError(
            "Cloudflare toolchain is not the reviewed production runtime"
        )
    for field in ("wrangler_file_count", "wrangler_total_bytes"):
        if (
            not isinstance(identity.get(field), int)
            or isinstance(identity[field], bool)
            or identity[field] <= 0
        ):
            raise ReleaseError(f"toolchain {field} must be positive")
    return dict(identity)


NORMALIZED_DEPLOYMENT_KEYS = {
    "deployment_id",
    "url",
    "release_sha",
    "branch",
    "commit_dirty",
    "environment",
    "stage_status",
    "created_on",
}


def _deployment_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ReleaseError("Pages deployment URL is missing")
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not (
            hostname == "tinyzkp.pages.dev" or hostname.endswith(".tinyzkp.pages.dev")
        )
    ):
        raise ReleaseError("Pages deployment URL is outside tinyzkp.pages.dev")
    return f"https://{hostname}"


def normalize_deployment(
    value: Any,
    *,
    expected_release_sha: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError("Cloudflare deployment must be an object")
    if value.get("project_name") != PROJECT_NAME:
        raise ReleaseError("Cloudflare deployment belongs to another project")
    trigger = value.get("deployment_trigger")
    metadata = trigger.get("metadata") if isinstance(trigger, dict) else None
    stage = value.get("latest_stage")
    if not isinstance(metadata, dict) or not isinstance(stage, dict):
        raise ReleaseError("Cloudflare deployment metadata/stage is missing")
    commit = release_sha(metadata.get("commit_hash"), "deployment commit hash")
    if expected_release_sha is not None and commit != expected_release_sha:
        raise ReleaseError(
            "Cloudflare deployment commit differs from the reviewed release SHA"
        )
    if (
        value.get("environment") != "production"
        or metadata.get("branch") != PRODUCTION_BRANCH
        or metadata.get("commit_dirty") is not False
        or stage.get("status") != "success"
    ):
        raise ReleaseError(
            "Cloudflare deployment is not a clean successful production build"
        )
    return {
        "deployment_id": deployment_id(value.get("id")),
        "url": _deployment_url(value.get("url")),
        "release_sha": commit,
        "branch": PRODUCTION_BRANCH,
        "commit_dirty": False,
        "environment": "production",
        "stage_status": "success",
        "created_on": api_timestamp(value.get("created_on"), "deployment created_on"),
    }


def validate_project(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict):
        raise ReleaseError("Cloudflare Pages project must be an object")
    if (
        value.get("name") != PROJECT_NAME
        or value.get("production_branch") != PRODUCTION_BRANCH
    ):
        raise ReleaseError(
            "Cloudflare account does not expose the exact tinyzkp/main Pages project"
        )
    project_id = value.get("id")
    project_id = deployment_id(project_id, "Cloudflare Pages project ID")
    canonical = normalize_deployment(value.get("canonical_deployment"))
    return {
        "project_id": project_id,
        "project_name": PROJECT_NAME,
        "production_branch": PRODUCTION_BRANCH,
    }, canonical


def validate_normalized_deployment(value: Any, label: str) -> dict[str, Any]:
    deployment = exact_object(value, NORMALIZED_DEPLOYMENT_KEYS, label)
    normalized = normalize_deployment(
        {
            "id": deployment.get("deployment_id"),
            "url": deployment.get("url"),
            "project_name": PROJECT_NAME,
            "environment": deployment.get("environment"),
            "deployment_trigger": {
                "metadata": {
                    "commit_hash": deployment.get("release_sha"),
                    "branch": deployment.get("branch"),
                    "commit_dirty": deployment.get("commit_dirty"),
                }
            },
            "latest_stage": {"status": deployment.get("stage_status")},
            "created_on": deployment.get("created_on"),
        }
    )
    if normalized != deployment:
        raise ReleaseError(f"{label} is not normalized")
    return deployment


ROLLBACK_OUTCOME_KEYS = {
    "status",
    "method",
    "target_deployment",
    "api_result_deployment",
    "canonical_deployment",
    "failure_code",
}
ROLLBACK_FAILURE_CODES = {
    "rollback_request_and_verification_failed",
    "rollback_response_invalid",
    "rollback_response_mismatch",
    "canonical_verification_failed",
}


def validate_rollback_outcome(value: Any) -> dict[str, Any]:
    outcome = exact_object(value, ROLLBACK_OUTCOME_KEYS, "rollback outcome")
    target = validate_normalized_deployment(
        outcome.get("target_deployment"), "rollback target"
    )
    for field in ("api_result_deployment", "canonical_deployment"):
        observed = outcome.get(field)
        if observed is not None:
            validate_normalized_deployment(observed, field.replace("_", " "))
    status = outcome.get("status")
    if status == "verified":
        if outcome.get("method") not in {
            "api_rollback",
            "already_canonical_after_api_error",
        }:
            raise ReleaseError("verified rollback method is invalid")
        if outcome.get("failure_code") is not None:
            raise ReleaseError("verified rollback cannot contain a failure code")
        if outcome.get("canonical_deployment") != target:
            raise ReleaseError("verified rollback canonical target differs")
        if (
            outcome["method"] == "api_rollback"
            and outcome.get("api_result_deployment") != target
        ):
            raise ReleaseError("verified rollback API result differs")
        if (
            outcome["method"] == "already_canonical_after_api_error"
            and outcome.get("api_result_deployment") is not None
        ):
            raise ReleaseError("API-error rollback cannot contain an API result")
    elif status == "failed":
        if outcome.get("method") != "unverified":
            raise ReleaseError("failed rollback method is invalid")
        if outcome.get("failure_code") not in ROLLBACK_FAILURE_CODES:
            raise ReleaseError("failed rollback code is invalid")
    else:
        raise ReleaseError("rollback outcome status is invalid")
    return outcome


def _verify_exact_canonical(
    api: Any, project_id: str, target: dict[str, Any]
) -> dict[str, Any]:
    project, current = validate_project(api.get_project())
    if project["project_id"] != project_id or current != target:
        raise ReleaseError("canonical deployment differs from the rollback target")
    exact = normalize_deployment(api.get_deployment(target["deployment_id"]))
    if exact != target:
        raise ReleaseError("rollback target deployment changed during verification")
    return exact


def _attempt_exact_rollback(
    api: Any, project_id: str, target_value: Any
) -> dict[str, Any]:
    """Compensate to one recorded target and return credential-free evidence.

    The function never raises for a Cloudflare rollback/verification failure so
    callers can persist a complete failure record. Structural errors in the
    caller-provided target still fail before any external write.
    """

    target = validate_normalized_deployment(target_value, "automatic rollback target")
    outcome: dict[str, Any] = {
        "status": "failed",
        "method": "unverified",
        "target_deployment": target,
        "api_result_deployment": None,
        "canonical_deployment": None,
        "failure_code": "rollback_request_and_verification_failed",
    }
    try:
        raw_result = api.rollback(target["deployment_id"])
    except BaseException:
        try:
            outcome["canonical_deployment"] = _verify_exact_canonical(
                api, project_id, target
            )
        except BaseException:
            validate_rollback_outcome(outcome)
            return outcome
        outcome.update(
            status="verified",
            method="already_canonical_after_api_error",
            failure_code=None,
        )
        validate_rollback_outcome(outcome)
        return outcome

    try:
        result = normalize_deployment(raw_result)
    except BaseException:
        outcome["failure_code"] = "rollback_response_invalid"
        try:
            outcome["canonical_deployment"] = _verify_exact_canonical(
                api, project_id, target
            )
        except BaseException:
            pass
        validate_rollback_outcome(outcome)
        return outcome
    outcome["api_result_deployment"] = result
    if result != target:
        outcome["failure_code"] = "rollback_response_mismatch"
        try:
            outcome["canonical_deployment"] = _verify_exact_canonical(
                api, project_id, target
            )
        except BaseException:
            pass
        validate_rollback_outcome(outcome)
        return outcome
    try:
        outcome["canonical_deployment"] = _verify_exact_canonical(
            api, project_id, target
        )
    except BaseException:
        outcome["failure_code"] = "canonical_verification_failed"
        validate_rollback_outcome(outcome)
        return outcome
    outcome.update(status="verified", method="api_rollback", failure_code=None)
    validate_rollback_outcome(outcome)
    return outcome


def validate_source_identity(value: Any, release: str) -> dict[str, Any]:
    source = exact_object(
        value,
        {
            "release_sha",
            "site_git_tree_oid",
            "site_archive_sha256",
            "site_manifest_sha256",
            "site_file_count",
            "site_total_bytes",
        },
        "site source identity",
    )
    if (
        source.get("release_sha") != release
        or GIT_OBJECT.fullmatch(str(source.get("site_git_tree_oid") or "")) is None
    ):
        raise ReleaseError("site source is not bound to the reviewed release")
    sha256_hex(source.get("site_archive_sha256"), "site archive SHA-256")
    sha256_hex(source.get("site_manifest_sha256"), "site manifest SHA-256")
    for field in ("site_file_count", "site_total_bytes"):
        if (
            not isinstance(source.get(field), int)
            or isinstance(source[field], bool)
            or source[field] <= 0
        ):
            raise ReleaseError(f"site source {field} must be positive")
    return source


def validate_toolchain_identity(value: Any) -> dict[str, Any]:
    identity = exact_object(value, TOOLCHAIN_KEYS, "toolchain identity")
    # Reuse the non-I/O portion by checking the frozen constants and fields here.
    for field in (
        "profile_sha256",
        "package_lock_sha256",
        "node_sha256",
        "wrangler_entrypoint_sha256",
        "materialization_sha256",
        "wrangler_tree_sha256",
    ):
        sha256_hex(identity.get(field), f"toolchain {field}")
    if (
        identity.get("profile_id") != "tinyzkp-cloudflare-production-v1"
        or identity.get("node_version") != "v24.18.0"
        or identity.get("wrangler_version") != "4.85.0"
        or identity.get("node_realpath") != str(PINNED_NODE)
        or identity.get("wrangler_entrypoint_realpath") != str(PINNED_WRANGLER)
    ):
        raise ReleaseError("deployment record toolchain is not the pinned runtime")
    for field in ("wrangler_file_count", "wrangler_total_bytes"):
        if (
            not isinstance(identity.get(field), int)
            or isinstance(identity[field], bool)
            or identity[field] <= 0
        ):
            raise ReleaseError(f"toolchain {field} must be positive")
    install_root = identity.get("wrangler_install_root")
    if not isinstance(install_root, str) or not Path(install_root).is_absolute():
        raise ReleaseError("toolchain install root must be absolute")
    return identity


def deploy_plan(
    *,
    reviewed_sha: str,
    expected_account_id: str,
    api: Any,
    source_provider: Callable[[Path, str], dict[str, Any]],
    toolchain_provider: Callable[[Path, Path], dict[str, Any]],
    node: Path = PINNED_NODE,
    wrangler: Path = PINNED_WRANGLER,
    root: Path = ROOT,
) -> dict[str, Any]:
    reviewed_sha = release_sha(reviewed_sha, "reviewed release SHA")
    account = account_id(expected_account_id)
    project, prior = validate_project(api.get_project())
    source = validate_source_identity(source_provider(root, reviewed_sha), reviewed_sha)
    toolchain = validate_toolchain_identity(toolchain_provider(node, wrangler))
    plan = {
        "schema_version": DEPLOY_PLAN_SCHEMA,
        "operation": "deploy",
        "account_id": account,
        **project,
        "release_sha": reviewed_sha,
        "prior_production_deployment": prior,
        "source": source,
        "toolchain": toolchain,
    }
    return {"plan": plan, "plan_sha256": canonical_sha256(plan)}


def _validate_deploy_plan(value: Any) -> dict[str, Any]:
    wrapper = exact_object(value, {"plan", "plan_sha256"}, "deploy plan")
    plan = exact_object(
        wrapper.get("plan"),
        {
            "schema_version",
            "operation",
            "account_id",
            "project_id",
            "project_name",
            "production_branch",
            "release_sha",
            "prior_production_deployment",
            "source",
            "toolchain",
        },
        "deploy plan payload",
    )
    if (
        plan.get("schema_version") != DEPLOY_PLAN_SCHEMA
        or plan.get("operation") != "deploy"
    ):
        raise ReleaseError("deploy plan schema/operation is invalid")
    account_id(plan.get("account_id"))
    deployment_id(plan.get("project_id"), "Cloudflare Pages project ID")
    if (
        plan.get("project_name") != PROJECT_NAME
        or plan.get("production_branch") != PRODUCTION_BRANCH
    ):
        raise ReleaseError("deploy plan project identity is invalid")
    release = release_sha(plan.get("release_sha"))
    prior = exact_object(
        plan.get("prior_production_deployment"),
        NORMALIZED_DEPLOYMENT_KEYS,
        "prior deployment",
    )
    if (
        normalize_deployment(
            {
                "id": prior.get("deployment_id"),
                "url": prior.get("url"),
                "project_name": PROJECT_NAME,
                "environment": prior.get("environment"),
                "deployment_trigger": {
                    "metadata": {
                        "commit_hash": prior.get("release_sha"),
                        "branch": prior.get("branch"),
                        "commit_dirty": prior.get("commit_dirty"),
                    }
                },
                "latest_stage": {"status": prior.get("stage_status")},
                "created_on": prior.get("created_on"),
            }
        )
        != prior
    ):
        raise ReleaseError("prior deployment is not normalized")
    validate_source_identity(plan.get("source"), release)
    validate_toolchain_identity(plan.get("toolchain"))
    digest = sha256_hex(wrapper.get("plan_sha256"), "deploy plan SHA-256")
    if digest != canonical_sha256(plan):
        raise ReleaseError("deploy plan hash mismatch")
    return wrapper


def _write_enabled(
    environment: dict[str, str], expected_plan: str, actual_plan: str
) -> None:
    if environment.get(WRITE_ENV) != "1":
        raise ReleaseError(f"write requires {WRITE_ENV}=1")
    if SHA256.fullmatch(expected_plan or "") is None or expected_plan != actual_plan:
        raise ReleaseError("write requires the exact preview plan SHA-256")


def _wrangler_environment(
    environment: dict[str, str], account: str, home: Path
) -> dict[str, str]:
    token = environment.get("CLOUDFLARE_API_TOKEN", "")
    configured_account = environment.get("CLOUDFLARE_ACCOUNT_ID", "")
    if configured_account != account:
        raise ReleaseError(
            "configured Cloudflare account differs from the reviewed account ID"
        )
    if (
        not 20 <= len(token) <= 512
        or token != token.strip()
        or any(c.isspace() for c in token)
    ):
        raise ReleaseError("Cloudflare API token is missing or malformed")
    return {
        "PATH": TRUSTED_PATH,
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_API_TOKEN": token,
        "CLOUDFLARE_ACCOUNT_ID": account,
    }


def _wrangler_command(
    source: Path, scratch: Path, release: str, node: Path, wrangler: Path
) -> tuple[str, ...]:
    return (
        str(node),
        str(wrangler),
        "pages",
        "deploy",
        str(source),
        "--cwd",
        str(scratch),
        "--project-name",
        PROJECT_NAME,
        "--branch",
        PRODUCTION_BRANCH,
        "--commit-hash",
        release,
        "--commit-message",
        f"TinyZKP release {release}",
        "--commit-dirty=false",
    )


def _run_checked(
    command: tuple[str, ...],
    *,
    environment: dict[str, str],
    runner: Callable[..., subprocess.CompletedProcess[str]],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = runner(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError("pinned deployment command could not complete") from error
    if (
        completed.returncode != 0
        or len(completed.stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES
        or len(completed.stderr.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise ReleaseError(
            "pinned deployment command failed or emitted oversized output"
        )
    return completed


DEPLOYMENT_RECORD_KEYS = {
    "schema_version",
    "status",
    "account_id",
    "project_id",
    "project_name",
    "production_branch",
    "release_sha",
    "deploy_plan_sha256",
    "new_deployment",
    "prior_production_deployment",
    "source",
    "toolchain",
    "wrangler_command_sha256",
    "recorded_at",
    "post_deploy_canary",
}


def validate_deployment_record(value: Any) -> dict[str, Any]:
    record = exact_object(value, DEPLOYMENT_RECORD_KEYS, "deployment record")
    if (
        record.get("schema_version") != DEPLOYMENT_RECORD_SCHEMA
        or record.get("status") != "deployed_pending_canary"
        or record.get("project_name") != PROJECT_NAME
        or record.get("production_branch") != PRODUCTION_BRANCH
        or record.get("post_deploy_canary") != "pending"
    ):
        raise ReleaseError("deployment record state/project is invalid")
    account_id(record.get("account_id"))
    deployment_id(record.get("project_id"), "Cloudflare Pages project ID")
    release = release_sha(record.get("release_sha"))
    sha256_hex(record.get("deploy_plan_sha256"), "deployment plan SHA-256")
    sha256_hex(record.get("wrangler_command_sha256"), "Wrangler command SHA-256")
    canonical_timestamp(record.get("recorded_at"), "deployment recorded_at")
    new = exact_object(
        record.get("new_deployment"), NORMALIZED_DEPLOYMENT_KEYS, "new deployment"
    )
    prior = exact_object(
        record.get("prior_production_deployment"),
        NORMALIZED_DEPLOYMENT_KEYS,
        "prior deployment",
    )
    if new.get("release_sha") != release or new.get("deployment_id") == prior.get(
        "deployment_id"
    ):
        raise ReleaseError("deployment record new/prior identities are inconsistent")
    for deployment, label in ((new, "new"), (prior, "prior")):
        deployment_id(deployment.get("deployment_id"), f"{label} deployment ID")
        _deployment_url(deployment.get("url"))
        release_sha(deployment.get("release_sha"), f"{label} release SHA")
        canonical_timestamp(deployment.get("created_on"), f"{label} created_on")
        if (
            deployment.get("branch") != PRODUCTION_BRANCH
            or deployment.get("commit_dirty") is not False
            or deployment.get("environment") != "production"
            or deployment.get("stage_status") != "success"
        ):
            raise ReleaseError(f"{label} deployment is not clean production success")
    validate_source_identity(record.get("source"), release)
    validate_toolchain_identity(record.get("toolchain"))
    return record


DEPLOY_FAILURE_RECORD_KEYS = {
    "schema_version",
    "status",
    "account_id",
    "project_id",
    "project_name",
    "release_sha",
    "deploy_plan_sha256",
    "source_sha256",
    "toolchain_materialization_sha256",
    "prior_production_deployment",
    "failure_stage",
    "failure_type",
    "deployment_record_published",
    "rollback",
    "recorded_at",
}
DEPLOY_FAILURE_STAGES = {
    "wrangler_invocation",
    "source_cleanup",
    "project_validation",
    "deployment_validation",
    "deployment_record_validation",
    "deployment_record_write",
}
DEPLOY_FAILURE_TYPES = {"release_error", "operator_interrupt", "unexpected_error"}


def deploy_failure_path(output: Path) -> Path:
    return output.with_name(f"{output.name}.failure.json")


def _failure_type(error: BaseException) -> str:
    if isinstance(error, ReleaseError):
        return "release_error"
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return "operator_interrupt"
    return "unexpected_error"


def validate_deploy_failure_record(value: Any) -> dict[str, Any]:
    record = exact_object(value, DEPLOY_FAILURE_RECORD_KEYS, "deploy failure record")
    if (
        record.get("schema_version") != DEPLOY_FAILURE_RECORD_SCHEMA
        or record.get("status")
        not in {"deploy_failed_rolled_back", "deploy_failed_rollback_failed"}
        or record.get("project_name") != PROJECT_NAME
    ):
        raise ReleaseError("deploy failure record schema/state/project is invalid")
    account_id(record.get("account_id"))
    deployment_id(record.get("project_id"), "Cloudflare Pages project ID")
    release_sha(record.get("release_sha"))
    for field in (
        "deploy_plan_sha256",
        "source_sha256",
        "toolchain_materialization_sha256",
    ):
        sha256_hex(record.get(field), field)
    prior = validate_normalized_deployment(
        record.get("prior_production_deployment"), "failure-record prior deployment"
    )
    if record.get("failure_stage") not in DEPLOY_FAILURE_STAGES:
        raise ReleaseError("deploy failure stage is invalid")
    if record.get("failure_type") not in DEPLOY_FAILURE_TYPES:
        raise ReleaseError("deploy failure type is invalid")
    if not isinstance(record.get("deployment_record_published"), bool):
        raise ReleaseError("deployment_record_published must be boolean")
    canonical_timestamp(record.get("recorded_at"), "deploy failure recorded_at")
    rollback = validate_rollback_outcome(record.get("rollback"))
    if rollback["target_deployment"] != prior:
        raise ReleaseError("automatic rollback target differs from the deploy plan")
    rolled_back = rollback["status"] == "verified"
    if (record["status"] == "deploy_failed_rolled_back") != rolled_back:
        raise ReleaseError("deploy failure status differs from rollback evidence")
    return record


def apply_deploy(
    *,
    reviewed_sha: str,
    expected_account_id: str,
    expected_plan_sha256: str,
    output: Path,
    api: Any,
    source_provider: Callable[[Path, str], dict[str, Any]],
    source_materializer: Callable[..., Any],
    toolchain_provider: Callable[[Path, Path], dict[str, Any]],
    runner: Callable[..., subprocess.CompletedProcess[str]],
    environment: dict[str, str],
    now: Callable[[], str] = utc_now,
    node: Path = PINNED_NODE,
    wrangler: Path = PINNED_WRANGLER,
    root: Path = ROOT,
) -> dict[str, Any]:
    _private_parent(output)
    failure_output = deploy_failure_path(output)
    if output.exists() or output.is_symlink():
        raise ReleaseError("deployment record output already exists")
    if failure_output.exists() or failure_output.is_symlink():
        raise ReleaseError("deployment failure record output already exists")
    with operation_lock(output.parent):
        preview = deploy_plan(
            reviewed_sha=reviewed_sha,
            expected_account_id=expected_account_id,
            api=api,
            source_provider=source_provider,
            toolchain_provider=toolchain_provider,
            node=node,
            wrangler=wrangler,
            root=root,
        )
        _validate_deploy_plan(preview)
        _write_enabled(environment, expected_plan_sha256, preview["plan_sha256"])
        plan = preview["plan"]
        account = plan["account_id"]
        invocation_started = False
        failure_stage = "wrangler_invocation"
        try:
            with source_materializer(root, reviewed_sha, plan["source"]) as (
                source,
                home,
            ):
                command = _wrangler_command(
                    source, home, reviewed_sha, node, wrangler
                )
                command_identity = tuple(
                    "<SOURCE>"
                    if item == str(source)
                    else "<SCRATCH>"
                    if item == str(home)
                    else item
                    for item in command
                )
                invocation_started = True
                _run_checked(
                    command,
                    environment=_wrangler_environment(environment, account, home),
                    runner=runner,
                    timeout=900,
                )
                failure_stage = "source_cleanup"
            failure_stage = "project_validation"
            project, new = validate_project(api.get_project())
            if project["project_id"] != plan["project_id"]:
                raise ReleaseError("Cloudflare project identity changed during deploy")
            failure_stage = "deployment_validation"
            new = normalize_deployment(
                api.get_deployment(new["deployment_id"]),
                expected_release_sha=reviewed_sha,
            )
            if (
                new["deployment_id"]
                == plan["prior_production_deployment"]["deployment_id"]
            ):
                raise ReleaseError(
                    "Wrangler did not create a new production deployment"
                )
            record = {
                "schema_version": DEPLOYMENT_RECORD_SCHEMA,
                "status": "deployed_pending_canary",
                "account_id": account,
                "project_id": project["project_id"],
                "project_name": PROJECT_NAME,
                "production_branch": PRODUCTION_BRANCH,
                "release_sha": reviewed_sha,
                "deploy_plan_sha256": preview["plan_sha256"],
                "new_deployment": new,
                "prior_production_deployment": plan["prior_production_deployment"],
                "source": plan["source"],
                "toolchain": plan["toolchain"],
                "wrangler_command_sha256": canonical_sha256(list(command_identity)),
                "recorded_at": canonical_timestamp(now(), "recorded_at"),
                "post_deploy_canary": "pending",
            }
            failure_stage = "deployment_record_validation"
            validate_deployment_record(record)
            failure_stage = "deployment_record_write"
            record_sha = write_canonical_exclusive(output, record)
        except BaseException as error:
            if not invocation_started:
                raise
            rollback = _attempt_exact_rollback(
                api,
                plan["project_id"],
                plan["prior_production_deployment"],
            )
            rollback_verified = rollback["status"] == "verified"
            failure_record = {
                "schema_version": DEPLOY_FAILURE_RECORD_SCHEMA,
                "status": (
                    "deploy_failed_rolled_back"
                    if rollback_verified
                    else "deploy_failed_rollback_failed"
                ),
                "account_id": account,
                "project_id": plan["project_id"],
                "project_name": PROJECT_NAME,
                "release_sha": reviewed_sha,
                "deploy_plan_sha256": preview["plan_sha256"],
                "source_sha256": plan["source"]["site_manifest_sha256"],
                "toolchain_materialization_sha256": plan["toolchain"][
                    "materialization_sha256"
                ],
                "prior_production_deployment": plan["prior_production_deployment"],
                "failure_stage": failure_stage,
                "failure_type": _failure_type(error),
                "deployment_record_published": output.exists() or output.is_symlink(),
                "rollback": rollback,
                "recorded_at": canonical_timestamp(now(), "failure recorded_at"),
            }
            try:
                validate_deploy_failure_record(failure_record)
                failure_sha = write_canonical_exclusive(failure_output, failure_record)
            except BaseException as evidence_error:
                state = "verified" if rollback_verified else "FAILED"
                raise ReleaseError(
                    "deployment failed after Wrangler invocation; automatic rollback "
                    f"{state}; failure evidence could not be persisted"
                ) from evidence_error
            state = "verified" if rollback_verified else "FAILED"
            raise ReleaseError(
                "deployment failed after Wrangler invocation; automatic rollback "
                f"{state}; failure evidence {failure_output} SHA-256 {failure_sha}"
            ) from error
        return {
            "status": "deployed_pending_canary",
            "deployment_id": new["deployment_id"],
            "deployment_url": new["url"],
            "release_sha": reviewed_sha,
            "deployment_record_sha256": record_sha,
            "deployment_record": str(output),
        }


def _recorded_deployment_matches_api(record: dict[str, Any], api: Any) -> None:
    project, current = validate_project(api.get_project())
    if project["project_id"] != record["project_id"]:
        raise ReleaseError("recorded Cloudflare project identity no longer matches")
    if current["deployment_id"] != record["new_deployment"]["deployment_id"]:
        raise ReleaseError(
            "recorded deployment is no longer the canonical production deployment"
        )
    current = normalize_deployment(
        api.get_deployment(current["deployment_id"]),
        expected_release_sha=record["release_sha"],
    )
    if current != record["new_deployment"]:
        raise ReleaseError(
            "recorded deployment is no longer the canonical production deployment"
        )


def _public_canary_environment() -> dict[str, str]:
    return {
        "PATH": TRUSTED_PATH,
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
    }


CANARY_RECORD_KEYS = {
    "schema_version",
    "status",
    "deployment_record_sha256",
    "deployment_id",
    "release_sha",
    "checked_at",
    "checks",
    "rollback",
}
CANARY_CHECK_KEYS = {
    "name",
    "command_sha256",
    "exit_code",
    "stdout_sha256",
    "stderr_sha256",
}


def validate_canary_record(value: Any) -> dict[str, Any]:
    record = exact_object(value, CANARY_RECORD_KEYS, "canary record")
    if record.get("schema_version") != CANARY_RECORD_SCHEMA or record.get(
        "status"
    ) not in {"passed", "failed_rolled_back", "failed_rollback_failed"}:
        raise ReleaseError("canary record schema/status is invalid")
    sha256_hex(record.get("deployment_record_sha256"), "deployment record SHA-256")
    deployment_id(record.get("deployment_id"))
    release_sha(record.get("release_sha"))
    canonical_timestamp(record.get("checked_at"), "canary checked_at")
    checks = record.get("checks")
    if not isinstance(checks, list) or len(checks) != 2:
        raise ReleaseError("canary record must contain exactly two checks")
    expected_names = ["static_contracts", "static_routes"]
    for index, check_value in enumerate(checks):
        check = exact_object(check_value, CANARY_CHECK_KEYS, f"canary check {index}")
        if check.get("name") != expected_names[index]:
            raise ReleaseError("canary checks are missing or out of order")
        for field in ("command_sha256", "stdout_sha256", "stderr_sha256"):
            sha256_hex(check.get(field), f"canary check {field}")
        if not isinstance(check.get("exit_code"), int) or isinstance(
            check["exit_code"], bool
        ):
            raise ReleaseError("canary check exit_code must be an integer")
    passed = all(check["exit_code"] == 0 for check in checks)
    rollback_value = record.get("rollback")
    if passed:
        if record["status"] != "passed" or rollback_value is not None:
            raise ReleaseError("passed canary cannot contain rollback evidence")
    else:
        rollback = validate_rollback_outcome(rollback_value)
        rolled_back = rollback["status"] == "verified"
        if (record["status"] == "failed_rolled_back") != rolled_back:
            raise ReleaseError("failed canary status differs from rollback evidence")
    return record


def _execute_canary_check(
    name: str,
    command: tuple[str, ...],
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    try:
        completed = runner(
            command,
            cwd=ROOT,
            env=_public_canary_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
            check=False,
        )
    except BaseException:
        return {
            "name": name,
            "command_sha256": canonical_sha256(list(command)),
            "exit_code": -1000,
            "stdout_sha256": sha256_bytes(b""),
            "stderr_sha256": sha256_bytes(b""),
        }
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        return {
            "name": name,
            "command_sha256": canonical_sha256(list(command)),
            "exit_code": -1001,
            "stdout_sha256": sha256_bytes(b""),
            "stderr_sha256": sha256_bytes(b""),
        }
    stdout = completed.stdout.encode("utf-8")
    stderr = completed.stderr.encode("utf-8")
    oversized = (
        len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES
    )
    return {
        "name": name,
        "command_sha256": canonical_sha256(list(command)),
        "exit_code": -1002 if oversized else completed.returncode,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
    }


def run_post_deploy_canary(
    *,
    deployment_record_path: Path,
    expected_record_sha256: str,
    expected_account_id: str,
    output: Path,
    api: Any,
    runner: Callable[..., subprocess.CompletedProcess[str]],
    environment: dict[str, str],
    now: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    _private_parent(output)
    if output.exists() or output.is_symlink():
        raise ReleaseError("canary record output already exists")
    payload, raw = read_canonical_record(deployment_record_path, "deployment record")
    record = validate_deployment_record(payload)
    record_sha = sha256_bytes(raw)
    if (
        sha256_hex(expected_record_sha256, "expected deployment record SHA-256")
        != record_sha
    ):
        raise ReleaseError("deployment record differs from the reviewed canary input")
    account = account_id(expected_account_id)
    if record["account_id"] != account:
        raise ReleaseError("deployment record belongs to another Cloudflare account")
    _write_enabled(environment, expected_record_sha256, record_sha)
    _recorded_deployment_matches_api(record, api)
    try:
        discovery = json.loads((ROOT / "site" / "discovery.json").read_text())
        monitoring_mode = discovery.get("service_status")
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError("cannot read Guard monitoring mode") from error
    if monitoring_mode not in {
        "guard_prelaunch",
        "guard_transition",
        "guard_live",
    }:
        raise ReleaseError("Guard monitoring mode is not deployable")
    commands = (
        (
            "static_contracts",
            (
                "/usr/bin/python3",
                str(ROOT / "scripts" / "deploy" / "static_site_canary.py"),
                "--base-url",
                record["new_deployment"]["url"],
                "--mode",
                monitoring_mode,
            ),
        ),
        (
            "static_routes",
            (
                "/usr/bin/python3",
                str(ROOT / "scripts" / "deploy" / "static_site_canary.py"),
                "--base-url",
                record["new_deployment"]["url"],
                "--mode",
                "routes",
            ),
        ),
    )
    checks = [
        _execute_canary_check(name, command, runner) for name, command in commands
    ]
    passed = all(check["exit_code"] == 0 for check in checks)
    rollback = None
    if not passed:
        rollback = _attempt_exact_rollback(
            api,
            record["project_id"],
            record["prior_production_deployment"],
        )
    rollback_verified = rollback is not None and rollback["status"] == "verified"
    canary_record = {
        "schema_version": CANARY_RECORD_SCHEMA,
        "status": (
            "passed"
            if passed
            else "failed_rolled_back"
            if rollback_verified
            else "failed_rollback_failed"
        ),
        "deployment_record_sha256": record_sha,
        "deployment_id": record["new_deployment"]["deployment_id"],
        "release_sha": record["release_sha"],
        "checked_at": canonical_timestamp(now(), "canary checked_at"),
        "checks": checks,
        "rollback": rollback,
    }
    validate_canary_record(canary_record)
    canary_sha = write_canonical_exclusive(output, canary_record)
    if not passed:
        state = "verified" if rollback_verified else "FAILED"
        raise ReleaseError(
            "post-deploy canary failed; automatic rollback "
            f"{state}; evidence SHA-256 is {canary_sha}"
        )
    return {
        "status": "passed",
        "canary_record": str(output),
        "canary_record_sha256": canary_sha,
        "deployment_id": record["new_deployment"]["deployment_id"],
        "release_sha": record["release_sha"],
    }


def rollback_plan(
    *,
    deployment_record_path: Path,
    expected_record_sha256: str,
    expected_account_id: str,
    api: Any,
) -> dict[str, Any]:
    payload, raw = read_canonical_record(deployment_record_path, "deployment record")
    record = validate_deployment_record(payload)
    record_sha = sha256_bytes(raw)
    if (
        sha256_hex(expected_record_sha256, "expected deployment record SHA-256")
        != record_sha
    ):
        raise ReleaseError("deployment record differs from the reviewed rollback input")
    account = account_id(expected_account_id)
    if record["account_id"] != account:
        raise ReleaseError("deployment record belongs to another Cloudflare account")
    _recorded_deployment_matches_api(record, api)
    target = normalize_deployment(
        api.get_deployment(record["prior_production_deployment"]["deployment_id"])
    )
    if target != record["prior_production_deployment"]:
        raise ReleaseError("recorded rollback target changed or is no longer valid")
    plan = {
        "schema_version": ROLLBACK_PLAN_SCHEMA,
        "operation": "rollback",
        "account_id": account,
        "project_id": record["project_id"],
        "project_name": PROJECT_NAME,
        "deployment_record_sha256": record_sha,
        "from_deployment": record["new_deployment"],
        "target_deployment": target,
        "deployed_release_sha": record["release_sha"],
        "source_sha256": record["source"]["site_manifest_sha256"],
        "toolchain_materialization_sha256": record["toolchain"][
            "materialization_sha256"
        ],
    }
    return {"plan": plan, "plan_sha256": canonical_sha256(plan)}


def _validate_rollback_plan(value: Any) -> dict[str, Any]:
    wrapper = exact_object(value, {"plan", "plan_sha256"}, "rollback plan")
    plan = exact_object(
        wrapper.get("plan"),
        {
            "schema_version",
            "operation",
            "account_id",
            "project_id",
            "project_name",
            "deployment_record_sha256",
            "from_deployment",
            "target_deployment",
            "deployed_release_sha",
            "source_sha256",
            "toolchain_materialization_sha256",
        },
        "rollback plan payload",
    )
    if (
        plan.get("schema_version") != ROLLBACK_PLAN_SCHEMA
        or plan.get("operation") != "rollback"
        or plan.get("project_name") != PROJECT_NAME
    ):
        raise ReleaseError("rollback plan schema/project is invalid")
    account_id(plan.get("account_id"))
    deployment_id(plan.get("project_id"), "Cloudflare Pages project ID")
    release_sha(plan.get("deployed_release_sha"))
    for field in (
        "deployment_record_sha256",
        "source_sha256",
        "toolchain_materialization_sha256",
    ):
        sha256_hex(plan.get(field), field)
    for field in ("from_deployment", "target_deployment"):
        deployment = exact_object(plan.get(field), NORMALIZED_DEPLOYMENT_KEYS, field)
        deployment_id(deployment.get("deployment_id"))
        release_sha(deployment.get("release_sha"))
        _deployment_url(deployment.get("url"))
        canonical_timestamp(deployment.get("created_on"), f"{field}.created_on")
        if (
            deployment.get("branch") != PRODUCTION_BRANCH
            or deployment.get("commit_dirty") is not False
            or deployment.get("environment") != "production"
            or deployment.get("stage_status") != "success"
        ):
            raise ReleaseError(
                f"{field} is not a clean successful production deployment"
            )
    if (
        plan["from_deployment"]["deployment_id"]
        == plan["target_deployment"]["deployment_id"]
    ):
        raise ReleaseError("rollback target must differ from the deployed release")
    digest = sha256_hex(wrapper.get("plan_sha256"), "rollback plan SHA-256")
    if digest != canonical_sha256(plan):
        raise ReleaseError("rollback plan hash mismatch")
    return wrapper


ROLLBACK_RECORD_KEYS = {
    "schema_version",
    "status",
    "account_id",
    "project_id",
    "project_name",
    "deployment_record_sha256",
    "rollback_plan_sha256",
    "from_deployment",
    "target_deployment",
    "api_result_deployment",
    "rolled_back_at",
}


def validate_rollback_record(value: Any) -> dict[str, Any]:
    record = exact_object(value, ROLLBACK_RECORD_KEYS, "rollback record")
    if (
        record.get("schema_version") != ROLLBACK_RECORD_SCHEMA
        or record.get("status") != "rolled_back_pending_canary"
        or record.get("project_name") != PROJECT_NAME
    ):
        raise ReleaseError("rollback record schema/state/project is invalid")
    account_id(record.get("account_id"))
    deployment_id(record.get("project_id"), "Cloudflare Pages project ID")
    for field in ("deployment_record_sha256", "rollback_plan_sha256"):
        sha256_hex(record.get(field), field)
    canonical_timestamp(record.get("rolled_back_at"), "rolled_back_at")
    for field in ("from_deployment", "target_deployment", "api_result_deployment"):
        deployment = exact_object(record.get(field), NORMALIZED_DEPLOYMENT_KEYS, field)
        deployment_id(deployment.get("deployment_id"))
        release_sha(deployment.get("release_sha"))
        _deployment_url(deployment.get("url"))
        canonical_timestamp(deployment.get("created_on"), f"{field}.created_on")
        if (
            deployment.get("branch") != PRODUCTION_BRANCH
            or deployment.get("commit_dirty") is not False
            or deployment.get("environment") != "production"
            or deployment.get("stage_status") != "success"
        ):
            raise ReleaseError(
                f"{field} is not a clean successful production deployment"
            )
    if record["target_deployment"] != record["api_result_deployment"]:
        raise ReleaseError("rollback API result differs from the exact recorded target")
    if (
        record["from_deployment"]["deployment_id"]
        == record["target_deployment"]["deployment_id"]
    ):
        raise ReleaseError("rollback record target equals its source deployment")
    return record


def apply_rollback(
    *,
    deployment_record_path: Path,
    expected_record_sha256: str,
    expected_account_id: str,
    expected_plan_sha256: str,
    output: Path,
    api: Any,
    environment: dict[str, str],
    now: Callable[[], str] = utc_now,
) -> dict[str, Any]:
    _private_parent(output)
    if output.exists() or output.is_symlink():
        raise ReleaseError("rollback record output already exists")
    with operation_lock(output.parent):
        preview = rollback_plan(
            deployment_record_path=deployment_record_path,
            expected_record_sha256=expected_record_sha256,
            expected_account_id=expected_account_id,
            api=api,
        )
        _validate_rollback_plan(preview)
        _write_enabled(environment, expected_plan_sha256, preview["plan_sha256"])
        plan = preview["plan"]
        result = normalize_deployment(
            api.rollback(plan["target_deployment"]["deployment_id"])
        )
        if result != plan["target_deployment"]:
            raise ReleaseError(
                "Cloudflare rollback returned a deployment other than the exact target"
            )
        project, current = validate_project(api.get_project())
        if (
            project["project_id"] != plan["project_id"]
            or current != plan["target_deployment"]
        ):
            raise ReleaseError(
                "Cloudflare canonical deployment did not move to the exact rollback target"
            )
        record = {
            "schema_version": ROLLBACK_RECORD_SCHEMA,
            "status": "rolled_back_pending_canary",
            "account_id": plan["account_id"],
            "project_id": plan["project_id"],
            "project_name": PROJECT_NAME,
            "deployment_record_sha256": plan["deployment_record_sha256"],
            "rollback_plan_sha256": preview["plan_sha256"],
            "from_deployment": plan["from_deployment"],
            "target_deployment": plan["target_deployment"],
            "api_result_deployment": result,
            "rolled_back_at": canonical_timestamp(now(), "rolled_back_at"),
        }
        validate_rollback_record(record)
        record_sha = write_canonical_exclusive(output, record)
        return {
            "status": "rolled_back_pending_canary",
            "rollback_record": str(output),
            "rollback_record_sha256": record_sha,
            "target_deployment_id": result["deployment_id"],
            "target_release_sha": result["release_sha"],
        }


def _api_from_environment(
    expected_account: str, environment: dict[str, str]
) -> CloudflareApi:
    expected = account_id(expected_account)
    if environment.get("CLOUDFLARE_ACCOUNT_ID") != expected:
        raise ReleaseError(
            "configured Cloudflare account differs from --expected-account-id"
        )
    return CloudflareApi(expected, environment.get("CLOUDFLARE_API_TOKEN", ""))


def _emit_plan(plan: dict[str, Any], output: Path | None) -> dict[str, Any]:
    if output is not None:
        write_canonical_exclusive(output, plan)
    return {
        "mode": "plan",
        "operation": plan["plan"]["operation"],
        "plan_sha256": plan["plan_sha256"],
        "plan_output": str(output) if output is not None else None,
        "writes_performed": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    deploy = subparsers.add_parser("deploy", help="plan or apply a Pages deployment")
    deploy.add_argument("--release-sha", required=True)
    deploy.add_argument("--expected-account-id", required=True)
    deploy.add_argument("--plan-output", type=Path)
    deploy.add_argument("--apply", action="store_true")
    deploy.add_argument("--expected-plan-sha256")
    deploy.add_argument("--record-output", type=Path)
    deploy.add_argument("--node-executable", type=Path, default=PINNED_NODE)
    deploy.add_argument("--wrangler-entrypoint", type=Path, default=PINNED_WRANGLER)

    canary = subparsers.add_parser("canary", help="verify a recorded deployment live")
    canary.add_argument("--deployment-record", type=Path, required=True)
    canary.add_argument("--expected-record-sha256", required=True)
    canary.add_argument("--expected-account-id", required=True)
    canary.add_argument("--output", type=Path, required=True)

    rollback = subparsers.add_parser(
        "rollback", help="plan or apply exact recorded rollback"
    )
    rollback.add_argument("--deployment-record", type=Path, required=True)
    rollback.add_argument("--expected-record-sha256", required=True)
    rollback.add_argument("--expected-account-id", required=True)
    rollback.add_argument("--plan-output", type=Path)
    rollback.add_argument("--apply", action="store_true")
    rollback.add_argument("--expected-plan-sha256")
    rollback.add_argument("--record-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    environment = dict(os.environ)
    try:
        api = _api_from_environment(args.expected_account_id, environment)
        if args.command == "deploy":
            source_provider = partial(inspect_site_source, git=Path("/usr/bin/git"))
            toolchain_provider = toolchain_identity
            if not args.apply:
                result = _emit_plan(
                    deploy_plan(
                        reviewed_sha=args.release_sha,
                        expected_account_id=args.expected_account_id,
                        api=api,
                        source_provider=source_provider,
                        toolchain_provider=toolchain_provider,
                        node=args.node_executable,
                        wrangler=args.wrangler_entrypoint,
                    ),
                    args.plan_output,
                )
            else:
                if args.record_output is None:
                    raise ReleaseError(
                        "--record-output is required with deploy --apply"
                    )
                result = apply_deploy(
                    reviewed_sha=args.release_sha,
                    expected_account_id=args.expected_account_id,
                    expected_plan_sha256=args.expected_plan_sha256 or "",
                    output=args.record_output,
                    api=api,
                    source_provider=source_provider,
                    source_materializer=partial(
                        materialized_site_source, git=Path("/usr/bin/git")
                    ),
                    toolchain_provider=toolchain_provider,
                    runner=subprocess.run,
                    environment=environment,
                    node=args.node_executable,
                    wrangler=args.wrangler_entrypoint,
                )
        elif args.command == "canary":
            result = run_post_deploy_canary(
                deployment_record_path=args.deployment_record,
                expected_record_sha256=args.expected_record_sha256,
                expected_account_id=args.expected_account_id,
                output=args.output,
                api=api,
                runner=subprocess.run,
                environment=environment,
            )
        elif not args.apply:
            result = _emit_plan(
                rollback_plan(
                    deployment_record_path=args.deployment_record,
                    expected_record_sha256=args.expected_record_sha256,
                    expected_account_id=args.expected_account_id,
                    api=api,
                ),
                args.plan_output,
            )
        else:
            if args.record_output is None:
                raise ReleaseError("--record-output is required with rollback --apply")
            result = apply_rollback(
                deployment_record_path=args.deployment_record,
                expected_record_sha256=args.expected_record_sha256,
                expected_account_id=args.expected_account_id,
                expected_plan_sha256=args.expected_plan_sha256 or "",
                output=args.record_output,
                api=api,
                environment=environment,
            )
    except ReleaseError as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
