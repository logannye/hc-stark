#!/usr/bin/env python3
"""Bind release evidence to a stable Git source tree without SHA self-reference."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys

import strict_json


ROOT = Path(__file__).resolve().parents[2]
TRUST_PATH = ROOT / "release" / "release-trust-v1.json"
EVIDENCE_ONLY_EXACT = {"release/backend-v1-gates.json"}
EVIDENCE_ONLY_PREFIXES = ("release/evidence/",)


def _runtime_platform() -> str:
    system = "linux" if sys.platform.startswith("linux") else sys.platform
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{system}-{machine}"


def _git_anchor(root: Path) -> tuple[Path, str, str]:
    local = root.resolve() / "release" / "release-trust-v1.json"
    trust_path = local if local.is_file() else TRUST_PATH
    try:
        trust = strict_json.loads(trust_path.read_bytes())
        anchor = trust["git"]["platforms"][_runtime_platform()]
        expected_sha256 = anchor["sha256"]
        expected_version = anchor["version"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise ValueError("Git is not anchored for this runner platform") from error
    configured = os.environ.get("TINYZKP_ANCHORED_GIT", "").strip()
    if configured:
        executable = Path(configured).resolve()
    else:
        raw = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
        if raw is None:
            raise ValueError("anchored Git executable is unavailable")
        executable = Path(raw).resolve()
    if not executable.is_file():
        raise ValueError("anchored Git executable is unavailable")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
        or not isinstance(expected_version, str)
        or not expected_version.startswith("git version ")
    ):
        raise ValueError("committed Git anchor is malformed")
    return executable, expected_sha256, expected_version


def git_output(
    root: Path,
    *args: str,
    input_bytes: bytes | None = None,
    timeout_seconds: int = 120,
) -> bytes:
    """Execute the reviewed Git binary without PATH resolution.

    Linux release evidence executes the already-hashed descriptor through
    procfs.  The macOS path is retained for local unit tests only; release
    evidence itself is Linux/Landlock-only.
    """
    executable, expected_sha256, expected_version = _git_anchor(root)
    descriptor = os.open(executable, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o111 == 0:
            raise ValueError("anchored Git is not a regular executable")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if digest.hexdigest() != expected_sha256:
            raise ValueError("Git executable differs from the committed anchor")
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        command = [str(executable), *args]
        pass_fds: tuple[int, ...] = ()
        if sys.platform.startswith("linux"):
            proc_path = Path(f"/proc/self/fd/{descriptor}")
            if not proc_path.exists():
                raise ValueError("procfs descriptor execution is unavailable for Git")
            command[0] = str(proc_path)
            pass_fds = (descriptor,)
        before = os.fstat(descriptor)
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            input=input_bytes,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            pass_fds=pass_fds,
        )
        after = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        final_digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            final_digest.update(block)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or final_digest.hexdigest() != expected_sha256
        ):
            raise ValueError("Git executable changed during execution")
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"git {' '.join(args)} failed: {detail[-1000:]}")
        if args == ("--version",) and completed.stdout.decode().strip() != expected_version:
            raise ValueError("Git version output differs from the committed anchor")
        return completed.stdout
    finally:
        os.close(descriptor)


def _git(root: Path, *args: str) -> bytes:
    return git_output(root, *args)


def canonical_commit(root: Path, revision: str) -> str:
    if not isinstance(revision, str) or not revision or len(revision) > 128:
        raise ValueError("release revision is missing or oversized")
    value = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if len(value) not in {40, 64} or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("release revision did not resolve to a canonical commit")
    return value


def require_canonical_commit(root: Path, revision: str) -> str:
    """Resolve and require the exact immutable Git commit identifier."""
    commit = canonical_commit(root, revision)
    if revision != commit:
        raise ValueError(
            "release revision must be the exact canonical Git commit identifier"
        )
    return commit


def evidence_only_path(path: str) -> bool:
    return path in EVIDENCE_ONLY_EXACT or any(path.startswith(prefix) for prefix in EVIDENCE_ONLY_PREFIXES)


def _blob_sha256(root: Path, object_ids: list[str]) -> dict[str, tuple[str, int]]:
    unique = sorted(set(object_ids))
    if not unique:
        return {}
    payload = git_output(
        root,
        "cat-file",
        "--batch",
        input_bytes=("\n".join(unique) + "\n").encode("ascii"),
    )
    offset = 0
    digests: dict[str, tuple[str, int]] = {}
    for expected in unique:
        header_end = payload.find(b"\n", offset)
        if header_end < 0:
            raise ValueError("git cat-file returned a truncated blob header")
        try:
            returned, kind, raw_size = payload[offset:header_end].decode("ascii").split()
            size = int(raw_size)
        except (UnicodeError, ValueError) as error:
            raise ValueError("git cat-file returned a malformed blob header") from error
        offset = header_end + 1
        end = offset + size
        if returned != expected or kind != "blob" or end >= len(payload):
            raise ValueError("git cat-file returned an unexpected object")
        blob = payload[offset:end]
        if payload[end : end + 1] != b"\n":
            raise ValueError("git cat-file returned a malformed blob boundary")
        digests[expected] = (hashlib.sha256(blob).hexdigest(), size)
        offset = end + 1
    if offset != len(payload):
        raise ValueError("git cat-file returned unexpected trailing data")
    return digests


def source_tree_manifest(root: Path, revision: str) -> list[dict[str, str | int]]:
    commit = canonical_commit(root, revision)
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: list[tuple[str, str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            identity, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = identity.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ValueError("git tree contained a malformed entry") from error
        if evidence_only_path(path):
            continue
        if kind != "blob":
            raise ValueError(f"source tree contains an unsupported non-blob entry: {path}")
        entries.append((mode, kind, object_id, path))
    blob_digests = _blob_sha256(root, [entry[2] for entry in entries])
    manifest: list[dict[str, str | int]] = []
    for mode, kind, object_id, path in entries:
        content_sha256, size = blob_digests[object_id]
        manifest.append(
            {
                "mode": mode,
                "type": kind,
                "content_sha256": content_sha256,
                "bytes": size,
                "path": path,
            }
        )
    return manifest


def source_tree_sha256(root: Path, revision: str) -> str:
    canonical = json.dumps(
        source_tree_manifest(root, revision),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def changed_paths(root: Path, source_revision: str, release_revision: str) -> list[str]:
    source = canonical_commit(root, source_revision)
    release = canonical_commit(root, release_revision)
    try:
        git_output(root, "merge-base", "--is-ancestor", source, release)
    except ValueError:
        raise ValueError("candidate source commit is not an ancestor of the release commit")
    raw = _git(root, "diff", "--name-only", "-z", source, release, "--")
    return sorted(path.decode("utf-8") for path in raw.split(b"\0") if path)


def verify_evidence_only_transition(
    root: Path,
    source_revision: str,
    release_revision: str,
    expected_source_tree_sha256: str,
) -> tuple[str, list[str]]:
    source_revision = require_canonical_commit(root, source_revision)
    release_revision = require_canonical_commit(root, release_revision)
    source_digest = source_tree_sha256(root, source_revision)
    release_digest = source_tree_sha256(root, release_revision)
    if source_digest != expected_source_tree_sha256:
        raise ValueError("candidate source-tree digest does not match its evidence")
    if release_digest != source_digest:
        raise ValueError("release commit changes production source outside evidence paths")
    paths = changed_paths(root, source_revision, release_revision)
    unexpected = [path for path in paths if not evidence_only_path(path)]
    if unexpected:
        raise ValueError(
            "release transition contains non-evidence paths: " + ", ".join(unexpected)
        )
    return release_digest, paths


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        print(source_tree_sha256(args.root.resolve(), args.revision))
    except ValueError as error:
        print(f"source-tree identity failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
