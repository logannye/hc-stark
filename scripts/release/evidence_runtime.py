#!/usr/bin/env python3
"""Fail-closed runtime helpers for locally generated release evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import BinaryIO
import platform
import ctypes
import ctypes.util
import fcntl
import select


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import source_tree_identity  # noqa: E402
import strict_json  # noqa: E402


TRUST_PATH = "release/release-trust-v1.json"


INHERITED_ENVIRONMENT = (
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "RUSTUP_HOME",
    "CARGO_HOME",
)
BUILD_AFFECTING_ENVIRONMENT = (
    "ASAN_OPTIONS",
    "CARGO_BUILD_JOBS",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
    "LIBFUZZER_OPTIONS",
    "LLVM_PROFILE_FILE",
    "MSAN_OPTIONS",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
    "TSAN_OPTIONS",
    "UBSAN_OPTIONS",
)
FIXED_ENVIRONMENT = {
    "CARGO_NET_OFFLINE": "true",
    "CARGO_TERM_COLOR": "never",
    "LANG": "C",
    "LC_ALL": "C",
    "RUST_BACKTRACE": "0",
    "SOURCE_DATE_EPOCH": "0",
}
CHILD_BOUNDARY_STARTUP_TIMEOUT_SECONDS = 10


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def pretty_json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def environment_policy() -> dict[str, object]:
    return {
        "schema_version": 1,
        "inherited_names": list(INHERITED_ENVIRONMENT),
        "fixed_values": FIXED_ENVIRONMENT,
        "rejected_build_affecting_names": list(BUILD_AFFECTING_ENVIRONMENT),
    }


def sanitized_environment(source: dict[str, str] | os._Environ[str]) -> dict[str, str]:
    environment = {
        name: source[name]
        for name in INHERITED_ENVIRONMENT
        if isinstance(source.get(name), str) and source[name]
    }
    environment.update(FIXED_ENVIRONMENT)
    return environment


def _candidate_under(root: Path, path: Path) -> tuple[Path, Path]:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"evidence path escapes the repository: {path}") from error
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"evidence path is unsafe: {path}")
    return root, relative


def assert_no_symlink_ancestry(root: Path, path: Path) -> Path:
    root, relative = _candidate_under(root, path)
    current = root
    for part in relative.parts:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise ValueError(f"evidence path contains a symlink: {path}")
    return root / relative


def ensure_private_directory(root: Path, path: Path) -> Path:
    root, relative = _candidate_under(root, path)
    current = root
    for part in relative.parts:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            details = os.lstat(current)
        if stat.S_ISLNK(details.st_mode):
            raise ValueError(f"evidence directory contains a symlink: {path}")
        if not stat.S_ISDIR(details.st_mode):
            raise ValueError(f"evidence directory is unsafe: {path}")
    details = os.lstat(current)
    if details.st_uid != os.geteuid():
        raise ValueError(f"evidence directory is not owned by the runner: {path}")
    os.chmod(current, 0o700, follow_symlinks=False)
    if stat.S_IMODE(os.lstat(current).st_mode) != 0o700:
        raise ValueError(f"evidence directory is not owner-only: {path}")
    return current


def _assert_safe_owned_tree(path: Path) -> None:
    expected_uid = os.geteuid()
    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        current_path = Path(current)
        details = os.lstat(current_path)
        if stat.S_ISLNK(details.st_mode) or details.st_uid != expected_uid:
            raise ValueError(f"evidence tree is unsafe: {current_path}")
        for name in [*directories, *files]:
            child = current_path / name
            details = os.lstat(child)
            if stat.S_ISLNK(details.st_mode) or details.st_uid != expected_uid:
                raise ValueError(f"evidence tree is unsafe: {child}")


def reset_private_directory(root: Path, owned_root: Path, path: Path) -> Path:
    root, owned_relative = _candidate_under(root, owned_root)
    _, relative = _candidate_under(root, path)
    if relative == owned_relative or not relative.is_relative_to(owned_relative):
        raise ValueError(
            f"refusing to reset a directory outside the owned evidence root: {path}"
        )
    candidate = assert_no_symlink_ancestry(root, root / relative)
    if candidate.exists():
        if not candidate.is_dir():
            raise ValueError(f"evidence reset target is not a directory: {path}")
        _assert_safe_owned_tree(candidate)
        shutil.rmtree(candidate)
    return ensure_private_directory(root, candidate)


def open_private_output(root: Path, path: Path, *, mode: int = 0o600) -> int:
    candidate = assert_no_symlink_ancestry(root, path)
    ensure_private_directory(root, candidate.parent)
    try:
        details = os.lstat(candidate)
    except FileNotFoundError:
        pass
    else:
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
        ):
            raise ValueError(f"evidence output is unsafe: {path}")
        candidate.unlink()
    return os.open(
        candidate,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )


def private_file_identity(descriptor: int) -> tuple[int, int, int, int, int]:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
    ):
        raise ValueError("open evidence file is unsafe")
    return (
        details.st_dev,
        details.st_ino,
        details.st_ctime_ns,
        details.st_mtime_ns,
        details.st_size,
    )


def read_private_output(
    root: Path,
    path: Path,
    expected_identity: tuple[int, int, int, int, int],
    *,
    max_bytes: int = 256 * 1024 * 1024,
) -> bytes:
    candidate = assert_no_symlink_ancestry(root, path)
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if private_file_identity(handle.fileno()) != expected_identity:
            raise ValueError(
                f"evidence output identity changed during execution: {path}"
            )
        payload = handle.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"evidence output exceeds the {max_bytes}-byte limit: {path}")
    return payload


def write_json_atomic(root: Path, path: Path, value: object) -> None:
    candidate = assert_no_symlink_ancestry(root, path)
    ensure_private_directory(root, candidate.parent)
    temporary = candidate.with_name(f".{candidate.name}.{os.getpid()}.tmp")
    descriptor = open_private_output(root, temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pretty_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        if candidate.exists():
            details = os.lstat(candidate)
            if (
                stat.S_ISLNK(details.st_mode)
                or not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
            ):
                raise ValueError(f"evidence output is unsafe: {path}")
        os.replace(temporary, candidate)
    finally:
        temporary.unlink(missing_ok=True)


def tool_identity_record(
    source_identity: dict[str, object],
    cargo_identity: dict[str, object],
    rustc_identity: dict[str, object],
    *,
    execution_profile: str,
    toolchain: str,
    cargo_version_command: list[str],
    rustc_version_command: list[str],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": source_identity["release_sha"],
        "source_tree_sha256": source_identity["source_tree_sha256"],
        "dependency_lock_sha256": source_identity["dependency_lock_sha256"],
        "rust_toolchain_sha256": source_identity["rust_toolchain_sha256"],
        "execution_profile": execution_profile,
        "toolchain": toolchain,
        "environment_policy_sha256": canonical_json_sha256(environment_policy()),
        "cargo_identity": cargo_identity,
        "rustc_identity": rustc_identity,
        "cargo_version_command": cargo_version_command,
        "rustc_version_command": rustc_version_command,
    }


def _git(root: Path, *arguments: str) -> bytes:
    return source_tree_identity.git_output(root, *arguments)


def _commit_blob(root: Path, release_sha: str, relative: str) -> bytes:
    return _git(root, "show", f"{release_sha}:{relative}")


def commit_blob(root: Path, release_sha: str, relative: str) -> bytes:
    """Read one regular source blob from the exact committed release tree."""
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or ".." in Path(relative).parts
        or "\x00" in relative
    ):
        raise ValueError("committed source path is unsafe")
    return _commit_blob(root.resolve(), release_sha, relative)


def commit_file_sha256(root: Path, release_sha: str, relative: str) -> str:
    return hashlib.sha256(
        _commit_blob(root.resolve(), release_sha, relative)
    ).hexdigest()


def committed_json(root: Path, release_sha: str, relative: str) -> object:
    return strict_json.loads(_commit_blob(root.resolve(), release_sha, relative))


def release_trust(root: Path, release_sha: str) -> dict[str, object]:
    value = committed_json(root, release_sha, TRUST_PATH)
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "cosign",
        "external_signers",
        "gate_tools",
        "git",
        "stripe_cli",
        "toolchains",
    } or value.get("schema_version") != 1 or isinstance(
        value.get("schema_version"), bool
    ):
        raise ValueError("committed release trust contract is malformed")
    return value


def _cosign_platform() -> str:
    system = sys.platform
    machine = platform.machine().lower()
    if system.startswith("linux"):
        system = "linux"
    elif system == "darwin":
        system = "darwin"
    aliases = {"amd64": "x86_64", "aarch64": "arm64"}
    return f"{system}-{aliases.get(machine, machine)}"


def runtime_platform_key() -> str:
    return _cosign_platform()


def _digest_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def run_anchored_cosign(
    root: Path,
    release_sha: str,
    executable: str | Path,
    arguments: list[str],
    *,
    timeout_seconds: int = 120,
) -> subprocess.CompletedProcess[str]:
    """Run the reviewed cosign binary without a post-hash path re-open.

    The executable is held open, hashed, and invoked through that exact file
    descriptor.  A path replacement after hashing therefore cannot swap the
    program that performs verification.
    """
    if not sys.platform.startswith("linux"):
        raise ValueError("anchored cosign execution is Linux-only")
    trust = release_trust(root, release_sha)
    cosign = trust.get("cosign")
    if not isinstance(cosign, dict) or set(cosign) != {
        "installer_action_sha",
        "platforms",
        "version",
    } or cosign.get("version") != "v2.4.3":
        raise ValueError("committed cosign trust anchor is malformed")
    platforms = cosign.get("platforms")
    anchor = platforms.get(_cosign_platform()) if isinstance(platforms, dict) else None
    if not isinstance(anchor, dict) or set(anchor) != {"sha256"}:
        raise ValueError("cosign is not anchored for this runner platform")
    expected = anchor.get("sha256")
    path = Path(executable).absolute()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or not details.st_mode & 0o111:
            raise ValueError("cosign executable is not a regular executable")
        if _digest_descriptor(descriptor) != expected:
            raise ValueError("cosign executable does not match the committed anchor")
        fd_path = Path(f"/proc/self/fd/{descriptor}")
        if not fd_path.exists():
            raise ValueError("procfs descriptor execution is unavailable")
        completed = subprocess.run(
            [str(fd_path), *arguments],
            cwd=root,
            env=sanitized_environment(os.environ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=timeout_seconds,
            pass_fds=(descriptor,),
        )
        if _digest_descriptor(descriptor) != expected:
            raise ValueError("cosign executable changed while it was running")
        return completed
    finally:
        os.close(descriptor)


def owner_ga_tool_policy(root: Path, release_sha: str) -> dict[str, object]:
    """Return the exact hosted-runner version/source policy.

    Host-built executable bytes are captured in each evidence envelope and
    rechecked through the open descriptor, but they are deliberately not
    compared with bytes produced on a different runner.
    """

    trust = release_trust(root, release_sha)
    gate_tools = trust.get("gate_tools")
    toolchains = trust.get("toolchains")
    expected_gate_tools = {
        "policy": "owner_only_ga_v1",
        "runner": "github-hosted-public-ubuntu-24.04",
        "tools": {
            "bash": {
                "source": "ubuntu-24.04",
                "version": "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)",
            },
            "python3": {
                "installer_action_sha": "a26af69be951a213d495a4c3e4e4022e16d87065",
                "version": "Python 3.12.13",
            },
        },
    }
    expected_toolchains = {
        "installer_action_sha": "4be7066ada62dd38de10e7b70166bc74ed198c30",
        "policy": "owner_only_ga_v1",
        "fuzz": {
            "cargo_commit": "eb94155a9a60943bd7b1cb04abec42f5d0de6ddc",
            "cargo_fuzz_install_command": [
                "cargo",
                "install",
                "cargo-fuzz",
                "--version",
                "0.13.2",
                "--locked",
            ],
            "cargo_fuzz_version": "cargo-fuzz 0.13.2",
            "channel": "nightly-2026-04-15",
            "release": "1.97.0-nightly",
            "rustc_commit": "a5c825cd824ee0ef9463021078a2f464b4cc1a0d",
        },
        "release": {
            "cargo_commit": "f2d3ce0bd7f24a49f8f72d9000448f8838c4e850",
            "channel": "1.95.0",
            "release": "1.95.0",
            "rustc_commit": "59807616e1fa2540724bfbac14d7976d7e4a3860",
        },
    }
    if gate_tools != expected_gate_tools or toolchains != expected_toolchains:
        raise ValueError("committed owner-only GA tool policy is malformed or changed")
    return {"gate_tools": gate_tools, "toolchains": toolchains}


def _untracked_files(root: Path) -> list[Path]:
    raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    return [root / Path(value.decode("utf-8")) for value in raw.split(b"\0") if value]


def release_source_identity(
    root: Path,
    requested_release_sha: str | None,
    *,
    evidence_root: Path,
    require_explicit_sha: bool,
) -> dict[str, object]:
    root = root.resolve()
    evidence_root = assert_no_symlink_ancestry(root, evidence_root)
    if evidence_root == root:
        raise ValueError("evidence root cannot be the repository root")
    head = source_tree_identity.canonical_commit(root, "HEAD")
    if requested_release_sha is None:
        if require_explicit_sha:
            raise ValueError("HC_RELEASE_SHA must name the exact source commit")
        release_sha = head
    else:
        release_sha = source_tree_identity.require_canonical_commit(
            root, requested_release_sha
        )
    if release_sha != head:
        raise ValueError("HC_RELEASE_SHA does not equal the checked-out HEAD commit")
    for arguments, label in (
        (("diff", "--quiet", "--ignore-submodules", "--"), "worktree"),
        (("diff", "--cached", "--quiet", "--ignore-submodules", "--"), "index"),
    ):
        try:
            source_tree_identity.git_output(root, *arguments)
        except ValueError:
            raise ValueError(f"release {label} contains tracked changes")
    unexpected = [
        path.relative_to(root).as_posix()
        for path in _untracked_files(root)
        if not path.absolute().is_relative_to(evidence_root.absolute())
    ]
    if unexpected:
        raise ValueError(
            "release worktree contains untracked source outside the evidence root: "
            + ", ".join(sorted(unexpected)[:20])
        )
    lock_payload = _commit_blob(root, release_sha, "Cargo.lock")
    if (root / "Cargo.lock").read_bytes() != lock_payload:
        raise ValueError("working Cargo.lock differs from the source commit")
    return {
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_identity.source_tree_sha256(
            root, release_sha
        ),
        "dependency_lock_sha256": hashlib.sha256(lock_payload).hexdigest(),
        "rust_toolchain_sha256": hashlib.sha256(
            _commit_blob(root, release_sha, "rust-toolchain.toml")
        ).hexdigest(),
    }


def assert_release_source_unchanged(
    root: Path, identity: dict[str, object], *, evidence_root: Path
) -> None:
    current = release_source_identity(
        root,
        str(identity["release_sha"]),
        evidence_root=evidence_root,
        require_explicit_sha=True,
    )
    if current != identity:
        raise ValueError("release source identity changed during evidence generation")


def materialize_read_only_source(
    root: Path,
    release_sha: str,
    *,
    evidence_root: Path,
) -> tuple[Path, list[dict[str, object]]]:
    """Materialize only committed blobs and lock the tree read-only.

    Evidence commands never execute the mutable checkout.  The returned
    inventory is later revalidated byte-for-byte before the materialization is
    removed.
    """
    destination = reset_private_directory(
        root, evidence_root, evidence_root / "immutable-source"
    )
    inventory = source_tree_identity.source_tree_manifest(root, release_sha)
    for entry in inventory:
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("committed source contains an unsafe path")
        target = destination / relative
        ensure_private_directory(root, target.parent)
        payload = _commit_blob(root, release_sha, relative.as_posix())
        if (
            len(payload) != entry["bytes"]
            or hashlib.sha256(payload).hexdigest() != entry["content_sha256"]
        ):
            raise ValueError("committed source materialization digest mismatch")
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o700 if entry["mode"] == "100755" else 0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(target, 0o500 if entry["mode"] == "100755" else 0o400)
    directories = sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    for directory in directories:
        os.chmod(directory, 0o500)
    os.chmod(destination, 0o500)
    verify_read_only_source(destination, inventory)
    return destination, inventory


def verify_read_only_source(
    destination: Path, inventory: list[dict[str, object]]
) -> None:
    expected = {str(entry["path"]): entry for entry in inventory}
    actual = {
        path.relative_to(destination).as_posix(): path
        for path in destination.rglob("*")
        if path.is_file()
    }
    if set(actual) != set(expected):
        raise ValueError("immutable source membership changed during execution")
    for name, path in actual.items():
        details = os.lstat(path)
        entry = expected[name]
        if (
            stat.S_ISLNK(details.st_mode)
            or not stat.S_ISREG(details.st_mode)
            or details.st_size != entry["bytes"]
            or hashlib.sha256(path.read_bytes()).hexdigest()
            != entry["content_sha256"]
            or stat.S_IMODE(details.st_mode)
            != (0o500 if entry["mode"] == "100755" else 0o400)
        ):
            raise ValueError(f"immutable source changed during execution: {name}")
    if stat.S_IMODE(os.lstat(destination).st_mode) != 0o500:
        raise ValueError("immutable source root became writable during execution")


def remove_read_only_source(root: Path, evidence_root: Path, path: Path) -> None:
    root, owned = _candidate_under(root, evidence_root)
    _, relative = _candidate_under(root, path)
    if not relative.is_relative_to(owned) or relative == owned:
        raise ValueError("immutable source cleanup escaped the evidence root")
    for current, directories, files in os.walk(path, topdown=False):
        for name in files:
            os.chmod(Path(current) / name, 0o600, follow_symlinks=False)
        for name in directories:
            os.chmod(Path(current) / name, 0o700, follow_symlinks=False)
        os.chmod(current, 0o700, follow_symlinks=False)
    shutil.rmtree(path)


def executable_identity(
    executable_name: str,
    version_arguments: list[str],
    *,
    environment: dict[str, str],
    root: Path,
) -> dict[str, object]:
    raw = shutil.which(executable_name, path=environment.get("PATH"))
    if raw is None:
        raise ValueError(f"required executable is unavailable: {executable_name}")
    executable = Path(raw).absolute()
    if not executable.is_file():
        raise ValueError(f"required executable is unsafe: {executable}")
    completed = subprocess.run(
        [str(executable), *version_arguments],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
        timeout=60,
    )
    version = completed.stdout.strip()
    if completed.returncode != 0 or not version:
        raise ValueError(f"unable to identify executable: {executable_name}")
    return {
        "path": str(executable),
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "version": version,
    }


def rustup_tool_path(
    toolchain: str,
    executable_name: str,
    *,
    environment: dict[str, str],
    root: Path,
) -> Path:
    if executable_name not in {"cargo", "rustc"}:
        raise ValueError("rustup tool selection is limited to cargo/rustc")
    rustup = shutil.which("rustup", path=environment.get("PATH"))
    if rustup is None:
        raise ValueError("rustup is required to resolve the pinned toolchain")
    completed = subprocess.run(
        [rustup, "which", "--toolchain", toolchain, executable_name],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=60,
    )
    path = Path(completed.stdout.strip()).resolve()
    if completed.returncode != 0 or not path.is_file() or path.name != executable_name:
        raise ValueError(f"rustup did not resolve pinned {executable_name}")
    return path


def run_logged(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log: BinaryIO,
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
    write_boundary_paths: tuple[Path, ...] | None = None,
    require_network_namespace: bool = False,
    network_boundary_result: dict[str, object] | None = None,
) -> tuple[int, bool]:
    if timeout_seconds <= 0:
        raise ValueError("subprocess timeout must be positive")
    preexec_fn = None
    parent_network_inode: int | None = None
    status_read = status_write = None
    if require_network_namespace:
        if not sys.platform.startswith("linux"):
            raise ValueError("release evidence network isolation is Linux-only")
        parent_network_inode = os.stat("/proc/self/ns/net").st_ino
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        pass_fds = (*pass_fds, status_write)
    if write_boundary_paths is not None:
        # Release evidence is deliberately Linux/fixed-host-only.  Landlock
        # denies every filesystem mutation except beneath the explicit build
        # output directories.  In particular, the committed source tree is not
        # allowlisted even though the child runs under the same Unix UID.
        if not sys.platform.startswith("linux"):
            raise ValueError("release evidence requires the Linux Landlock write boundary")
        writable = tuple(path.resolve() for path in write_boundary_paths)

        def apply_write_boundary() -> None:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(CHILD_BOUNDARY_STARTUP_TIMEOUT_SECONDS)
            if require_network_namespace:
                assert status_write is not None and parent_network_inode is not None
                status = _enter_verified_no_network_namespace(parent_network_inode)
                os.write(status_write, json.dumps(status, sort_keys=True).encode("ascii"))
                os.close(status_write)
            _apply_landlock_write_boundary(writable)
            signal.alarm(0)

        preexec_fn = apply_write_boundary
    elif require_network_namespace:
        def apply_network_boundary() -> None:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(CHILD_BOUNDARY_STARTUP_TIMEOUT_SECONDS)
            assert status_write is not None and parent_network_inode is not None
            status = _enter_verified_no_network_namespace(parent_network_inode)
            os.write(status_write, json.dumps(status, sort_keys=True).encode("ascii"))
            os.close(status_write)
            signal.alarm(0)

        preexec_fn = apply_network_boundary
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            pass_fds=pass_fds,
            preexec_fn=preexec_fn,
        )
    except Exception:
        if status_read is not None:
            os.close(status_read)
            status_read = None
        raise
    finally:
        if status_write is not None:
            try:
                os.close(status_write)
            except OSError:
                pass
    if status_read is not None:
        ready, _, _ = select.select([status_read], [], [], 10.0)
        if not ready:
            assert process is not None
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            os.close(status_read)
            raise ValueError("network namespace startup timed out")
        with os.fdopen(status_read, "rb") as status_handle:
            raw_status = status_handle.read(16 * 1024 + 1)
        if len(raw_status) > 16 * 1024:
            assert process is not None
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise ValueError("network namespace status exceeds the reviewed limit")
        try:
            status = json.loads(raw_status)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            assert process is not None
            process.kill()
            process.wait()
            raise ValueError("network namespace status was not reported") from error
        if (
            not isinstance(status, dict)
            or status.get("kind") != "linux-network-namespace-v1"
            or status.get("parent_namespace_inode") != parent_network_inode
            or status.get("child_namespace_inode") == parent_network_inode
            or status.get("interfaces") != ["lo"]
            or status.get("external_routes") is not False
        ):
            assert process is not None
            process.kill()
            process.wait()
            raise ValueError("child did not enter a verified no-network namespace")
        if network_boundary_result is None:
            assert process is not None
            process.kill()
            process.wait()
            raise ValueError("network namespace result must be recorded")
        network_boundary_result.update(status)
    assert process is not None
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            return_code = 124
    if timed_out:
        return_code = 124
    return return_code, timed_out


def elapsed_milliseconds(started: float) -> int:
    return max(1, int((time.monotonic() - started) * 1000))


LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_WRITE_ACCESS = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000


def _unshare(flags: int) -> None:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    if libc.unshare(flags) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "unshare failed")


def _enter_verified_no_network_namespace(parent_inode: int) -> dict[str, object]:
    """Enter a fresh network namespace, creating a user namespace if needed."""
    try:
        _unshare(CLONE_NEWNET)
    except OSError as direct_error:
        uid, gid = os.geteuid(), os.getegid()
        try:
            _unshare(CLONE_NEWUSER)
            try:
                Path("/proc/self/setgroups").write_text("deny\n", encoding="ascii")
            except FileNotFoundError:
                pass
            Path("/proc/self/uid_map").write_text(f"0 {uid} 1\n", encoding="ascii")
            Path("/proc/self/gid_map").write_text(f"0 {gid} 1\n", encoding="ascii")
            os.setresgid(0, 0, 0)
            os.setresuid(0, 0, 0)
            _unshare(CLONE_NEWNET)
        except (OSError, PermissionError) as error:
            raise OSError(
                getattr(error, "errno", 1),
                f"verified no-network namespace unavailable: {direct_error}; {error}",
            ) from error
    child_inode = os.stat("/proc/self/ns/net").st_ino
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    external_routes = any(line.split()[0] != "lo" for line in routes if line.split())
    if child_inode == parent_inode or interfaces != ["lo"] or external_routes:
        raise OSError("new network namespace is not isolated")
    return {
        "kind": "linux-network-namespace-v1",
        "parent_namespace_inode": parent_inode,
        "child_namespace_inode": child_inode,
        "interfaces": interfaces,
        "external_routes": False,
    }


MEMFD_SEALS = (
    getattr(fcntl, "F_SEAL_WRITE", 0x0008)
    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
    | getattr(fcntl, "F_SEAL_SEAL", 0x0001)
)


def sealed_memfd_from_bytes(name: str, payload: bytes) -> tuple[int, dict[str, object]]:
    """Copy reviewed bytes into an immutable, descriptor-held Linux memfd."""
    if not sys.platform.startswith("linux") or not hasattr(os, "memfd_create"):
        raise ValueError("sealed dependency descriptors require Linux memfd_create")
    flags = getattr(os, "MFD_CLOEXEC", 0x0001) | getattr(os, "MFD_ALLOW_SEALING", 0x0002)
    descriptor = os.memfd_create(name, flags)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, MEMFD_SEALS)
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        if seals & MEMFD_SEALS != MEMFD_SEALS:
            raise ValueError("dependency memfd could not be fully sealed")
        identity = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "seals": seals,
        }
        return descriptor, identity
    except Exception:
        os.close(descriptor)
        raise


def verify_sealed_memfd(descriptor: int, identity: dict[str, object]) -> None:
    details = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_size != identity.get("bytes")
        or seals != identity.get("seals")
        or seals & MEMFD_SEALS != MEMFD_SEALS
        or _digest_descriptor(descriptor) != identity.get("sha256")
    ):
        raise ValueError("sealed dependency descriptor changed")


def python_runtime_manifest(
    python_fd_path: str, python_descriptor: int, *, environment: dict[str, str], root: Path
) -> dict[str, object]:
    """Bind the complete base stdlib plus every shared object mapped by Python."""
    discovery = r'''
import bz2, ctypes, hashlib, json, lzma, os, sqlite3, ssl, sys, sysconfig, venv, zipfile, zlib
roots = sorted({os.path.realpath(value) for key, value in sysconfig.get_paths().items()
                if key in {"stdlib", "platstdlib"} and value})
mapped = set()
with open("/proc/self/maps", encoding="ascii") as handle:
    for line in handle:
        candidate = line.rstrip().split(None, 5)
        if len(candidate) == 6 and candidate[5].startswith("/"):
            path = os.path.realpath(candidate[5])
            if os.path.isfile(path): mapped.add(path)
print(json.dumps({"roots": roots, "mapped": sorted(mapped)}))
'''
    completed = subprocess.run(
        [python_fd_path, "-I", "-S", "-c", discovery],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        pass_fds=(python_descriptor,),
        check=False,
        timeout=120,
    )
    try:
        discovered = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Python runtime discovery failed") from error
    if completed.returncode != 0 or not isinstance(discovered, dict):
        raise ValueError("Python runtime discovery failed")
    roots = discovered.get("roots")
    mapped = discovered.get("mapped")
    if not isinstance(roots, list) or not roots or not isinstance(mapped, list):
        raise ValueError("Python runtime discovery is incomplete")
    paths: set[Path] = {Path(value) for value in mapped if isinstance(value, str)}
    max_files = 50_000
    max_total_bytes = 2 * 1024 * 1024 * 1024
    if len(mapped) > 4096:
        raise ValueError("Python runtime maps too many shared files")
    for raw_root in roots:
        runtime_root = Path(raw_root)
        if not runtime_root.is_absolute() or not runtime_root.is_dir():
            raise ValueError("Python stdlib root is unsafe")
        for path in runtime_root.rglob("*"):
            if any(part in {"site-packages", "dist-packages", "__pycache__"} for part in path.parts):
                continue
            if path.is_file() and not path.is_symlink():
                paths.add(path)
                if len(paths) > max_files:
                    raise ValueError("Python runtime exceeds the file-count limit")
    executable = Path(f"/proc/self/fd/{python_descriptor}")
    records: list[dict[str, object]] = []
    total_bytes = 0
    for path in sorted(paths, key=lambda item: str(item)):
        if len(str(path).encode("utf-8")) > 4096:
            raise ValueError("Python runtime path exceeds the reviewed limit")
        details = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"Python runtime member is not regular: {path}")
        payload = path.read_bytes()
        total_bytes += len(payload)
        if total_bytes > max_total_bytes:
            raise ValueError("Python runtime exceeds the byte limit")
        records.append({"path": str(path), "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    interpreter_sha = _digest_descriptor(python_descriptor)
    full = {
        "schema_version": 1,
        "interpreter_sha256": interpreter_sha,
        "stdlib_roots": roots,
        "file_count": len(records),
        "total_bytes": total_bytes,
        "files_sha256": canonical_json_sha256(records),
        "mapped_file_count": len(mapped),
    }
    if full["file_count"] <= 0 or not executable.exists():
        raise ValueError("Python runtime manifest is empty")
    return full


class _LandlockRuleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneath(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


def _landlock_syscall_numbers() -> tuple[int, int, int]:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise ValueError(f"unsupported Landlock architecture: {machine}")
    return 444, 445, 446


def landlock_abi_version() -> int:
    if not sys.platform.startswith("linux"):
        raise ValueError("Landlock is available only on Linux")
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    create, _, _ = _landlock_syscall_numbers()
    result = libc.syscall(create, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    if result < 1:
        error = ctypes.get_errno()
        raise ValueError(f"Landlock ABI is unavailable (errno={error})")
    return int(result)


def _apply_landlock_write_boundary(writable_paths: tuple[Path, ...]) -> None:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    create, add, restrict = _landlock_syscall_numbers()
    abi = landlock_abi_version()
    # TRUNCATE was introduced in ABI 3 and REFER in ABI 2.  Refuse older
    # kernels instead of silently leaving mutation operations unconfined.
    if abi < 3:
        raise OSError("Landlock ABI 3 or newer is required")
    ruleset_attr = _LandlockRuleset(LANDLOCK_WRITE_ACCESS)
    ruleset = libc.syscall(
        create, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0
    )
    if ruleset < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    opened: list[int] = []
    try:
        for path in writable_paths:
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            opened.append(descriptor)
            rule = _LandlockPathBeneath(LANDLOCK_WRITE_ACCESS, descriptor, 0)
            if libc.syscall(
                add,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                ctypes.byref(rule),
                0,
            ) != 0:
                raise OSError(ctypes.get_errno(), "landlock_add_rule failed")
        # Rust build scripts commonly use Stdio::null while probing compiler
        # features. Permit writes to that exact kernel sink without allowing
        # any other device node or the surrounding /dev directory. Validate
        # the opened inode before installing the file-scoped rule so a replaced
        # path cannot widen the boundary.
        null_path = Path("/dev/null")
        null_before = os.lstat(null_path)
        if (
            not stat.S_ISCHR(null_before.st_mode)
            or null_before.st_uid != 0
            or null_before.st_rdev != os.makedev(1, 3)
        ):
            raise OSError("/dev/null does not have the expected device identity")
        null_descriptor = os.open(
            null_path,
            os.O_PATH | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        opened.append(null_descriptor)
        null_opened = os.fstat(null_descriptor)
        if (
            (null_opened.st_dev, null_opened.st_ino, null_opened.st_rdev)
            != (null_before.st_dev, null_before.st_ino, null_before.st_rdev)
            or not stat.S_ISCHR(null_opened.st_mode)
        ):
            raise OSError("/dev/null changed before the Landlock rule was installed")
        null_rule = _LandlockPathBeneath(
            LANDLOCK_ACCESS_FS_WRITE_FILE, null_descriptor, 0
        )
        if libc.syscall(
            add,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(null_rule),
            0,
        ) != 0:
            raise OSError(
                ctypes.get_errno(), "landlock_add_rule failed for /dev/null"
            )
        PR_SET_NO_NEW_PRIVS = 38
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
        if libc.syscall(restrict, ruleset, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset)


def open_executable_descriptor(
    path: str | Path, *, expected_sha256: str
) -> tuple[int, str]:
    if not sys.platform.startswith("linux"):
        raise ValueError("descriptor-bound executable launch is Linux-only")
    candidate = Path(path).absolute()
    descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o111 == 0:
            raise ValueError(f"executable is not a regular executable: {candidate}")
        if _digest_descriptor(descriptor) != expected_sha256:
            raise ValueError(f"executable digest changed before execution: {candidate}")
        fd_path = Path(f"/proc/self/fd/{descriptor}")
        if not fd_path.exists():
            raise ValueError("procfs descriptor execution is unavailable")
        return descriptor, str(fd_path)
    except Exception:
        os.close(descriptor)
        raise
