#!/usr/bin/env python3
"""Materialize the reviewed Node/Wrangler runtime outside the Git checkout.

The installer is intentionally one-way: it refuses an existing destination and
has no update/delete mode. It verifies the official Node archive before
extraction, invokes the bundled pinned npm with ``ci --ignore-scripts``, removes
npm's PATH shims, freezes the result, then runs the production runtime checker.
It does not contact Cloudflare.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

from cloudflare_toolchain_check import (
    PROFILE_PATH,
    ToolchainError,
    _installation_identity,
    canonical_materialization_bytes,
    load_profile,
    materialization_document,
    validate_runtime,
    validate_root_materialization_source,
    validate_static,
)


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
TRUSTED_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class MaterializationError(ValueError):
    """The reviewed toolchain could not be safely materialized."""


def _sha256_file(path: pathlib.Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MaterializationError("Node archive is unavailable or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise MaterializationError("Node archive must be a non-linked regular file")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise MaterializationError("Node archive exceeds its size limit")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _seal_verified_archive(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_sha256: str,
    max_bytes: int,
) -> pathlib.Path:
    """Copy one verified source inode into the private staging directory.

    A caller-supplied archive may live in a directory another user can rename
    within.  Hashing that pathname and then reopening it for tar inspection
    would allow a swap between the two operations.  Keep the source descriptor
    open for the entire hash/copy, publish only the sealed private copy, and
    make all later tar operations consume that copy.
    """

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise MaterializationError("archive sealing requires O_NOFOLLOW")
    source_flags |= os.O_NOFOLLOW
    destination_flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, source_flags)
    except OSError as error:
        raise MaterializationError("Node archive is unavailable or unsafe") from error
    destination_descriptor: int | None = None
    try:
        opened = os.fstat(source_descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise MaterializationError("Node archive must be a non-linked regular file")
        try:
            destination_descriptor = os.open(destination, destination_flags, 0o600)
        except OSError as error:
            raise MaterializationError("sealed Node archive cannot be created") from error

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise MaterializationError("Node archive exceeds its size limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written < 1:
                    raise MaterializationError("sealed Node archive write failed")
                view = view[written:]
        after = os.fstat(source_descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or total != opened.st_size
        ):
            raise MaterializationError("Node archive changed while it was sealed")
        if digest.hexdigest() != expected_sha256:
            raise MaterializationError(
                "Node archive SHA-256 differs from the reviewed profile"
            )
        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, 0o400)
    except BaseException:
        if destination_descriptor is not None:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    return destination


def _download_archive(url: str, destination: pathlib.Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "tinyzkp-production-toolchain-materializer/1"},
        method="GET",
    )
    total = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            destination.open("xb") as output,
        ):
            if response.geturl() != url:
                raise MaterializationError(
                    "Node archive download redirected unexpectedly"
                )
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise MaterializationError(
                        "Node archive download exceeds its size limit"
                    )
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, urllib.error.URLError) as error:
        raise MaterializationError("Node archive download failed") from error


def _validate_archive_layout(archive: pathlib.Path, *, expected_root: str) -> None:
    total_size = 0
    count = 0
    try:
        with tarfile.open(archive, mode="r:xz") as source:
            for member in source:
                count += 1
                total_size += member.size
                if count > 20_000 or total_size > 1024 * 1024 * 1024:
                    raise MaterializationError("Node archive layout exceeds its limits")
                path = pathlib.PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or path.parts[0] != expected_root
                    or any(part in {"", ".", ".."} for part in path.parts)
                ):
                    raise MaterializationError("Node archive contains an unsafe path")
                if member.isdev() or member.isfifo():
                    raise MaterializationError("Node archive contains a special file")
                if member.issym() or member.islnk():
                    base = posixpath.dirname(member.name) if member.issym() else ""
                    target = posixpath.normpath(posixpath.join(base, member.linkname))
                    target_path = pathlib.PurePosixPath(target)
                    if (
                        target_path.is_absolute()
                        or not target_path.parts
                        or target_path.parts[0] != expected_root
                        or ".." in target_path.parts
                    ):
                        raise MaterializationError(
                            "Node archive link escapes its reviewed root"
                        )
    except (OSError, tarfile.TarError) as error:
        raise MaterializationError("Node archive layout is unreadable") from error


def _extract_build_inputs(
    archive: pathlib.Path, destination: pathlib.Path, *, expected_root: str
) -> None:
    node_name = f"{expected_root}/bin/node"
    npm_prefix = f"{expected_root}/lib/node_modules/npm/"
    extracted_node = False
    extracted_npm_package = False
    try:
        with tarfile.open(archive, mode="r:xz") as source:
            for member in source:
                if member.name != node_name and not member.name.startswith(npm_prefix):
                    continue
                if not (member.isdir() or member.isreg()):
                    raise MaterializationError(
                        "reviewed Node/npm build inputs contain a link or special file"
                    )
                relative = pathlib.PurePosixPath(member.name)
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if member.isdir():
                    target.mkdir(exist_ok=True, mode=0o700)
                    continue
                extracted = source.extractfile(member)
                if extracted is None:
                    raise MaterializationError("reviewed Node/npm file is unreadable")
                with extracted, target.open("xb") as output:
                    shutil.copyfileobj(extracted, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                target.chmod(0o700 if member.name == node_name else 0o600)
                extracted_node = extracted_node or member.name == node_name
                extracted_npm_package = extracted_npm_package or member.name == (
                    f"{expected_root}/lib/node_modules/npm/package.json"
                )
    except (OSError, tarfile.TarError) as error:
        raise MaterializationError(
            "reviewed Node/npm build inputs cannot be extracted"
        ) from error
    if not extracted_node or not extracted_npm_package:
        raise MaterializationError("Node archive omits required Node/npm build inputs")


def npm_ci_command(node_root: pathlib.Path) -> tuple[str, ...]:
    return (
        str(node_root / "bin" / "node"),
        str(node_root / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"),
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )


def _subprocess_environment(home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": TRUSTED_SYSTEM_PATH,
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "NPM_CONFIG_CACHE": str(home / ".npm-cache"),
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        # npm 11 rejects assigning the same file to both configuration
        # scopes (including /dev/null) as a double-loaded configuration.
        # Distinct nonexistent paths beneath the freshly-created private
        # staging home disable both ambient scopes without allowing npm to
        # fall back to an operator or system configuration.
        "NPM_CONFIG_USERCONFIG": str(home / ".npmrc-user-disabled"),
        "NPM_CONFIG_GLOBALCONFIG": str(home / ".npmrc-global-disabled"),
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
    }


def _run_checked(
    command: tuple[str, ...], *, cwd: pathlib.Path, home: pathlib.Path
) -> None:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=_subprocess_environment(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MaterializationError(
            "toolchain materialization command failed"
        ) from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-2000:]
        raise MaterializationError(
            f"toolchain materialization command failed: {detail}"
        )


def _reject_symlinks(root: pathlib.Path) -> None:
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = pathlib.Path(current)
        for name in [*directory_names, *file_names]:
            if (current_path / name).is_symlink():
                raise MaterializationError(
                    "npm installation contains an unexpected symlink"
                )


def _freeze_tree(root: pathlib.Path) -> None:
    """Make the installed runtime immutable without disabling native tools.

    npm preserves executable bits from integrity-bound package archives. Wrangler
    invokes those reviewed native binaries directly (notably esbuild when a Pages
    ``_worker.js`` is present), so freezing every file to mode 0444 makes an
    otherwise valid installation unusable. Preserve only the existing execute
    classification while removing every write bit; the complete path, content,
    and resulting mode remain bound by the materialization identity.
    """

    directories: list[pathlib.Path] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = pathlib.Path(current)
        directories.append(current_path)
        for name in directory_names:
            candidate = current_path / name
            if candidate.is_symlink():
                raise MaterializationError("cannot freeze a symlinked directory")
        for name in file_names:
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                raise MaterializationError("cannot freeze a non-regular file")
            installed_mode = stat.S_IMODE(candidate.lstat().st_mode)
            candidate.chmod(0o555 if installed_mode & 0o111 else 0o444)
    for directory in reversed(directories):
        directory.chmod(0o555)


def _write_materialization_evidence(
    destination: pathlib.Path,
    *,
    static_identity: dict[str, object],
    node_sha256: str,
    wrangler_version: str,
    installation_identity: dict[str, object],
) -> pathlib.Path:
    document = materialization_document(
        static_identity=static_identity,
        node_sha256=node_sha256,
        wrangler_version=wrangler_version,
        installation_identity=installation_identity,
    )
    raw = canonical_materialization_bytes(document)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise MaterializationError("materialization evidence requires O_NOFOLLOW")
    flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, 0o400)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise MaterializationError("materialization evidence write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    except Exception as error:
        try:
            destination.unlink()
        except OSError:
            pass
        if isinstance(error, MaterializationError):
            raise
        raise MaterializationError("materialization evidence cannot be created") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return destination


def _directory_identity(path: pathlib.Path) -> tuple[int, int]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise MaterializationError("publish source is not a current-owner directory")
    return metadata.st_dev, metadata.st_ino


def _rollback_created_directory(path: pathlib.Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (metadata.st_dev, metadata.st_ino) != identity
    ):
        raise MaterializationError(f"refusing to roll back changed destination {path}")
    # The root inode proves this invocation published the destination. chmod is
    # needed only because the just-created tree was deliberately frozen.
    for current, directory_names, file_names in os.walk(
        path, topdown=False, followlinks=False
    ):
        current_path = pathlib.Path(current)
        current_path.chmod(0o700)
        for name in file_names:
            candidate = current_path / name
            if candidate.is_symlink():
                candidate.unlink()
            else:
                candidate.chmod(0o600)
                candidate.unlink()
        for name in directory_names:
            candidate = current_path / name
            if candidate.is_symlink():
                candidate.unlink()
            else:
                candidate.chmod(0o700)
                candidate.rmdir()
    path.rmdir()


def materialize(archive: pathlib.Path | None, *, download: bool) -> dict[str, object]:
    if os.geteuid() != 0:
        raise MaterializationError(
            "production toolchain materialization must run as root"
        )
    architecture = platform.machine().lower()
    if sys.platform != "linux" or architecture not in {"x86_64", "amd64"}:
        raise MaterializationError(
            "production toolchain materialization requires linux/x86_64"
        )
    validate_root_materialization_source(PROFILE_PATH, label="toolchain profile")
    profile, _raw, package_path, lock_path = load_profile()
    validate_root_materialization_source(
        package_path, label="toolchain package.json"
    )
    validate_root_materialization_source(
        lock_path, label="toolchain package-lock.json"
    )
    static_identity = validate_static()
    node_profile = profile["node"]
    wrangler_profile = profile["wrangler"]
    node_destination = pathlib.Path(node_profile["production_path"]).parents[1]
    install_root = pathlib.Path(wrangler_profile["production_install_root"])
    toolchain_destination = install_root.parent
    runtime_root = node_destination.parent
    if runtime_root != pathlib.Path("/var/lib/tinyzkp-runtime"):
        raise MaterializationError("profile runtime root is unsupported")
    try:
        runtime_metadata = runtime_root.lstat()
    except OSError as error:
        raise MaterializationError(
            "create /var/lib/tinyzkp-runtime before materialization"
        ) from error
    if (
        runtime_root.is_symlink()
        or not stat.S_ISDIR(runtime_metadata.st_mode)
        or runtime_metadata.st_uid != 0
        or stat.S_IMODE(runtime_metadata.st_mode) & 0o022
    ):
        raise MaterializationError(
            "runtime root must be root-owned and not group/world writable"
        )
    for destination in (node_destination, toolchain_destination):
        if destination.exists() or destination.is_symlink():
            raise MaterializationError(f"refusing existing destination {destination}")
    if (archive is None) == (not download):
        raise MaterializationError(
            "select exactly one of a local archive or --download"
        )

    staging = pathlib.Path(
        tempfile.mkdtemp(prefix=".cloudflare-toolchain-", dir=runtime_root)
    )
    staging.chmod(0o700)
    try:
        archive_path = archive
        if download:
            archive_path = staging / "node.download.tar.xz"
            _download_archive(node_profile["archive_url"], archive_path)
        assert archive_path is not None
        sealed_archive = _seal_verified_archive(
            archive_path,
            staging / "node.verified.tar.xz",
            expected_sha256=node_profile["archive_sha256"],
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        if download:
            archive_path.unlink()
        _validate_archive_layout(
            sealed_archive, expected_root=node_destination.name
        )

        _extract_build_inputs(
            sealed_archive, staging, expected_root=node_destination.name
        )
        staged_node = staging / node_destination.name
        node_binary = staged_node / "bin" / "node"
        node_sha256 = _sha256_file(node_binary, max_bytes=256 * 1024 * 1024)
        if node_sha256 != node_profile["binary_sha256"]:
            raise MaterializationError(
                "extracted Node binary differs from the reviewed profile"
            )
        npm_package = json.loads(
            (staged_node / "lib" / "node_modules" / "npm" / "package.json").read_text(
                encoding="utf-8"
            )
        )
        if npm_package.get("version") != node_profile["bundled_npm_version"]:
            raise MaterializationError("bundled npm differs from the reviewed profile")

        staged_toolchain = staging / "cloudflare-toolchain"
        staged_toolchain.mkdir(mode=0o700)
        shutil.copyfile(package_path, staged_toolchain / "package.json")
        shutil.copyfile(lock_path, staged_toolchain / "package-lock.json")
        _run_checked(npm_ci_command(staged_node), cwd=staged_toolchain, home=staging)
        shim_directory = staged_toolchain / "node_modules" / ".bin"
        if shim_directory.is_symlink():
            shim_directory.unlink()
        elif shim_directory.is_dir():
            shutil.rmtree(shim_directory)
        elif shim_directory.exists():
            raise MaterializationError("npm .bin path is not a directory or symlink")
        _reject_symlinks(staged_toolchain / "node_modules")
        _freeze_tree(staged_toolchain / "node_modules")
        # npm and every other archive member are build-time inputs only. The
        # production runtime retains exactly the reviewed Node executable, so
        # evidence does not leave unmeasured npm/npx/symlink bytes in service.
        staged_node_runtime = staging / "node-runtime"
        (staged_node_runtime / "bin").mkdir(parents=True, mode=0o755)
        shutil.copyfile(node_binary, staged_node_runtime / "bin" / "node")
        (staged_node_runtime / "bin" / "node").chmod(0o555)
        (staged_node_runtime / "bin").chmod(0o555)
        staged_node_runtime.chmod(0o555)
        staged_install_root = staged_toolchain / "node_modules"
        staged_entrypoint = staged_install_root.joinpath(
            *pathlib.PurePosixPath(wrangler_profile["entrypoint"]).parts
        )
        installation_identity = _installation_identity(staged_install_root)
        _write_materialization_evidence(
            staged_toolchain / "materialization.json",
            static_identity=static_identity,
            node_sha256=node_sha256,
            wrangler_version=wrangler_profile["version"],
            installation_identity=installation_identity,
        )
        # Root package inputs are needed only by npm ci. Do not publish mutable,
        # unmeasured package-manager state alongside the runtime tree.
        (staged_toolchain / "package.json").unlink()
        (staged_toolchain / "package-lock.json").unlink()
        staged_toolchain.chmod(0o555)
        validate_runtime(
            staged_node_runtime / "bin" / "node",
            staged_entrypoint,
            install_root=staged_install_root,
            enforce_profile_paths=False,
        )

        node_identity = _directory_identity(staged_node_runtime)
        toolchain_identity = _directory_identity(staged_toolchain)
        published: list[tuple[pathlib.Path, tuple[int, int]]] = []
        try:
            os.rename(staged_node_runtime, node_destination)
            published.append((node_destination, node_identity))
            os.rename(staged_toolchain, toolchain_destination)
            published.append((toolchain_destination, toolchain_identity))
            identity = validate_runtime(
                pathlib.Path(node_profile["production_path"]),
                install_root.joinpath(
                    *pathlib.PurePosixPath(wrangler_profile["entrypoint"]).parts
                ),
            )
        except Exception as error:
            rollback_errors: list[str] = []
            for destination, expected_identity in reversed(published):
                try:
                    _rollback_created_directory(destination, expected_identity)
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if rollback_errors:
                raise MaterializationError(
                    "publish failed and bounded rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from error
            raise
        return {**static_identity, **identity}
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--archive", type=pathlib.Path, help="reviewed local Node archive"
    )
    source.add_argument(
        "--download", action="store_true", help="download the exact manifest URL"
    )
    args = parser.parse_args(argv)
    try:
        identity = materialize(args.archive, download=args.download)
    except (OSError, ToolchainError, MaterializationError) as error:
        print(f"FAIL Cloudflare toolchain materialization - {error}", file=sys.stderr)
        return 1
    print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
