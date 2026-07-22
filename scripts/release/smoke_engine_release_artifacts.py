#!/usr/bin/env python3
"""Execute and bind the standalone and OCI TinyZKP engine release artifacts.

The OCI archive is copied only between local transports and the resulting image
is run with an explicitly confined Docker configuration.  This is a runtime
smoke test, not a substitute for the signed release checksum or static OCI
identity checks.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Protocol, Sequence

import build_engine_identity_report as identity


ROOT = Path(__file__).resolve().parents[2]
MAX_RELEASE_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
DOCKER_HOST = "unix:///var/run/docker.sock"
EXPECTED_USER = "10001:10001"
EXPECTED_ENTRYPOINT = ["/usr/local/bin/tinyzkp-engine"]
TMPFS_BYTES = 16 * 1024 * 1024
MEMORY_BYTES = 256 * 1024 * 1024
NANO_CPUS = 1_000_000_000
PIDS_LIMIT = 64
RELEASE_KEYS = {
    "service",
    "package_version",
    "release_sha",
    "release_ref",
    "backend",
    "plonky3_version",
    "compatibility_profile",
    "dependency_lock_sha256",
}
SAFE_IMAGE_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
SAFE_RELEASE_REF = re.compile(r"^backend-v[0-9A-Za-z][0-9A-Za-z._-]{0,116}$")


class RuntimeSmokeError(ValueError):
    """Raised when a release artifact cannot prove the runtime contract."""


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes


class Runner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str],
        cwd: Path,
        timeout: int,
        check: bool = True,
    ) -> CommandResult: ...


class BoundedRunner:
    """Run a command without allowing its output into unbounded Python memory."""

    def run(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str],
        cwd: Path,
        timeout: int,
        check: bool = True,
    ) -> CommandResult:
        if not argv or any(
            not isinstance(value, str) or "\x00" in value for value in argv
        ):
            raise RuntimeSmokeError("runtime smoke command is malformed")
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.Popen(
                    list(argv),
                    cwd=cwd,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    close_fds=True,
                )
            except OSError as error:
                raise RuntimeSmokeError(
                    f"runtime smoke command failed to start: {argv[0]}"
                ) from error
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait()
                raise RuntimeSmokeError(
                    f"runtime smoke command timed out: {argv[0]}"
                ) from error
            stdout_size = stdout.tell()
            stderr_size = stderr.tell()
            if (
                stdout_size > MAX_COMMAND_OUTPUT_BYTES
                or stderr_size > MAX_COMMAND_OUTPUT_BYTES
            ):
                raise RuntimeSmokeError(
                    f"runtime smoke command output exceeded 1 MiB: {argv[0]}"
                )
            stdout.seek(0)
            stderr.seek(0)
            result = CommandResult(stdout=stdout.read(), stderr=stderr.read())
            if check and returncode != 0:
                detail = result.stderr.decode("utf-8", errors="replace")[:2048].strip()
                suffix = f": {detail}" if detail else ""
                raise RuntimeSmokeError(
                    f"runtime smoke command exited {returncode}: {argv[0]}{suffix}"
                )
            return result


@dataclass(frozen=True)
class RuntimeTools:
    skopeo: Path
    docker: Path


def timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def strict_json(payload: bytes, *, label: str) -> object:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeSmokeError(f"{label} contains a duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise RuntimeSmokeError(f"{label} contains a non-finite JSON number: {value}")

    try:
        return json.loads(
            payload,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeSmokeError(f"{label} is not valid UTF-8 JSON") from error


def read_bounded(path: Path, limit: int, *, label: str) -> bytes:
    if path.stat().st_size > limit:
        raise RuntimeSmokeError(f"{label} exceeds {limit} bytes")
    payload = path.read_bytes()
    if len(payload) != path.stat().st_size:
        raise RuntimeSmokeError(f"{label} changed while it was read")
    return payload


def validate_release(
    payload: bytes,
    *,
    release_sha: str,
    release_ref: str,
    label: str,
) -> dict[str, object]:
    if not payload or len(payload) > MAX_RELEASE_BYTES:
        raise RuntimeSmokeError(f"{label} is empty or oversized")
    value = strict_json(payload, label=label)
    if not isinstance(value, dict) or set(value) != RELEASE_KEYS:
        raise RuntimeSmokeError(f"{label} does not have the closed release schema")
    if (
        value.get("service") != "cli"
        or value.get("release_sha") != release_sha
        or value.get("release_ref") != release_ref
        or value.get("backend") != "plonky3"
        or value.get("plonky3_version") != identity.PLONKY3_VERSION
        or value.get("compatibility_profile") != identity.PROFILE
        or not isinstance(value.get("package_version"), str)
        or not value["package_version"]
        or identity.SHA256.fullmatch(str(value.get("dependency_lock_sha256"))) is None
    ):
        raise RuntimeSmokeError(f"{label} is incomplete or release-skewed")
    return value


def parse_json_output(payload: bytes, *, label: str) -> object:
    try:
        return strict_json(payload, label=label)
    except RuntimeSmokeError as error:
        raise RuntimeSmokeError(f"{label} returned malformed JSON: {error}") from error


def one_json_object(payload: bytes, *, label: str) -> dict[str, object]:
    value = parse_json_output(payload, label=label)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise RuntimeSmokeError(f"{label} must return exactly one JSON object")
    return value[0]


def resolve_tool(name: str) -> Path:
    fixed_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    found = shutil.which(name, path=fixed_path)
    if found is None:
        raise RuntimeSmokeError(f"required runtime smoke tool is unavailable: {name}")
    path = Path(found).resolve()
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise RuntimeSmokeError(
            f"required runtime smoke tool is unreadable: {name}"
        ) from error
    if not stat.S_ISREG(mode) or mode & 0o111 == 0:
        raise RuntimeSmokeError(
            f"required runtime smoke tool is not executable: {name}"
        )
    return path


def resolve_runtime_tools() -> RuntimeTools:
    socket_path = Path(DOCKER_HOST.removeprefix("unix://"))
    try:
        socket_mode = socket_path.stat().st_mode
    except OSError as error:
        raise RuntimeSmokeError(
            "the local Docker Unix socket is unavailable"
        ) from error
    if not stat.S_ISSOCK(socket_mode):
        raise RuntimeSmokeError("the configured Docker endpoint is not a Unix socket")
    return RuntimeTools(skopeo=resolve_tool("skopeo"), docker=resolve_tool("docker"))


def safe_output(root: Path, path: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.absolute()
    if not candidate.is_relative_to(root):
        raise RuntimeSmokeError("runtime smoke report output is outside the repository")
    current = root
    for part in candidate.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise RuntimeSmokeError(
                "runtime smoke report output path contains a symlink"
            )
    return candidate


def validate_tool(path: Path, *, label: str) -> Path:
    path = path.resolve()
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise RuntimeSmokeError(f"{label} executable is unavailable") from error
    if not path.is_absolute() or not stat.S_ISREG(mode) or mode & 0o111 == 0:
        raise RuntimeSmokeError(f"{label} executable is unsafe")
    return path


def clean_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }


def tmpfs_option() -> str:
    return f"rw,nosuid,nodev,noexec,size={TMPFS_BYTES},uid=10001,gid=10001,mode=0700"


def validate_tmpfs(value: object, *, mountpoint: str) -> None:
    if not isinstance(value, str):
        raise RuntimeSmokeError(f"container {mountpoint} tmpfs policy is missing")
    tokens = value.split(",")
    if len(tokens) != len(set(tokens)) or set(tokens) != set(tmpfs_option().split(",")):
        raise RuntimeSmokeError(f"container {mountpoint} tmpfs policy is skewed")


def validate_image_inspect(
    image: dict[str, object],
    *,
    image_reference: str,
    static_oci: dict[str, object],
) -> str:
    config = image.get("Config")
    tags = image.get("RepoTags")
    expected_id = static_oci["config_digest"]
    if (
        image.get("Id") != expected_id
        or image.get("Os") != "linux"
        or image.get("Architecture") != "amd64"
        or not isinstance(tags, list)
        or image_reference not in tags
        or not isinstance(config, dict)
        or config.get("User") != EXPECTED_USER
        or config.get("WorkingDir") != "/work"
        or config.get("Entrypoint") != EXPECTED_ENTRYPOINT
        or config.get("Cmd") != ["--help"]
    ):
        raise RuntimeSmokeError("locally imported OCI image identity is skewed")
    return str(expected_id)


def validate_container_inspect(
    container: dict[str, object],
    *,
    container_id: str,
    image_id: str,
    after_run: bool,
) -> None:
    config = container.get("Config")
    host = container.get("HostConfig")
    state = container.get("State")
    mounts = container.get("Mounts")
    if (
        container.get("Id") != container_id
        or container.get("Image") != image_id
        or container.get("Path") != EXPECTED_ENTRYPOINT[0]
        or container.get("Args") != ["release"]
        or not isinstance(config, dict)
        or config.get("User") != EXPECTED_USER
        or config.get("Entrypoint") != EXPECTED_ENTRYPOINT
        or config.get("Cmd") != ["release"]
        or not isinstance(host, dict)
        or not isinstance(state, dict)
        or not isinstance(mounts, list)
    ):
        raise RuntimeSmokeError("runtime container identity is incomplete or skewed")

    cap_drop = host.get("CapDrop")
    security = host.get("SecurityOpt")
    devices = host.get("Devices")
    device_requests = host.get("DeviceRequests")
    tmpfs = host.get("Tmpfs")
    if (
        host.get("NetworkMode") != "none"
        or host.get("ReadonlyRootfs") is not True
        or host.get("Privileged") is not False
        or cap_drop != ["ALL"]
        or not isinstance(security, list)
        or set(security) not in ({"no-new-privileges"}, {"no-new-privileges:true"})
        or host.get("Binds") not in (None, [])
        or devices not in (None, [])
        or device_requests not in (None, [])
        or host.get("PublishAllPorts") is not False
        or host.get("PidMode") not in (None, "")
        or host.get("IpcMode") not in ("private", "")
        or host.get("UTSMode") not in (None, "")
        or host.get("Memory") != MEMORY_BYTES
        or host.get("NanoCpus") != NANO_CPUS
        or host.get("PidsLimit") != PIDS_LIMIT
        or not isinstance(tmpfs, dict)
        or set(tmpfs) != {"/scratch", "/work"}
    ):
        raise RuntimeSmokeError("runtime container confinement policy is skewed")
    validate_tmpfs(tmpfs["/work"], mountpoint="/work")
    validate_tmpfs(tmpfs["/scratch"], mountpoint="/scratch")

    if after_run:
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != 0
            or state.get("OOMKilled") is not False
            or state.get("Error") not in (None, "")
        ):
            raise RuntimeSmokeError("runtime container did not exit cleanly")
        if len(mounts) != 2:
            raise RuntimeSmokeError("runtime container mount inventory is skewed")
        mountpoints: set[str] = set()
        for mount in mounts:
            if (
                not isinstance(mount, dict)
                or mount.get("Type") != "tmpfs"
                or mount.get("Destination") not in {"/scratch", "/work"}
                or mount.get("Source") not in (None, "")
                or mount.get("RW") is not True
            ):
                raise RuntimeSmokeError("runtime container has an unexpected mount")
            mountpoints.add(str(mount["Destination"]))
        if mountpoints != {"/scratch", "/work"}:
            raise RuntimeSmokeError("runtime container tmpfs inventory is incomplete")
    elif state.get("Running") is not False or state.get("Status") != "created":
        raise RuntimeSmokeError("runtime container was not inspected before execution")


def run_smoke(
    *,
    runner: Runner,
    tools: RuntimeTools,
    work: Path,
    engine: Path,
    oci_archive: Path,
    supplied_release: bytes,
    release_sha: str,
    release_ref: str,
    static_oci: dict[str, object],
) -> tuple[bytes, bytes, str]:
    env = clean_environment(work)
    direct = runner.run([str(engine), "release"], env=env, cwd=work, timeout=30)
    if direct.stderr:
        raise RuntimeSmokeError("standalone CLI emitted unexpected stderr")
    validate_release(
        direct.stdout,
        release_sha=release_sha,
        release_ref=release_ref,
        label="standalone CLI release output",
    )
    if direct.stdout != supplied_release:
        raise RuntimeSmokeError(
            "standalone CLI release bytes differ from supplied engine-release.json"
        )

    suffix = secrets.token_hex(6)
    component = f"{release_sha[:12]}-{os.getpid()}-{suffix}"
    if SAFE_IMAGE_COMPONENT.fullmatch(component) is None:
        raise RuntimeSmokeError("temporary image identity is malformed")
    image_reference = f"tinyzkp-engine-runtime-smoke:{component}"
    container_name = f"tinyzkp-engine-smoke-{component}"
    docker = [str(tools.docker), "--host", DOCKER_HOST]
    image_cleanup_required = False
    container_cleanup_required = False
    container_id: str | None = None
    try:
        image_cleanup_required = True
        runner.run(
            [
                str(tools.skopeo),
                "--insecure-policy",
                "copy",
                "--retry-times",
                "0",
                "--dest-daemon-host",
                DOCKER_HOST,
                f"oci-archive:{oci_archive}",
                f"docker-daemon:{image_reference}",
            ],
            env=env,
            cwd=work,
            timeout=300,
        )
        inspected_image = one_json_object(
            runner.run(
                [*docker, "image", "inspect", image_reference],
                env=env,
                cwd=work,
                timeout=30,
            ).stdout,
            label="docker image inspect",
        )
        image_id = validate_image_inspect(
            inspected_image,
            image_reference=image_reference,
            static_oci=static_oci,
        )
        container_cleanup_required = True
        created = runner.run(
            [
                *docker,
                "create",
                "--pull=never",
                "--name",
                container_name,
                "--network",
                "none",
                "--read-only",
                "--user",
                EXPECTED_USER,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                str(PIDS_LIMIT),
                "--memory",
                str(MEMORY_BYTES),
                "--cpus",
                "1",
                "--tmpfs",
                f"/work:{tmpfs_option()}",
                "--tmpfs",
                f"/scratch:{tmpfs_option()}",
                image_reference,
                "release",
            ],
            env=env,
            cwd=work,
            timeout=30,
        )
        try:
            container_id = created.stdout.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise RuntimeSmokeError(
                "docker create returned a non-ASCII container ID"
            ) from error
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            raise RuntimeSmokeError("docker create returned an invalid container ID")
        if created.stderr:
            raise RuntimeSmokeError("docker create emitted unexpected stderr")
        before = one_json_object(
            runner.run(
                [*docker, "container", "inspect", container_id],
                env=env,
                cwd=work,
                timeout=30,
            ).stdout,
            label="docker container inspect",
        )
        validate_container_inspect(
            before,
            container_id=container_id,
            image_id=image_id,
            after_run=False,
        )
        container_run = runner.run(
            [*docker, "start", "--attach", container_id],
            env=env,
            cwd=work,
            timeout=30,
        )
        if container_run.stderr:
            raise RuntimeSmokeError("OCI CLI emitted unexpected stderr")
        validate_release(
            container_run.stdout,
            release_sha=release_sha,
            release_ref=release_ref,
            label="OCI CLI release output",
        )
        if container_run.stdout != supplied_release:
            raise RuntimeSmokeError(
                "OCI CLI release bytes differ from supplied engine-release.json"
            )
        after = one_json_object(
            runner.run(
                [*docker, "container", "inspect", container_id],
                env=env,
                cwd=work,
                timeout=30,
            ).stdout,
            label="docker post-run container inspect",
        )
        validate_container_inspect(
            after,
            container_id=container_id,
            image_id=image_id,
            after_run=True,
        )
        return direct.stdout, container_run.stdout, image_id
    finally:
        if container_cleanup_required:
            runner.run(
                [
                    *docker,
                    "container",
                    "rm",
                    "--force",
                    container_id or container_name,
                ],
                env=env,
                cwd=work,
                timeout=30,
                check=False,
            )
        if image_cleanup_required:
            runner.run(
                [*docker, "image", "rm", "--force", image_reference],
                env=env,
                cwd=work,
                timeout=30,
                check=False,
            )


def build_report(
    *,
    root: Path,
    release_sha: str,
    release_ref: str,
    engine: Path,
    engine_release: Path,
    oci_archive: Path,
    checked_at: str | None = None,
    runner: Runner | None = None,
    tools: RuntimeTools | None = None,
) -> dict[str, object]:
    root = root.resolve()
    if identity.SHA1.fullmatch(release_sha) is None:
        raise RuntimeSmokeError("release SHA must be one full lowercase Git SHA-1")
    if SAFE_RELEASE_REF.fullmatch(release_ref) is None:
        raise RuntimeSmokeError("release ref must be one backend-v tag")

    engine = identity.safe_file(root, engine)
    engine_release = identity.safe_file(root, engine_release)
    oci_archive = identity.safe_file(root, oci_archive)
    engine_mode = engine.stat().st_mode
    if engine_mode & 0o111 == 0 or engine_mode & 0o022:
        raise RuntimeSmokeError(
            "standalone CLI must be executable and not group/world writable"
        )

    supplied_release = read_bounded(
        engine_release, MAX_RELEASE_BYTES, label="engine-release.json"
    )
    release = validate_release(
        supplied_release,
        release_sha=release_sha,
        release_ref=release_ref,
        label="engine-release.json",
    )
    engine_sha256 = identity.sha256_file(engine)
    oci_sha256 = identity.sha256_file(oci_archive)
    static_oci = identity.oci_identity(
        oci_archive,
        release_sha=release_sha,
        release_ref=release_ref,
        expected_engine_sha256=engine_sha256,
    )

    runtime_tools = tools or resolve_runtime_tools()
    runtime_tools = RuntimeTools(
        skopeo=validate_tool(runtime_tools.skopeo, label="skopeo"),
        docker=validate_tool(runtime_tools.docker, label="docker"),
    )
    command_runner = runner or BoundedRunner()
    with tempfile.TemporaryDirectory(prefix="tinyzkp-engine-smoke-") as directory:
        work = Path(directory)
        direct, oci, image_id = run_smoke(
            runner=command_runner,
            tools=runtime_tools,
            work=work,
            engine=engine,
            oci_archive=oci_archive,
            supplied_release=supplied_release,
            release_sha=release_sha,
            release_ref=release_ref,
            static_oci=static_oci,
        )

    if (
        identity.sha256_file(engine) != engine_sha256
        or identity.sha256_file(oci_archive) != oci_sha256
        or identity.sha256_file(engine_release) != sha256_bytes(supplied_release)
    ):
        raise RuntimeSmokeError(
            "a release artifact changed during runtime smoke execution"
        )

    canonical_release = canonical_json(release)
    canonical_sha256 = sha256_bytes(canonical_release)
    return {
        "schema_version": 1,
        "status": "pass",
        "release_sha": release_sha,
        "release_ref": release_ref,
        "checked_at": checked_at or timestamp(),
        "claims": {
            "cli_smoke": True,
            "oci_smoke": True,
        },
        "artifacts": {
            "engine_cli": {
                "path": identity.artifact_path(root, engine),
                "sha256": engine_sha256,
            },
            "engine_oci": {
                "path": identity.artifact_path(root, oci_archive),
                "sha256": oci_sha256,
                "manifest_digest": static_oci["manifest_digest"],
                "config_digest": static_oci["config_digest"],
                "runtime_image_id": image_id,
            },
            "engine_release": {
                "path": identity.artifact_path(root, engine_release),
                "sha256": identity.sha256_file(engine_release),
            },
        },
        "release_identity": release,
        "executions": {
            "engine_cli": {
                "command": ["release"],
                "stdout_sha256": sha256_bytes(direct),
                "canonical_release_sha256": canonical_sha256,
            },
            "engine_oci": {
                "command": ["release"],
                "stdout_sha256": sha256_bytes(oci),
                "canonical_release_sha256": canonical_sha256,
            },
        },
        "runtime_policy": {
            "image_source_transport": "oci-archive",
            "image_destination_transport": "docker-daemon",
            "docker_host": DOCKER_HOST,
            "pull_policy": "never",
            "network_mode": "none",
            "user": EXPECTED_USER,
            "read_only_rootfs": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "host_binds": [],
            "devices": [],
            "memory_bytes": MEMORY_BYTES,
            "nano_cpus": NANO_CPUS,
            "pids_limit": PIDS_LIMIT,
            "tmpfs": {
                "/scratch": {
                    "bytes": TMPFS_BYTES,
                    "exec": False,
                    "mode": "0700",
                    "nodev": True,
                    "nosuid": True,
                    "uid": 10001,
                    "gid": 10001,
                },
                "/work": {
                    "bytes": TMPFS_BYTES,
                    "exec": False,
                    "mode": "0700",
                    "nodev": True,
                    "nosuid": True,
                    "uid": 10001,
                    "gid": 10001,
                },
            },
        },
        "binding": {
            "cli_matches_engine_release_bytes": True,
            "oci_matches_engine_release_bytes": True,
            "cli_matches_oci_semantics": True,
            "oci_embeds_cli_binary": True,
            "oci_runtime_policy_inspected": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--release-ref", required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--engine-release", type=Path, required=True)
    parser.add_argument("--oci-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = safe_output(ROOT, args.output)
        report = build_report(
            root=ROOT,
            release_sha=args.release_sha,
            release_ref=args.release_ref,
            engine=args.engine,
            engine_release=args.engine_release,
            oci_archive=args.oci_archive,
        )
        identity.write_json_atomic(output, report)
    except (OSError, RuntimeSmokeError, ValueError) as error:
        print(f"engine runtime smoke failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
