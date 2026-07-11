#!/usr/bin/env python3
"""Run one allowlisted gate from an immutable commit materialization."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import evidence_runtime  # noqa: E402
import run_crash_matrix  # noqa: E402
import verify_sdk_python_wheelhouse  # noqa: E402
import verify_sdk_npm_tarballs  # noqa: E402


PROFILE = "tinyzkp-p3-goldilocks-v1"
SDK_PYTHON_RUNTIME_ANCHOR = "release/python/sdk-python-runtime-linux-x86_64-cp312-v1.json"
GATES: dict[str, dict[str, object]] = {
    "clean_release_source": {
        "command": ["python3", "scripts/ci/backend_source_scan.py"],
        "profile": "ci",
        "parser": "source_scan_v1",
        "timeout": 120,
    },
    "plonky3_dependency_profile_pinned": {
        "command": ["python3", "scripts/ci/plonky3_compatibility_gate.py"],
        "profile": "ci",
        "parser": "compatibility_v1",
        "timeout": 120,
    },
    "official_verifier_fibonacci": {
        "command": [
            "cargo", "test", "-p", "hc-plonky3", "--release", "--locked",
            "fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
        ],
        "profile": "release",
        "parser": "cargo_exact_test_v1",
        "test": "fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
        "timeout": 1800,
    },
    "official_verifier_poseidon2": {
        "command": [
            "cargo", "test", "-p", "hc-plonky3", "--release", "--locked",
            "poseidon2_proof_is_accepted_by_unmodified_plonky3_verifier",
        ],
        "profile": "release",
        "parser": "cargo_exact_test_v1",
        "test": "poseidon2_proof_is_accepted_by_unmodified_plonky3_verifier",
        "timeout": 1800,
    },
    "deterministic_cross_mode_proofs": {
        "command": ["bash", "scripts/ci/check_plonky3_known_answers.sh"],
        "profile": "release",
        "parser": "known_answers_v1",
        "timeout": 1800,
    },
    "replacement_sdk_contracts": {
        "command": ["bash", "scripts/ci/sdk_contract_gate.sh"],
        "profile": "ci",
        "parser": "sdk_contracts_v1",
        "timeout": 3600,
    },
}


def sdk_python_lock_identity(root: Path, release_sha: str) -> dict[str, object]:
    identity = verify_sdk_python_wheelhouse.committed_lock_identity(
        root, release_sha, evidence_runtime.commit_blob
    )
    return {key: value for key, value in identity.items() if key != "wheels"}


def sdk_python_lock_ready(root: Path, release_sha: str) -> bool:
    try:
        sdk_python_lock_identity(root, release_sha)
        sdk_npm_lock_identity(root, release_sha)
        sdk_python_runtime_anchor(root, release_sha)
    except (OSError, ValueError):
        return False
    return True


def sdk_npm_lock_identity(root: Path, release_sha: str) -> dict[str, object]:
    identity = verify_sdk_npm_tarballs.committed_lock_identity(
        root, release_sha, evidence_runtime.commit_blob
    )
    return {key: value for key, value in identity.items() if key != "packages"}


def sdk_python_runtime_anchor(root: Path, release_sha: str) -> dict[str, object]:
    value = evidence_runtime.committed_json(root, release_sha, SDK_PYTHON_RUNTIME_ANCHOR)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "target", "status", "runtime"}
        or value.get("schema_version") != 1
        or value.get("target") != "cp312-cp312-manylinux_2_17_x86_64"
        or value.get("status") != "reviewed"
    ):
        raise ValueError("committed SDK Python runtime anchor is not reviewed and ready")
    runtime = value.get("runtime")
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {
            "schema_version", "interpreter_sha256", "stdlib_roots", "file_count",
            "total_bytes", "files_sha256", "mapped_file_count"
        }
        or runtime.get("schema_version") != 1
    ):
        raise ValueError("committed SDK Python runtime anchor is malformed")
    return runtime


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_output(gate: str, payload: bytes) -> dict[str, object]:
    spec = GATES[gate]
    parser = str(spec["parser"])
    text = payload.decode("utf-8", errors="replace")
    passed = False
    details: dict[str, object] = {"parser": parser}
    if parser == "source_scan_v1":
        matches = re.findall(
            r"^PASS  backend source scan \(([1-9][0-9]*) files, ([0-9a-f]{64})\)$",
            text,
            re.MULTILINE,
        )
        passed = len(matches) == 1
        if passed:
            details.update(file_count=int(matches[0][0]), candidate_set_sha256=matches[0][1])
    elif parser == "compatibility_v1":
        matches = re.findall(
            r"^PASS Plonky3 compatibility gate \(([1-9][0-9]*) exact crates\)$",
            text,
            re.MULTILINE,
        )
        passed = len(matches) == 1 and int(matches[0]) >= 1
        if passed:
            details["exact_crate_count"] = int(matches[0])
    elif parser == "cargo_exact_test_v1":
        execution = run_crash_matrix.parse_test_execution(payload, str(spec["test"]))
        passed = run_crash_matrix.test_execution_passed(execution)
        details["test_execution"] = execution
    elif parser == "known_answers_v1":
        marker = "PASS TinyZKP deterministic cross-mode proof vectors"
        passed = text.splitlines().count(marker) == 1
        details["marker"] = marker
    elif parser == "sdk_contracts_v1":
        marker = "PASS TinyZKP replacement SDK contracts"
        locked = re.findall(
            r"^PASS TinyZKP locked Python SDK environment "
            r"\(([1-9][0-9]*) wheels, ([0-9a-f]{64})\)$",
            text,
            re.MULTILINE,
        )
        npm_locked = re.findall(
            r"^PASS TinyZKP locked TypeScript SDK environment "
            r"\(([1-9][0-9]*) tarballs, ([0-9a-f]{64})\)$",
            text,
            re.MULTILINE,
        )
        passed = text.splitlines().count(marker) == 1 and len(locked) == 1 and len(npm_locked) == 1
        details["marker"] = marker
        if len(locked) == 1:
            details["python_wheel_count"] = int(locked[0][0])
            details["python_wheel_set_sha256"] = locked[0][1]
        if len(npm_locked) == 1:
            details["npm_tarball_count"] = int(npm_locked[0][0])
            details["npm_tarball_set_sha256"] = npm_locked[0][1]
    return {**details, "passed": passed}


def _resolved_tools(spec: dict[str, object], environment: dict[str, str]) -> dict[str, dict[str, object]]:
    logical = list(spec["command"])
    names = {str(logical[0])}
    if logical[0] == "bash":
        names.add("cargo")
    if "cargo" in names:
        names.add("rustc")
    if logical[0] == "bash" and "sdk_contract_gate.sh" in logical[1]:
        names.update({"python3", "node", "wasm-pack"})
    tools: dict[str, dict[str, object]] = {}
    for name in sorted(names):
        if name == "python3":
            path = Path(sys.executable).resolve()
            arguments = ["--version"]
        elif name == "bash":
            path = Path("/bin/bash")
            arguments = ["--version"]
        else:
            if name in {"cargo", "rustc"}:
                path = evidence_runtime.rustup_tool_path(
                    "1.95.0", name, environment=environment, root=ROOT
                )
            else:
                raw = shutil.which(name, path=environment.get("PATH"))
                if raw is None:
                    raise ValueError(f"required gate executable is unavailable: {name}")
                path = Path(raw).resolve()
            arguments = ["-Vv"] if name in {"cargo", "rustc"} else ["--version"]
        identity = evidence_runtime.executable_identity(
            str(path), arguments, environment=environment, root=ROOT
        )
        tools[name] = identity
    return tools


def run(
    *,
    gate: str,
    release_sha: str,
    report_path: Path,
    log_path: Path,
    timeout_seconds: int | None = None,
    sdk_python_wheelhouse: Path | None = None,
    sdk_npm_tarballs: Path | None = None,
    root: Path = ROOT,
) -> dict[str, object]:
    if gate not in GATES:
        raise ValueError("evidence gate is not allowlisted")
    spec = GATES[gate]
    expected_timeout = int(spec["timeout"])
    timeout_seconds = expected_timeout if timeout_seconds is None else timeout_seconds
    if timeout_seconds != expected_timeout:
        raise ValueError("evidence timeout must equal the reviewed gate timeout")
    root = root.resolve()
    sdk_lock: dict[str, object] | None = None
    npm_lock: dict[str, object] | None = None
    if gate == "replacement_sdk_contracts":
        try:
            sdk_lock = sdk_python_lock_identity(root, release_sha)
        except (OSError, ValueError) as error:
            raise ValueError(
                "replacement SDK evidence requires its exact committed Python dependency lock"
            ) from error
        if sdk_python_wheelhouse is None:
            raise ValueError(
                "replacement SDK evidence requires a pre-materialized Python wheelhouse"
            )
        try:
            npm_lock = sdk_npm_lock_identity(root, release_sha)
        except (OSError, ValueError) as error:
            raise ValueError(
                "replacement SDK evidence requires its exact committed npm tarball lock"
            ) from error
        if sdk_npm_tarballs is None:
            raise ValueError("replacement SDK evidence requires pre-materialized npm tarballs")
        sdk_python_runtime_anchor(root, release_sha)
    elif sdk_python_wheelhouse is not None or sdk_npm_tarballs is not None:
        raise ValueError("SDK dependency inputs are valid only for the SDK evidence gate")
    report_path = evidence_runtime.assert_no_symlink_ancestry(root, report_path)
    log_path = evidence_runtime.assert_no_symlink_ancestry(root, log_path)
    evidence_root = report_path.parent
    if log_path.parent != evidence_root:
        raise ValueError("evidence report and log must share one owner-only directory")
    source = evidence_runtime.release_source_identity(
        root,
        release_sha,
        evidence_root=evidence_root,
        require_explicit_sha=True,
    )
    boundary_abi = evidence_runtime.landlock_abi_version()
    immutable, inventory = evidence_runtime.materialize_read_only_source(
        root,
        str(source["release_sha"]),
        evidence_root=evidence_root,
    )
    environment = evidence_runtime.sanitized_environment(os.environ)
    environment.update(
        {
            "HC_RELEASE_SHA": str(source["release_sha"]),
            "TINYZKP_IMMUTABLE_SOURCE": "1",
            "CARGO_TARGET_DIR": str(evidence_root / "cargo-target"),
        }
    )
    writable_paths = tuple(
        evidence_runtime.reset_private_directory(
            root, evidence_root, evidence_root / name
        )
        for name in ("cargo-target", "sdk-work", "tmp")
    )
    if sdk_lock is not None:
        private_home = writable_paths[1] / "home"
        private_home.mkdir(mode=0o700)
        private_cargo_home = writable_paths[1] / "cargo-home"
        private_cargo_home.mkdir(mode=0o700)
        environment["HOME"] = str(private_home)
        environment["NPM_CONFIG_USERCONFIG"] = os.devnull
        # Never consult ambient Cargo config, wrappers, source replacement, or
        # mutable registry caches. The SDK release must provide reviewed
        # vendored sources; until then this deliberately makes this gate fail.
        environment["CARGO_HOME"] = str(private_cargo_home)
    environment.update(
        {
            "TINYZKP_EVIDENCE_WORK_DIR": str(writable_paths[1]),
            "TMPDIR": str(writable_paths[2]),
            "TMP": str(writable_paths[2]),
            "TEMP": str(writable_paths[2]),
        }
    )
    sdk_wheelhouse: Path | None = None
    verified_sdk_wheelhouse: dict[str, object] | None = None
    verified_npm_tarballs: dict[str, object] | None = None
    full_sdk_identity: dict[str, object] | None = None
    full_npm_identity: dict[str, object] | None = None
    if sdk_lock is not None:
        verify_sdk_python_wheelhouse.require_runtime_target()
        sdk_wheelhouse = evidence_runtime.assert_no_symlink_ancestry(
            root, sdk_python_wheelhouse
        )
        full_sdk_identity = verify_sdk_python_wheelhouse.committed_lock_identity(
            root, str(source["release_sha"]), evidence_runtime.commit_blob
        )
        verified_sdk_wheelhouse = verify_sdk_python_wheelhouse.verify_wheelhouse(
            sdk_wheelhouse, full_sdk_identity
        )
        if verified_sdk_wheelhouse != sdk_lock:
            raise ValueError("pre-materialized SDK Python wheelhouse identity is skewed")
        if any(
            sdk_wheelhouse == writable
            or sdk_wheelhouse.is_relative_to(writable)
            or writable.is_relative_to(sdk_wheelhouse)
            for writable in writable_paths
        ):
            raise ValueError("SDK Python wheelhouse overlaps a writable evidence path")
        environment["TINYZKP_SDK_PYTHON_WHEELHOUSE"] = str(sdk_wheelhouse)
        assert sdk_npm_tarballs is not None and npm_lock is not None
        npm_path = evidence_runtime.assert_no_symlink_ancestry(root, sdk_npm_tarballs)
        full_npm_identity = verify_sdk_npm_tarballs.committed_lock_identity(
            root, str(source["release_sha"]), evidence_runtime.commit_blob
        )
        verified_npm_tarballs = verify_sdk_npm_tarballs.verify_tarball_directory(
            npm_path, full_npm_identity
        )
        if verified_npm_tarballs != npm_lock:
            raise ValueError("pre-materialized npm tarball identity is skewed")
        if any(
            npm_path == writable or npm_path.is_relative_to(writable) or writable.is_relative_to(npm_path)
            for writable in writable_paths
        ):
            raise ValueError("npm tarball directory overlaps a writable evidence path")
    tools = _resolved_tools(spec, environment)
    generic_anchors = evidence_runtime.gate_tool_anchors(
        root, str(source["release_sha"])
    )
    for name, identity in tools.items():
        if name in {"cargo", "rustc"}:
            continue
        if generic_anchors.get(name) != identity["sha256"]:
            raise ValueError(f"{name} executable does not match the committed anchor")
    if "cargo" in tools:
        cargo_version = str(tools["cargo"]["version"])
        hosts = [
            line.removeprefix("host: ")
            for line in cargo_version.splitlines()
            if line.startswith("host: ")
        ]
        if len(hosts) != 1:
            raise ValueError("Cargo host identity is ambiguous")
        anchor = evidence_runtime.toolchain_anchor(
            root,
            str(source["release_sha"]),
            execution_profile="release",
            host=hosts[0],
        )
        if (
            tools["cargo"]["sha256"] != anchor["cargo_sha256"]
            or "rustc" not in tools
            or tools["rustc"]["sha256"] != anchor["rustc_sha256"]
        ):
            raise ValueError("Cargo executable does not match the committed anchor")
    tool_directories = [str(Path(str(value["path"])).parent) for value in tools.values()]
    environment["PATH"] = os.pathsep.join(
        dict.fromkeys([*tool_directories, "/usr/bin", "/bin"])
    )
    primary = str(spec["command"][0])
    actual_command = [str(tools[primary]["path"]), *list(spec["command"])[1:]]
    opened_tools: dict[str, tuple[int, str]] = {}
    for name, identity in tools.items():
        opened_tools[name] = evidence_runtime.open_executable_descriptor(
            str(identity["path"]), expected_sha256=str(identity["sha256"])
        )
    execution_command = [opened_tools[primary][1], *list(spec["command"])[1:]]
    variable_names = {
        "bash": "TINYZKP_BASH",
        "cargo": "TINYZKP_CARGO",
        "rustc": "RUSTC",
        "python3": "TINYZKP_PYTHON",
        "node": "TINYZKP_NODE",
        "wasm-pack": "TINYZKP_WASM_PACK",
    }
    for name, variable in variable_names.items():
        if name in opened_tools:
            environment[variable] = opened_tools[name][1]
    if "cargo" in opened_tools:
        environment["CARGO"] = opened_tools["cargo"][1]
        environment["TINYZKP_CARGO"] = opened_tools["cargo"][1]
    if "rustc" in opened_tools:
        environment["RUSTC"] = opened_tools["rustc"][1]

    sealed_dependencies: list[tuple[int, dict[str, object]]] = []
    sealed_summary: dict[str, object] | None = None
    python_runtime: dict[str, object] | None = None
    if sdk_lock is not None:
        assert full_sdk_identity is not None and full_npm_identity is not None
        sealed_python_dir = writable_paths[1] / "sealed-python-wheelhouse"
        sealed_npm_dir = writable_paths[1] / "sealed-npm-tarballs"
        sealed_python_dir.mkdir(mode=0o700)
        sealed_npm_dir.mkdir(mode=0o700)
        python_records: list[dict[str, object]] = []
        npm_records: list[dict[str, object]] = []
        for record in full_sdk_identity["wheels"]:
            filename = str(record["filename"])
            payload = (sdk_wheelhouse / filename).read_bytes()
            fd, identity = evidence_runtime.sealed_memfd_from_bytes(f"py-{filename}", payload)
            link = sealed_python_dir / filename
            os.symlink(f"/proc/self/fd/{fd}", link)
            item = {"filename": filename, "fd": fd, **identity}
            if item["sha256"] != record["sha256"] or item["bytes"] != record["bytes"]:
                os.close(fd)
                raise ValueError("sealed Python wheel differs from its lock")
            sealed_dependencies.append((fd, identity))
            python_records.append(item)
        npm_path = evidence_runtime.assert_no_symlink_ancestry(root, sdk_npm_tarballs)
        for record in full_npm_identity["packages"]:
            filename = str(record["filename"])
            payload = (npm_path / filename).read_bytes()
            fd, identity = evidence_runtime.sealed_memfd_from_bytes(f"npm-{filename}", payload)
            os.symlink(f"/proc/self/fd/{fd}", sealed_npm_dir / filename)
            if len(payload) != record["bytes"] or identity["sha256"] != record["sha256"]:
                os.close(fd)
                raise ValueError("sealed npm tarball differs from its lock")
            sealed_dependencies.append((fd, identity))
            npm_records.append({"filename": filename, "fd": fd, **identity})
        environment["TINYZKP_SDK_PYTHON_WHEELHOUSE"] = str(sealed_python_dir)
        environment["TINYZKP_SEALED_PYTHON_WHEELS"] = json.dumps(python_records, sort_keys=True)
        environment["TINYZKP_SDK_NPM_TARBALLS"] = str(sealed_npm_dir)
        environment["TINYZKP_SEALED_NPM_TARBALLS"] = json.dumps(npm_records, sort_keys=True)
        sealed_summary = {
            "kind": "sealed-memfd-dependencies-v1",
            "python_count": len(python_records),
            "npm_count": len(npm_records),
            "descriptor_set_sha256": evidence_runtime.canonical_json_sha256(
                [{key: value for key, value in item.items() if key != "fd"} for item in [*python_records, *npm_records]]
            ),
            "required_seals": evidence_runtime.MEMFD_SEALS,
        }
        python_runtime = evidence_runtime.python_runtime_manifest(
            opened_tools["python3"][1], opened_tools["python3"][0], environment=environment, root=immutable
        )
        if python_runtime != sdk_python_runtime_anchor(root, str(source["release_sha"])):
            raise ValueError("Python runtime differs from the committed reviewed anchor")
    descriptor = evidence_runtime.open_private_output(root, log_path)
    started_at = timestamp()
    started = time.monotonic()
    try:
        with os.fdopen(descriptor, "wb") as log:
            network_boundary: dict[str, object] = {}
            exit_status, timed_out = evidence_runtime.run_logged(
                execution_command,
                cwd=immutable,
                environment=environment,
                log=log,
                timeout_seconds=timeout_seconds,
                pass_fds=tuple(value[0] for value in opened_tools.values()) + tuple(fd for fd, _ in sealed_dependencies),
                write_boundary_paths=writable_paths,
                require_network_namespace=sdk_lock is not None,
                network_boundary_result=network_boundary if sdk_lock is not None else None,
            )
            log.flush()
            os.fsync(log.fileno())
            log_identity = evidence_runtime.private_file_identity(log.fileno())
        payload = evidence_runtime.read_private_output(root, log_path, log_identity)
        parsed = parse_output(gate, payload)
        if sdk_wheelhouse is not None:
            post_run_sdk_lock = verify_sdk_python_wheelhouse.verify_wheelhouse(
                sdk_wheelhouse, full_sdk_identity
            )
            if post_run_sdk_lock != verified_sdk_wheelhouse:
                raise ValueError("SDK Python wheelhouse changed during evidence execution")
            assert full_npm_identity is not None and sdk_npm_tarballs is not None
            if verify_sdk_npm_tarballs.verify_tarball_directory(
                evidence_runtime.assert_no_symlink_ancestry(root, sdk_npm_tarballs), full_npm_identity
            ) != verified_npm_tarballs:
                raise ValueError("npm tarballs changed during evidence execution")
            for fd, identity in sealed_dependencies:
                evidence_runtime.verify_sealed_memfd(fd, identity)
            if evidence_runtime.python_runtime_manifest(
                opened_tools["python3"][1], opened_tools["python3"][0], environment=environment, root=immutable
            ) != python_runtime:
                raise ValueError("Python runtime changed during SDK evidence execution")
        evidence_runtime.verify_read_only_source(immutable, inventory)
        evidence_runtime.assert_release_source_unchanged(
            root, source, evidence_root=evidence_root
        )
        for name, original in tools.items():
            if (
                evidence_runtime._digest_descriptor(opened_tools[name][0])
                != original["sha256"]
            ):
                raise ValueError(f"gate executable changed during execution: {name}")
    finally:
        for dependency_fd, _ in sealed_dependencies:
            os.close(dependency_fd)
        for descriptor_value, _ in opened_tools.values():
            os.close(descriptor_value)
        evidence_runtime.remove_read_only_source(root, evidence_root, immutable)
    report: dict[str, object] = {
        "schema_version": 4,
        **source,
        "profile": PROFILE,
        "gate": gate,
        "execution_profile": spec["profile"],
        "logical_command": spec["command"],
        "actual_command": actual_command,
        "descriptor_execution": True,
        "output_parser": spec["parser"],
        "parsed_result": parsed,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit_status": exit_status,
        "started_at": started_at,
        "finished_at": timestamp(),
        "duration_ms": evidence_runtime.elapsed_milliseconds(started),
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
        "environment_policy": evidence_runtime.environment_policy(),
        "environment_policy_sha256": evidence_runtime.canonical_json_sha256(
            evidence_runtime.environment_policy()
        ),
        "immutable_source": True,
        "write_boundary": {
            "kind": "landlock-write-deny-v1",
            "abi_version": boundary_abi,
            "source_write_allowed": False,
            "writable_paths": [path.name for path in writable_paths],
        },
        "network_boundary": network_boundary if sdk_lock is not None else None,
        "immutable_file_count": len(inventory),
        "tools": tools,
        "gate_inputs": (
            {
                "sdk_python_lock": sdk_lock,
                "sdk_python_wheelhouse": verified_sdk_wheelhouse,
                "sdk_npm_lock": npm_lock,
                "sdk_npm_tarballs": verified_npm_tarballs,
                "sealed_dependencies": sealed_summary,
                "python_runtime": python_runtime,
            }
            if sdk_lock is not None
            else {}
        ),
    }
    evidence_runtime.write_json_atomic(root, report_path, report)
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", choices=tuple(sorted(GATES)), required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--sdk-python-wheelhouse", type=Path)
    parser.add_argument("--sdk-npm-tarballs", type=Path)
    args = parser.parse_args(argv)
    try:
        report = run(
            gate=args.gate,
            release_sha=args.release_sha,
            report_path=args.report,
            log_path=args.log,
            timeout_seconds=args.timeout_seconds,
            sdk_python_wheelhouse=args.sdk_python_wheelhouse,
            sdk_npm_tarballs=args.sdk_npm_tarballs,
        )
    except (OSError, ValueError) as error:
        print(f"evidenced gate failed to run: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["exit_status"] == 0 and report["parsed_result"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
