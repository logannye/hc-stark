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


PROFILE = "tinyzkp-p3-goldilocks-v1"
GENERIC_TOOL_VERSIONS = {
    "bash": "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)",
    "python3": "Python 3.12.13",
}
RUST_TOOL_VERSIONS = {
    "cargo": {
        "first_line": "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
        "release": "1.95.0",
        "commit-hash": "f2d3ce0bd7f24a49f8f72d9000448f8838c4e850",
        "commit-date": "2026-03-21",
        "host": "x86_64-unknown-linux-gnu",
    },
    "rustc": {
        "first_line": "rustc 1.95.0 (59807616e 2026-04-14)",
        "binary": "rustc",
        "release": "1.95.0",
        "commit-hash": "59807616e1fa2540724bfbac14d7976d7e4a3860",
        "commit-date": "2026-04-14",
        "host": "x86_64-unknown-linux-gnu",
    },
}
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
            "cargo",
            "test",
            "-p",
            "hc-plonky3",
            "--release",
            "--locked",
            "fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
        ],
        "profile": "release",
        "parser": "cargo_exact_test_v1",
        "test": "fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
        "timeout": 1800,
    },
    "official_verifier_poseidon2": {
        "command": [
            "cargo",
            "test",
            "-p",
            "hc-plonky3",
            "--release",
            "--locked",
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
    "air_job_contracts": {
        "command": [
            "cargo",
            "test",
            "-p",
            "hc-cli",
            "--locked",
            "plonky3_air_job_contracts",
        ],
        "profile": "ci",
        "parser": "cargo_exact_test_v1",
        "test": "plonky3_air_job_contracts",
        "timeout": 1800,
    },
}


def timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
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
            details.update(
                file_count=int(matches[0][0]), candidate_set_sha256=matches[0][1]
            )
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
    return {**details, "passed": passed}


def owner_ga_generic_tool_identity_valid(name: str, identity: object) -> bool:
    expected = GENERIC_TOOL_VERSIONS.get(name)
    if expected is None or not isinstance(identity, dict):
        return False
    version = identity.get("version")
    if not isinstance(version, str):
        return False
    lines = version.splitlines()
    return bool(lines) and lines[0] == expected


def generic_tool_version_valid(name: str, version: object) -> bool:
    """Validate a captured generic-tool version using the owner-GA policy."""
    return owner_ga_generic_tool_identity_valid(name, {"version": version})


def rust_tool_version_valid(name: str, version: object) -> bool:
    expected = RUST_TOOL_VERSIONS.get(name)
    if expected is None or not isinstance(version, str):
        return False
    lines = version.splitlines()
    if not lines or lines[0] != expected["first_line"]:
        return False
    observed: dict[str, str] = {}
    for line in lines[1:]:
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in observed:
            return False
        observed[key] = value
    return all(
        observed.get(key) == value
        for key, value in expected.items()
        if key != "first_line"
    )


def _resolved_tools(
    spec: dict[str, object], environment: dict[str, str]
) -> dict[str, dict[str, object]]:
    logical = list(spec["command"])
    names = {str(logical[0])}
    if logical[0] == "bash":
        names.add("cargo")
    if "cargo" in names:
        names.add("rustc")
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
        if name in GENERIC_TOOL_VERSIONS and not owner_ga_generic_tool_identity_valid(
            name, identity
        ):
            raise ValueError(f"{name} executable version differs from policy")
        if name in RUST_TOOL_VERSIONS and not rust_tool_version_valid(
            name, identity.get("version")
        ):
            raise ValueError(f"{name} executable version differs from policy")
        tools[name] = identity
    return tools


def run(
    *,
    gate: str,
    release_sha: str,
    report_path: Path,
    log_path: Path,
    timeout_seconds: int | None = None,
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
    evidence_runtime.owner_ga_tool_policy(root, str(source["release_sha"]))
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
        for name in ("cargo-target", "gate-work", "tmp")
    )
    environment.update(
        {
            "TINYZKP_EVIDENCE_WORK_DIR": str(writable_paths[1]),
            "TMPDIR": str(writable_paths[2]),
            "TMP": str(writable_paths[2]),
            "TEMP": str(writable_paths[2]),
        }
    )
    tools = _resolved_tools(spec, environment)
    tool_directories = [
        str(Path(str(value["path"])).parent) for value in tools.values()
    ]
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
    }
    for name, variable in variable_names.items():
        if name in opened_tools:
            environment[variable] = opened_tools[name][1]
    if "cargo" in opened_tools:
        environment["CARGO"] = opened_tools["cargo"][1]
        environment["TINYZKP_CARGO"] = opened_tools["cargo"][1]
    if "rustc" in opened_tools:
        environment["RUSTC"] = opened_tools["rustc"][1]

    descriptor = evidence_runtime.open_private_output(root, log_path)
    started_at = timestamp()
    started = time.monotonic()
    try:
        with os.fdopen(descriptor, "wb") as log:
            exit_status, timed_out = evidence_runtime.run_logged(
                execution_command,
                cwd=immutable,
                environment=environment,
                log=log,
                timeout_seconds=timeout_seconds,
                pass_fds=tuple(value[0] for value in opened_tools.values()),
                write_boundary_paths=writable_paths,
                require_network_namespace=False,
                network_boundary_result=None,
            )
            log.flush()
            os.fsync(log.fileno())
            log_identity = evidence_runtime.private_file_identity(log.fileno())
        payload = evidence_runtime.read_private_output(root, log_path, log_identity)
        parsed = parse_output(gate, payload)
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
        "network_boundary": None,
        "immutable_file_count": len(inventory),
        "tools": tools,
        "gate_inputs": {},
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
    args = parser.parse_args(argv)
    try:
        report = run(
            gate=args.gate,
            release_sha=args.release_sha,
            report_path=args.report,
            log_path=args.log,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ValueError) as error:
        print(f"evidenced gate failed to run: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["exit_status"] == 0 and report["parsed_result"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
