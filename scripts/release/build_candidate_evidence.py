#!/usr/bin/env python3
"""Construct a validated backend release candidate from unhashed input paths."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import backend_prerelease_ready as prerelease  # noqa: E402
import backend_release_ready as final_gate  # noqa: E402
import source_tree_identity  # noqa: E402
import strict_json  # noqa: E402


MAX_INPUT_BYTES = 1024 * 1024
WORKLOADS = ("fibonacci", "poseidon2")
RESOURCE_MATRIX_ROLE = "matrix_manifest"
CRASH_CASES = tuple(f"checkpoint_{phase}" for phase in final_gate.CRASH_PHASES) + tuple(
    sorted(final_gate.CRASH_INTEGRITY_CASES)
)
FUZZ_TARGETS = tuple(sorted(final_gate.FUZZ_TARGETS))


def resource_roles(*, baseline: bool, workloads: tuple[str, ...] = WORKLOADS) -> list[str]:
    suffixes = ["manifest", "candidate_report", "candidate_normalized_manifest"]
    if baseline:
        suffixes.extend(("baseline_report", "baseline_normalized_manifest"))
    return [f"{workload}_{suffix}" for workload in workloads for suffix in suffixes]


ONE_MILLION_WORKLOAD_ROLES = resource_roles(baseline=True)
TEN_MILLION_WORKLOAD_ROLES = resource_roles(
    baseline=False, workloads=("fibonacci",)
)
ONE_MILLION_ROLES = [RESOURCE_MATRIX_ROLE, *ONE_MILLION_WORKLOAD_ROLES]
TEN_MILLION_ROLES = [RESOURCE_MATRIX_ROLE, *TEN_MILLION_WORKLOAD_ROLES]
GATE_ROLES = {
    "clean_release_source": ["test_report", "test_log"],
    "plonky3_dependency_profile_pinned": ["test_report", "test_log"],
    "official_verifier_fibonacci": ["test_report", "test_log"],
    "official_verifier_poseidon2": ["test_report", "test_log"],
    "deterministic_cross_mode_proofs": ["test_report", "test_log"],
    "one_million_row_resource_gate": ONE_MILLION_ROLES,
    "ten_million_row_resource_gate": TEN_MILLION_ROLES,
    "crash_resume_and_corruption_suite": [
        "crash_matrix",
        "fuzz_smoke",
        "crash_tool_identity",
        "fuzz_tool_identity",
        *(f"crash_log_{name}" for name in CRASH_CASES),
        *(f"fuzz_log_{name}" for name in FUZZ_TARGETS),
    ],
    "air_job_contracts": ["test_report", "test_log"],
}


def command_metadata(
    release_sha: str, command: list[str], profile: str, gate_id: str
) -> dict[str, object]:
    return {
        "release_sha": release_sha,
        "exit_status": 0,
        "execution_profile": profile,
        "command": command,
        "gate_id": gate_id,
    }


def gate_metadata(name: str, release_sha: str) -> dict[str, object]:
    commands = {
        "clean_release_source": ["python3", "scripts/ci/backend_source_scan.py"],
        "plonky3_dependency_profile_pinned": [
            "python3",
            "scripts/ci/plonky3_compatibility_gate.py",
        ],
        "official_verifier_fibonacci": [
            "cargo",
            "test",
            "-p",
            "hc-plonky3",
            "--release",
            "--locked",
            "prover::tests::fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
            "--",
            "--exact",
        ],
        "official_verifier_poseidon2": [
            "cargo",
            "test",
            "-p",
            "hc-plonky3",
            "--release",
            "--locked",
            "prover::tests::poseidon2_proof_is_accepted_by_unmodified_plonky3_verifier",
            "--",
            "--exact",
        ],
        "deterministic_cross_mode_proofs": [
            "bash",
            "scripts/ci/check_plonky3_known_answers.sh",
        ],
        "air_job_contracts": [
            "cargo",
            "test",
            "-p",
            "hc-cli",
            "--locked",
            "plonky3_air_job_contracts",
            "--",
            "--exact",
        ],
    }
    if name in commands:
        release_profile = name.startswith("official_") or name == "deterministic_cross_mode_proofs"
        metadata = command_metadata(
            release_sha,
            commands[name],
            "release" if release_profile else "ci",
            name,
        )
        if name == "clean_release_source":
            metadata.update(secret_scan_clean=True, generated_scan_clean=True)
        return metadata
    if name == "crash_resume_and_corruption_suite":
        return {"release_sha": release_sha, "exit_status": 0}
    return {}


def safe_existing_file(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("artifact path must be a non-empty repository-relative string")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"artifact path is unsafe: {raw}")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"artifact path contains a symlink: {raw}")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f"artifact is missing or unsafe: {raw}")
    return resolved


def safe_output(root: Path, path: Path) -> Path:
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    candidate = candidate.absolute()
    if not candidate.is_relative_to(root):
        raise ValueError(f"candidate output is outside the repository: {path}")
    relative = candidate.relative_to(root)
    if ".." in relative.parts:
        raise ValueError(f"candidate output is unsafe: {path}")
    current = root
    for part in relative.parent.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"candidate output parent contains a symlink: {path}")
    if candidate.exists() and candidate.is_symlink():
        raise ValueError(f"candidate output is a symlink: {path}")
    return candidate


def read_source(path: Path) -> dict[str, object]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("candidate input exceeds 1 MiB")
    value = strict_json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("candidate input must contain a JSON object")
    return value


def hashed_artifact(root: Path, raw: object) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {"role", "path"}:
        raise ValueError("input artifact must contain exactly role and path")
    role = raw.get("role")
    relative = raw.get("path")
    if not isinstance(role, str) or not role:
        raise ValueError("artifact role must be a non-empty string")
    path = safe_existing_file(root, relative)
    return {
        "role": role,
        "path": path.relative_to(root.resolve()).as_posix(),
        "sha256": final_gate.bounded_file_sha256(path),
    }


def construct_evidence(
    source: dict[str, object],
    *,
    root: Path,
) -> dict[str, object]:
    if not final_gate.exact_int(source.get("schema_version"), 1):
        raise ValueError("candidate input schema_version must equal 1")
    release_sha = source.get("release_sha")
    if not isinstance(release_sha, str) or not release_sha or len(release_sha) > 128:
        raise ValueError("candidate release_sha is missing or oversized")
    release_sha = source_tree_identity.require_canonical_commit(root, release_sha)
    source_gates = source.get("gates")
    if not isinstance(source_gates, dict):
        raise ValueError("candidate gate map is missing")
    expected = prerelease.EXPECTED_GATES
    missing = expected - set(source_gates)
    extra = set(source_gates) - expected
    if missing:
        raise ValueError(f"candidate gates are missing: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"candidate gates are unknown: {', '.join(sorted(extra))}")

    gates: dict[str, object] = {}
    for name in sorted(expected):
        raw = source_gates[name]
        if not isinstance(raw, dict) or set(raw) != {"metadata", "artifacts"}:
            raise ValueError(
                f"{name}: gate input must contain exactly metadata and artifacts"
            )
        metadata = raw.get("metadata")
        artifacts = raw.get("artifacts")
        if not isinstance(metadata, dict):
            raise ValueError(f"{name}: metadata must be an object")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError(f"{name}: artifact list must be non-empty")
        hashed = [hashed_artifact(root, artifact) for artifact in artifacts]
        roles = [artifact["role"] for artifact in hashed]
        if len(roles) != len(set(roles)):
            raise ValueError(f"{name}: artifact roles must be unique")
        gates[name] = {
            "kind": final_gate.EXPECTED_KINDS[name],
            "metadata": metadata,
            "artifacts": hashed,
        }
    evidence = {
        "schema_version": 1,
        "status": "candidate",
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_identity.source_tree_sha256(root, release_sha),
        "gates": gates,
    }
    problems = prerelease.evidence_failures(evidence, root=root)
    if problems:
        raise ValueError("candidate evidence failed validation: " + "; ".join(problems))
    return evidence


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def template() -> dict[str, object]:
    release_sha = "REPLACE_WITH_SOURCE_RELEASE_SHA"
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "gates": {
            name: {
                "metadata": gate_metadata(name, release_sha),
                "artifacts": [
                    {
                        "role": role,
                        "path": (
                            "release/evidence/REPLACE/fixed-host-release-matrix-v1.json"
                            if role == RESOURCE_MATRIX_ROLE
                            else f"release/evidence/REPLACE/{name}/{role}"
                        ),
                    }
                    for role in GATE_ROLES[name]
                ],
            }
            for name in sorted(prerelease.EXPECTED_GATES)
        },
    }


def build(args: argparse.Namespace) -> None:
    root = ROOT.resolve()
    source_path = safe_existing_file(root, args.input.as_posix())
    source = read_source(source_path)
    evidence = construct_evidence(source, root=root)
    output_evidence = safe_output(root, args.output_evidence)
    output_config = safe_output(root, args.output_config)
    if output_evidence == output_config:
        raise ValueError("candidate evidence and config outputs must differ")
    config = {
        "schema_version": 2,
        "release": "tinyzkp-plonky3-backend-v1",
        "status": "candidate",
        "evidence_manifest": output_evidence.relative_to(root).as_posix(),
        "policy": "All pre-signing gates are derived from hashed, validated artifacts.",
    }
    write_json_atomic(output_evidence, evidence)
    write_json_atomic(output_config, config)
    problems = prerelease.candidate_content_failures(config, root=root)
    if problems:
        output_evidence.unlink(missing_ok=True)
        output_config.unlink(missing_ok=True)
        raise ValueError("emitted candidate failed validation: " + "; ".join(problems))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    template_command = subcommands.add_parser("template")
    template_command.add_argument("--output", type=Path, required=True)
    build_command = subcommands.add_parser("build")
    build_command.add_argument("--input", type=Path, required=True)
    build_command.add_argument("--output-evidence", type=Path, required=True)
    build_command.add_argument("--output-config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "template":
            write_json_atomic(safe_output(ROOT, args.output), template())
        else:
            build(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"candidate evidence build failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
