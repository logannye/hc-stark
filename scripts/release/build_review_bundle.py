#!/usr/bin/env python3
"""Build a deterministic, hashed backend review ZIP for one release identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import source_tree_identity  # noqa: E402
import strict_json  # noqa: E402


FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
REQUIRED_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "release/plonky3-compatibility-v1.json",
    "release/backend-v1-gates.json",
    "release/evidence/README.md",
    "docs/recovery/architecture.md",
    "docs/recovery/plonky3-transcript-equivalence.md",
    "docs/security/threat_model.md",
    "test-vectors/canonical-json-v1.json",
    "test-vectors/plonky3/fibonacci-16.manifest.json",
    "test-vectors/plonky3/fibonacci-16.bundle.json",
    "test-vectors/plonky3/fibonacci-max-field.manifest.json",
    "test-vectors/plonky3/poseidon2-8.manifest.json",
    "test-vectors/plonky3/poseidon2-8.bundle.json",
    "test-vectors/plonky3/benchmark-report-v1.json",
    "scripts/ci/source_tree_identity.py",
    "scripts/ci/test_source_tree_identity.py",
    "scripts/release/run_crash_matrix_disk_full.sh",
)
SOURCE_GLOBS = (
    "crates/hc-plonky3/**/*.rs",
    "crates/hc-plonky3/Cargo.toml",
    "crates/hc-plonky3/README.md",
    "crates/hc-stream/**/*.rs",
    "crates/hc-stream/Cargo.toml",
    "crates/hc-stream/README.md",
    "crates/hc-cli/**/*.rs",
    "crates/hc-cli/Cargo.toml",
    "fuzz/fuzz_targets/*.rs",
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "scripts/benchmark/*.py",
    "scripts/benchmark/requirements.txt",
    "scripts/ci/backend_release_ready.py",
    "scripts/ci/backend_prerelease_ready.py",
    "scripts/ci/source_tree_identity.py",
    "scripts/ci/test_source_tree_identity.py",
    "scripts/ci/backend_source_scan.py",
    "scripts/ci/generate_sdk_schema_models.py",
    "scripts/ci/check_plonky3_known_answers.sh",
    "scripts/ci/sdk_contract_gate.sh",
    "scripts/ci/plonky3_compatibility_gate.py",
    "scripts/release/*.py",
    "examples/partner-adapter/src/*.rs",
    "examples/partner-adapter/Cargo.toml",
    "examples/partner-adapter/Dockerfile",
    "examples/partner-adapter/README.md",
    "examples/partner-adapter/*.py",
    "clients/python/tinyzkp/*.py",
    "clients/python/pyproject.toml",
    "clients/typescript/src/*.ts",
    "clients/typescript/package.json",
    "clients/typescript/package-lock.json",
    "clients/rust/src/*.rs",
    "clients/rust/Cargo.toml",
    "site/schemas/*.json",
    "crates/hc-wasm/src/*.rs",
    "crates/hc-wasm/Cargo.toml",
    "crates/hc-wasm/LICENSE",
    "examples/plonky3/*.json",
    ".github/workflows/ci.yml",
    ".github/workflows/nightly-backend.yml",
    ".github/workflows/benches.yml",
    ".github/workflows/release-backend.yml",
    ".github/workflows/publish-sdks.yml",
    ".github/workflows/sdks-ci.yml",
    ".github/workflows/publish-backend-crates.yml",
)
CRASH_PHASES = (
    "trace", "trace_lde", "trace_commitment", "quotient", "quotient_lde",
    "quotient_commitment", "openings", "fri_layer_0", "fri_layer_1",
    "fri_layer_2", "fri_layer_3", "fri_layer_4", "fri_layer_5",
    "proof_assembly",
)
CRASH_INTEGRITY = (
    "saved_artifact_reuse", "corrupt_artifact_and_stale_identity",
    "cancellation_retention", "truncation_and_checksum", "path_traversal",
    "symlink_rejection", "disk_full_resume",
)
FUZZ_TARGETS = (
    "workload_manifest_v1", "proof_bundle_v1", "plonky3_proof_bytes_v1",
    "benchmark_report_v1", "checkpoint_manifest_v2", "challenger_snapshot_v1",
    "scratch_artifact_header_v1", "checkpoint_identity_v2",
    "resume_checkpoint_v2",
)
REQUIRED_EVIDENCE_ROLES = {
    "raw-reports": {
        "one_million_fibonacci_baseline_report",
        "one_million_fibonacci_candidate_report",
        "one_million_poseidon2_baseline_report",
        "one_million_poseidon2_candidate_report",
        "ten_million_fibonacci_candidate_report",
        "ten_million_poseidon2_candidate_report",
    },
    "known-answers": {"known_answer_test_report", "known_answer_test_log"},
    "crash": {
        "crash_matrix",
        "crash_tool_identity",
        *(f"crash_log_checkpoint_{phase}" for phase in CRASH_PHASES),
        *(f"crash_log_{case}" for case in CRASH_INTEGRITY),
    },
    "fuzz": {
        "fuzz_smoke",
        "fuzz_tool_identity",
        *(f"fuzz_log_{target}" for target in FUZZ_TARGETS),
    },
    "sbom": {"preliminary_sbom"},
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_output(root: Path, *args: str) -> bytes:
    return source_tree_identity.git_output(root, *args)


def committed_review_sources(
    root: Path, release_sha: str
) -> dict[str, tuple[bytes, str, str]]:
    """Read every review source from the exact commit, never the worktree."""
    raw = git_output(root, "ls-tree", "-r", "-z", "--full-tree", release_sha)
    tree: dict[str, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            identity, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = identity.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ValueError("release commit contains a malformed Git tree entry") from error
        tree[path] = (mode, kind, object_id)

    missing = sorted(set(REQUIRED_FILES) - set(tree))
    if missing:
        raise ValueError(
            "release commit omits required review sources: " + ", ".join(missing)
        )
    # Reviewers receive the entire immutable production source identity, not a
    # hand-selected subset that could omit the vulnerable implementation.
    selected = {
        path
        for path in tree
        if not source_tree_identity.evidence_only_path(path)
        or path in REQUIRED_FILES
    }
    sources: dict[str, tuple[bytes, str, str]] = {}
    for path in sorted(selected):
        mode, kind, object_id = tree[path]
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"review source is not a regular Git file: {path}")
        sources[path] = (
            git_output(root, "cat-file", "blob", object_id),
            mode,
            object_id,
        )
    return sources


def safe_optional(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError(f"review input is missing or unsafe: {path}")
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"review input is missing or unsafe: {path}")
    return resolved


def validate_spdx(path: Path) -> None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"review SBOM is not valid JSON: {path}") from error
    creation = value.get("creationInfo") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("spdxVersion") != "SPDX-2.3"
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(value.get("documentNamespace"), str)
        or not isinstance(creation, dict)
        or not isinstance(creation.get("created"), str)
        or not isinstance(value.get("packages"), list)
        or not value["packages"]
    ):
        raise ValueError(f"review SBOM is not a complete SPDX 2.3 dependency inventory: {path}")


def verify_bundle(
    bundle_path: Path,
    *,
    root: Path,
    release_sha: str,
) -> tuple[dict[str, object], bytes]:
    """Recompute a review archive from Git and reject omissions/substitutions."""
    release_sha = source_tree_identity.require_canonical_commit(root, release_sha)
    committed = committed_review_sources(root, release_sha)
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or "review-manifest.json" not in names:
                raise ValueError("review archive has duplicate or missing members")
            if any(
                info.is_dir()
                or info.flag_bits & 0x1
                or Path(info.filename).is_absolute()
                or ".." in Path(info.filename).parts
                or "\\" in info.filename
                or info.file_size < 0
                or info.file_size > 256 * 1024 * 1024
                for info in infos
            ):
                raise ValueError("review archive contains an unsafe member")
            if sum(info.file_size for info in infos) > 1024 * 1024 * 1024:
                raise ValueError("review archive expands beyond the 1 GiB limit")
            manifest_info = next(
                info for info in infos if info.filename == "review-manifest.json"
            )
            if manifest_info.file_size > 16 * 1024 * 1024:
                raise ValueError("review manifest is oversized")
            manifest_bytes = archive.read(manifest_info)
            manifest = strict_json.loads(manifest_bytes)
            if not isinstance(manifest, dict) or set(manifest) != {
                "schema_version",
                "release_sha",
                "source_tree_sha256",
                "profile",
                "plonky3_version",
                "files",
                "reproduction_commands",
            }:
                raise ValueError("review manifest schema is not closed")
            if (
                manifest.get("schema_version") != 2
                or isinstance(manifest.get("schema_version"), bool)
                or manifest.get("release_sha") != release_sha
                or manifest.get("source_tree_sha256")
                != source_tree_identity.source_tree_sha256(root, release_sha)
                or manifest.get("profile") != "tinyzkp-p3-goldilocks-v1"
                or manifest.get("plonky3_version") != "0.6.1"
            ):
                raise ValueError("review manifest identity is release-skewed")
            files = manifest.get("files")
            if not isinstance(files, list) or not files:
                raise ValueError("review manifest file inventory is empty")
            records: dict[str, dict[str, object]] = {}
            for raw in files:
                if not isinstance(raw, dict):
                    raise ValueError("review file descriptor is malformed")
                origin = raw.get("origin")
                expected_keys = {
                    "path",
                    "origin",
                    "source_sha256",
                    "source_bytes",
                    "archive_sha256",
                    "archive_bytes",
                    "normalized",
                } | (
                    {"git_mode", "git_object"}
                    if origin == "git"
                    else {"evidence_category", "evidence_role"}
                )
                if set(raw) != expected_keys:
                    raise ValueError("review file descriptor schema is not closed")
                name = raw.get("path")
                if (
                    not isinstance(name, str)
                    or not name
                    or name in records
                    or name == "review-manifest.json"
                ):
                    raise ValueError("review file path is missing or duplicated")
                records[name] = raw
            if set(names) != set(records) | {"review-manifest.json"}:
                raise ValueError("review archive membership differs from its manifest")
            expected_git_paths = set(committed)
            actual_git_paths = {
                name for name, raw in records.items() if raw.get("origin") == "git"
            }
            if actual_git_paths != expected_git_paths:
                raise ValueError("review archive does not cover the full committed source")
            artifact_records = [
                raw for raw in records.values() if raw.get("origin") == "artifact"
            ]
            observed_roles: dict[str, set[str]] = {}
            observed_pairs: set[tuple[str, str]] = set()
            for raw in artifact_records:
                category = raw.get("evidence_category")
                role = raw.get("evidence_role")
                if not isinstance(category, str) or not isinstance(role, str):
                    raise ValueError("review artifact role is malformed")
                pair = (category, role)
                if pair in observed_pairs:
                    raise ValueError(
                        "review archive duplicates an execution-evidence role"
                    )
                observed_pairs.add(pair)
                observed_roles.setdefault(category, set()).add(role)
            if observed_roles != REQUIRED_EVIDENCE_ROLES:
                raise ValueError("review archive omits required execution evidence")
            for name, raw in records.items():
                payload = archive.read(name)
                if (
                    raw.get("archive_bytes") != len(payload)
                    or raw.get("archive_sha256")
                    != hashlib.sha256(payload).hexdigest()
                ):
                    raise ValueError(f"review archive member digest mismatch: {name}")
                if raw.get("origin") == "git":
                    source, mode, object_id = committed[name]
                    if (
                        payload != source
                        or raw.get("source_bytes") != len(source)
                        or raw.get("source_sha256")
                        != hashlib.sha256(source).hexdigest()
                        or raw.get("archive_bytes") != len(source)
                        or raw.get("normalized") is not False
                        or raw.get("git_mode") != mode
                        or raw.get("git_object") != object_id
                    ):
                        raise ValueError(
                            f"review archive Git identity mismatch: {name}"
                        )
                elif raw.get("origin") != "artifact":
                    raise ValueError("review archive contains an unknown origin")
            commands = manifest.get("reproduction_commands")
            if (
                not isinstance(commands, list)
                or not commands
                or any(not isinstance(item, str) or not item for item in commands)
            ):
                raise ValueError("review reproduction commands are incomplete")
    except (OSError, zipfile.BadZipFile) as error:
        raise ValueError(f"review archive is malformed: {error}") from error
    return manifest, manifest_bytes


def archive_name(path: Path, category: str, role: str) -> str:
    suffix = "".join(path.suffixes[-2:]) if path.suffixes else ".bin"
    return f"evidence/{category}/{role}{suffix}"


def normalized_archive_payload(
    path: Path, category: str | None, source_payload: bytes
) -> bytes:
    if category is None:
        return source_payload
    repository = str(ROOT.resolve())
    home = str(Path.home().resolve())

    if path.suffix.lower() != ".json":
        if b"\0" in source_payload:
            return source_payload
        try:
            text = source_payload.decode("utf-8")
        except UnicodeError:
            return source_payload
        return text.replace(repository, "$REPO").replace(home, "$HOME").encode()

    try:
        value = json.loads(source_payload)
    except (UnicodeError, json.JSONDecodeError):
        return source_payload

    def normalize(item: object) -> object:
        if isinstance(item, dict):
            return {str(key): normalize(value) for key, value in item.items()}
        if isinstance(item, list):
            return [normalize(value) for value in item]
        if isinstance(item, str):
            return item.replace(repository, "$REPO").replace(home, "$HOME")
        return item

    return json.dumps(normalize(value), indent=2, sort_keys=True).encode() + b"\n"


def build_bundle(
    *,
    output: Path,
    release_sha: str,
    optional: dict[str, list[tuple[str, Path]]],
) -> dict[str, object]:
    actual_roles = {
        category: {role for role, _ in values}
        for category, values in optional.items()
    }
    if set(actual_roles) != set(REQUIRED_EVIDENCE_ROLES):
        raise ValueError("review execution-evidence categories are incomplete")
    for category, required in REQUIRED_EVIDENCE_ROLES.items():
        if (
            len(optional.get(category, [])) != len(actual_roles.get(category, set()))
            or actual_roles.get(category) != required
        ):
            missing = sorted(required - actual_roles.get(category, set()))
            extra = sorted(actual_roles.get(category, set()) - required)
            raise ValueError(
                f"review {category} roles mismatch; missing={missing}, extra={extra}"
            )
    sboms = [path for _, path in optional.get("sbom", [])]
    if not sboms:
        raise ValueError("a preliminary SPDX SBOM is required for a review bundle")
    for sbom in sboms:
        validate_spdx(safe_optional(sbom))
    root = ROOT.resolve()
    release_sha = source_tree_identity.require_canonical_commit(root, release_sha)
    committed = committed_review_sources(root, release_sha)

    entries: dict[str, dict[str, object]] = {}
    for name, (source_payload, git_mode, git_object) in committed.items():
        entries[name] = {
            "source_payload": source_payload,
            "archive_payload": source_payload,
            "origin": "git",
            "git_mode": git_mode,
            "git_object": git_object,
        }

    categorized: list[tuple[Path, str, str]] = []
    for category, values in optional.items():
        categorized.extend(
            (safe_optional(path), category, role) for role, path in values
        )
    for path, category, role in categorized:
        name = archive_name(path, category, role)
        if name in entries:
            raise ValueError(f"duplicate review archive path: {name}")
        source_payload = path.read_bytes()
        entries[name] = {
            "source_payload": source_payload,
            "archive_payload": normalized_archive_payload(
                path, category, source_payload
            ),
            "origin": "artifact",
            "evidence_category": category,
            "evidence_role": role,
        }

    files = [
        {
            "path": name,
            "origin": entry["origin"],
            "source_sha256": hashlib.sha256(entry["source_payload"]).hexdigest(),
            "source_bytes": len(entry["source_payload"]),
            "archive_sha256": hashlib.sha256(entry["archive_payload"]).hexdigest(),
            "archive_bytes": len(entry["archive_payload"]),
            "normalized": entry["source_payload"] != entry["archive_payload"],
            **(
                {
                    "git_mode": entry["git_mode"],
                    "git_object": entry["git_object"],
                }
                if entry["origin"] == "git"
                else {
                    "evidence_category": entry["evidence_category"],
                    "evidence_role": entry["evidence_role"],
                }
            ),
        }
        for name, entry in sorted(entries.items())
    ]
    manifest = {
        "schema_version": 2,
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_identity.source_tree_sha256(
            root, release_sha
        ),
        "profile": "tinyzkp-p3-goldilocks-v1",
        "plonky3_version": "0.6.1",
        "files": files,
        "reproduction_commands": [
            "cargo fetch --locked",
            "cargo +nightly-2026-04-15 fetch --manifest-path fuzz/Cargo.toml --locked",
            "cargo install cargo-fuzz --version 0.13.2 --locked",
            "cargo test -p hc-stream -p hc-plonky3 -p hc-cli --locked",
            "python3 -m venv .benchmark-venv",
            ".benchmark-venv/bin/python -m pip install -r scripts/benchmark/requirements.txt",
            f"HC_RELEASE_SHA={release_sha} cargo build --release -p hc-cli --locked",
            "sudo --preserve-env=HC_RELEASE_SHA .benchmark-venv/bin/python scripts/benchmark/run_fixed_host_release_matrix.py --release-sha $HC_RELEASE_SHA --hc-cli target/release/hc-cli --output-dir raw-reports/fixed-host-release-matrix",
            f"HC_RELEASE_SHA={release_sha} scripts/release/run_crash_matrix_disk_full.sh raw-reports/crash-matrix.json raw-reports/crash-logs",
            f"HC_RELEASE_SHA={release_sha} python3 scripts/release/run_fuzz_smoke.py --seconds 60 --rss-limit-mb 2048 --output raw-reports/fuzz-smoke.json --log-dir raw-reports/fuzz-logs",
        ],
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w+b") as handle:
            with zipfile.ZipFile(
                handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
            ) as bundle:
                for name, entry in sorted(entries.items()):
                    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                    info.external_attr = 0o100644 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    bundle.writestr(info, entry["archive_payload"])
                info = zipfile.ZipInfo("review-manifest.json", FIXED_ZIP_TIME)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(info, manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {**manifest, "bundle_sha256": sha256(output)}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-report", action="append", default=[])
    parser.add_argument("--known-answer", action="append", default=[])
    parser.add_argument("--fuzz-result", action="append", default=[])
    parser.add_argument("--crash-result", action="append", default=[])
    parser.add_argument("--sbom", action="append", required=True)
    return parser.parse_args(argv)


def role_paths(values: list[str]) -> list[tuple[str, Path]]:
    parsed: list[tuple[str, Path]] = []
    for value in values:
        if "=" not in value:
            raise ValueError("review evidence must be ROLE=PATH")
        role, raw = value.split("=", 1)
        if not role or not raw:
            raise ValueError("review evidence role/path is empty")
        parsed.append((role, Path(raw)))
    return parsed


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    metadata = build_bundle(
        output=args.output,
        release_sha=args.release_sha,
        optional={
            "raw-reports": role_paths(args.raw_report),
            "known-answers": role_paths(args.known_answer),
            "fuzz": role_paths(args.fuzz_result),
            "crash": role_paths(args.crash_result),
            "sbom": role_paths(args.sbom),
        },
    )
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"review bundle failed: {error}", file=sys.stderr)
        raise SystemExit(2)
