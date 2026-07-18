#!/usr/bin/env python3
"""Verify signed release artifacts and construct final backend evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import backend_prerelease_ready as prerelease  # noqa: E402
import backend_release_ready as final_gate  # noqa: E402
import source_tree_identity  # noqa: E402


CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")
SIGSTORE_ISSUER = "https://token.actions.githubusercontent.com"
SIGSTORE_IDENTITY_REGEXP = (
    r"^https://github\.com/logannye/hc-stark/\.github/workflows/"
    r"release-backend\.yml@refs/tags/backend-v[^/]+$"
)
REQUIRED_CHECKSUM_ENTRIES = set(final_gate.SIGNED_RELEASE_CHECKSUM_NAMES)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(root: Path, path: Path) -> Path:
    resolved_root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"release artifact is outside the repository: {path}") from error
    if ".." in relative.parts:
        raise ValueError(f"release artifact path is unsafe: {path}")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"release artifact path contains a symlink: {path}")
    resolved = candidate.resolve()
    if (
        not resolved.is_relative_to(resolved_root)
        or not resolved.is_file()
    ):
        raise ValueError(f"release artifact is missing or unsafe: {path}")
    return resolved


def relative_path(root: Path, path: Path) -> str:
    return safe_file(root, path).relative_to(root.resolve()).as_posix()


def verify_checksum_manifest(
    checksums: Path, sbom: Path, required_names: set[str] | None = None
) -> int:
    directory = checksums.parent.resolve()
    listed: set[Path] = set()
    entries = 0
    for line in checksums.read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError("checksum manifest contains a malformed line")
        expected, raw_name = match.groups()
        name = Path(raw_name)
        if name.is_absolute() or ".." in name.parts:
            raise ValueError("checksum manifest contains an unsafe path")
        unresolved = directory / name
        current = directory
        for part in name.parts:
            current /= part
            if current.is_symlink():
                raise ValueError(
                    f"checksummed artifact path contains a symlink: {raw_name}"
                )
        artifact = unresolved.resolve()
        if (
            not artifact.is_relative_to(directory)
            or not artifact.is_file()
        ):
            raise ValueError(f"checksummed artifact is missing or unsafe: {raw_name}")
        if sha256(artifact) != expected:
            raise ValueError(f"checksummed artifact digest mismatch: {raw_name}")
        if artifact in listed:
            raise ValueError(f"checksum manifest contains a duplicate path: {raw_name}")
        listed.add(artifact)
        entries += 1
    if entries == 0:
        raise ValueError("checksum manifest is empty")
    if sbom.resolve() not in listed:
        raise ValueError("SBOM is not covered by the checksum manifest")
    if required_names is not None:
        actual_names = {path.name for path in listed}
        missing = required_names - actual_names
        unexpected = actual_names - required_names
        if missing or unexpected:
            details = []
            if missing:
                details.append("missing " + ", ".join(sorted(missing)))
            if unexpected:
                details.append("unexpected " + ", ".join(sorted(unexpected)))
            raise ValueError(
                "checksum manifest release artifact inventory differs: "
                + "; ".join(details)
            )
    return entries


def verify_spdx_sbom(sbom: Path) -> None:
    try:
        value = json.loads(sbom.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("SBOM is not valid SPDX JSON") from error
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("spdxVersion"), str)
        or not value["spdxVersion"].startswith("SPDX-2.")
        or value.get("dataLicense") != "CC0-1.0"
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(value.get("name"), str)
        or not value.get("name")
        or not isinstance(value.get("documentNamespace"), str)
        or not value.get("documentNamespace")
    ):
        raise ValueError("SBOM is missing required SPDX document identity")


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


def finalize(
    *,
    root: Path,
    candidate_config_path: Path,
    release_sha: str,
    sbom: Path,
    checksums: Path,
    signature: Path,
    identity_report: Path,
    output_evidence: Path,
    output_config: Path,
    cosign: str,
) -> tuple[dict[str, object], dict[str, object]]:
    root = root.resolve()
    candidate_config = final_gate.read_object(safe_file(root, candidate_config_path))
    problems = prerelease.failures(candidate_config, root=root)
    if problems:
        raise ValueError("candidate evidence is not ready: " + "; ".join(problems))
    evidence_path = root / str(candidate_config["evidence_manifest"])
    candidate_evidence = final_gate.read_object(safe_file(root, evidence_path))
    source_release_sha = candidate_evidence.get("release_sha")
    source_tree_sha256 = candidate_evidence.get("source_tree_sha256")
    if not isinstance(source_release_sha, str) or not final_gate.lower_hex(
        source_tree_sha256, 64
    ):
        raise ValueError("candidate source identity is malformed")
    release_tree_sha256, evidence_delta_paths = (
        source_tree_identity.verify_evidence_only_transition(
            root,
            source_release_sha,
            release_sha,
            source_tree_sha256,
        )
    )

    sbom = safe_file(root, sbom)
    checksums = safe_file(root, checksums)
    signature = safe_file(root, signature)
    identity_report = safe_file(root, identity_report)
    verify_spdx_sbom(sbom)
    checksum_entries = verify_checksum_manifest(
        checksums, sbom, REQUIRED_CHECKSUM_ENTRIES
    )
    identity_metadata = {
        "identities": {
            "engine_cli": release_sha,
            "engine_oci": release_sha,
        }
    }
    identity_failures = final_gate.validate_identity_evidence(
        [(identity_report, {"role": "identity_report"})],
        identity_metadata,
        release_sha,
    )
    identity_failures.extend(
        final_gate.validate_identity_checksum_binding(identity_report, checksums)
    )
    if identity_failures:
        raise ValueError(
            "engine identity evidence is invalid: " + "; ".join(identity_failures)
        )
    verification_command = [
        cosign,
        "verify-blob",
        "--bundle",
        str(signature),
        "--certificate-identity-regexp",
        SIGSTORE_IDENTITY_REGEXP,
        "--certificate-oidc-issuer",
        SIGSTORE_ISSUER,
        str(checksums),
    ]
    verified = final_gate.evidence_runtime.run_anchored_cosign(
        root,
        release_sha,
        cosign,
        verification_command[1:],
    )
    if verified.returncode != 0:
        raise ValueError(f"Sigstore verification failed: {verified.stdout[-2000:]}")

    evidence = json.loads(json.dumps(candidate_evidence))
    evidence["status"] = "ready"
    evidence["source_release_sha"] = source_release_sha
    evidence["release_sha"] = release_sha
    gates = evidence["gates"]
    gates[prerelease.IDENTITY_GATE] = {
        "kind": final_gate.EXPECTED_KINDS[prerelease.IDENTITY_GATE],
        "metadata": identity_metadata,
        "artifacts": [
            {
                "role": "identity_report",
                "path": relative_path(root, identity_report),
                "sha256": sha256(identity_report),
            }
        ],
    }
    gates[prerelease.SIGNED_GATE] = {
        "kind": "signed_release",
        "metadata": {
            "release_sha": release_sha,
            "source_release_sha": source_release_sha,
            "source_tree_sha256": source_tree_sha256,
            "release_tree_sha256": release_tree_sha256,
            "evidence_only_delta_verified": True,
            "evidence_delta_paths": evidence_delta_paths,
            "signatures_verified": True,
            "signer_identity_regexp": SIGSTORE_IDENTITY_REGEXP,
            "signer_oidc_issuer": SIGSTORE_ISSUER,
            "verification_command": verification_command,
            "checksum_entries": checksum_entries,
        },
        "artifacts": [
            {
                "role": "sbom",
                "path": relative_path(root, sbom),
                "sha256": sha256(sbom),
            },
            {
                "role": "checksums",
                "path": relative_path(root, checksums),
                "sha256": sha256(checksums),
            },
            {
                "role": "signature",
                "path": relative_path(root, signature),
                "sha256": sha256(signature),
            },
        ],
    }
    output_evidence = output_evidence.resolve()
    output_config = output_config.resolve()
    if not output_evidence.is_relative_to(root) or not output_config.is_relative_to(root):
        raise ValueError("final evidence outputs must remain inside the repository")
    if output_evidence == output_config:
        raise ValueError("final evidence and config outputs must differ")
    config = {
        "schema_version": 2,
        "release": candidate_config.get("release", "tinyzkp-plonky3-backend-v1"),
        "status": "ready",
        "evidence_manifest": output_evidence.relative_to(root).as_posix(),
        "policy": "Final gate includes cryptographically verified signed release artifacts.",
    }
    final_problems = final_gate.evidence_failures(evidence, root=root)
    if final_problems:
        raise ValueError(
            "constructed final evidence failed validation: "
            + "; ".join(final_problems)
        )
    staged_evidence = output_evidence.with_name(
        f".{output_evidence.name}.validation-{os.getpid()}.json"
    )
    staged_config = output_config.with_name(
        f".{output_config.name}.validation-{os.getpid()}.json"
    )
    try:
        write_json_atomic(staged_evidence, evidence)
        write_json_atomic(staged_config, config)
        os.replace(staged_evidence, output_evidence)
        os.replace(staged_config, output_config)
    except Exception:
        staged_evidence.unlink(missing_ok=True)
        staged_config.unlink(missing_ok=True)
        raise
    return evidence, config


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-config", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--identity-report", type=Path, required=True)
    parser.add_argument("--output-evidence", type=Path, required=True)
    parser.add_argument("--output-config", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args(argv)
    try:
        finalize(
            root=ROOT,
            candidate_config_path=args.candidate_config,
            release_sha=args.release_sha,
            sbom=args.sbom,
            checksums=args.checksums,
            signature=args.signature,
            identity_report=args.identity_report,
            output_evidence=args.output_evidence,
            output_config=args.output_config,
            cosign=args.cosign,
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"signed evidence finalization failed: {error}", file=sys.stderr)
        return 2
    print(f"PASS  signed backend evidence finalized for {args.release_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
