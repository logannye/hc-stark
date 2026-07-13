#!/usr/bin/env python3
"""Derive public-beta readiness from hash-bound first-party evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CHANNELS = ROOT / "release" / "release-channels-v1.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PASSING_STATUSES = {
    "passed",
    "ready",
    "clean",
    "complete",
    "completed",
    "local_matrix_complete_external_gates_pending",
}
FORBIDDEN_EVIDENCE = (b"sk_live_", b"sk_test_", b"whsec_", b"X-Amz-Signature=", b"__Host-tinyzkp_beta=")
FORBIDDEN_JSON_KEYS = {
    "api_key",
    "authorization",
    "checkout_url",
    "cookie",
    "password",
    "portal_url",
    "presigned_url",
    "secret",
    "session_cookie",
    "webhook_secret",
}
REQUIRED_VERIFIER_MODES = {"memory", "scratch", "uninterrupted", "resumed"}
REQUIRED_WORKLOADS = {"fibonacci", "poseidon2", "customer_cubic8"}
REQUIRED_FUZZ_TARGETS = {
    "air_json",
    "expression_compilation",
    "trace_manifest",
    "zstandard_decoding",
    "hosted_bundle",
    "api_request",
}
REQUIRED_FAULT_OUTCOMES = {
    "durable_boundary_crash": "completed_verified",
    "sigkill": "completed_verified",
    "lease_expiry": "released_without_charge",
    "disk_full": "released_without_charge",
    "valid_checkpoint_recovery": "completed_verified",
    "corrupt_checkpoint": "released_without_charge",
    "corrupt_r2_chunk": "released_without_charge",
    "cancellation_heartbeat": "released_without_charge",
    "cancellation_durable_boundary": "released_without_charge",
    "stale_worker_completion": "stale_rejected",
    "estimate_overflow": "released_without_charge",
    "abandoned_scratch_cleanup": "released_without_charge",
    "path_traversal": "released_without_charge",
    "symlink": "released_without_charge",
    "cancellation_retention": "released_without_charge",
    "sigterm_resume": "completed_verified",
}
REQUIRED_SECURITY_TOPICS = {
    "oauth",
    "sessions",
    "api_keys",
    "tenant_isolation",
    "r2_signing",
    "decompression",
    "ssrf",
    "lease_replay",
    "stripe_spoofing",
    "refunds",
    "secrets",
    "account_deletion",
    "activation_rollback",
}
REQUIRED_IDENTITIES = {
    "api",
    "worker",
    "mcp",
    "site",
    "cli",
    "sdk_rust",
    "sdk_python",
    "sdk_typescript",
    "container_api",
    "container_worker",
    "container_postgres",
    "bundle",
    "evidence",
}
REQUIRED_SUPPLY_CHAIN_ARTIFACTS = {
    "api",
    "worker",
    "cli",
    "sdk_rust",
    "sdk_python",
    "sdk_typescript",
    "container_api",
    "container_worker",
    "container_postgres",
}


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load evidence validator: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def json_records(paths: list[Path]) -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        if path.suffix != ".json" or path.stat().st_size > 32 * 1024 * 1024:
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError):
            continue
        if isinstance(value, dict):
            records.append((path, value))
    return records


def exact_record(
    records: list[tuple[Path, dict[str, Any]]],
    schema: str,
    release_sha: str,
) -> tuple[Path, dict[str, Any]]:
    matches = [
        (path, value)
        for path, value in records
        if value.get("schema_version") == schema
        and value.get("release_sha") == release_sha
        and value.get("status") in PASSING_STATUSES
    ]
    if len(matches) != 1:
        raise ValueError(f"requires exactly one passing {schema} record")
    return matches[0]


def reject_secret_like_json(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_JSON_KEYS or normalized.endswith("_secret"):
                raise ValueError(f"secret-like evidence field is forbidden: {location}.{key}")
            reject_secret_like_json(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_like_json(child, f"{location}[{index}]")
    elif isinstance(value, str):
        if value.startswith(("Bearer ", "sk_test_", "sk_live_", "whsec_")) or (
            value.startswith(("http://", "https://")) and "?" in value
        ):
            raise ValueError(f"secret-like evidence value is forbidden: {location}")


def validate_clean_merged_ci(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, value = exact_record(records, "public-beta-clean-ci-v1", release_sha)
    if (
        value.get("branch") != "main"
        or value.get("source_clean") is not True
        or value.get("merged_source") is not True
        or value.get("candidate_workflow_conclusion") != "success"
        or not isinstance(value.get("candidate_workflow_run_id"), int)
        or value["candidate_workflow_run_id"] <= 0
    ):
        raise ValueError("merged main, clean source, or candidate workflow is not proven")
    checks = value.get("required_checks")
    if (
        not isinstance(checks, list)
        or len(checks) < 4
        or len({item.get("name") for item in checks if isinstance(item, dict)})
        != len(checks)
        or any(
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or item.get("status") not in {"passed", "success"}
            for item in checks
        )
    ):
        raise ValueError("required merged-main checks are incomplete or not successful")


def validate_verifier_equivalence(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, value = exact_record(
        records, "public-beta-verifier-equivalence-v1", release_sha
    )
    workloads = value.get("workloads")
    if not isinstance(workloads, dict) or set(workloads) != REQUIRED_WORKLOADS:
        raise ValueError("verifier equivalence workload set is incomplete")
    for workload, result in workloads.items():
        if not isinstance(result, dict) or result.get("official_verification") is not True:
            raise ValueError(f"{workload}: official verification did not pass")
        digests = result.get("proof_sha256_by_mode")
        if not isinstance(digests, dict) or set(digests) != REQUIRED_VERIFIER_MODES:
            raise ValueError(f"{workload}: proof mode set is incomplete")
        values = list(digests.values())
        if (
            any(not isinstance(item, str) or not SHA256.fullmatch(item) for item in values)
            or len(set(values)) != 1
        ):
            raise ValueError(f"{workload}: official proof bytes differ across modes")


def validate_fixed_host(
    gate_id: str,
    records: list[tuple[Path, dict[str, Any]]],
    release_sha: str,
    root: Path,
) -> None:
    matrix_matches = [
        (path, value)
        for path, value in records
        if value.get("kind") == "tinyzkp_fixed_host_release_matrix_v1"
        and value.get("release_sha") == release_sha
        and value.get("status") in PASSING_STATUSES
    ]
    if len(matrix_matches) != 1:
        raise ValueError("requires exactly one passing fixed-host release matrix")
    matrix_path, matrix_value = matrix_matches[0]
    if (
        matrix_value.get("fixed_host_evidence_eligible") is not True
        or matrix_value.get("local_matrix_gates_passed") is not True
        or matrix_value.get("release_eligible") is not False
    ):
        raise ValueError("fixed-host matrix eligibility or authority contract is invalid")
    matrix_module = load_module(
        "public_beta_fixed_host_matrix_gate",
        root / "scripts" / "benchmark" / "run_fixed_host_release_matrix.py",
    )
    wanted = (
        {"fibonacci_1m", "poseidon2_1m"}
        if gate_id == "fixed_host_1m"
        else {"fibonacci_16m", "poseidon2_16m"}
    )
    entries = matrix_value.get("entries")
    if not isinstance(entries, list):
        raise ValueError("fixed-host matrix entries are missing")
    by_id = {
        item.get("entry_id"): item for item in entries if isinstance(item, dict)
    }
    if not wanted.issubset(by_id) or any(
        by_id[entry_id].get("status") != "complete" for entry_id in wanted
    ):
        raise ValueError(f"{gate_id}: required matrix entries are incomplete")
    matrix_entries = {entry.entry_id: entry for entry in matrix_module.MATRIX}
    for entry_id in sorted(wanted):
        artifacts = by_id[entry_id].get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError(f"{entry_id}: artifact inventory is empty")
        for descriptor in artifacts:
            matrix_module.verify_artifact_descriptor(
                descriptor, matrix_path.parent, os.geteuid()
            )
        matrix_module.validate_entry_gate(
            matrix_entries[entry_id], matrix_path.parent, release_sha
        )

    customer_path, customer = exact_record(
        records, "customer-cubic8-fixed-host-matrix-v1", release_sha
    )
    if customer.get("local_matrix_gates_passed") is not True:
        raise ValueError("customer_cubic8 fixed-host matrix did not pass")
    report_names = customer.get("reports")
    if not isinstance(report_names, dict) or set(report_names) != {
        "reference_1m",
        "bounded_1m",
        "bounded_16m",
    }:
        raise ValueError("customer_cubic8 report inventory is incomplete")
    customer_validator = load_module(
        "public_beta_customer_cubic8_gate",
        root / "scripts" / "benchmark" / "validate_customer_cubic8.py",
    )
    loaded: dict[str, dict[str, Any]] = {}
    for role, descriptor in report_names.items():
        if not isinstance(descriptor, dict) or set(descriptor) != {
            "path",
            "sha256",
        }:
            raise ValueError(f"customer_cubic8 {role} descriptor is malformed")
        path = (customer_path.parent / str(descriptor["path"])).resolve()
        path.relative_to(customer_path.parent.resolve())
        if not path.is_file() or file_sha256(path) != descriptor["sha256"]:
            raise ValueError(f"customer_cubic8 {role} digest mismatch")
        details = path.stat()
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
            raise ValueError(
                f"customer_cubic8 {role} is not operator-owned and mode 0600"
            )
        loaded[role] = customer_validator.load(path)
    customer_validator.validate(
        loaded["reference_1m"], loaded["bounded_1m"], loaded["bounded_16m"]
    )


def validate_fault_and_fuzz(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, root: Path
) -> None:
    race_module = load_module(
        "public_beta_race_gate", root / "scripts" / "load" / "run_public_beta_races.py"
    )
    race_matches = [
        value
        for _, value in records
        if value.get("schema_version") == race_module.SCHEMA
    ]
    if len(race_matches) != 1:
        raise ValueError("requires exactly one PostgreSQL race record")
    race_module.validate_evidence(race_matches[0], release_sha)

    _, fault = exact_record(records, "public-beta-hosted-fault-matrix-v1", release_sha)
    cases = fault.get("cases")
    validate_fault_cases(cases)
    _, fuzz = exact_record(records, "public-beta-fuzz-evidence-v1", release_sha)
    targets = fuzz.get("targets")
    if (
        not isinstance(targets, list)
        or {item.get("id") for item in targets if isinstance(item, dict)}
        != REQUIRED_FUZZ_TARGETS
    ):
        raise ValueError("release fuzz target set is incomplete")
    for item in targets:
        target_id = item.get("id") if isinstance(item, dict) else "malformed"
        if (
            not isinstance(item, dict)
            or item.get("status") != "passed"
            or int(item.get("duration_seconds", 0)) < 1800
            or int(item.get("memory_limit_bytes", 0)) > 2 * 1024**3
            or any(int(item.get(field, 1)) != 0 for field in ("crashes", "hangs", "sanitizer_findings"))
        ):
            raise ValueError(f"{target_id}: fuzz qualification is incomplete")


def validate_fault_cases(cases: object) -> None:
    if (
        not isinstance(cases, list)
        or {item.get("id") for item in cases if isinstance(item, dict)}
        != set(REQUIRED_FAULT_OUTCOMES)
    ):
        raise ValueError("hosted fault case set is incomplete")
    for item in cases:
        if not isinstance(item, dict) or item.get("status") != "passed":
            raise ValueError("hosted fault matrix contains a failed case")
        case_id = str(item.get("id"))
        expected = REQUIRED_FAULT_OUTCOMES[case_id]
        if item.get("outcome") != expected:
            raise ValueError(f"{case_id}: fault outcome does not match the contract")
        if expected == "completed_verified":
            if (
                item.get("official_verification") is not True
                or item.get("settlement_count") != 1
                or int(item.get("charged_millicredits", 0)) <= 0
                or item.get("residual_reservation_released") is not True
            ):
                raise ValueError(f"{case_id}: recovered proof was not verified and settled once")
        elif (
            item.get("charged_millicredits", 0) != 0
            or item.get("reservation_released") is not True
        ):
            raise ValueError(f"{case_id}: rejected or failed work retained a charge")
        if expected == "stale_rejected" and item.get("stale_completion_rejected") is not True:
            raise ValueError("stale_worker_completion: stale attempt was not rejected")


def validate_internal_security(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, security = exact_record(records, "public-beta-security-review-v1", release_sha)
    if (
        security.get("reviewer") != "Logan Nye"
        or security.get("unresolved_critical") != 0
        or security.get("unresolved_high") != 0
    ):
        raise ValueError("security review identity or high-severity closure is incomplete")
    topics = security.get("topics")
    if not isinstance(topics, list) or not REQUIRED_SECURITY_TOPICS.issubset(topics):
        raise ValueError("security threat-model topic set is incomplete")
    findings = security.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(item, dict)
        or (
            item.get("severity") in {"critical", "high"}
            and item.get("status") not in {"resolved", "accepted"}
        )
        for item in findings
    ):
        raise ValueError("security review contains unresolved critical/high findings")


def validate_sdk_vectors(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, sdk = exact_record(records, "public-beta-sdk-golden-vectors-v1", release_sha)
    vectors = sdk.get("vectors")
    if not isinstance(vectors, list) or {
        item.get("id") for item in vectors if isinstance(item, dict)
    } != {"maximum_width", "maximum_goldilocks"}:
        raise ValueError("required SDK golden vectors are incomplete")
    for vector in vectors:
        digests = vector.get("sha256_by_language") if isinstance(vector, dict) else None
        vector_id = vector.get("id") if isinstance(vector, dict) else "malformed"
        if not isinstance(digests, dict) or set(digests) != {
            "rust",
            "python",
            "typescript",
        }:
            raise ValueError("SDK vector language set is incomplete")
        if any(not SHA256.fullmatch(str(item)) for item in digests.values()) or len(
            set(digests.values())
        ) != 1:
            raise ValueError(f"{vector_id}: cross-language bytes differ")


def validate_supply_chain(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, supply = exact_record(records, "public-beta-supply-chain-v1", release_sha)
    if any(
        supply.get(key) is not True
        for key in (
            "artifacts_signed",
            "sbom_complete",
            "provenance_verified",
            "checksums_signature_verified",
        )
    ):
        raise ValueError("supply-chain summary is incomplete")
    artifacts = supply.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != REQUIRED_SUPPLY_CHAIN_ARTIFACTS:
        raise ValueError("signed supply-chain artifact set is incomplete")
    for name, item in artifacts.items():
        if (
            not isinstance(item, dict)
            or item.get("release_sha") != release_sha
            or not SHA256.fullmatch(str(item.get("sha256")))
            or any(
                item.get(field) is not True
                for field in ("signature_verified", "sbom_verified", "provenance_verified")
            )
        ):
            raise ValueError(f"{name}: supply-chain verification is incomplete")


def validate_release_identity(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, _root: Path
) -> None:
    _, identity = exact_record(records, "public-beta-release-identity-v1", release_sha)
    identities = identity.get("identities")
    if not isinstance(identities, dict) or set(identities) != REQUIRED_IDENTITIES:
        raise ValueError("release identity surface set is incomplete")
    if any(item != release_sha for item in identities.values()):
        raise ValueError("published release identities differ from the candidate")


def validate_recovery_and_billing(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, root: Path
) -> None:
    stripe_module = load_module(
        "public_beta_stripe_drill_gate", root / "billing" / "public_beta_stripe_drill.py"
    )
    stripe_records = [
        value for _, value in records if value.get("schema_version") == stripe_module.SCHEMA
    ]
    if len(stripe_records) != 1:
        raise ValueError("requires exactly one Stripe sandbox drill record")
    stripe_module.validate_evidence(stripe_records[0], release_sha)
    _, restore = exact_record(records, "public-beta-restore-evidence-v1", release_sha)
    if any(
        restore.get(key) is not True
        for key in (
            "encrypted_backup",
            "wal_replay",
            "api_key_authentication",
            "queued_job_recovery",
            "bundle_download",
            "official_verification",
            "ledger_reconstruction",
            "stripe_replay",
        )
    ) or restore.get("ledger_differences") != 0 or restore.get("stripe_differences") != 0:
        raise ValueError("restore, replay, or immutable-ledger evidence is incomplete")


def validate_advertised_load(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, root: Path
) -> None:
    load_module_value = load_module(
        "public_beta_load_gate", root / "scripts" / "load" / "run_public_beta_load.py"
    )
    matches = [
        value
        for _, value in records
        if value.get("schema_version") == 2 and value.get("concurrency") == 4
    ]
    if len(matches) != 1:
        raise ValueError("requires exactly one four-job load record")
    load_module_value.validate_evidence(matches[0], release_sha)


def validate_production_canary(
    records: list[tuple[Path, dict[str, Any]]], release_sha: str, root: Path
) -> None:
    canary_module = load_module(
        "public_beta_canary_gate",
        root / "scripts" / "ci" / "validate_public_beta_canary.py",
    )
    matches = [
        value
        for _, value in records
        if value.get("release_channel") == "public_beta"
        and "hourly_verified_proofs" in value
    ]
    if len(matches) != 1:
        raise ValueError("requires exactly one 24-hour canary record")
    problems = canary_module.validate(matches[0], release_sha)
    if problems:
        raise ValueError("; ".join(problems))


GATE_VALIDATORS = {
    "clean_merged_ci": validate_clean_merged_ci,
    "official_verifier_equivalence": validate_verifier_equivalence,
    "fault_and_fuzz": validate_fault_and_fuzz,
    "internal_security": validate_internal_security,
    "sdk_golden_vectors": validate_sdk_vectors,
    "signed_supply_chain": validate_supply_chain,
    "release_identity": validate_release_identity,
    "recovery_and_billing_replay": validate_recovery_and_billing,
    "advertised_concurrency_load": validate_advertised_load,
    "production_canary_24h": validate_production_canary,
}


def validate_gate_semantics(
    gate_id: str, paths: list[Path], release_sha: str, root: Path
) -> list[str]:
    failures: list[str] = []
    records = json_records(paths)
    try:
        for _, value in records:
            reject_secret_like_json(value)
    except ValueError as error:
        return [f"{gate_id}: {error}"]
    identity_records = [
        value for _, value in records
        if value.get("release_sha") == release_sha and value.get("status") in PASSING_STATUSES
    ]
    if not identity_records:
        failures.append(f"{gate_id}: no passing exact-release semantic record")
        return failures
    try:
        if gate_id in {"fixed_host_1m", "fixed_host_16m"}:
            validate_fixed_host(gate_id, records, release_sha, root)
        else:
            validator = GATE_VALIDATORS.get(gate_id)
            if validator is None:
                raise ValueError("no dedicated semantic validator is registered")
            validator(records, release_sha, root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        failures.append(f"{gate_id}: {error}")
    return failures


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def current_sha(root: Path = ROOT) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def audit(evidence_path: Path, root: Path = ROOT, expected_sha: str | None = None) -> dict[str, Any]:
    channels = json.loads((root / "release" / "release-channels-v1.json").read_text())
    required = channels["channels"]["public_beta"]["required_gate_ids"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    release_sha = evidence.get("release_sha")
    if evidence.get("schema_version") != 1 or evidence.get("release_channel") != "public_beta":
        failures.append("evidence schema/channel mismatch")
    if not isinstance(release_sha, str) or not GIT_SHA.fullmatch(release_sha):
        failures.append("release_sha must be a full lowercase Git SHA")
    if expected_sha is not None and release_sha != expected_sha:
        failures.append("evidence release_sha does not match candidate")
    gates = evidence.get("gates", {})
    if set(gates) != set(required):
        failures.append("evidence gate set differs from public-beta policy")
    verified: dict[str, list[dict[str, str]]] = {}
    for gate_id in required:
        artifacts = gates.get(gate_id, [])
        if not isinstance(artifacts, list) or not artifacts:
            failures.append(f"{gate_id}: missing evidence")
            continue
        verified[gate_id] = []
        verified_paths: list[Path] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
                failures.append(f"{gate_id}: malformed artifact reference")
                continue
            relative = Path(str(artifact["path"]))
            digest = str(artifact["sha256"])
            path = (root / relative).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError:
                failures.append(f"{gate_id}: artifact escapes repository")
                continue
            if not SHA256.fullmatch(digest) or not path.is_file():
                failures.append(f"{gate_id}: missing artifact or invalid SHA-256")
                continue
            details = path.stat()
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
                failures.append(f"{gate_id}: artifact is not operator-owned and owner-only")
                continue
            raw = path.read_bytes()
            if any(marker in raw for marker in FORBIDDEN_EVIDENCE):
                failures.append(f"{gate_id}: artifact contains a secret or bearer URL")
                continue
            actual = file_sha256(path)
            if actual != digest:
                failures.append(f"{gate_id}: artifact digest mismatch")
                continue
            verified[gate_id].append({"path": relative.as_posix(), "sha256": actual})
            verified_paths.append(path)
        if verified_paths:
            failures.extend(validate_gate_semantics(gate_id, verified_paths, str(release_sha), root))
    status = "ready" if not failures else "blocked"
    report = {
        "schema_version": 1,
        "release_channel": "public_beta",
        "status": status,
        "release_sha": release_sha,
        "evidence_manifest_sha256": hashlib.sha256(canonical_json(evidence)).hexdigest(),
        "verified_gates": verified,
        "failures": failures,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--release-sha", default=current_sha())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.evidence, expected_sha=args.release_sha)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    raise SystemExit(0 if report["status"] == "ready" else 1)


if __name__ == "__main__":
    main()
