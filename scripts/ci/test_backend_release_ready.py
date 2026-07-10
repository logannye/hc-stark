import hashlib
import json
import os

import backend_release_ready as gate


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_missing_evidence_keeps_release_blocked(tmp_path):
    problems = gate.failures(
        {
            "schema_version": 2,
            "status": "blocked",
            "evidence_manifest": "release/evidence/backend-v1-evidence.json",
        },
        root=tmp_path,
    )
    assert any("evidence manifest is unavailable" in problem for problem in problems)


def test_hashed_artifact_rejects_symlinked_path_component(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    artifact = actual / "report.json"
    digest = write_json(artifact, {"status": "pass"})
    os.symlink(actual, tmp_path / "linked")
    try:
        gate.safe_artifact(
            tmp_path,
            {"path": "linked/report.json", "sha256": digest},
        )
    except ValueError as error:
        assert "missing or unsafe" in str(error)
    else:
        raise AssertionError("symlinked evidence path was accepted")


def test_signed_release_metadata_is_bound_to_release(tmp_path):
    artifacts = []
    for role in ("sbom", "checksums", "signature"):
        path = tmp_path / role
        path.write_text(role, encoding="utf-8")
        artifacts.append(
            {
                "role": role,
                "path": role,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    failures = gate.validate_gate(
        "signed_release_sbom_and_checksums",
        {
            "kind": "signed_release",
            "metadata": {
                "release_sha": "different",
                "signatures_verified": True,
                "verification_command": [
                    "cosign",
                    "verify-blob",
                    "--bundle",
                    "signature",
                    "--certificate-identity-regexp",
                    gate.SIGSTORE_IDENTITY_REGEXP,
                    "--certificate-oidc-issuer",
                    gate.SIGSTORE_ISSUER,
                    "checksums",
                ],
                "signer_identity_regexp": gate.SIGSTORE_IDENTITY_REGEXP,
                "signer_oidc_issuer": gate.SIGSTORE_ISSUER,
                "checksum_entries": 9,
            },
            "artifacts": artifacts,
        },
        root=tmp_path,
        release_sha="abc",
    )
    assert failures == [
        "signed_release_sbom_and_checksums: signed SBOM/checksum evidence is incomplete"
    ]


def test_identity_gate_requires_typed_report_and_matching_metadata(tmp_path):
    report = tmp_path / "identity.json"
    identities = {name: "abc" for name in ("api", "mcp", "site", "cli")}
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "checked_at": "2026-01-01T00:00:00Z",
            "surfaces": {
                name: {
                    "service": name,
                    "release_sha": "abc",
                    "package_version": "0.1.0",
                    **(
                        {"artifact": "release-artifacts/cli-release.json"}
                        if name == "cli"
                        else {
                            "url": {
                                "site": "https://tinyzkp.com/api/release",
                                "api": "https://api.tinyzkp.com/version",
                                "mcp": "https://mcp.tinyzkp.com/version",
                            }[name]
                        }
                    ),
                }
                for name in identities
            },
        },
    )
    artifacts = [(report, {"role": "identity_report"})]
    assert gate.validate_identity_evidence(
        artifacts, {"identities": identities}, "abc"
    ) == []

    skewed = identities.copy()
    skewed["cli"] = "old"
    assert gate.validate_identity_evidence(
        artifacts, {"identities": skewed}, "abc"
    ) == ["release identity metadata does not match the machine report"]


def test_evidenced_command_binds_release_command_profile_and_log(tmp_path):
    log = tmp_path / "test.log"
    log.write_text("all tests passed\n", encoding="utf-8")
    command = ["cargo", "test", "--release", "--locked"]
    report = tmp_path / "test-report.json"
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "execution_profile": "release",
            "command": command,
            "exit_status": 0,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "duration_ms": 1000,
            "log_bytes": len(log.read_bytes()),
            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        },
    )
    artifacts = [
        (report, {"role": "test_report"}),
        (log, {"role": "test_log"}),
    ]
    metadata = {
        "release_sha": "abc",
        "execution_profile": "release",
        "command": command,
        "exit_status": 0,
    }
    assert gate.validate_test_run_evidence(
        artifacts, metadata, "abc", require_release_profile=True
    ) == []
    log.write_text("mutated", encoding="utf-8")
    assert gate.validate_test_run_evidence(
        artifacts, metadata, "abc", require_release_profile=True
    ) == ["evidenced command report is incomplete or release-skewed"]


def test_review_risk_acceptance_cannot_waive_a_high_finding(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("independent review", encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    metadata = {
        "reviewer": "independent reviewer",
        "completed_at": "2026-01-01T00:00:00Z",
        "review_scope": "implementation",
    }
    write_json(
        ledger,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "review_scope": "implementation",
            "completed_at": metadata["completed_at"],
            "reviewer": metadata["reviewer"],
            "reviewer_independent": True,
            "review_report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "findings": [
                {
                    "id": "HIGH-1",
                    "severity": "high",
                    "status": "accepted_by_reviewer",
                    "reviewer_verified": True,
                }
            ],
        },
    )
    assert gate.validate_review(
        metadata,
        [
            (report, {"role": "review_report"}),
            (ledger, {"role": "remediation_ledger"}),
        ],
        "abc",
        "implementation",
    ) == ["critical/high review finding remains unresolved"]


def test_manual_passed_boolean_and_unresolved_high_finding_fail(tmp_path):
    report = tmp_path / "review.json"
    digest = write_json(report, {"report": "review"})
    gates = {}
    for name, kind in gate.EXPECTED_KINDS.items():
        metadata = {"exit_status": 0, "command": ["test"], "release_sha": "abc"}
        artifacts = [{"path": "review.json", "sha256": digest}]
        if kind == "review":
            scope = (
                "plonky3_specialist"
                if name == "plonky3_specialist_review"
                else "implementation"
            )
            metadata = {
                "reviewer": "independent reviewer",
                "completed_at": "2026-01-01T00:00:00Z",
                "review_scope": scope,
            }
            ledger = tmp_path / f"{scope}-ledger.json"
            ledger_digest = write_json(
                ledger,
                {
                    "schema_version": 1,
                    "release_sha": "abc",
                    "profile": "tinyzkp-p3-goldilocks-v1",
                    "review_scope": scope,
                    "completed_at": metadata["completed_at"],
                    "reviewer": metadata["reviewer"],
                    "reviewer_independent": True,
                    "review_report_sha256": digest,
                    "findings": [
                        {
                            "id": "HIGH-1",
                            "severity": "high",
                            "status": "open",
                            "reviewer_verified": False,
                        }
                    ],
                },
            )
            artifacts = [
                {"role": "review_report", "path": "review.json", "sha256": digest},
                {
                    "role": "remediation_ledger",
                    "path": ledger.name,
                    "sha256": ledger_digest,
                },
            ]
        gates[name] = {
            "kind": kind,
            "passed": True,
            "metadata": metadata,
            "artifacts": artifacts,
        }
    evidence = {
        "schema_version": 1,
        "status": "ready",
        "release_sha": "abc",
        "gates": gates,
    }
    evidence_path = tmp_path / "evidence.json"
    write_json(evidence_path, evidence)
    problems = gate.failures(
        {"schema_version": 2, "status": "ready", "evidence_manifest": "evidence.json"},
        root=tmp_path,
    )
    assert any("manual passed booleans are forbidden" in problem for problem in problems)
    assert any("critical/high review finding remains unresolved" in problem for problem in problems)


def test_resource_gate_requires_hashed_normalized_manifest_artifacts(tmp_path):
    manifest = tmp_path / "manifest.json"
    candidate = tmp_path / "candidate.json"
    write_json(manifest, {"workload_id": "fibonacci"})
    write_json(candidate, {})
    failures = gate.validate_resource_gate(
        "resource_one_million",
        [
            (manifest, {"role": "fibonacci_manifest"}),
            (candidate, {"role": "fibonacci_candidate_report"}),
        ],
        "abc",
    )
    assert any("candidate_normalized_manifest" in failure for failure in failures)


def test_independent_reproduction_requires_typed_record(tmp_path):
    record = tmp_path / "reproduction.json"
    write_json(record, {"schema_version": 1, "independent": False})
    failures = gate.validate_independent_reproduction(
        [(record, {"role": "reproduction_record"})],
        {
            "reproducer": "review lab",
            "organization": "independent org",
            "completed_at": "2026-01-01T00:00:00Z",
        },
        "abc",
    )
    assert "independent reproduction record is incomplete or release-skewed" in failures
    assert "one_million: fibonacci fixed-host evidence is missing" in failures
    assert "ten_million: poseidon2 fixed-host evidence is missing" in failures


def test_crash_matrix_requires_every_phase_disk_full_and_release_identity(tmp_path):
    cases = [
        {
            "case": f"checkpoint_{phase}",
            "command": ["cargo", "test"],
            "exit_status": 0,
            "log_sha256": "a" * 64,
        }
        for phase in gate.CRASH_PHASES
    ]
    cases.extend(
        {
            "case": name,
            "command": ["cargo", "test"],
            "exit_status": 0,
            "log_sha256": "b" * 64,
        }
        for name in gate.CRASH_INTEGRITY_CASES
        if name != "disk_full_resume"
    )
    report = tmp_path / "crash.json"
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "build_profile": "release",
            "complete_for_release": True,
            "cases": cases,
        },
    )
    failures = gate.validate_crash_matrix(
        [(report, {"role": "crash_matrix"})], "abc"
    )
    assert failures == ["required crash matrix case is missing: disk_full_resume"]

    cases.append(
        {
            "case": "disk_full_resume",
            "command": ["cargo", "test"],
            "exit_status": 0,
            "log_sha256": "c" * 64,
        }
    )
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "build_profile": "release",
            "complete_for_release": True,
            "cases": cases,
        },
    )
    assert gate.validate_crash_matrix(
        [(report, {"role": "crash_matrix"})], "abc"
    ) == []


def fuzz_target(name):
    return {
        "target": name,
        "command": [
            "cargo",
            "+nightly",
            "fuzz",
            "run",
            name,
            f"/private/execution-corpus/{name}",
            f"/private/smoke-corpus/{name}",
            "--",
            "-max_total_time=30",
            "-rss_limit_mb=2048",
            "-timeout=30",
            f"-artifact_prefix=/private/artifacts/{name}/",
            "-print_final_stats=1",
        ],
        "exit_status": 0,
        "duration_ms": 1000,
        "log_bytes": 100,
        "smoke_seed_count": gate.FUZZ_SMOKE_SEED_LIMIT,
        "smoke_corpus_sha256": "a" * 64,
        "log_sha256": "b" * 64,
        "artifacts": [],
    }


def test_fuzz_smoke_requires_every_bounded_reproducible_target(tmp_path):
    report = tmp_path / "fuzz.json"
    targets = [fuzz_target(name) for name in sorted(gate.FUZZ_TARGETS)]
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "toolchain": "nightly",
            "rustc_version": "rustc nightly\ncommit-hash: abc\nrelease: nightly",
            "cargo_fuzz_version": "cargo-fuzz 0.13.2",
            "all_targets_passed": True,
            "targets": targets,
        },
    )
    artifacts = [(report, {"role": "fuzz_smoke"})]
    assert gate.validate_fuzz_smoke(artifacts, "abc") == []

    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "toolchain": "nightly",
            "rustc_version": "rustc nightly\ncommit-hash: abc\nrelease: nightly",
            "cargo_fuzz_version": "cargo-fuzz 0.13.2",
            "all_targets_passed": True,
            "targets": targets[:-1],
        },
    )
    assert gate.validate_fuzz_smoke(artifacts, "abc") == [
        f"required fuzz smoke target is missing: {targets[-1]['target']}"
    ]


def test_fuzz_smoke_rejects_unbounded_or_noncanonical_evidence(tmp_path):
    report = tmp_path / "fuzz.json"
    targets = [fuzz_target(name) for name in sorted(gate.FUZZ_TARGETS)]
    targets[0]["smoke_seed_count"] = gate.FUZZ_SMOKE_SEED_LIMIT + 1
    targets[1]["smoke_corpus_sha256"] = "A" * 64
    targets[2]["command"][6] = 42
    targets[3]["duration_ms"] = True
    targets.append(fuzz_target("unknown_target"))
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "toolchain": "nightly",
            "rustc_version": "rustc nightly\ncommit-hash: abc\nrelease: nightly",
            "cargo_fuzz_version": "cargo-fuzz 0.13.2",
            "all_targets_passed": True,
            "targets": targets,
        },
    )
    failures = gate.validate_fuzz_smoke(
        [(report, {"role": "fuzz_smoke"})], "abc"
    )
    assert any("did not pass reproducibly" in failure for failure in failures)
    assert "unknown fuzz smoke target: unknown_target" in failures


def test_partner_evidence_requires_typed_adapter_report_and_acceptance(tmp_path):
    adapter = tmp_path / "adapter.json"
    resource = tmp_path / "resource.json"
    acceptance = tmp_path / "acceptance.txt"
    write_json(
        adapter,
        {
            "schema_version": 1,
            "mode": "compare",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "plonky3_version": "0.6.1",
            "dependency_lock_sha256": "7a3e859e9d457006e38737f418fdf16f0e538977c23bf9882b4225d43b3db455",
            "release_sha": "abc",
            "official_verification": True,
            "bounded_equals_conventional": True,
            "witness_data_included": False,
            "preflight_estimate": {
                "peak_resident_bytes": 1,
                "scratch_high_water_bytes": 1,
                "total_read_bytes": 0,
                "total_write_bytes": 0,
                "phases": [],
            },
            "proof_size_bytes": 1,
            "proof_blake3_hex": "d" * 64,
        },
    )
    write_json(
        resource,
        {
            "schema_version": 1,
            "scope": "full_pipeline",
            "mode": "bounded",
            "benchmark_session_id": "0123456789abcdef0123456789abcdef",
            "hardware": "partner-test-host",
            "logical_cpu_count": 8,
            "total_memory_bytes": 16 * 1024**3,
            "operating_system": "linux",
            "storage": "nvme",
            "storage_device": "259:1:nvme0n1p1",
            "storage_is_rotational": False,
            "storage_is_nvme": True,
            "release_sha": "abc",
            "dependency_profile": "tinyzkp-p3-goldilocks-v1",
            "normalized_manifest_path": "partner.normalized.json",
            "workload_manifest_digest_hex": "a" * 64,
            "normalized_manifest_digest_hex": "b" * 64,
            "preflight_estimate": {
                "peak_resident_bytes": 1,
                "scratch_high_water_bytes": 1,
                "total_read_bytes": 0,
                "total_write_bytes": 0,
                "phases": [],
            },
            "cpu_seconds": 1.0,
            "wall_time_ms": 1,
            "verification_succeeded": True,
            "exit_status": 0,
            "peak_rss_bytes": 1,
            "cgroup_peak_bytes": 1,
            "scratch_high_water_bytes": 1,
            "read_bytes": 0,
            "write_bytes": 0,
            "proof_size_bytes": 1,
            "verification_time_ms": 0,
            "exact_command": ["partner-adapter"],
        },
    )
    artifacts = [
        (adapter, {"role": "adapter_result"}),
        (resource, {"role": "resource_report"}),
    ]
    assert gate.validate_partner_evidence(artifacts, "abc") == [
        "partner evidence role is missing: acceptance_record"
    ]
    write_json(
        acceptance,
        {
            "schema_version": 1,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "acceptance_id": "acceptance-1",
            "partner_id": "opaque-partner-1",
            "accepted_at": "2026-01-01T00:00:00Z",
            "official_verification": True,
            "bounded_equals_conventional": True,
            "witness_data_committed": False,
            "adapter_result_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
            "resource_report_sha256": hashlib.sha256(resource.read_bytes()).hexdigest(),
        },
    )
    artifacts.append((acceptance, {"role": "acceptance_record"}))
    assert gate.validate_partner_evidence(
        artifacts, "abc", {"partner_acceptance_id": "acceptance-1"}
    ) == []
