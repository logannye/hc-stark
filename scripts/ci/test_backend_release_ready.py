import hashlib
import json
import os
import subprocess
import zipfile

import backend_release_ready as gate
import pytest


@pytest.fixture(autouse=True)
def trusted_external_and_tool_fixtures(monkeypatch):
    monkeypatch.setattr(gate, "verify_external_signature", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        gate.evidence_runtime,
        "toolchain_anchor",
        lambda *args, **kwargs: {
            "cargo_sha256": "c" * 64,
            "rustc_sha256": "d" * 64,
        },
    )
    monkeypatch.setattr(
        gate.evidence_runtime,
        "gate_tool_anchors",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        gate.evidence_runtime,
        "cargo_fuzz_anchor",
        lambda *args, **kwargs: "e" * 64,
    )

    def fixture_bundle(path, *, root, release_sha):
        with zipfile.ZipFile(path) as archive:
            payload = archive.read("review-manifest.json")
        return json.loads(payload), payload

    monkeypatch.setattr(gate.build_review_bundle, "verify_bundle", fixture_bundle)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_gate_rebinds_review_bundle_to_exact_candidate_artifacts(
    tmp_path, monkeypatch
):
    bundle = tmp_path / "review.zip"
    bundle.write_bytes(b"signed review bundle")
    bundle_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    digest = "a" * 64

    def descriptor(role, sha256=digest, path=None):
        return {
            "role": role,
            "path": str(path or tmp_path / role),
            "sha256": sha256,
        }

    one = []
    ten = []
    observed = []
    matrix = descriptor("matrix_manifest")
    one.append(matrix)
    ten.append(dict(matrix))
    observed.append(
        {
            "origin": "artifact",
            "evidence_category": "raw-reports",
            "evidence_role": "fixed_host_matrix_manifest",
            "source_sha256": digest,
        }
    )
    for workload in ("fibonacci", "poseidon2"):
        for mode in ("baseline", "candidate"):
            role = f"{workload}_{mode}_report"
            one.append(descriptor(role))
            observed.append(
                {
                    "origin": "artifact",
                    "evidence_category": "raw-reports",
                    "evidence_role": f"one_million_{role}",
                    "source_sha256": digest,
                }
            )
        role = f"{workload}_candidate_report"
        ten.append(descriptor(role))
        observed.append(
            {
                "origin": "artifact",
                "evidence_category": "raw-reports",
                "evidence_role": f"ten_million_{role}",
                "source_sha256": digest,
            }
        )
    known = [descriptor("test_report"), descriptor("test_log")]
    for role in ("test_report", "test_log"):
        observed.append(
            {
                "origin": "artifact",
                "evidence_category": "known-answers",
                "evidence_role": f"known_answer_{role}",
                "source_sha256": digest,
            }
        )
    crash = [descriptor("crash_matrix"), descriptor("fuzz_smoke")]
    for category, role in (("crash", "crash_matrix"), ("fuzz", "fuzz_smoke")):
        observed.append(
            {
                "origin": "artifact",
                "evidence_category": category,
                "evidence_role": role,
                "source_sha256": digest,
            }
        )
    review = [
        descriptor(
            "review_bundle", bundle_digest, bundle.relative_to(tmp_path)
        )
    ]
    gates = {
        "one_million_row_resource_gate": {"artifacts": one},
        "ten_million_row_resource_gate": {"artifacts": ten},
        "deterministic_cross_mode_proofs": {"artifacts": known},
        "crash_resume_and_corruption_suite": {"artifacts": crash},
        "plonky3_specialist_review": {"artifacts": review},
        "implementation_review_no_high_findings": {"artifacts": list(review)},
    }
    monkeypatch.setattr(
        gate.build_review_bundle,
        "verify_bundle",
        lambda *args, **kwargs: ({"files": observed}, b"manifest"),
    )

    assert gate.validate_review_execution_bindings(
        gates, "a" * 40, root=tmp_path
    ) == []
    one[1]["sha256"] = "b" * 64
    assert any(
        "does not contain exact candidate evidence" in failure
        for failure in gate.validate_review_execution_bindings(
            gates, "a" * 40, root=tmp_path
        )
    )


def source_release_sha():
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=gate.ROOT, text=True
    ).strip()


def resource_matrix_fixture(tmp_path):
    release_sha = "a" * 40
    source_digest = "b" * 64
    stable_host = {
        "hardware": "fixed-host; logical_cpus=8",
        "logical_cpu_count": 8,
        "total_memory_bytes": 16 * 1024**3,
        "operating_system": "Linux-fixed",
        "storage_device": "259:1:nvme0n1p1",
        "storage_is_rotational": False,
        "storage_is_nvme": True,
        "storage_total_bytes": 1_000_000_000_000,
    }
    gates = {
        "one_million_row_resource_gate": {"artifacts": []},
        "ten_million_row_resource_gate": {"artifacts": []},
    }
    entries = []

    def evidence_artifact(gate_name, role, payload):
        path = tmp_path / gate_name / f"{role}.json"
        digest = write_json(path, payload)
        descriptor = {
            "role": role,
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": digest,
        }
        gates[gate_name]["artifacts"].append(descriptor)
        return path, descriptor

    for entry_id, specification in gate.RESOURCE_MATRIX_ENTRIES.items():
        gate_name = specification["evidence_gate"]
        prefix = specification["prefix"]
        source_path, source_descriptor = evidence_artifact(
            gate_name,
            f"{prefix}_manifest",
            {
                "workload_id": specification["workload"],
                "logical_rows": specification["logical_rows"],
            },
        )
        matrix_artifacts = []
        expected_paths = gate._matrix_artifact_paths(
            specification["stem"], baseline=specification["baseline"]
        )
        bindings = {
            "candidate_report": f"{prefix}_candidate_report",
            "candidate_manifest": f"{prefix}_candidate_normalized_manifest",
        }
        if specification["baseline"]:
            bindings.update(
                {
                    "baseline_report": f"{prefix}_baseline_report",
                    "baseline_manifest": f"{prefix}_baseline_normalized_manifest",
                }
            )
        for matrix_role, evidence_role in bindings.items():
            payload = (
                {**stable_host, "release_sha": release_sha}
                if matrix_role.endswith("report")
                else {"normalized": True, "entry_id": entry_id}
            )
            path, descriptor = evidence_artifact(gate_name, evidence_role, payload)
            matrix_artifacts.append(
                {
                    "role": matrix_role,
                    "path": expected_paths[matrix_role],
                    "sha256": descriptor["sha256"],
                    "size_bytes": path.stat().st_size,
                    "mode": 0o600,
                }
            )
        for matrix_role, path in expected_paths.items():
            if matrix_role not in bindings:
                matrix_artifacts.append(
                    {
                        "role": matrix_role,
                        "path": path,
                        "sha256": "c" * 64,
                        "size_bytes": 0,
                        "mode": 0o600,
                    }
                )
        entries.append(
            {
                "entry_id": entry_id,
                "workload": specification["workload"],
                "logical_rows": specification["logical_rows"],
                "mode": specification["mode"],
                "gate": specification["gate"],
                "manifest_path": specification["manifest_path"],
                "manifest_sha256": source_descriptor["sha256"],
                "status": "complete",
                "attempts": 1,
                "artifacts": matrix_artifacts,
                "last_error": None,
                "completed_at": "2026-07-10T00:00:00+00:00",
            }
        )

    matrix = {
        "schema_version": 1,
        "kind": "tinyzkp_fixed_host_release_matrix_v1",
        "release_sha": release_sha,
        "source_tree_sha256": source_digest,
        "profile": "tinyzkp-p3-goldilocks-v1",
        "plonky3_version": "0.6.1",
        "source_root": str(tmp_path),
        "cli_path": str(tmp_path / "hc-cli"),
        "cli_sha256": "d" * 64,
        "cli_identity": {
            "service": "cli",
            "package_version": "0.1.0",
            "release_sha": release_sha,
            "release_ref": None,
            "backend": "plonky3",
            "plonky3_version": "0.6.1",
            "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
            "dependency_lock_sha256": "e" * 64,
        },
        "output_dir": str(tmp_path / "reports"),
        "scratch_root": str(tmp_path / "scratch"),
        "cgroup_parent": str(tmp_path / "cgroup"),
        "created_at": "2026-07-10T00:00:00+00:00",
        "updated_at": "2026-07-10T01:00:00+00:00",
        "status": "local_matrix_complete_external_gates_pending",
        "fixed_host_evidence_eligible": True,
        "stable_host_identity": stable_host,
        "local_matrix_gates_passed": True,
        "release_eligible": False,
        "authority": {
            "may_approve_backend_release": False,
            "may_provision_or_mutate_infrastructure": False,
            "may_publish_or_upload_evidence": False,
        },
        "external_gates": {
            "independent_reproduction": "required_external",
            "plonky3_specialist_review": "required_external",
            "implementation_review": "required_external",
            "design_partner_acceptance": "required_external",
            "signed_release_assembly": "required_external",
        },
        "entries": entries,
        "last_error": None,
        "completed_at": "2026-07-10T01:00:00+00:00",
    }
    matrix_path = tmp_path / "fixed-host-release-matrix-v1.json"

    def persist_matrix():
        digest = write_json(matrix_path, matrix)
        descriptor = {
            "role": "matrix_manifest",
            "path": matrix_path.relative_to(tmp_path).as_posix(),
            "sha256": digest,
        }
        for value in gates.values():
            value["artifacts"] = [
                item
                for item in value["artifacts"]
                if item.get("role") != "matrix_manifest"
            ]
            value["artifacts"].insert(0, dict(descriptor))

    persist_matrix()
    return release_sha, source_digest, gates, matrix, persist_matrix


def test_resource_matrix_binds_exact_first_party_evidence_and_denies_authority(
    tmp_path,
):
    release_sha, source_digest, gates, matrix, persist = resource_matrix_fixture(
        tmp_path
    )
    assert gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    ) == []

    matrix["release_eligible"] = True
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert "fixed-host matrix completion or source identity is invalid" in failures

    matrix["release_eligible"] = False
    matrix["external_gates"]["independent_reproduction"] = "satisfied"
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert "fixed-host matrix may not satisfy external gates" in failures

    matrix["external_gates"]["independent_reproduction"] = "required_external"
    matrix["entries"][0]["artifacts"][0]["sha256"] = "f" * 64
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert any("does not bind exact evidence" in failure for failure in failures)


def test_resource_matrix_rejects_source_cli_and_cross_host_skew(tmp_path):
    release_sha, source_digest, gates, matrix, persist = resource_matrix_fixture(
        tmp_path
    )
    matrix["source_tree_sha256"] = "0" * 64
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert "fixed-host matrix completion or source identity is invalid" in failures

    matrix["source_tree_sha256"] = source_digest
    matrix["cli_identity"]["release_sha"] = "0" * 40
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert "fixed-host matrix CLI identity is incomplete or skewed" in failures

    matrix["cli_identity"]["release_sha"] = release_sha
    report_descriptor = next(
        item
        for item in gates["one_million_row_resource_gate"]["artifacts"]
        if item["role"] == "fibonacci_candidate_report"
    )
    report_path = tmp_path / report_descriptor["path"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["hardware"] = "different-fixed-host"
    report_descriptor["sha256"] = write_json(report_path, report)
    entry = next(item for item in matrix["entries"] if item["entry_id"] == "fibonacci_1m")
    matrix_report = next(
        item for item in entry["artifacts"] if item["role"] == "candidate_report"
    )
    matrix_report["sha256"] = report_descriptor["sha256"]
    matrix_report["size_bytes"] = report_path.stat().st_size
    persist()
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert any("report host identity mismatch" in failure for failure in failures)


def test_resource_matrix_is_mandatory_in_both_first_party_gates(tmp_path):
    release_sha, source_digest, gates, _, _ = resource_matrix_fixture(tmp_path)
    gates["ten_million_row_resource_gate"]["artifacts"] = [
        item
        for item in gates["ten_million_row_resource_gate"]["artifacts"]
        if item["role"] != "matrix_manifest"
    ]
    failures = gate.validate_resource_matrix_binding(
        gates, release_sha, source_digest, root=tmp_path
    )
    assert "fixed-host matrix manifest is required by both resource gates" in failures


def runtime_identity(release_sha, *, fuzz=False):
    environment = gate.evidence_runtime.environment_policy()
    if fuzz:
        cargo_version = (
            "cargo 1.97.0-nightly (eb94155a9 2026-04-09)\n"
            "release: 1.97.0-nightly\n"
            f"commit-hash: {gate.FUZZ_CARGO_COMMIT}\n"
            "commit-date: 2026-04-09\n"
            "host: x86_64-unknown-linux-gnu"
        )
        rustc_version = (
            "rustc 1.97.0-nightly (a5c825cd8 2026-04-14)\n"
            "binary: rustc\n"
            f"commit-hash: {gate.FUZZ_RUSTC_COMMIT}\n"
            "commit-date: 2026-04-14\n"
            "host: x86_64-unknown-linux-gnu\n"
            "release: 1.97.0-nightly"
        )
    else:
        cargo_version = (
            "cargo 1.95.0 (f2d3ce0bd 2026-03-21)\n"
            "release: 1.95.0\n"
            f"commit-hash: {gate.RELEASE_CARGO_COMMIT}\n"
            "commit-date: 2026-03-21\n"
            "host: x86_64-unknown-linux-gnu"
        )
        rustc_version = (
            "rustc 1.95.0 (59807616e 2026-04-14)\n"
            "binary: rustc\n"
            f"commit-hash: {gate.RELEASE_RUSTC_COMMIT}\n"
            "commit-date: 2026-04-14\n"
            "host: x86_64-unknown-linux-gnu\n"
            "release: 1.95.0"
        )
    return {
        "release_sha": release_sha,
        "source_tree_sha256": gate.source_tree_identity.source_tree_sha256(
            gate.ROOT, release_sha
        ),
        "dependency_lock_sha256": gate.evidence_runtime.commit_file_sha256(
            gate.ROOT, release_sha, "Cargo.lock"
        ),
        "rust_toolchain_sha256": gate.evidence_runtime.commit_file_sha256(
            gate.ROOT, release_sha, "rust-toolchain.toml"
        ),
        "partial": False,
        "environment_policy": environment,
        "environment_policy_sha256": gate.evidence_runtime.canonical_json_sha256(
            environment
        ),
        "cargo_identity": {
            "path": "/tool/cargo",
            "sha256": "c" * 64,
            "version": cargo_version,
        },
        "rustc_identity": {
            "path": "/tool/rustc",
            "sha256": "d" * 64,
            "version": rustc_version,
        },
    }


def artifact_descriptor(path, role):
    return (
        path,
        {
            "role": role,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        },
    )


def replace_artifact(artifacts, path, role):
    replacement = artifact_descriptor(path, role)
    for index, (_, descriptor) in enumerate(artifacts):
        if descriptor.get("role") == role:
            artifacts[index] = replacement
            return
    raise AssertionError(f"missing artifact role: {role}")


def attach_tool_identity(tmp_path, report, *, fuzz):
    filename = (
        gate.run_fuzz_smoke.TOOL_IDENTITY_FILE
        if fuzz
        else gate.run_crash_matrix.TOOL_IDENTITY_FILE
    )
    role = "fuzz_tool_identity" if fuzz else "crash_tool_identity"
    toolchain = gate.FUZZ_TOOLCHAIN if fuzz else gate.run_crash_matrix.RELEASE_TOOLCHAIN
    cargo_arguments = ["-Vv"]
    rustc_arguments = ["-Vv"]
    record = gate.evidence_runtime.tool_identity_record(
        report,
        report["cargo_identity"],
        report["rustc_identity"],
        execution_profile="fuzz" if fuzz else "release",
        toolchain=toolchain,
        cargo_version_command=[report["cargo_identity"]["path"], *cargo_arguments],
        rustc_version_command=[report["rustc_identity"]["path"], *rustc_arguments],
    )
    payload = gate.evidence_runtime.pretty_json_bytes(record)
    path = tmp_path / filename
    path.write_bytes(payload)
    report.update(
        tool_identity_file=filename,
        tool_identity_bytes=len(payload),
        tool_identity_sha256=hashlib.sha256(payload).hexdigest(),
    )
    return artifact_descriptor(path, role)


def exact_test_log(test_name, marker=""):
    return (
        marker
        + f"test {test_name} ... ok\n"
        + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        + "59 filtered out; finished in 1.00s\n"
    ).encode()


def write_review_bundle(path, release_sha="abc", source_tree_sha256="d" * 64):
    manifest = {
        "schema_version": 2,
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_sha256,
        "profile": "tinyzkp-p3-goldilocks-v1",
        "plonky3_version": "0.6.1",
        "files": [],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("review-manifest.json", manifest_bytes)
    return (
        hashlib.sha256(path.read_bytes()).hexdigest(),
        hashlib.sha256(manifest_bytes).hexdigest(),
    )


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


def test_config_evidence_manifest_cannot_escape_root_or_cross_symlink(tmp_path):
    outside = tmp_path.parent / "outside-evidence.json"
    outside.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(outside.parent, target_is_directory=True)
    for manifest in (
        str(outside),
        "../outside-evidence.json",
        "linked/outside-evidence.json",
    ):
        problems = gate.failures(
            {
                "schema_version": 2,
                "status": "ready",
                "evidence_manifest": manifest,
            },
            root=tmp_path,
        )
        assert any(
            "evidence manifest is unavailable" in problem for problem in problems
        )
        assert any("unsafe" in problem or "symlink" in problem for problem in problems)


def test_final_gate_recomputes_source_transition_instead_of_trusting_metadata(
    tmp_path, monkeypatch
):
    observed = {}

    def reject(root, source_revision, release_revision, expected_digest):
        observed.update(
            source=source_revision,
            release=release_revision,
            digest=expected_digest,
        )
        raise ValueError("non-evidence source changed")

    monkeypatch.setattr(
        gate.source_tree_identity,
        "verify_evidence_only_transition",
        reject,
    )
    problems = gate.evidence_failures(
        {
            "schema_version": 1,
            "status": "ready",
            "source_release_sha": "a" * 40,
            "release_sha": "b" * 40,
            "source_tree_sha256": "c" * 64,
            "gates": {},
        },
        root=tmp_path,
    )
    assert observed == {
        "source": "a" * 40,
        "release": "b" * 40,
        "digest": "c" * 64,
    }
    assert any(
        "source transition could not be verified" in problem for problem in problems
    )


def test_hashed_artifact_rejects_symlinked_path_component(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    artifact = actual / "report.json"
    digest = write_json(artifact, {"status": "pass"})
    os.symlink(actual, tmp_path / "linked")
    try:
        gate.safe_artifact(
            tmp_path,
            {"role": "report", "path": "linked/report.json", "sha256": digest},
        )
    except ValueError as error:
        assert "missing or unsafe" in str(error)
    else:
        raise AssertionError("symlinked evidence path was accepted")


def test_bounded_reads_reject_oversize_and_in_place_mutation(tmp_path, monkeypatch):
    oversized = tmp_path / "oversized.log"
    with oversized.open("wb") as handle:
        handle.truncate(gate.MAX_EVIDENCE_ARTIFACT_BYTES + 1)
    try:
        gate.read_bounded_file(
            oversized, maximum=gate.MAX_EVIDENCE_ARTIFACT_BYTES
        )
    except ValueError as error:
        assert "oversized" in str(error)
    else:
        raise AssertionError("oversized evidence was read")

    raced = tmp_path / "raced.log"
    raced.write_bytes(b"original")
    original_read = gate.os.read
    mutated = False

    def mutate_during_read(descriptor, count):
        nonlocal mutated
        payload = original_read(descriptor, count)
        if not mutated and payload:
            mutated = True
            raced.write_bytes(b"modified")
            details = raced.stat()
            os.utime(
                raced,
                ns=(details.st_atime_ns, details.st_mtime_ns + 1_000_000_000),
            )
        return payload

    monkeypatch.setattr(gate.os, "read", mutate_during_read)
    try:
        gate.read_bounded_file(raced, maximum=1024)
    except ValueError as error:
        assert "changed during validation" in str(error)
    else:
        raise AssertionError("concurrently modified evidence was accepted")


def test_disk_device_identity_is_canonical_and_bounded():
    for valid in ("0:0", "7:1", "259:1048575", "4294967295:4294967295"):
        assert gate.canonical_device_identity(valid)
    for invalid in (
        "07:1",
        "7:01",
        "7:-1",
        "7:1:2",
        "loop7",
        "4294967296:1",
        True,
    ):
        assert not gate.canonical_device_identity(invalid)


def test_bounded_string_rejects_non_utf8_null_and_oversize_values():
    assert gate.bounded_string("canonical")
    assert not gate.bounded_string("\ud800")
    assert not gate.bounded_string("contains\x00null")
    assert not gate.bounded_string("x" * (gate.MAX_EVIDENCE_STRING_BYTES + 1))


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
                "checksum_entries": len(gate.SIGNED_RELEASE_CHECKSUM_NAMES),
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
    release_sha = "a" * 40
    identities = {name: release_sha for name in ("engine_cli", "engine_oci")}
    write_json(
        report,
        {
            "schema_version": 1,
            "release_sha": release_sha,
            "release_ref": "backend-v1.0.0",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "checked_at": "2026-01-01T00:00:00Z",
            "surfaces": {
                "engine_cli": {
                    "service": "engine_cli",
                    "release_sha": release_sha,
                    "artifact": "release-artifacts/tinyzkp-engine-linux-x86_64",
                    "artifact_sha256": "a" * 64,
                    "identity_artifact": "release-artifacts/engine-release.json",
                    "identity_artifact_sha256": "b" * 64,
                    "package_version": "0.1.0",
                },
                "engine_oci": {
                    "service": "engine_oci",
                    "release_sha": release_sha,
                    "artifact": "release-artifacts/tinyzkp-engine.oci.tar",
                    "artifact_sha256": "c" * 64,
                    "manifest_digest": "sha256:" + "d" * 64,
                    "config_digest": "sha256:" + "e" * 64,
                    "platform": "linux/amd64",
                    "entrypoint": ["/usr/local/bin/tinyzkp-engine"],
                },
            },
            "compatibility": {
                "artifact": "release-artifacts/plonky3-compatibility-v1.json",
                "artifact_sha256": "f" * 64,
                "profile_id": "tinyzkp-p3-goldilocks-v1",
                "plonky3_version": "0.6.1",
                "release_status": "reviewed",
            },
        },
    )
    artifacts = [(report, {"role": "identity_report"})]
    assert (
        gate.validate_identity_evidence(
            artifacts, {"identities": identities}, release_sha
        )
        == []
    )

    skewed = identities.copy()
    skewed["engine_cli"] = "old"
    assert gate.validate_identity_evidence(
        artifacts, {"identities": skewed}, release_sha
    ) == ["release identity metadata does not match the machine report"]


def test_identity_gate_is_bound_to_signed_artifact_digests(tmp_path):
    artifacts = {
        "tinyzkp-engine-linux-x86_64": b"engine",
        "engine-release.json": b"release",
        "tinyzkp-engine.oci.tar": b"oci",
        "plonky3-compatibility-v1.json": b"compatibility",
    }
    digests = {}
    for name, payload in artifacts.items():
        path = tmp_path / name
        path.write_bytes(payload)
        digests[name] = hashlib.sha256(payload).hexdigest()
    report = tmp_path / "engine-identity.json"
    write_json(
        report,
        {
            "surfaces": {
                "engine_cli": {
                    "artifact": "tinyzkp-engine-linux-x86_64",
                    "artifact_sha256": digests["tinyzkp-engine-linux-x86_64"],
                    "identity_artifact": "engine-release.json",
                    "identity_artifact_sha256": digests["engine-release.json"],
                },
                "engine_oci": {
                    "artifact": "tinyzkp-engine.oci.tar",
                    "artifact_sha256": digests["tinyzkp-engine.oci.tar"],
                },
            },
            "compatibility": {
                "artifact": "plonky3-compatibility-v1.json",
                "artifact_sha256": digests["plonky3-compatibility-v1.json"],
            },
        },
    )
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())),
        encoding="utf-8",
    )
    assert gate.validate_identity_checksum_binding(report, checksums) == []

    (tmp_path / "tinyzkp-engine.oci.tar").write_bytes(b"mutated")
    assert gate.validate_identity_checksum_binding(report, checksums) == [
        "engine identity does not match the signed artifact checksums"
    ]


@pytest.mark.parametrize(
    ("gate_id", "test_name", "profile", "require_release_profile"),
    [
        (
            "official_verifier_fibonacci",
            "fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier",
            "release",
            True,
        ),
        (
            "air_job_contracts",
            "plonky3_air_job_contracts",
            "ci",
            False,
        ),
    ],
)
def test_evidenced_command_binds_release_command_profile_and_log(
    tmp_path, gate_id, test_name, profile, require_release_profile
):
    release_sha = source_release_sha()
    spec = gate.run_evidenced_command.GATES[gate_id]
    log = tmp_path / "test.log"
    log.write_bytes(exact_test_log(test_name))
    command = spec["command"]
    environment = gate.evidence_runtime.environment_policy()
    report = tmp_path / "test-report.json"
    write_json(
        report,
        {
            "schema_version": 4,
            "release_sha": release_sha,
            "source_tree_sha256": gate.source_tree_identity.source_tree_sha256(
                gate.ROOT, release_sha
            ),
            "dependency_lock_sha256": gate.evidence_runtime.commit_file_sha256(
                gate.ROOT, release_sha, "Cargo.lock"
            ),
            "rust_toolchain_sha256": gate.evidence_runtime.commit_file_sha256(
                gate.ROOT, release_sha, "rust-toolchain.toml"
            ),
            "profile": "tinyzkp-p3-goldilocks-v1",
            "gate": gate_id,
            "execution_profile": profile,
            "logical_command": command,
            "actual_command": ["/tool/cargo", *command[1:]],
            "descriptor_execution": True,
            "output_parser": spec["parser"],
            "parsed_result": gate.run_evidenced_command.parse_output(
                gate_id, log.read_bytes()
            ),
            "timeout_seconds": spec["timeout"],
            "timed_out": False,
            "exit_status": 0,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "duration_ms": 1000,
            "log_bytes": len(log.read_bytes()),
            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            "environment_policy": environment,
            "environment_policy_sha256": gate.evidence_runtime.canonical_json_sha256(
                environment
            ),
            "immutable_source": True,
            "write_boundary": {
                "kind": "landlock-write-deny-v1",
                "abi_version": 3,
                "source_write_allowed": False,
                "writable_paths": ["cargo-target", "gate-work", "tmp"],
            },
            "network_boundary": None,
            "immutable_file_count": 1,
            "gate_inputs": {},
            "tools": {
                "cargo": {
                    "path": "/tool/cargo",
                    "sha256": "c" * 64,
                    "version": runtime_identity(release_sha)["cargo_identity"]["version"],
                },
                "rustc": {
                    "path": "/tool/rustc",
                    "sha256": "d" * 64,
                    "version": runtime_identity(release_sha)["rustc_identity"]["version"],
                },
            },
        },
    )
    artifacts = [
        (report, {"role": "test_report"}),
        (log, {"role": "test_log"}),
    ]
    metadata = {
        "release_sha": release_sha,
        "execution_profile": profile,
        "command": command,
        "exit_status": 0,
        "gate_id": gate_id,
    }
    assert (
        gate.validate_test_run_evidence(
            artifacts,
            metadata,
            release_sha,
            require_release_profile=require_release_profile,
            expected_gate=gate_id,
        )
        == []
    )
    log.write_text("mutated", encoding="utf-8")
    assert gate.validate_test_run_evidence(
        artifacts,
        metadata,
        release_sha,
        require_release_profile=require_release_profile,
        expected_gate=gate_id,
    ) == ["evidenced command report is incomplete or release-skewed"]


def test_review_risk_acceptance_cannot_waive_a_high_finding(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("independent review", encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    bundle = tmp_path / "review.zip"
    bundle_sha256, manifest_sha256 = write_review_bundle(bundle)
    metadata = {
        "reviewer": "independent reviewer",
        "completed_at": "2026-01-01T00:00:00Z",
        "review_scope": "implementation",
        "signer_id": "implementation-reviewer",
    }
    write_json(
        ledger,
        {
            "schema_version": 2,
            "release_sha": "abc",
            "profile": "tinyzkp-p3-goldilocks-v1",
            "review_scope": "implementation",
            "completed_at": metadata["completed_at"],
            "reviewer": metadata["reviewer"],
            "reviewer_independent": True,
            "review_bundle_sha256": bundle_sha256,
            "review_manifest_sha256": manifest_sha256,
            "source_tree_sha256": "d" * 64,
            "review_report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            "findings": [
                {
                    "id": "HIGH-1",
                    "severity": "high",
                    "status": "accepted_by_reviewer",
                    "reviewer_verified": True,
                }
            ],
            "security_assessment": None,
            "signer_id": metadata["signer_id"],
        },
    )
    assert gate.validate_review(
        metadata,
        [
            (bundle, {"role": "review_bundle"}),
            (report, {"role": "review_report"}),
            (ledger, {"role": "remediation_ledger"}),
        ],
        "abc",
        "implementation",
        "d" * 64,
    ) == ["critical/high review finding remains unresolved"]

    with zipfile.ZipFile(bundle, "a") as archive:
        archive.writestr("post-review-mutation.txt", "changed")
    failures = gate.validate_review(
        metadata,
        [
            (bundle, {"role": "review_bundle"}),
            (report, {"role": "review_report"}),
            (ledger, {"role": "remediation_ledger"}),
        ],
        "abc",
        "implementation",
        "d" * 64,
    )
    assert "review evidence is incomplete, bundle-skewed, or release-skewed" in failures


def test_manual_passed_boolean_and_unresolved_high_finding_fail(tmp_path):
    report = tmp_path / "review.json"
    digest = write_json(report, {"report": "review"})
    bundle = tmp_path / "review.zip"
    bundle_digest, manifest_digest = write_review_bundle(bundle)
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
                "signer_id": f"{scope}-reviewer",
            }
            ledger = tmp_path / f"{scope}-ledger.json"
            ledger_digest = write_json(
                ledger,
                {
                    "schema_version": 2,
                    "release_sha": "abc",
                    "profile": "tinyzkp-p3-goldilocks-v1",
                    "review_scope": scope,
                    "completed_at": metadata["completed_at"],
                    "reviewer": metadata["reviewer"],
                    "reviewer_independent": True,
                    "review_bundle_sha256": bundle_digest,
                    "review_manifest_sha256": manifest_digest,
                    "source_tree_sha256": "d" * 64,
                    "review_report_sha256": digest,
                    "findings": [
                        {
                            "id": "HIGH-1",
                            "severity": "high",
                            "status": "open",
                            "reviewer_verified": False,
                        }
                    ],
                    "security_assessment": (
                        {
                            "schema_version": 1,
                            "profile_id": "tinyzkp-p3-goldilocks-v1",
                            "plonky3_version": "0.6.1",
                            "fri_constructor": "FriParameters::new_benchmark",
                            "log_blowup": 1,
                            "log_final_poly_len": 0,
                            "max_log_arity": 1,
                            "num_queries": 100,
                            "commit_proof_of_work_bits": 0,
                            "query_proof_of_work_bits": 16,
                            "conjectured_soundness_reviewed": True,
                            "proven_soundness_reviewed": True,
                            "duplicate_query_probability_reviewed": True,
                            "challenger_capacity_reviewed": True,
                            "minimum_security_bits": 96,
                            "production_use_approved": True,
                            "analysis_summary": "Frozen profile assessed.",
                            "limitations": ["Documented FRI assumptions apply."],
                        }
                        if scope == "plonky3_specialist"
                        else None
                    ),
                    "signer_id": metadata["signer_id"],
                },
            )
            artifacts = [
                {
                    "role": "review_bundle",
                    "path": bundle.name,
                    "sha256": bundle_digest,
                },
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
        "source_release_sha": "abc",
        "source_tree_sha256": "d" * 64,
        "gates": gates,
    }
    evidence_path = tmp_path / "evidence.json"
    write_json(evidence_path, evidence)
    problems = gate.failures(
        {"schema_version": 2, "status": "ready", "evidence_manifest": "evidence.json"},
        root=tmp_path,
    )
    assert any(
        "manual passed booleans are forbidden" in problem for problem in problems
    )
    assert any(
        "critical/high review finding remains unresolved" in problem
        for problem in problems
    )


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
    release_sha = source_release_sha()
    identity = runtime_identity(release_sha)
    cargo_path = identity["cargo_identity"]["path"]
    timeout = 900
    artifacts = []
    cases = []
    for phase in gate.CRASH_PHASES:
        name = f"checkpoint_{phase}"
        digest = "a" * 64
        log = tmp_path / f"{name}.log"
        payload = exact_test_log(
            gate.CRASH_PHASE_TEST[1],
            f"tinyzkp-crash-proof phase={phase} resumed={digest} reference={digest}\n",
        )
        log.write_bytes(payload)
        cases.append(
            {
                "case": name,
                "command": gate.expected_crash_command(name, cargo_path),
                "exit_status": 0,
                "timed_out": False,
                "timeout_seconds": timeout,
                "duration_ms": 1,
                "phase": phase,
                "observed_phase": phase,
                "selected_environment": {"TINYZKP_SINGLE_CRASH_PHASE": phase},
                "proof_blake3_hex": digest,
                "reference_proof_blake3_hex": digest,
                "proof_bytes_equal": True,
                "log_file": log.name,
                "log_bytes": len(log.read_bytes()),
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                "test_execution": gate.run_crash_matrix.parse_test_execution(
                    payload, gate.CRASH_PHASE_TEST[1]
                ),
            }
        )
        artifacts.append(artifact_descriptor(log, f"crash_log_{name}"))
    for name in sorted(gate.CRASH_INTEGRITY_CASES - {"disk_full_resume"}):
        test_name = gate.CRASH_INTEGRITY_TESTS[name][1]
        log = tmp_path / f"{name}.log"
        payload = exact_test_log(test_name)
        log.write_bytes(payload)
        cases.append(
            {
                "case": name,
                "command": gate.expected_crash_command(name, cargo_path),
                "exit_status": 0,
                "timed_out": False,
                "timeout_seconds": timeout,
                "duration_ms": 1,
                "log_file": log.name,
                "log_bytes": len(log.read_bytes()),
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                "test_execution": gate.run_crash_matrix.parse_test_execution(
                    payload, test_name
                ),
            }
        )
        artifacts.append(artifact_descriptor(log, f"crash_log_{name}"))
    report = tmp_path / "crash.json"
    report_body = {
        "schema_version": 1,
        **identity,
        "profile": "tinyzkp-p3-goldilocks-v1",
        "build_profile": "release",
        "case_timeout_seconds": timeout,
        "all_executed_cases_passed": True,
        "complete_for_release": True,
        "execution_boundary": {
            "kind": "landlock-write-deny-v1",
            "abi_version": 3,
            "source_write_allowed": False,
            "descriptor_execution": True,
            "writable_paths": ["cargo-target", "tmp", "tinyzkp-disk-full"],
        },
        "cases": cases,
    }
    artifacts.append(attach_tool_identity(tmp_path, report_body, fuzz=False))
    write_json(
        report,
        report_body,
    )
    failures = gate.validate_crash_matrix(
        [(report, {"role": "crash_matrix"}), *artifacts], release_sha
    )
    assert failures == ["required crash matrix case is missing: disk_full_resume"]

    disk_log = tmp_path / "disk_full_resume.log"
    digest = "b" * 64
    disk_test_name = gate.CRASH_INTEGRITY_TESTS["disk_full_resume"][1]
    disk_payload = exact_test_log(
        disk_test_name,
        f"tinyzkp-disk-full-resume enospc=true resumed={digest} reference={digest}\n",
    )
    disk_log.write_bytes(disk_payload)
    disk_contract = {
        "schema_version": 1,
        "created_by": "tinyzkp-run-crash-matrix",
        "mount_path": "/mnt/tinyzkp-disk-full",
        "mount_device": "7:1",
        "parent_device": "259:1",
        "filesystem": "ext4",
        "mount_options": ["nodev", "noexec", "nosuid", "rw"],
        "total_bytes": 128 * 1024 * 1024,
        "available_bytes_before": 120 * 1024 * 1024,
        "max_total_bytes": 512 * 1024 * 1024,
        "owner_uid": 1000,
        "directory_mode": 0o700,
        "release_sha": release_sha,
        "source_tree_sha256": identity["source_tree_sha256"],
        "sentinel_file": gate.run_crash_matrix.DISK_FULL_SENTINEL,
        "sentinel_sha256": "e" * 64,
    }
    cases.append(
        {
            "case": "disk_full_resume",
            "command": gate.expected_crash_command("disk_full_resume", cargo_path),
            "exit_status": 0,
            "timed_out": False,
            "timeout_seconds": timeout,
            "duration_ms": 1,
            "selected_environment": {
                "TINYZKP_DISK_FULL_SCRATCH": "<runner-owned-disk-full-scratch>"
            },
            "disk_full_contract": disk_contract,
            "disk_full_contract_verified": True,
            "disk_full_enospc_observed": True,
            "proof_blake3_hex": digest,
            "reference_proof_blake3_hex": digest,
            "proof_bytes_equal": True,
            "log_file": disk_log.name,
            "log_bytes": len(disk_log.read_bytes()),
            "log_sha256": hashlib.sha256(disk_log.read_bytes()).hexdigest(),
            "test_execution": gate.run_crash_matrix.parse_test_execution(
                disk_payload, disk_test_name
            ),
        }
    )
    artifacts.append(artifact_descriptor(disk_log, "crash_log_disk_full_resume"))
    write_json(report, {**report_body, "cases": cases})
    assert (
        gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
        == []
    )

    shared_artifacts = list(artifacts)
    first_path, first_descriptor = shared_artifacts[0]
    second_role = shared_artifacts[1][1]["role"]
    shared_artifacts[1] = (
        first_path,
        {"role": second_role, "sha256": first_descriptor["sha256"]},
    )
    assert any(
        "reuses a log artifact path" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *shared_artifacts], release_sha
        )
    )
    assert any(
        "reuses log artifact bytes" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *shared_artifacts], release_sha
        )
    )

    phase_case = cases[0]
    phase_log = artifacts[0][0]
    original_phase_payload = phase_log.read_bytes()
    duplicate_marker = (
        f"tinyzkp-crash-proof phase={phase_case['phase']} "
        f"resumed={phase_case['proof_blake3_hex']} "
        f"reference={phase_case['reference_proof_blake3_hex']}\n"
    ).encode()
    phase_log.write_bytes(original_phase_payload + duplicate_marker)
    phase_case["log_bytes"] = len(phase_log.read_bytes())
    phase_case["log_sha256"] = hashlib.sha256(phase_log.read_bytes()).hexdigest()
    replace_artifact(artifacts, phase_log, f"crash_log_{phase_case['case']}")
    write_json(report, report_body)
    assert any(
        "checkpoint phase/proof evidence is incomplete" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    phase_log.write_bytes(original_phase_payload)
    phase_case["log_bytes"] = len(original_phase_payload)
    phase_case["log_sha256"] = hashlib.sha256(original_phase_payload).hexdigest()
    replace_artifact(artifacts, phase_log, f"crash_log_{phase_case['case']}")

    phase_case["duration_ms"] = True
    write_json(report, report_body)
    assert any(
        "case did not run exactly once" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    phase_case["duration_ms"] = 1
    phase_case["unexpected"] = "closed-schema"
    write_json(report, report_body)
    assert any(
        "case did not run exactly once" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    phase_case.pop("unexpected")

    disk_contract["mount_device"] = "07:1"
    write_json(report, report_body)
    assert any(
        "disk-full crash/resume evidence" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    disk_contract["mount_device"] = "7:1"

    report_body["unexpected"] = "closed-schema"
    write_json(report, report_body)
    assert "crash matrix identity or completion status is invalid" in (
        gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    report_body.pop("unexpected")

    tool_path = next(
        path
        for path, descriptor in artifacts
        if descriptor["role"] == "crash_tool_identity"
    )
    original_tool_payload = tool_path.read_bytes()
    original_tool_fields = {
        name: report_body[name]
        for name in (
            "tool_identity_file",
            "tool_identity_bytes",
            "tool_identity_sha256",
        )
    }
    tool_record = json.loads(original_tool_payload)
    tool_record["cargo_version_command"][-1] = "--version"
    skewed_tool_payload = gate.evidence_runtime.pretty_json_bytes(tool_record)
    tool_path.write_bytes(skewed_tool_payload)
    report_body.update(
        tool_identity_bytes=len(skewed_tool_payload),
        tool_identity_sha256=hashlib.sha256(skewed_tool_payload).hexdigest(),
    )
    replace_artifact(artifacts, tool_path, "crash_tool_identity")
    write_json(report, report_body)
    assert "tool identity artifact is incomplete, noncanonical, or skewed" in (
        gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )
    tool_path.write_bytes(original_tool_payload)
    report_body.update(original_tool_fields)
    replace_artifact(artifacts, tool_path, "crash_tool_identity")
    write_json(report, report_body)
    assert (
        gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
        == []
    )

    cases[-1]["disk_full_enospc_observed"] = False
    write_json(report, {**report_body, "cases": cases})
    assert any(
        "disk-full crash/resume evidence" in failure
        for failure in gate.validate_crash_matrix(
            [(report, {"role": "crash_matrix"}), *artifacts], release_sha
        )
    )


def test_runtime_identity_rejects_partial_source_environment_and_tool_skew():
    release_sha = source_release_sha()
    report = runtime_identity(release_sha)
    assert (
        gate.validate_runtime_identity(
            report,
            release_sha,
            cargo_release="1.95.0",
            cargo_commit=gate.RELEASE_CARGO_COMMIT,
            rustc_release="1.95.0",
            rustc_commit=gate.RELEASE_RUSTC_COMMIT,
        )
        == []
    )

    report["partial"] = True
    report["source_tree_sha256"] = "0" * 64
    report["environment_policy_sha256"] = "1" * 64
    report["cargo_identity"]["version"] = (
        "cargo 1.95.0\nrelease: 1.95.0\ncommit-hash: " + "2" * 40
    )
    failures = gate.validate_runtime_identity(
        report,
        release_sha,
        cargo_release="1.95.0",
        cargo_commit=gate.RELEASE_CARGO_COMMIT,
        rustc_release="1.95.0",
        rustc_commit=gate.RELEASE_RUSTC_COMMIT,
    )
    assert "runtime source/environment identity is incomplete or skewed" in failures
    assert "runtime Cargo identity is incomplete or unpinned" in failures


def fuzz_log(name, *, seconds=60, executed_units=120_000, peak_rss_mb=128):
    corpus = gate.run_fuzz_smoke.expected_corpus_descriptor(name)
    marker = gate.run_fuzz_smoke.target_marker_line(
        gate.run_fuzz_smoke.expected_target_marker(
            name, corpus["corpus_sha256"]
        )
    ).decode("ascii")
    return (
        marker
        + f"#{executed_units}\tDONE   cov: 1 ft: 1 corp: 1/1b lim: 4 "
        f"exec/s: 1 rss: {peak_rss_mb}Mb\n"
        f"Done {executed_units} runs in {seconds} second(s)\n"
        f"stat::number_of_executed_units: {executed_units}\n"
        "stat::average_exec_per_sec: 2000\n"
        f"stat::peak_rss_mb: {peak_rss_mb}\n"
    ).encode()


def fuzz_target(name):
    corpus = gate.run_fuzz_smoke.expected_corpus_descriptor(name)
    marker = gate.run_fuzz_smoke.expected_target_marker(
        name, corpus["corpus_sha256"]
    )
    target_root = "raw-reports/fuzz-logs"
    evidence_root = "raw-reports"
    target_triple = "x86_64-unknown-linux-gnu"
    binary_path = f"{evidence_root}/cargo-target/{target_triple}/release/{name}"
    return {
        "target": name,
        "build_command": [
            "/tool/cargo-fuzz",
            "build",
            "--target",
            target_triple,
            "--target-dir",
            f"{evidence_root}/cargo-target",
            name,
        ],
        "build_exit_status": 0,
        "build_timed_out": False,
        "build_timeout_seconds": 900,
        "build_duration_ms": 10_000,
        "run_command": [
            binary_path,
            "-max_total_time=60",
            "-rss_limit_mb=2048",
            "-timeout=60",
            f"-artifact_prefix={target_root}/artifacts/{name}/",
            "-print_final_stats=1",
            f"{target_root}/execution-corpus/{name}",
            f"{target_root}/smoke-corpus/{name}",
        ],
        "fuzz_binary": {
            "path": binary_path,
            "bytes": 1024,
            "sha256": "f" * 64,
            "descriptor_execution": True,
        },
        "exit_status": 0,
        "timed_out": False,
        "timeout_seconds": 960,
        "duration_ms": 60_000,
        "log_bytes": len(fuzz_log(name)),
        "log_file": f"{name}.log",
        "smoke_seed_count": corpus["seed_count"],
        "smoke_corpus_sha256": corpus["corpus_sha256"],
        "smoke_corpus": corpus,
        "target_marker": marker,
        "log_sha256": "b" * 64,
        "artifacts": [],
        "libfuzzer_done": True,
        "done_executed_units": 120_000,
        "libfuzzer_elapsed_seconds": 60,
        "executed_units": 120_000,
        "peak_rss_mb": 128,
    }


def fuzz_report(release_sha, targets):
    identity = runtime_identity(release_sha, fuzz=True)
    return {
        "schema_version": 2,
        **identity,
        "profile": "tinyzkp-p3-goldilocks-v1",
        "toolchain": gate.FUZZ_TOOLCHAIN,
        "rustc_version": identity["rustc_identity"]["version"],
        "cargo_fuzz_version": "cargo-fuzz 0.13.2",
        "cargo_fuzz_identity": {
            "path": "/tool/cargo-fuzz",
            "sha256": "e" * 64,
            "version": "cargo-fuzz 0.13.2",
        },
        "sanitizer": gate.run_fuzz_smoke.FUZZ_SANITIZER,
        "sanitizer_runtime_environment": {
            "ASAN_OPTIONS": gate.run_fuzz_smoke.FUZZ_ASAN_OPTIONS
        },
        "execution_boundary": {
            "kind": "landlock-write-deny-v1",
            "abi_version": 3,
            "source_write_allowed": False,
            "descriptor_execution": True,
            "build_writable_roots": ["cargo-target", "tmp"],
            "run_writable_roots": ["tmp"],
            "target_scoped_writes": ["execution-corpus", "artifacts"],
        },
        "fuzz_dependency_lock_sha256": gate.evidence_runtime.commit_file_sha256(
            gate.ROOT, release_sha, "fuzz/Cargo.lock"
        ),
        "seconds_per_target": 60,
        "startup_timeout_seconds": 900,
        "release_eligible": True,
        "all_targets_passed": True,
        "targets": targets,
    }


def test_fuzz_smoke_requires_every_bounded_reproducible_target(tmp_path):
    release_sha = source_release_sha()
    report = tmp_path / "fuzz.json"
    targets = [fuzz_target(name) for name in sorted(gate.FUZZ_TARGETS)]
    log_artifacts = []
    for target in targets:
        log = tmp_path / target["log_file"]
        log.write_bytes(fuzz_log(target["target"]))
        target["log_bytes"] = len(log.read_bytes())
        target["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        log_artifacts.append(
            artifact_descriptor(log, f"fuzz_log_{target['target']}")
        )
    report_body = fuzz_report(release_sha, targets)
    tool_artifact = attach_tool_identity(tmp_path, report_body, fuzz=True)
    write_json(report, report_body)
    artifacts = [
        (report, {"role": "fuzz_smoke"}),
        tool_artifact,
        *log_artifacts,
    ]
    assert gate.validate_fuzz_smoke(artifacts, release_sha) == []

    shared_artifacts = list(artifacts)
    first_log_index = 2
    second_log_index = 3
    first_path, first_descriptor = shared_artifacts[first_log_index]
    second_role = shared_artifacts[second_log_index][1]["role"]
    shared_artifacts[second_log_index] = (
        first_path,
        {"role": second_role, "sha256": first_descriptor["sha256"]},
    )
    assert any(
        "reuses a log artifact path" in failure
        for failure in gate.validate_fuzz_smoke(shared_artifacts, release_sha)
    )
    assert any(
        "reuses log artifact bytes" in failure
        for failure in gate.validate_fuzz_smoke(shared_artifacts, release_sha)
    )

    original_paths = [targets[0]["run_command"][index] for index in (4, 6, 7)]
    name = targets[0]["target"]
    targets[0]["run_command"][4] = f"-artifact_prefix=unrelated/fuzz/artifacts/{name}/"
    targets[0]["run_command"][6] = f"unrelated/fuzz/execution-corpus/{name}"
    targets[0]["run_command"][7] = f"unrelated/fuzz/smoke-corpus/{name}"
    write_json(report, report_body)
    assert "fuzz smoke commands do not share one canonical log root" in (
        gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    for index, original in zip((4, 6, 7), original_paths, strict=True):
        targets[0]["run_command"][index] = original

    first_target = targets[0]
    first_log = log_artifacts[0][0]
    original_log_payload = first_log.read_bytes()
    first_log.write_bytes(
        original_log_payload
        + gate.run_fuzz_smoke.target_marker_line(first_target["target_marker"])
    )
    first_target["log_bytes"] = len(first_log.read_bytes())
    first_target["log_sha256"] = hashlib.sha256(first_log.read_bytes()).hexdigest()
    replace_artifact(artifacts, first_log, f"fuzz_log_{first_target['target']}")
    write_json(report, report_body)
    assert any(
        "did not pass reproducibly" in failure
        for failure in gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    first_log.write_bytes(original_log_payload)
    first_target["log_bytes"] = len(original_log_payload)
    first_target["log_sha256"] = hashlib.sha256(original_log_payload).hexdigest()
    replace_artifact(artifacts, first_log, f"fuzz_log_{first_target['target']}")

    first_target["duration_ms"] = True
    write_json(report, report_body)
    assert any(
        "did not pass reproducibly" in failure
        for failure in gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    first_target["duration_ms"] = 60_000
    first_target["unexpected"] = "closed-schema"
    write_json(report, report_body)
    assert any(
        "did not pass reproducibly" in failure
        for failure in gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    first_target.pop("unexpected")

    report_body["unexpected"] = "closed-schema"
    write_json(report, report_body)
    assert "fuzz smoke identity or completion status is invalid" in (
        gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    report_body.pop("unexpected")

    tool_path = tool_artifact[0]
    original_tool_payload = tool_path.read_bytes()
    original_tool_fields = {
        key: report_body[key]
        for key in (
            "tool_identity_file",
            "tool_identity_bytes",
            "tool_identity_sha256",
        )
    }
    tool_record = json.loads(original_tool_payload)
    tool_record["rustc_version_command"][-1] = "--version"
    skewed_tool_payload = gate.evidence_runtime.pretty_json_bytes(tool_record)
    tool_path.write_bytes(skewed_tool_payload)
    report_body.update(
        tool_identity_bytes=len(skewed_tool_payload),
        tool_identity_sha256=hashlib.sha256(skewed_tool_payload).hexdigest(),
    )
    replace_artifact(artifacts, tool_path, "fuzz_tool_identity")
    write_json(report, report_body)
    assert "tool identity artifact is incomplete, noncanonical, or skewed" in (
        gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    tool_path.write_bytes(original_tool_payload)
    report_body.update(original_tool_fields)
    replace_artifact(artifacts, tool_path, "fuzz_tool_identity")
    write_json(report, report_body)
    assert gate.validate_fuzz_smoke(artifacts, release_sha) == []

    log_artifacts[0][0].write_bytes(b"claimed success without libFuzzer statistics\n")
    assert any(
        "did not pass reproducibly" in failure
        for failure in gate.validate_fuzz_smoke(artifacts, release_sha)
    )
    log_artifacts[0][0].write_bytes(fuzz_log(targets[0]["target"]))

    report_body["targets"] = targets[:-1]
    write_json(report, report_body)
    assert gate.validate_fuzz_smoke(artifacts, release_sha) == [
        f"required fuzz smoke target is missing: {targets[-1]['target']}"
    ]


def test_active_fuzz_boundary_matches_runner_and_review_bundle():
    expected = set(gate.run_fuzz_smoke.TARGETS)
    assert gate.FUZZ_TARGETS == expected
    assert set(gate.build_review_bundle.FUZZ_TARGETS) == expected
    assert {"air_proof_bundle_v1", "public_inputs_v1"} <= expected
    assert {"hosted_proof_bundle_v1", "beta_api_request_v1"}.isdisjoint(expected)


def test_fuzz_smoke_rejects_unbounded_or_noncanonical_evidence(tmp_path):
    release_sha = source_release_sha()
    report = tmp_path / "fuzz.json"
    targets = [fuzz_target(name) for name in sorted(gate.FUZZ_TARGETS)]
    targets[0]["smoke_seed_count"] = gate.FUZZ_SMOKE_SEED_LIMIT + 1
    targets[1]["smoke_corpus_sha256"] = "A" * 64
    targets[2]["run_command"][1] = 42
    targets[3]["duration_ms"] = True
    unknown = fuzz_target(sorted(gate.FUZZ_TARGETS)[0])
    unknown["target"] = "unknown_target"
    unknown["build_command"][6] = "unknown_target"
    targets.append(unknown)
    write_json(report, fuzz_report(release_sha, targets))
    failures = gate.validate_fuzz_smoke([(report, {"role": "fuzz_smoke"})], release_sha)
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
            "dependency_lock_sha256": "0e9a8928370fdd4c4218a98a642f734e955d3801ade78f52ebec31ddbcd18a78",
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
            "storage_total_bytes": 1_000_000_000_000,
            "storage_available_bytes": 500_000_000_000,
            "scratch_directory_mode": 0o700,
            "scratch_owned_by_runner": True,
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
            "cpu_seconds": 1,
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
            "signer_id": "partner-signer",
        },
    )
    artifacts.append((acceptance, {"role": "acceptance_record"}))
    assert (
        gate.validate_partner_evidence(
            artifacts,
            "abc",
            {
                "partner_acceptance_id": "acceptance-1",
                "signer_id": "partner-signer",
            },
        )
        == []
    )
