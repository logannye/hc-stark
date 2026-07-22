import validate_release_gate as gate


def fixtures(rows=1_048_576):
    manifest = {
        "logical_rows": rows,
        "resource_policy": {
            "max_resident_bytes": 2_000,
            "scratch_dir": "/source-scratch",
        },
    }
    manifest_digest = gate.canonical_manifest_digest(manifest)
    baseline_normalized = {
        **manifest,
        "resource_policy": {
            **manifest["resource_policy"],
            "scratch_dir": "/run/baseline",
        },
    }
    candidate_normalized = {
        **manifest,
        "resource_policy": {
            **manifest["resource_policy"],
            "scratch_dir": "/run/candidate",
        },
    }
    common = {
        "schema_version": 2,
        "scope": "full_pipeline",
        "benchmark_session_id": "0123456789abcdef0123456789abcdef",
        "hardware": "test-host",
        "physical_logical_cpu_count": 4,
        "physical_memory_bytes": 16 * 1024**3,
        "effective_cpu_count": 4,
        "effective_cpu_affinity": list(range(4)),
        "effective_memory_max_bytes": 16 * 1024**3,
        "effective_swap_max_bytes": 0,
        "cgroup_v2_path": "/tinyzkp-bench",
        "operating_system": "linux",
        "storage": "nvme",
        "storage_device": "259:1:nvme0n1p1",
        "effective_storage_device": "259:1:nvme0n1p1",
        "storage_is_rotational": False,
        "storage_is_nvme": False,
        "storage_total_bytes": 14_000_000_000,
        "storage_available_bytes": 12_000_000_000,
        "scratch_directory_mode": 0o700,
        "scratch_owned_by_runner": True,
        "dependency_profile": gate.PROFILE,
        "release_sha": "abc",
        "exact_command": ["hc-cli", "benchmark"],
        "normalized_manifest_path": "normalized.json",
        "workload_manifest_digest_hex": manifest_digest,
        "normalized_manifest_digest_hex": "",
        "cpu_seconds": 1.0,
        "verification_succeeded": True,
        "exit_status": 0,
        "scratch_high_water_bytes": 900,
        "read_bytes": 1,
        "write_bytes": 1,
        "proof_size_bytes": 1,
        "verification_time_ms": 1,
        "preflight_estimate": {
            "peak_resident_bytes": 500,
            "scratch_high_water_bytes": 1_000,
            "total_read_bytes": 1,
            "total_write_bytes": 1,
            "phases": [],
        },
    }
    baseline = {
        **common,
        "mode": "baseline",
        "peak_rss_bytes": 2_000,
        "cgroup_peak_bytes": 2_000,
        "wall_time_ms": 1_000,
        "normalized_manifest_digest_hex": gate.canonical_manifest_digest(
            baseline_normalized
        ),
    }
    candidate = {
        **common,
        "mode": "bounded",
        "peak_rss_bytes": 500,
        "cgroup_peak_bytes": 500,
        "wall_time_ms": 3_000,
        "normalized_manifest_digest_hex": gate.canonical_manifest_digest(
            candidate_normalized
        ),
    }
    return manifest, baseline, candidate, baseline_normalized, candidate_normalized


def test_one_million_accepts_boundary_values():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures()
    assert gate.validate_gate(
        "one-million",
        manifest,
        baseline,
        candidate,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    ) == []


def test_one_million_rejects_inflated_claims():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures()
    candidate["peak_rss_bytes"] = 600
    candidate["wall_time_ms"] = 3_001
    failures = gate.validate_gate(
        "one-million",
        manifest,
        baseline,
        candidate,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )
    assert "one-million gate requires at least 4x RAM reduction" in failures
    assert "one-million gate requires candidate wall time within 3x baseline" in failures


def test_ten_million_requires_embedded_scratch_estimate_and_two_gib_ceiling():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures(
        16_777_216
    )
    manifest["resource_policy"]["max_resident_bytes"] = 2 * 1024**3
    digest = gate.canonical_manifest_digest(manifest)
    candidate["workload_manifest_digest_hex"] = digest
    candidate_normalized["resource_policy"]["max_resident_bytes"] = 2 * 1024**3
    candidate["normalized_manifest_digest_hex"] = gate.canonical_manifest_digest(
        candidate_normalized
    )
    candidate["peak_rss_bytes"] = 2 * 1024**3
    candidate["cgroup_peak_bytes"] = 2 * 1024**3
    assert gate.validate_gate(
        "ten-million",
        manifest,
        None,
        candidate,
        candidate_normalized=candidate_normalized,
    ) == []
    candidate.pop("preflight_estimate")
    failures = gate.validate_gate(
        "ten-million",
        manifest,
        None,
        candidate,
        candidate_normalized=candidate_normalized,
    )
    assert "ten-million gate requires a positive preflight scratch estimate" in failures


def test_report_release_and_manifest_identity_are_bound():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures()
    candidate["normalized_manifest_digest_hex"] = "00" * 32
    candidate["release_sha"] = "different"
    failures = gate.validate_gate(
        "one-million",
        manifest,
        baseline,
        candidate,
        expected_release_sha="abc",
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )
    assert "candidate normalized manifest digest mismatch" in failures
    assert "candidate release identity does not match evidence" in failures


def test_release_reports_require_the_same_qualification_session():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures()
    candidate["benchmark_session_id"] = "f" * 32
    candidate["storage_device"] = "259:2:nvme1n1p1"
    candidate["effective_cpu_count"] = 3
    candidate["effective_cpu_affinity"] = list(range(3))
    candidate["effective_memory_max_bytes"] = 32 * 1024**3
    candidate["storage_is_nvme"] = None
    candidate["storage_available_bytes"] = 11_999_999_999
    candidate["scratch_directory_mode"] = 0o755
    candidate["scratch_owned_by_runner"] = False
    failures = gate.validate_gate(
        "one-million",
        manifest,
        baseline,
        candidate,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )
    assert "candidate qualification runner must expose exactly 4 effective CPUs" in failures
    assert "candidate qualification runner is not in the 16-GiB memory class" in failures
    assert "candidate qualification scratch storage type is unknown" in failures
    assert (
        "candidate qualification scratch storage must have at least 12 GB available"
        in failures
    )
    assert "candidate release scratch directory must have mode 0700" in failures
    assert (
        "candidate release scratch directory is not owned by the benchmark runner"
        in failures
    )
    assert "baseline/candidate benchmark_session_id mismatch" in failures
    assert "baseline/candidate storage_device mismatch" in failures
