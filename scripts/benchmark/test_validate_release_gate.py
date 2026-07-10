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
        "schema_version": 1,
        "scope": "full_pipeline",
        "benchmark_session_id": "0123456789abcdef0123456789abcdef",
        "hardware": "test-host",
        "logical_cpu_count": 8,
        "total_memory_bytes": 16 * 1024**3,
        "operating_system": "linux",
        "storage": "nvme",
        "storage_device": "259:1:nvme0n1p1",
        "storage_is_rotational": False,
        "storage_is_nvme": True,
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


def test_release_reports_require_the_same_fixed_host_session():
    manifest, baseline, candidate, baseline_normalized, candidate_normalized = fixtures()
    candidate["benchmark_session_id"] = "f" * 32
    candidate["storage_device"] = "259:2:nvme1n1p1"
    candidate["logical_cpu_count"] = 16
    candidate["total_memory_bytes"] = 32 * 1024**3
    candidate["storage_is_nvme"] = False
    failures = gate.validate_gate(
        "one-million",
        manifest,
        baseline,
        candidate,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )
    assert "candidate release host must expose exactly 8 logical CPUs" in failures
    assert "candidate release host is not in the 16-GB memory class" in failures
    assert "candidate release scratch storage is not verified NVMe" in failures
    assert "baseline/candidate benchmark_session_id mismatch" in failures
    assert "baseline/candidate storage_device mismatch" in failures
