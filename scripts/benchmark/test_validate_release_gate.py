import validate_release_gate as gate


def fixtures(rows=1_048_576):
    manifest = {
        "logical_rows": rows,
        "resource_policy": {"max_resident_bytes": 2_000},
    }
    common = {
        "schema_version": 1,
        "scope": "full_pipeline",
        "dependency_profile": gate.PROFILE,
        "release_sha": "abc",
        "workload_manifest_digest_hex": "00" * 32,
        "verification_succeeded": True,
        "exit_status": 0,
        "scratch_high_water_bytes": 900,
    }
    baseline = {**common, "mode": "baseline", "peak_rss_bytes": 2_000, "wall_time_ms": 1_000}
    candidate = {**common, "mode": "bounded", "peak_rss_bytes": 500, "wall_time_ms": 3_000}
    return manifest, baseline, candidate


def test_one_million_accepts_boundary_values():
    manifest, baseline, candidate = fixtures()
    assert gate.validate_gate("one-million", manifest, baseline, candidate) == []


def test_one_million_rejects_inflated_claims():
    manifest, baseline, candidate = fixtures()
    candidate["peak_rss_bytes"] = 600
    candidate["wall_time_ms"] = 3_001
    failures = gate.validate_gate("one-million", manifest, baseline, candidate)
    assert "one-million gate requires at least 4x RAM reduction" in failures
    assert "one-million gate requires candidate wall time within 3x baseline" in failures


def test_ten_million_requires_scratch_estimate_and_two_gib_ceiling():
    manifest, baseline, candidate = fixtures(10_000_000)
    manifest["resource_policy"]["max_resident_bytes"] = 2 * 1024**3
    candidate["peak_rss_bytes"] = 2 * 1024**3
    assert gate.validate_gate(
        "ten-million",
        manifest,
        baseline,
        candidate,
        preflight_scratch_estimate=1_000,
    ) == []
    failures = gate.validate_gate("ten-million", manifest, baseline, candidate)
    assert "ten-million gate requires a positive preflight scratch estimate" in failures
