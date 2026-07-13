import json
import os

import pytest

import run_customer_cubic8_matrix as matrix


def report(rows, mode, rss, wall, proof="a" * 64):
    return {
        "schema_version": 1,
        "workload_id": "customer_cubic8",
        "logical_rows": rows,
        "mode": mode,
        "release_sha": "b" * 40,
        "effective_cpu_count": 8,
        "effective_memory_bytes": 16 * 1024**3,
        "effective_swap_bytes": 0,
        "policy_resident_bytes": 512 * 1024**2,
        "policy_max_threads": 2,
        "peak_resident_bytes": rss,
        "wall_time_ms": wall,
        "proof_digest_hex": proof,
        "official_verification": True,
    }


def test_report_inventory_is_hash_bound_and_revalidated(tmp_path):
    values = {
        "reference_1m": report(1_048_576, "reference", 4_000, 100),
        "bounded_1m": report(1_048_576, "bounded", 1_000, 250),
        "bounded_16m": report(16_777_216, "bounded", 2 * 1024**3, 1_000),
    }
    descriptors = {}
    for role, value in values.items():
        path = tmp_path / f"{role}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        descriptors[role] = matrix.descriptor(path, tmp_path)
    matrix.validate_reports(descriptors, tmp_path)
    (tmp_path / "bounded_16m.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="digest changed"):
        matrix.validate_reports(descriptors, tmp_path)
