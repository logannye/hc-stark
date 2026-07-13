import customer_cubic8
import run_customer_cubic8 as runner
import validate_customer_cubic8 as validator


def test_air_is_valid_shape_and_exercises_degree_three_boundaries():
    air = customer_cubic8.build_air()
    assert air["trace_width"] == 8
    assert len(air["public_inputs"]) == 16
    assert {item["kind"] for item in air["constraints"]} == {"first_row", "transition", "last_row"}
    assert sum(item["op"] == "mul" for item in air["expressions"]) == 16


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


def test_validator_enforces_public_beta_thresholds():
    validator.validate(
        report(1_048_576, "reference", 4_000, 100),
        report(1_048_576, "bounded", 1_000, 300),
        report(16_777_216, "bounded", 2 * 1024**3, 1_000),
    )


def test_fixed_host_runner_freezes_bounded_policy():
    assert runner.BOUNDED_RESIDENT_CAP_BYTES == 512 * 1024**2
    assert runner.BOUNDED_MAX_THREADS == 2
    assert validator.BOUNDED_RESIDENT_CAP_BYTES == runner.BOUNDED_RESIDENT_CAP_BYTES
    assert validator.BOUNDED_MAX_THREADS == runner.BOUNDED_MAX_THREADS
