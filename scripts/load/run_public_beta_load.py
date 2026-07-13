#!/usr/bin/env python3
"""Run the four-job advertised-concurrency public-beta release test."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request
import uuid


TERMINAL = {"completed", "cancelled", "platform_failed", "customer_failed"}
MAX_PREDICTED_RSS = 2 * 1024 * 1024 * 1024
# Scratch DFTs receive at most half the hard resident policy; the other half is
# deliberately reserved for the retained pipeline and runtime. Include the
# bounded prover's 64-MiB accounting floor when selecting a near-limit load.
EFFECTIVE_PREDICTED_RSS_ENVELOPE = MAX_PREDICTED_RSS // 2 + 64 * 1024 * 1024
MIN_RELEASE_PREDICTED_RSS = EFFECTIVE_PREDICTED_RSS_ENVELOPE * 85 // 100
READY_P95_LIMIT_MS = 500.0
READY_MAX_LIMIT_MS = 2_000.0
CONTROL_P95_LIMIT_MS = 1_000.0
CONTROL_MAX_LIMIT_MS = 5_000.0
MAX_PREDICTED_WALL_MS = 60 * 60 * 1000


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        raise ValueError("refusing to replace load scenario or evidence")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("latency sample is empty")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def record_latency(
    operation: str,
    latency: float,
    control_plane: list[float],
    artifact: list[float],
) -> None:
    if operation in {"job_submission", "bundle_download"}:
        artifact.append(latency)
    else:
        control_plane.append(latency)


def validate_scenario(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") != 2:
        raise ValueError("load scenario schema_version must equal 2")
    base = value.get("api_base_url")
    if not isinstance(base, str) or not base.startswith(("https://", "http://127.0.0.1:")):
        raise ValueError("load scenario API URL must be HTTPS or a loopback tunnel")
    jobs = value.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 4:
        raise ValueError("advertised-concurrency evidence requires exactly four jobs")
    keys: set[str] = set()
    air_packages: set[str] = set()
    uploads: set[str] = set()
    for job in jobs:
        if not isinstance(job, dict) or set(job) != {"idempotency_key", "request"}:
            raise ValueError("each load job must contain only idempotency_key and request")
        key = job["idempotency_key"]
        request = job["request"]
        if not isinstance(key, str) or not 16 <= len(key) <= 200 or key in keys:
            raise ValueError("load job idempotency keys must be unique and bounded")
        if not isinstance(request, dict) or set(request) != {
            "air_package_id",
            "upload_id",
            "public_inputs",
        }:
            raise ValueError("load job request shape is invalid")
        keys.add(key)
        air_packages.add(str(request["air_package_id"]))
        uploads.add(str(request["upload_id"]))
    if len(air_packages) != 4 or len(uploads) != 4:
        raise ValueError("load evidence requires four independent AIR packages and uploads")
    timeout = value.get("timeout_seconds", 3600)
    poll = value.get("poll_interval_seconds", 5)
    minimum_rss = value.get("minimum_predicted_rss_bytes", MIN_RELEASE_PREDICTED_RSS)
    if not isinstance(timeout, int) or not 60 <= timeout <= 7200:
        raise ValueError("load timeout must be between 60 and 7200 seconds")
    if not isinstance(poll, int) or not 1 <= poll <= 60:
        raise ValueError("load poll interval must be between 1 and 60 seconds")
    if not isinstance(minimum_rss, int) or not MIN_RELEASE_PREDICTED_RSS <= minimum_rss <= MAX_PREDICTED_RSS:
        raise ValueError(
            "minimum predicted RSS must cover at least 85% of the bounded working-set envelope"
        )
    return value


def validate_telemetry(value: dict[str, Any], release_sha: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "status", "release_sha", "sample_interval_seconds",
        "worker", "postgres",
    }:
        raise ValueError("load telemetry fields are missing or unknown")
    if value["schema_version"] != 1 or value["status"] != "passed" or value["release_sha"] != release_sha:
        raise ValueError("load telemetry identity or status mismatch")
    if not isinstance(value["sample_interval_seconds"], int) or not 1 <= value["sample_interval_seconds"] <= 5:
        raise ValueError("load telemetry must sample at least every five seconds")
    worker = value["worker"]
    expected_worker = {
        "slots": 4, "threads_per_job": 2, "effective_cpus": 8,
        "memory_limit_bytes": 16 * 1024 * 1024 * 1024,
        "swap_bytes": 0, "oom_events": 0, "unexpected_restarts": 0,
        "leaked_scratch_directories": 0,
    }
    if not isinstance(worker, dict) or any(worker.get(key) != expected for key, expected in expected_worker.items()):
        raise ValueError("worker telemetry violates the fixed production envelope")
    if worker.get("max_heartbeat_age_seconds", 61) > 60 or worker.get("max_scratch_utilization_percent", 101) > 70:
        raise ValueError("worker heartbeat or scratch telemetry is outside limits")
    postgres = value["postgres"]
    if not isinstance(postgres, dict) or postgres.get("configured_max_connections") != 40:
        raise ValueError("PostgreSQL telemetry does not use the production limit")
    if postgres.get("max_observed_connections", 41) > 32 or any(
        postgres.get(field, 1) != 0 for field in ("deadlocks", "statement_timeouts", "lock_timeouts")
    ):
        raise ValueError("PostgreSQL load telemetry contains resource or transaction failures")
    return value


def validate_evidence(value: dict[str, Any], release_sha: str) -> dict[str, Any]:
    required = {
        "schema_version", "release_channel", "release_sha", "started_at", "completed_at",
        "status", "concurrency", "ready_failures", "jobs", "initial_credit_account",
        "final_credit_account", "charges", "latency_ms", "telemetry",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("load evidence fields are missing or unknown")
    if (
        value["schema_version"] != 2
        or value["release_channel"] != "public_beta"
        or value["release_sha"] != release_sha
        or value["status"] != "passed"
        or value["concurrency"] != 4
        or value["ready_failures"] != 0
    ):
        raise ValueError("load evidence identity, status, or concurrency mismatch")
    jobs = value["jobs"]
    if not isinstance(jobs, list) or len(jobs) != 4:
        raise ValueError("load evidence requires four jobs")
    for job in jobs:
        result = job.get("result", {})
        submission = job.get("submission", {})
        estimate = submission.get("estimate", {})
        predicted = estimate.get("resources", {}).get("peak_resident_bytes")
        reservation = estimate.get("reservation_millicredits")
        settled = result.get("settled_millicredits")
        if (
            job.get("status") != "completed"
            or job.get("bundle", {}).get("official_verification") is not True
            or job.get("bundle", {}).get("signed_cli_verification") is not True
            or job.get("bundle", {}).get("api_verification") is not True
            or not isinstance(predicted, int)
            or not MIN_RELEASE_PREDICTED_RSS <= predicted <= MAX_PREDICTED_RSS
            or not isinstance(reservation, int)
            or not isinstance(settled, int)
            or settled > reservation
        ):
            raise ValueError("load evidence contains an invalid job result")
    latency = value["latency_ms"]
    ready = latency.get("ready", {}) if isinstance(latency, dict) else {}
    control = latency.get("control_plane", {}) if isinstance(latency, dict) else {}
    if ready.get("p95", READY_P95_LIMIT_MS + 1) > READY_P95_LIMIT_MS or ready.get("max", READY_MAX_LIMIT_MS + 1) > READY_MAX_LIMIT_MS:
        raise ValueError("load evidence readiness latency exceeded limits")
    if control.get("p95", CONTROL_P95_LIMIT_MS + 1) > CONTROL_P95_LIMIT_MS or control.get("max", CONTROL_MAX_LIMIT_MS + 1) > CONTROL_MAX_LIMIT_MS:
        raise ValueError("load evidence control-plane latency exceeded limits")
    if value["charges"].get("residual_reservation_millicredits") != 0:
        raise ValueError("load evidence contains residual reservations")
    validate_telemetry(value["telemetry"], release_sha)
    return value


def signed_cli(release_sha: str) -> Path:
    configured = os.environ.get("TINYZKP_CLI", "").strip()
    if not configured:
        raise RuntimeError("TINYZKP_CLI is required for independent load verification")
    cli = Path(configured).resolve(strict=True)
    completed = subprocess.run(
        [str(cli), "release"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    try:
        identity = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("signed CLI returned an invalid release identity") from error
    if completed.returncode != 0 or identity.get("release_sha") != release_sha:
        raise RuntimeError("signed CLI release identity does not match the load candidate")
    return cli


def verify_bundle_with_signed_cli(cli: Path, bundle: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory(prefix="tinyzkp-load-bundle-") as directory:
        path = Path(directory) / "hosted-bundle.json"
        write_private_json(path, bundle)
        completed = subprocess.run(
            [str(cli), "plonky3", "verify-hosted", "--bundle", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10 * 60,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("signed CLI rejected a hosted load-test bundle")


def parse_candidate_rows(raw: str) -> list[int]:
    try:
        rows = [int(item.strip()) for item in raw.split(",") if item.strip()]
    except ValueError as error:
        raise ValueError("candidate row counts must be comma-separated integers") from error
    if not rows or len(rows) != len(set(rows)):
        raise ValueError("candidate row counts must be non-empty and unique")
    if any(value < 1 << 10 or value > 1 << 24 or value & (value - 1) for value in rows):
        raise ValueError("candidate rows must be powers of two from 2^10 through 2^24")
    return sorted(rows, reverse=True)


def customer_load_variant(fixtures: Any, index: int) -> Any:
    if index not in range(4):
        raise ValueError("load fixture index must be from zero through three")
    original = fixtures.customer_cubic8()
    air = copy.deepcopy(original.air)
    for public_input in air["public_inputs"]:
        public_input["name"] = f"{public_input['name']}_load_{index}"
    return fixtures.Fixture(
        name=f"customer_cubic8_load_{index}",
        air=air,
        initial_state=original.initial_state,
        row=original.row,
        step=original.step,
        public_values=original.public_values,
    )


def predicted_wall_time_ms(air: dict[str, Any], rows: int) -> int:
    expression_work = len(air["expressions"]) + len(air["constraints"]) + int(air["trace_width"])
    return max(1_000, (rows * expression_work + 49_999) // 50_000)


def prepare_scenario(
    *,
    release_sha: str,
    output: Path,
    state_dir: Path,
    candidate_rows: list[int],
    api_key_env: str,
    retain_state: bool,
) -> dict[str, Any]:
    if len(release_sha) != 40 or any(character not in "0123456789abcdef" for character in release_sha):
        raise ValueError("release SHA must be a full lowercase Git commit")
    canary = Path(__file__).resolve().parents[1] / "canary"
    sys.path.insert(0, str(canary))
    try:
        import declarative_fixtures
        import hc_beta_e2e
    finally:
        sys.path.pop(0)
    cli_value = os.environ.get("TINYZKP_CLI", "").strip()
    api_url = os.environ.get("TINYZKP_API_URL", "").strip()
    token = os.environ.get(api_key_env, "").strip()
    if not cli_value or not api_url or not token:
        raise ValueError("TINYZKP_CLI, TINYZKP_API_URL, and the configured load API key are required")
    cli = Path(cli_value).resolve(strict=True)
    resolved_output = output.resolve()
    resolved_state = state_dir.resolve()
    if resolved_output == resolved_state or resolved_state in resolved_output.parents:
        raise ValueError("load scenario output must remain outside disposable preparation state")
    identity = hc_beta_e2e.run([str(cli), "release"], expect_json=True)
    if not isinstance(identity, dict) or identity.get("release_sha") != release_sha:
        raise ValueError("signed CLI release identity does not match the load candidate")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(state_dir, 0o700)
    client = hc_beta_e2e.ApiClient(api_url, token)
    prepared: list[tuple[Any, dict[str, Any], Path]] = []
    selected_rows: int | None = None
    try:
        first = customer_load_variant(declarative_fixtures, 0)
        for rows in candidate_rows:
            candidate_root = state_dir / f"candidate-{rows}"
            candidate_root.mkdir(mode=0o700)
            statement = hc_beta_e2e.prepare_statement(cli, first, rows, candidate_root)
            estimate = hc_beta_e2e.run(
                [
                    str(cli), "plonky3", "estimate-air",
                    "--air", str(statement["air_path"]),
                    "--trace-manifest", str(Path(statement["hosted_packed"]) / "trace-manifest-v1.json"),
                    "--public-inputs", str(statement["hosted_public_path"]),
                    "--policy", str(candidate_root / "policy.json"),
                ],
                expect_json=True,
            )
            if not isinstance(estimate, dict) or not isinstance(estimate.get("estimate"), dict):
                raise RuntimeError("signed CLI returned malformed load preflight evidence")
            peak = estimate["estimate"].get("peak_resident_bytes")
            wall = predicted_wall_time_ms(first.air, rows)
            if isinstance(peak, int) and MIN_RELEASE_PREDICTED_RSS <= peak <= MAX_PREDICTED_RSS and wall < MAX_PREDICTED_WALL_MS:
                selected_rows = rows
                statement["load_preflight"] = {
                    "resources": estimate["estimate"],
                    "predicted_wall_time_ms": wall,
                }
                prepared.append((first, statement, candidate_root))
                break
            shutil.rmtree(candidate_root)
        if selected_rows is None:
            raise RuntimeError("no candidate row count is within the 85%-to-100% RSS and 60-minute load envelope")

        for index in range(1, 4):
            fixture = customer_load_variant(declarative_fixtures, index)
            root = state_dir / f"load-{index}"
            root.mkdir(mode=0o700)
            statement = hc_beta_e2e.prepare_statement(cli, fixture, selected_rows, root)
            statement["load_preflight"] = prepared[0][1]["load_preflight"]
            prepared.append((fixture, statement, root))

        jobs: list[dict[str, Any]] = []
        for index, (fixture, statement, _root) in enumerate(prepared):
            nonce = uuid.uuid4().hex
            status, registered = client.request(
                "POST",
                "/v1/air-packages",
                {"air": statement["air"], "local_proof": statement["local_proof"]},
                idempotency_key=f"load-air-{release_sha[:12]}-{index}-{nonce}",
            )
            if status != 201:
                raise RuntimeError(f"load AIR registration {index} returned HTTP {status}")
            status, upload = client.request(
                "POST",
                "/v1/uploads",
                {
                    "air_package_id": registered["air_package_id"],
                    "manifest": statement["hosted_manifest"],
                },
                idempotency_key=f"load-upload-{release_sha[:12]}-{index}-{nonce}",
            )
            if status != 201:
                raise RuntimeError(f"load upload creation {index} returned HTTP {status}")
            hc_beta_e2e.upload_chunks(client, upload, Path(statement["hosted_packed"]))
            jobs.append(
                {
                    "idempotency_key": f"load-job-{release_sha[:12]}-{index}-{nonce}",
                    "request": {
                        "air_package_id": registered["air_package_id"],
                        "upload_id": upload["upload_id"],
                        "public_inputs": statement["hosted_public"],
                    },
                }
            )
        scenario = validate_scenario(
            {
                "schema_version": 2,
                "api_base_url": api_url,
                "jobs": jobs,
                "timeout_seconds": 3600,
                "poll_interval_seconds": 5,
                "minimum_predicted_rss_bytes": MIN_RELEASE_PREDICTED_RSS,
            }
        )
        write_private_json(output, scenario)
        return scenario
    finally:
        if not retain_state:
            shutil.rmtree(state_dir, ignore_errors=True)


def request_json(
    method: str,
    url: str,
    token: str | None,
    body: object | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, Any, float]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    raw = None
    if body is not None:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, method=method, data=raw, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(110 * 1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as error:
        payload = error.read(2 * 1024 * 1024)
        status = error.code
    latency = time.monotonic() - started
    decoded = json.loads(payload) if payload else None
    return status, decoded, latency


def run(
    scenario: dict[str, Any], token: str, release_sha: str, telemetry: dict[str, Any]
) -> dict[str, Any]:
    scenario = validate_scenario(scenario)
    cli = signed_cli(release_sha)
    base = scenario["api_base_url"].rstrip("/")
    control_latencies: list[float] = []
    ready_latencies: list[float] = []
    artifact_latencies: list[float] = []
    ready_failures = 0
    started_at = now()

    initial_status, initial_credit, initial_latency = request_json("GET", f"{base}/v1/me", token)
    control_latencies.append(initial_latency)
    if initial_status != 200 or not isinstance(initial_credit, dict):
        raise RuntimeError("initial credit balance read failed")

    def submit(job: dict[str, Any]) -> tuple[int, Any, float]:
        return request_json(
            "POST",
            f"{base}/v1/proof-jobs",
            token,
            job["request"],
            {"Idempotency-Key": job["idempotency_key"]},
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        submissions = list(executor.map(submit, scenario["jobs"]))
    jobs: dict[str, dict[str, Any]] = {}
    for status, payload, latency in submissions:
        # Submission performs the upload's R2 HEAD reconciliation. Keep that
        # object-store work in the artifact latency class so it cannot hide a
        # slow database/auth/control path or falsely fail the control-plane SLO.
        record_latency("job_submission", latency, control_latencies, artifact_latencies)
        if status != 201 or not isinstance(payload, dict):
            raise RuntimeError(f"job submission failed with HTTP {status}: {payload}")
        estimate = payload.get("estimate", {})
        resources = estimate.get("resources", {}) if isinstance(estimate, dict) else {}
        predicted_rss = resources.get("peak_resident_bytes")
        if (
            not isinstance(predicted_rss, int)
            or predicted_rss > MAX_PREDICTED_RSS
            or predicted_rss < scenario.get("minimum_predicted_rss_bytes", 0)
        ):
            raise RuntimeError("submitted job is outside the configured RSS load envelope")
        jobs[str(payload["job_id"])] = {
            "submission": payload,
            "status": payload.get("status"),
        }

    deadline = time.monotonic() + scenario.get("timeout_seconds", 3600)
    while any(item["status"] not in TERMINAL for item in jobs.values()):
        if time.monotonic() >= deadline:
            raise RuntimeError("advertised-concurrency load test timed out")
        ready_status, _, ready_latency = request_json("GET", f"{base}/readyz", None)
        ready_latencies.append(ready_latency)
        if ready_status != 200:
            ready_failures += 1
        for job_id, item in jobs.items():
            if item["status"] in TERMINAL:
                continue
            status, payload, latency = request_json(
                "GET", f"{base}/v1/proof-jobs/{job_id}", token
            )
            control_latencies.append(latency)
            if status != 200 or not isinstance(payload, dict):
                raise RuntimeError(f"job poll failed with HTTP {status}: {payload}")
            item["status"] = payload.get("status")
            item["result"] = payload
        if any(item["status"] not in TERMINAL for item in jobs.values()):
            time.sleep(scenario.get("poll_interval_seconds", 5))

    for job_id, item in jobs.items():
        if item["status"] != "completed":
            raise RuntimeError(f"load job {job_id} terminated as {item['status']}")
        status, bundle_response, latency = request_json(
            "GET", f"{base}/v1/proof-jobs/{job_id}/bundle", token
        )
        control_latencies.append(latency)
        if status != 200 or not isinstance(bundle_response, dict):
            raise RuntimeError(f"bundle authorization failed for {job_id}")
        signed = bundle_response.get("download", {})
        bundle_status, bundle, download_latency = request_json(
            "GET",
            str(signed.get("url")),
            None,
            extra_headers=dict(signed.get("headers", {})),
        )
        record_latency(
            "bundle_download", download_latency, control_latencies, artifact_latencies
        )
        if bundle_status != 200 or not isinstance(bundle, dict):
            raise RuntimeError(f"bundle download failed for {job_id}")
        verify_bundle_with_signed_cli(cli, bundle)
        verify_status, verification, verify_latency = request_json(
            "POST", f"{base}/v1/verify", token, {"bundle": bundle}
        )
        control_latencies.append(verify_latency)
        if verify_status != 200 or verification.get("valid") is not True:
            raise RuntimeError(f"official verification failed for {job_id}")
        item["bundle"] = {
            "size_bytes": bundle_response.get("size_bytes"),
            "blake3_hex": bundle_response.get("blake3_hex"),
            "official_verification": True,
            "signed_cli_verification": True,
            "api_verification": True,
        }
        reservation = item["submission"]["estimate"].get("reservation_millicredits")
        charge = item["result"].get("settled_millicredits")
        if not isinstance(reservation, int) or not isinstance(charge, int) or charge > reservation:
            raise RuntimeError(f"job {job_id} charge exceeds or lacks its reservation")

    me_status, me, me_latency = request_json("GET", f"{base}/v1/me", token)
    control_latencies.append(me_latency)
    if me_status != 200 or not isinstance(me, dict):
        raise RuntimeError("final credit balance read failed")
    initial_total = sum(int(initial_credit.get(field, 0)) for field in ("subscription_millicredits", "purchased_millicredits"))
    final_total = sum(int(me.get(field, 0)) for field in ("subscription_millicredits", "purchased_millicredits"))
    charges = sum(int(item["result"]["settled_millicredits"]) for item in jobs.values())
    if final_total != initial_total - charges:
        raise RuntimeError("final available credit does not equal initial credit minus settled charges")
    if me.get("reserved_millicredits") != initial_credit.get("reserved_millicredits"):
        raise RuntimeError("load jobs left residual reservations")

    def latency_summary(values: list[float]) -> dict[str, float | int]:
        latency_ms = [value * 1000 for value in values]
        return {
            "samples": len(latency_ms),
            "mean": round(statistics.fmean(latency_ms), 3),
            "p50": round(percentile(latency_ms, 0.50), 3),
            "p95": round(percentile(latency_ms, 0.95), 3),
            "p99": round(percentile(latency_ms, 0.99), 3),
            "max": round(max(latency_ms), 3),
        }

    ready_summary = latency_summary(ready_latencies)
    control_summary = latency_summary(control_latencies)
    artifact_summary = latency_summary(artifact_latencies)
    if ready_failures != 0 or ready_summary["p95"] > READY_P95_LIMIT_MS or ready_summary["max"] > READY_MAX_LIMIT_MS:
        raise RuntimeError("readiness latency or availability exceeded the release limit")
    if control_summary["p95"] > CONTROL_P95_LIMIT_MS or control_summary["max"] > CONTROL_MAX_LIMIT_MS:
        raise RuntimeError("control-plane latency exceeded the release limit")
    telemetry = validate_telemetry(telemetry, release_sha)
    return {
        "schema_version": 2,
        "release_channel": "public_beta",
        "release_sha": release_sha,
        "started_at": started_at,
        "completed_at": now(),
        "status": "passed",
        "concurrency": 4,
        "ready_failures": ready_failures,
        "jobs": [jobs[key] | {"job_id": key} for key in sorted(jobs)],
        "initial_credit_account": initial_credit,
        "final_credit_account": me,
        "charges": {
            "settled_millicredits": charges,
            "residual_reservation_millicredits": int(me.get("reserved_millicredits", 0))
            - int(initial_credit.get("reserved_millicredits", 0)),
        },
        "latency_ms": {"ready": ready_summary, "control_plane": control_summary, "artifact": artifact_summary},
        "telemetry": telemetry,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--prepare-scenario", action="store_true")
    parser.add_argument("--prepare-state-dir", type=Path)
    parser.add_argument(
        "--candidate-rows",
        default="16777216,8388608,4194304,2097152,1048576",
    )
    parser.add_argument("--retain-prepared-state", action="store_true")
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path)
    parser.add_argument("--api-key-env", default="TINYZKP_LOAD_API_KEY")
    args = parser.parse_args()
    if args.prepare_scenario:
        if args.scenario is not None or args.telemetry is not None or args.prepare_state_dir is None:
            raise SystemExit("prepare mode requires --prepare-state-dir and forbids --scenario/--telemetry")
        prepare_scenario(
            release_sha=args.release_sha,
            output=args.output,
            state_dir=args.prepare_state_dir,
            candidate_rows=parse_candidate_rows(args.candidate_rows),
            api_key_env=args.api_key_env,
            retain_state=args.retain_prepared_state,
        )
        return
    if args.scenario is None or args.telemetry is None or args.prepare_state_dir is not None:
        raise SystemExit("run mode requires --scenario and --telemetry")
    token = os.environ.get(args.api_key_env, "")
    if not token:
        raise SystemExit(f"{args.api_key_env} is required")
    scenario = validate_scenario(json.loads(args.scenario.read_text(encoding="utf-8")))
    telemetry = json.loads(args.telemetry.read_text(encoding="utf-8"))
    result = run(scenario, token, args.release_sha, telemetry)
    validate_evidence(result, args.release_sha)
    write_private_json(args.output, result)


if __name__ == "__main__":
    main()
