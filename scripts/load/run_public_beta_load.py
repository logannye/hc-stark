#!/usr/bin/env python3
"""Run the four-job advertised-concurrency public-beta release test."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import statistics
import time
from typing import Any
import urllib.error
import urllib.request


TERMINAL = {"completed", "cancelled", "platform_failed", "customer_failed"}
MAX_PREDICTED_RSS = 2 * 1024 * 1024 * 1024
MIN_RELEASE_PREDICTED_RSS = MAX_PREDICTED_RSS * 85 // 100
READY_P95_LIMIT_MS = 500.0
READY_MAX_LIMIT_MS = 2_000.0
CONTROL_P95_LIMIT_MS = 1_000.0
CONTROL_MAX_LIMIT_MS = 5_000.0


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("latency sample is empty")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))
    return ordered[index]


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
        raise ValueError("minimum predicted RSS must be between 85% and 100% of the beta limit")
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
        control_latencies.append(latency)
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
        artifact_latencies.append(download_latency)
        if bundle_status != 200 or not isinstance(bundle, dict):
            raise RuntimeError(f"bundle download failed for {job_id}")
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
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path, required=True)
    parser.add_argument("--api-key-env", default="TINYZKP_LOAD_API_KEY")
    args = parser.parse_args()
    token = os.environ.get(args.api_key_env, "")
    if not token:
        raise SystemExit(f"{args.api_key_env} is required")
    scenario = validate_scenario(json.loads(args.scenario.read_text(encoding="utf-8")))
    telemetry = json.loads(args.telemetry.read_text(encoding="utf-8"))
    result = run(scenario, token, args.release_sha, telemetry)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
