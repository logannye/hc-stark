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


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("latency sample is empty")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def validate_scenario(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema_version") != 1:
        raise ValueError("load scenario schema_version must equal 1")
    base = value.get("api_base_url")
    if not isinstance(base, str) or not base.startswith(("https://", "http://127.0.0.1:")):
        raise ValueError("load scenario API URL must be HTTPS or a loopback tunnel")
    jobs = value.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 4:
        raise ValueError("advertised-concurrency evidence requires exactly four jobs")
    keys: set[str] = set()
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
    timeout = value.get("timeout_seconds", 3600)
    poll = value.get("poll_interval_seconds", 5)
    minimum_rss = value.get("minimum_predicted_rss_bytes", 0)
    if not isinstance(timeout, int) or not 60 <= timeout <= 7200:
        raise ValueError("load timeout must be between 60 and 7200 seconds")
    if not isinstance(poll, int) or not 1 <= poll <= 60:
        raise ValueError("load poll interval must be between 1 and 60 seconds")
    if not isinstance(minimum_rss, int) or not 0 <= minimum_rss <= MAX_PREDICTED_RSS:
        raise ValueError("minimum predicted RSS is outside the beta envelope")
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


def run(scenario: dict[str, Any], token: str, release_sha: str) -> dict[str, Any]:
    scenario = validate_scenario(scenario)
    base = scenario["api_base_url"].rstrip("/")
    latencies: list[float] = []
    ready_failures = 0
    started_at = now()

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
        latencies.append(latency)
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
        latencies.append(ready_latency)
        if ready_status != 200:
            ready_failures += 1
        for job_id, item in jobs.items():
            if item["status"] in TERMINAL:
                continue
            status, payload, latency = request_json(
                "GET", f"{base}/v1/proof-jobs/{job_id}", token
            )
            latencies.append(latency)
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
        latencies.append(latency)
        if status != 200 or not isinstance(bundle_response, dict):
            raise RuntimeError(f"bundle authorization failed for {job_id}")
        signed = bundle_response.get("download", {})
        bundle_status, bundle, download_latency = request_json(
            "GET",
            str(signed.get("url")),
            None,
            extra_headers=dict(signed.get("headers", {})),
        )
        latencies.append(download_latency)
        if bundle_status != 200 or not isinstance(bundle, dict):
            raise RuntimeError(f"bundle download failed for {job_id}")
        verify_status, verification, verify_latency = request_json(
            "POST", f"{base}/v1/verify", token, {"bundle": bundle}
        )
        latencies.append(verify_latency)
        if verify_status != 200 or verification.get("valid") is not True:
            raise RuntimeError(f"official verification failed for {job_id}")
        item["bundle"] = {
            "size_bytes": bundle_response.get("size_bytes"),
            "blake3_hex": bundle_response.get("blake3_hex"),
            "official_verification": True,
        }

    me_status, me, me_latency = request_json("GET", f"{base}/v1/me", token)
    latencies.append(me_latency)
    if me_status != 200 or not isinstance(me, dict):
        raise RuntimeError("final credit balance read failed")
    latency_ms = [value * 1000 for value in latencies]
    return {
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": release_sha,
        "started_at": started_at,
        "completed_at": now(),
        "status": "passed",
        "concurrency": 4,
        "ready_failures": ready_failures,
        "jobs": [jobs[key] | {"job_id": key} for key in sorted(jobs)],
        "final_credit_account": me,
        "latency_ms": {
            "samples": len(latency_ms),
            "mean": round(statistics.fmean(latency_ms), 3),
            "p50": round(percentile(latency_ms, 0.50), 3),
            "p95": round(percentile(latency_ms, 0.95), 3),
            "p99": round(percentile(latency_ms, 0.99), 3),
            "max": round(max(latency_ms), 3),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-key-env", default="TINYZKP_LOAD_API_KEY")
    args = parser.parse_args()
    token = os.environ.get(args.api_key_env, "")
    if not token:
        raise SystemExit(f"{args.api_key_env} is required")
    scenario = validate_scenario(json.loads(args.scenario.read_text(encoding="utf-8")))
    result = run(scenario, token, args.release_sha)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
