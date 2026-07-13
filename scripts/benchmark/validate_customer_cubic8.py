#!/usr/bin/env python3
"""Validate customer_cubic8 fixed-host public-beta evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or value.get("workload_id") != "customer_cubic8":
        raise ValueError(f"invalid customer_cubic8 report: {path}")
    if value.get("official_verification") is not True:
        raise ValueError(f"proof was not officially verified: {path}")
    return value


def validate(reference_1m: dict[str, object], bounded_1m: dict[str, object], bounded_16m: dict[str, object]) -> None:
    if reference_1m["logical_rows"] != 1_048_576 or bounded_1m["logical_rows"] != 1_048_576:
        raise ValueError("1M row evidence is missing")
    if bounded_16m["logical_rows"] != 16_777_216:
        raise ValueError("16M row evidence is missing")
    releases = {reference_1m["release_sha"], bounded_1m["release_sha"], bounded_16m["release_sha"]}
    if len(releases) != 1 or not GIT_SHA.fullmatch(str(next(iter(releases)))):
        raise ValueError("release identity mismatch")
    if (
        reference_1m.get("mode") != "reference"
        or bounded_1m.get("mode") != "bounded"
        or bounded_16m.get("mode") != "bounded"
    ):
        raise ValueError("customer_cubic8 mode identity is invalid")
    for report in (reference_1m, bounded_1m, bounded_16m):
        if (
            report.get("effective_cpu_count") != 8
            or not 15 * 1024**3
            <= int(report.get("effective_memory_bytes", 0))
            <= 17 * 1024**3
            or report.get("effective_swap_bytes") != 0
        ):
            raise ValueError("customer_cubic8 report is outside the fixed-host envelope")
        if not SHA256.fullmatch(str(report.get("proof_digest_hex"))):
            raise ValueError("customer_cubic8 proof digest is malformed")
    if reference_1m["proof_digest_hex"] != bounded_1m["proof_digest_hex"]:
        raise ValueError("reference and bounded proof bytes differ")
    if int(reference_1m["peak_resident_bytes"]) < 4 * int(bounded_1m["peak_resident_bytes"]):
        raise ValueError("bounded 1M RSS improvement is below 4x")
    if int(bounded_1m["wall_time_ms"]) > 3 * int(reference_1m["wall_time_ms"]):
        raise ValueError("bounded 1M wall time exceeds 3x baseline")
    if int(bounded_16m["peak_resident_bytes"]) > 2 * 1024**3:
        raise ValueError("bounded 16M peak RSS exceeds 2 GiB")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-1m", type=Path, required=True)
    parser.add_argument("--bounded-1m", type=Path, required=True)
    parser.add_argument("--bounded-16m", type=Path, required=True)
    args = parser.parse_args()
    validate(load(args.reference_1m), load(args.bounded_1m), load(args.bounded_16m))
    print("PASS customer_cubic8 fixed-host evidence")


if __name__ == "__main__":
    main()
