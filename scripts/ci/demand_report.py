#!/usr/bin/env python3
"""Aggregate the shape-only `demand_log` D1 table and state the kill-criterion
verdict for the hosted-estimator strategy.

This is the report the whole "hosted estimator" phase exists to produce:
without it there is no cheap way to evaluate the project's pre-committed kill
criterion, and the business would instead be decided by months of
speculative engineering instead of 90 days of measured demand.

Design commitments this file exists to keep honest, not just measure:

* Keyed organizations and approximate anonymous sources are counted and
  reported SEPARATELY and are NEVER summed into one "distinct callers"
  number. `key_id` identifies a real (if free) registered organization
  (Task 5); `anon_ip_hash` is a salted, coarse proxy for a distinct
  anonymous IP -- NAT and rotating IPs mean it both over- and
  under-counts real distinct callers. Summing the two would flatter the
  measured number in exactly the direction that defeats the point of
  measuring it, so the schema and this report keep them apart everywhere,
  including in the kill-criterion verdict itself (which is computed from
  keyed organizations alone).

* Blocking-reason codes -- the signal for "which profile/feature should
  we build next" -- are ranked by the number of DISTINCT callers that hit
  each code, never by raw row count. One caller retrying the same
  unsupported config fifty times must not outvote fifteen distinct
  callers who each tried it once. Distinct-keyed-organization count and
  distinct-approximate-anonymous-source count are reported side by side
  per reason code (again, never summed into one figure) and the ranking
  sorts on the keyed count first, the anonymous count second -- so the
  ranking is meaningful even before Task 5 ships keys (when every code's
  keyed count is 0 and the ranking is driven entirely by the anonymous,
  approximate signal), and becomes more authoritative as keyed traffic
  accrues.

* The verdict is stated outright as `CONTINUE` or `KILL_THRESHOLD_MET`
  rather than left as bare numbers for a reader to interpret favourably.
  The frozen threshold: fewer than 15 distinct KEYED organizations in the
  trailing 90-day window means `KILL_THRESHOLD_MET`. Anonymous traffic
  never counts toward this threshold, by design -- see above.

Until Task 5 ships free keys, every `demand_log` row's `key_id` is NULL (see
site/_worker.js), so `distinct_keyed_organizations` will read 0 and every
report will show `KILL_THRESHOLD_MET` -- that is the expected, honest state
of an unstarted clock, not a bug in this script.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

DEFAULT_WINDOW_DAYS = 90
KILL_THRESHOLD_ORGANIZATIONS = 15  # fewer than this distinct KEYED orgs in the window => KILL_THRESHOLD_MET
TOP_REQUEST_DIGESTS_LIMIT = 20

VERDICT_CONTINUE = "CONTINUE"
VERDICT_KILL = "KILL_THRESHOLD_MET"


def connect_readonly(db_path: Path) -> sqlite3.Connection:
    """Open `db_path` read-only; this report never writes to the demand log."""
    uri = f"file:{db_path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def window_start_hour(now: int, window_days: int) -> int:
    """The earliest `observed_at_hour` still inside the trailing window."""
    cutoff = now - window_days * 86400
    return (cutoff // 3600) * 3600


def _blocking_reason_codes(raw: Any) -> list[str]:
    if not raw:
        return []
    try:
        codes = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(codes, list):
        return []
    return [code for code in codes if isinstance(code, str)]


def build_report(
    conn: sqlite3.Connection,
    *,
    now: int | None = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    cutoff_hour = window_start_hour(now, window_days)

    rows = conn.execute(
        """
        SELECT key_id, anon_ip_hash, request_digest, blocking_reason_codes
        FROM demand_log
        WHERE observed_at_hour >= ?
        """,
        (cutoff_hour,),
    ).fetchall()

    keyed_organizations: set[str] = set()
    anonymous_sources: set[str] = set()
    digest_counts: dict[str, int] = {}
    # code -> {"keyed_organizations": set(...), "anonymous_sources": set(...), "request_count": int}
    reason_stats: dict[str, dict[str, Any]] = {}

    for row in rows:
        key_id = row["key_id"]
        anon_hash = row["anon_ip_hash"]
        if key_id:
            keyed_organizations.add(key_id)
        if anon_hash:
            anonymous_sources.add(anon_hash)

        digest = row["request_digest"]
        if digest:
            digest_counts[digest] = digest_counts.get(digest, 0) + 1

        for code in _blocking_reason_codes(row["blocking_reason_codes"]):
            stats = reason_stats.setdefault(
                code,
                {"keyed_organizations": set(), "anonymous_sources": set(), "request_count": 0},
            )
            stats["request_count"] += 1
            if key_id:
                stats["keyed_organizations"].add(key_id)
            elif anon_hash:
                stats["anonymous_sources"].add(anon_hash)

    top_request_digests = [
        {"request_digest": digest, "request_count": count}
        for digest, count in sorted(digest_counts.items(), key=lambda item: (-item[1], item[0]))[
            :TOP_REQUEST_DIGESTS_LIMIT
        ]
    ]

    blocking_reason_codes = [
        {
            "code": code,
            "distinct_keyed_organizations": len(stats["keyed_organizations"]),
            "distinct_approximate_anonymous_sources": len(stats["anonymous_sources"]),
            "request_count": stats["request_count"],
        }
        for code, stats in reason_stats.items()
    ]
    # Ranked by distinct organization, never by raw request count: keyed
    # count first (the confirmed signal), approximate anonymous count as
    # the tiebreaker (so the ranking is still meaningful before any keyed
    # traffic exists), request count only decides ties of ties.
    blocking_reason_codes.sort(
        key=lambda entry: (
            -entry["distinct_keyed_organizations"],
            -entry["distinct_approximate_anonymous_sources"],
            -entry["request_count"],
            entry["code"],
        )
    )

    distinct_keyed_organizations = len(keyed_organizations)
    verdict = VERDICT_KILL if distinct_keyed_organizations < KILL_THRESHOLD_ORGANIZATIONS else VERDICT_CONTINUE

    return {
        "schema_version": 1,
        "generated_at": now,
        "window_days": window_days,
        "window_start_hour": cutoff_hour,
        # Reported separately and NEVER summed: anonymous attribution is
        # approximate, and blending them would flatter the measured number.
        "distinct_keyed_organizations": distinct_keyed_organizations,
        "distinct_approximate_anonymous_sources": len(anonymous_sources),
        "top_request_digests": top_request_digests,
        "blocking_reason_codes": blocking_reason_codes,
        "kill_threshold_organizations": KILL_THRESHOLD_ORGANIZATIONS,
        "verdict": verdict,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--db",
        type=Path,
        required=True,
        help="Path to a SQLite file with the demand_log schema (migrations/0001_demand_log.sql)",
    )
    parser.add_argument("--window-days", type=int, default=DEFAULT_WINDOW_DAYS)
    parser.add_argument(
        "--now",
        type=int,
        default=None,
        help="Override 'now' as unix seconds, for reproducible reports; defaults to the current time",
    )
    args = parser.parse_args(argv)

    if not args.db.is_file():
        print(f"demand_report: no such database file: {args.db}", file=sys.stderr)
        return 1

    conn = connect_readonly(args.db)
    try:
        report = build_report(conn, now=args.now, window_days=args.window_days)
    finally:
        conn.close()

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
