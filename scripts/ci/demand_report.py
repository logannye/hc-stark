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

* The verdict is stated outright as `CONTINUE`, `KILL_THRESHOLD_MET`, or
  `MEASUREMENT_INVALID` rather than left as bare numbers for a reader to
  interpret favourably. The frozen threshold: fewer than 15 distinct KEYED
  organizations in the trailing 90-day window means `KILL_THRESHOLD_MET`.
  Anonymous traffic never counts toward this threshold, by design.

* A kill verdict is withheld until the measurement can produce another
  answer. See `PRECONDITIONS` below: until 2026-07-29 the estimator was in
  no sitemap and no llms.txt, and llms.txt told agents TinyZKP had no proof
  API, so a zero reading was fully explained by zero discoverability. That
  is a NON-RESULT, and retiring a product on it would be retiring it on an
  artifact of its own marketing. `MEASUREMENT_INVALID` names the specific
  unmet precondition instead. The threshold itself is untouched, and
  `CONTINUE` is decided first so real keyed demand still lands immediately.

* Rejected requests are counted (migrations/0003_rejected_log.sql) and
  reported separately from every demand figure. They were previously
  dropped entirely, which made a failed integration attempt -- strong
  evidence someone wanted the tool -- indistinguishable from silence.

The previous version of this docstring carried a caveat explaining that a
zero reading was "the expected, honest state of an unstarted clock" because
free keys had not shipped yet. They shipped in Phase 1b. That caveat was the
only thing preventing a reader from taking a zero at face value, and it had
silently stopped describing reality; the precondition block above replaces
it with something the code actually enforces.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEMAND_CLOCK = ROOT / "release" / "demand-clock-v1.json"

DEFAULT_WINDOW_DAYS = 90
KILL_THRESHOLD_ORGANIZATIONS = 15  # fewer than this distinct KEYED orgs in the window => KILL_THRESHOLD_MET
TOP_REQUEST_DIGESTS_LIMIT = 20

VERDICT_CONTINUE = "CONTINUE"
VERDICT_KILL = "KILL_THRESHOLD_MET"
# Emitted when the measurement is not yet capable of producing any answer
# other than zero. See `evaluate_preconditions` below.
VERDICT_INVALID = "MEASUREMENT_INVALID"

# Discoverability preconditions, each a (name, repo-relative file, required
# substring) triple checked against the repository rather than asserted by
# hand.
#
# Why this exists. The frozen threshold reads "fewer than 15 distinct KEYED
# organizations in 90 days => KILL". For that to be a RESULT, a caller has
# to have been able to find the endpoint and be counted. Until 2026-07-29
# they could not: `/estimate` appeared in no sitemap and no llms.txt, and
# llms.txt actively instructed agents that TinyZKP has no proof API. A zero
# under those conditions is fully explained by zero discoverability, which
# makes it a NON-RESULT -- indistinguishable from "nobody could find it" --
# and firing a kill on it would retire a product on an artifact of its own
# marketing.
#
# So the verdict is gated, NOT the threshold. 15 organizations in 90 days
# stands, anonymous traffic still never counts, and CONTINUE stays reachable
# the moment real keyed demand appears. Only the KILL direction waits for
# the measurement to be able to say something.
PRECONDITIONS: tuple[tuple[str, str, str], ...] = (
    ("estimate_page_in_sitemap", "site/sitemap.xml", "https://tinyzkp.com/estimate"),
    ("estimate_page_in_llms_txt", "site/llms.txt", "https://tinyzkp.com/estimate"),
    ("estimate_api_in_llms_txt", "site/llms.txt", "https://tinyzkp.com/v1/estimate"),
    ("keys_api_in_llms_txt", "site/llms.txt", "https://tinyzkp.com/v1/keys"),
    ("keys_form_on_estimate_page", "site/estimate.html", "data-key-form"),
    ("estimator_documented_in_docs", "site/docs.html", "/v1/estimate"),
    # The estimate page shipped with `noindex,follow`, grouped with the legal
    # pages and the gated SEO landing pages. Being in the sitemap means
    # nothing while the page itself tells crawlers to skip it, so this is a
    # precondition in its own right rather than an implication of the first.
    ("estimate_page_is_indexable", "site/estimate.html", 'content="index,follow"'),
)


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


def evaluate_preconditions(root: Path = ROOT) -> dict[str, bool]:
    """Check each discoverability precondition against the working tree."""
    results: dict[str, bool] = {}
    for name, relative, needle in PRECONDITIONS:
        path = root / relative
        try:
            results[name] = needle in path.read_text(encoding="utf-8")
        except OSError:
            results[name] = False
    return results


def demand_clock_started_at(path: Path = DEMAND_CLOCK) -> str | None:
    """The date discoverability first held, or None if never recorded."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    started = data.get("demand_clock_started_at") if isinstance(data, dict) else None
    return started if isinstance(started, str) and started else None


def _clock_days_elapsed(started: str | None, now: int) -> int | None:
    if started is None:
        return None
    try:
        start = datetime.strptime(started, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (now - int(start.timestamp())) // 86400


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


def _rejected_by_reason(conn: sqlite3.Connection, cutoff_hour: int) -> dict[str, int]:
    """Rejected-request counts by reason code, or {} if the table is absent.

    A database created before migrations/0003_rejected_log.sql has no such
    table; that is an empty observation, not an error.
    """
    try:
        rows = conn.execute(
            "SELECT reason_code, COUNT(*) AS n FROM rejected_log "
            "WHERE observed_at_hour >= ? GROUP BY reason_code",
            (cutoff_hour,),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {
        (row["reason_code"] or "unknown"): int(row["n"])
        for row in rows
    }


def build_report(
    conn: sqlite3.Connection,
    *,
    now: int | None = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    root: Path = ROOT,
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

    # Ordering matters. Real keyed demand is a real signal whenever it
    # arrives, so CONTINUE is decided FIRST and is never blocked by the
    # preconditions. Only the KILL direction has to wait for the measurement
    # to be capable of producing a different answer.
    preconditions = evaluate_preconditions(root)
    unmet = sorted(name for name, met in preconditions.items() if not met)
    started = demand_clock_started_at(root / "release" / "demand-clock-v1.json")
    days_elapsed = _clock_days_elapsed(started, now)

    if distinct_keyed_organizations >= KILL_THRESHOLD_ORGANIZATIONS:
        verdict = VERDICT_CONTINUE
        invalid_because: list[str] = []
    else:
        invalid_because = [f"discoverability:{name}" for name in unmet]
        if started is None:
            invalid_because.append("demand_clock:not_started")
        elif days_elapsed is None:
            invalid_because.append("demand_clock:unparseable")
        elif days_elapsed < window_days:
            invalid_because.append(
                f"demand_clock:only_{days_elapsed}_of_{window_days}_days_elapsed"
            )
        verdict = VERDICT_INVALID if invalid_because else VERDICT_KILL

    rejected_by_reason = _rejected_by_reason(conn, cutoff_hour)

    return {
        "schema_version": 2,
        "generated_at": now,
        "window_days": window_days,
        "window_start_hour": cutoff_hour,
        # Requests the engine REJECTED, reported separately and NEVER summed
        # into any demand figure: a rejected request is evidence that someone
        # tried, not evidence that a need was served. Before
        # migrations/0003_rejected_log.sql these were dropped entirely, which
        # biased the measurement toward zero.
        "rejected_requests_by_reason": rejected_by_reason,
        "measurement": {
            "discoverability_preconditions": preconditions,
            "demand_clock_started_at": started,
            "demand_clock_days_elapsed": days_elapsed,
            "invalid_because": invalid_because,
        },
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
