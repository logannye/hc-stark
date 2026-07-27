"""Tests for scripts/ci/demand_report.py against a real temporary SQLite file
built from the exact committed `demand_log` schema
(migrations/0001_demand_log.sql) -- not a hand-described approximation of it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import demand_report as report

ROOT = Path(__file__).resolve().parents[2]
DEMAND_LOG_MIGRATION = ROOT / "migrations" / "0001_demand_log.sql"

NOW = 1_800_000_000  # an arbitrary, fixed "current time" for reproducible tests
HOUR = 3600
DAY = 86400


def _make_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "demand_log.sqlite3"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(DEMAND_LOG_MIGRATION.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()
    return db_path


def _insert_row(
    db_path: Path,
    *,
    observed_at_hour: int,
    key_id: str | None = None,
    anon_ip_hash: str | None = None,
    request_digest: str | None = "digest-default",
    blocking_reason_codes: list[str] | None = None,
    provable_today: int = 0,
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO demand_log (
              observed_at_hour, request_digest, field, extension_degree,
              trace_width_bucket, logical_rows_bucket,
              uses_lookups, uses_buses, uses_permutations, uses_multi_table,
              uses_preprocessed_columns, uses_periodic_columns, uses_recursion, uses_gpu,
              provable_today, blocking_reason_codes, key_id, anon_ip_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed_at_hour,
                request_digest,
                "goldilocks",
                2,
                "1-32",
                "2^10-2^13",
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                provable_today,
                json.dumps(blocking_reason_codes or []),
                key_id,
                anon_ip_hash,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _report(db_path: Path, *, window_days: int = 90):
    conn = report.connect_readonly(db_path)
    try:
        return report.build_report(conn, now=NOW, window_days=window_days)
    finally:
        conn.close()


def test_migration_schema_matches_what_this_test_exercises(tmp_path):
    """Sanity check: the fixture is built from the real committed migration,
    not a hand-copied schema that could silently drift from it."""
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(demand_log)")}
    finally:
        conn.close()
    assert {
        "observed_at_hour",
        "request_digest",
        "field",
        "extension_degree",
        "trace_width_bucket",
        "logical_rows_bucket",
        "uses_lookups",
        "uses_buses",
        "uses_permutations",
        "uses_multi_table",
        "uses_preprocessed_columns",
        "uses_periodic_columns",
        "uses_recursion",
        "uses_gpu",
        "provable_today",
        "blocking_reason_codes",
        "key_id",
        "anon_ip_hash",
    } <= columns


def test_fourteen_distinct_keyed_organizations_meets_kill_threshold(tmp_path):
    db_path = _make_db(tmp_path)
    for index in range(14):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    result = _report(db_path)
    assert result["distinct_keyed_organizations"] == 14
    assert result["verdict"] == report.VERDICT_KILL


def test_fifteen_distinct_keyed_organizations_continues(tmp_path):
    db_path = _make_db(tmp_path)
    for index in range(15):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    result = _report(db_path)
    assert result["distinct_keyed_organizations"] == 15
    assert result["verdict"] == report.VERDICT_CONTINUE


def test_records_older_than_ninety_days_are_excluded(tmp_path):
    db_path = _make_db(tmp_path)
    # 15 distinct keyed orgs, but one of them is entirely outside the window.
    for index in range(14):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    stale_hour = ((NOW - 100 * DAY) // HOUR) * HOUR
    _insert_row(db_path, observed_at_hour=stale_hour, key_id="org-outside-window")

    result = _report(db_path)
    assert result["distinct_keyed_organizations"] == 14
    assert result["verdict"] == report.VERDICT_KILL

    # The same org, if it had instead called again inside the window, would
    # push the count to 15 -- proving the exclusion above is really about
    # the timestamp, not some other property of that row.
    _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id="org-outside-window")
    refreshed = _report(db_path)
    assert refreshed["distinct_keyed_organizations"] == 15
    assert refreshed["verdict"] == report.VERDICT_CONTINUE


def test_keyed_and_anonymous_counts_are_reported_separately_and_never_summed(tmp_path):
    db_path = _make_db(tmp_path)
    # 10 distinct keyed orgs (below the threshold of 15) and 10 distinct
    # anonymous sources. If these were ever summed, 10 + 10 = 20 >= 15 would
    # read CONTINUE -- a flattering, wrong answer. They must not be summed.
    for index in range(10):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    for index in range(10):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, anon_ip_hash=f"anon-hash-{index}")

    result = _report(db_path)
    assert result["distinct_keyed_organizations"] == 10
    assert result["distinct_approximate_anonymous_sources"] == 10
    assert result["verdict"] == report.VERDICT_KILL, (
        "the verdict must be driven by keyed organizations alone, never by "
        "keyed + anonymous summed together"
    )
    # The two counts are reported as their own separate fields; no top-level
    # field anywhere blends them into one "total distinct callers" number.
    assert set(result) == {
        "schema_version",
        "generated_at",
        "window_days",
        "window_start_hour",
        "distinct_keyed_organizations",
        "distinct_approximate_anonymous_sources",
        "top_request_digests",
        "blocking_reason_codes",
        "kill_threshold_organizations",
        "verdict",
    }


def test_blocking_reason_codes_are_ranked_by_distinct_organization_not_volume(tmp_path):
    db_path = _make_db(tmp_path)
    # One enthusiastic anonymous caller hits "unsupported_air_feature" fifty
    # times. Five distinct anonymous callers each hit "unsupported_profile"
    # once. By raw request count, unsupported_air_feature (50) would beat
    # unsupported_profile (5) -- but ranked by distinct source, the reverse
    # must be true, because this ranking is a profile-expansion queue, not a
    # popularity contest for one caller.
    for _ in range(50):
        _insert_row(
            db_path,
            observed_at_hour=NOW - HOUR,
            anon_ip_hash="loud-single-caller",
            blocking_reason_codes=["unsupported_air_feature"],
        )
    for index in range(5):
        _insert_row(
            db_path,
            observed_at_hour=NOW - HOUR,
            anon_ip_hash=f"quiet-caller-{index}",
            blocking_reason_codes=["unsupported_profile"],
        )

    result = _report(db_path)
    codes_in_rank_order = [entry["code"] for entry in result["blocking_reason_codes"]]
    assert codes_in_rank_order.index("unsupported_profile") < codes_in_rank_order.index("unsupported_air_feature")

    by_code = {entry["code"]: entry for entry in result["blocking_reason_codes"]}
    assert by_code["unsupported_air_feature"]["distinct_approximate_anonymous_sources"] == 1
    assert by_code["unsupported_air_feature"]["request_count"] == 50
    assert by_code["unsupported_profile"]["distinct_approximate_anonymous_sources"] == 5
    assert by_code["unsupported_profile"]["request_count"] == 5


def test_blocking_reason_ranking_keeps_keyed_and_anonymous_counts_apart(tmp_path):
    db_path = _make_db(tmp_path)
    _insert_row(
        db_path,
        observed_at_hour=NOW - HOUR,
        key_id="org-a",
        blocking_reason_codes=["ram_budget_insufficient"],
    )
    _insert_row(
        db_path,
        observed_at_hour=NOW - HOUR,
        anon_ip_hash="anon-x",
        blocking_reason_codes=["ram_budget_insufficient"],
    )
    result = _report(db_path)
    entry = next(item for item in result["blocking_reason_codes"] if item["code"] == "ram_budget_insufficient")
    assert entry["distinct_keyed_organizations"] == 1
    assert entry["distinct_approximate_anonymous_sources"] == 1
    assert "distinct_organizations" not in entry  # never a single blended count


def test_top_request_digests_are_ranked_by_volume(tmp_path):
    db_path = _make_db(tmp_path)
    for _ in range(3):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id="org-a", request_digest="digest-common")
    _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id="org-b", request_digest="digest-rare")

    result = _report(db_path)
    assert result["top_request_digests"][0] == {"request_digest": "digest-common", "request_count": 3}
    assert {"request_digest": "digest-rare", "request_count": 1} in result["top_request_digests"]


def test_verdict_field_is_explicit_and_matches_the_frozen_threshold(tmp_path):
    db_path = _make_db(tmp_path)
    result = _report(db_path)
    assert result["kill_threshold_organizations"] == 15
    assert result["verdict"] in {report.VERDICT_CONTINUE, report.VERDICT_KILL}
    assert result["distinct_keyed_organizations"] == 0
    assert result["verdict"] == report.VERDICT_KILL


def test_main_prints_json_report_to_stdout(tmp_path, capsys):
    db_path = _make_db(tmp_path)
    for index in range(15):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")

    exit_code = report.main(["--db", str(db_path), "--now", str(NOW)])
    assert exit_code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["verdict"] == report.VERDICT_CONTINUE
    assert printed["distinct_keyed_organizations"] == 15


def test_main_reports_a_clean_failure_for_a_missing_database(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.sqlite3"
    exit_code = report.main(["--db", str(missing)])
    assert exit_code == 1
    assert "no such database file" in capsys.readouterr().err
