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


def _measurable_root(base: Path, *, started: str = "2020-01-01") -> Path:
    """A repo root where every discoverability precondition holds and the
    demand clock elapsed long ago.

    Threshold tests must not be silently converted into tests of the
    precondition gate: without this, every existing KILL assertion would
    start reading MEASUREMENT_INVALID for reasons unrelated to what it is
    checking, and the threshold would stop being covered at all.
    """
    root = base / "measurable-root"
    for _, relative, needle in report.PRECONDITIONS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(needle + "\n")
    clock = root / "release" / "demand-clock-v1.json"
    clock.parent.mkdir(parents=True, exist_ok=True)
    clock.write_text(
        json.dumps({"demand_clock_started_at": started}), encoding="utf-8"
    )
    return root


def _report(db_path: Path, *, window_days: int = 90, root: Path | None = None):
    conn = report.connect_readonly(db_path)
    try:
        return report.build_report(
            conn,
            now=NOW,
            window_days=window_days,
            root=_measurable_root(db_path.parent) if root is None else root,
        )
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
        "rejected_requests_by_reason",
        "measurement",
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


# --- Achievability precheck --------------------------------------------
#
# The threshold reads "fewer than 15 distinct KEYED organizations in 90 days
# => KILL". Until 2026-07-29 that number could not be anything but zero for
# reasons unrelated to demand: the estimator was in no sitemap and no
# llms.txt, and llms.txt told agents TinyZKP had no proof API. These tests
# pin the rule that a kill verdict is withheld while the measurement is
# incapable of producing another answer -- and, just as importantly, that
# the threshold itself was not weakened to achieve that.


def test_kill_is_withheld_when_the_product_is_undiscoverable(tmp_path):
    """The load-bearing case: zero orgs, but zero was never reachable."""
    db_path = _make_db(tmp_path)
    blind = tmp_path / "undiscoverable"
    (blind / "release").mkdir(parents=True)
    (blind / "release" / "demand-clock-v1.json").write_text(
        json.dumps({"demand_clock_started_at": "2020-01-01"}), encoding="utf-8"
    )

    result = _report(db_path, root=blind)

    assert result["distinct_keyed_organizations"] == 0
    assert result["verdict"] == report.VERDICT_INVALID, (
        "a zero reading against an undiscoverable endpoint is a NON-RESULT; "
        "emitting KILL_THRESHOLD_MET for it would retire the product on an "
        "artifact of its own marketing"
    )
    assert result["measurement"]["invalid_because"], "must name what is unmet"
    assert all(
        reason.startswith("discoverability:") or reason.startswith("demand_clock:")
        for reason in result["measurement"]["invalid_because"]
    )


def test_kill_still_fires_once_the_measurement_is_valid(tmp_path):
    """The gate must not become a permanent excuse for never deciding."""
    db_path = _make_db(tmp_path)
    _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id="org-0")

    result = _report(db_path)

    assert result["verdict"] == report.VERDICT_KILL
    assert result["measurement"]["invalid_because"] == []


def test_kill_is_withheld_until_the_window_has_actually_elapsed(tmp_path):
    db_path = _make_db(tmp_path)
    fresh = _measurable_root(tmp_path / "fresh", started="2027-01-01")

    result = _report(db_path, root=fresh)

    assert result["verdict"] == report.VERDICT_INVALID
    assert any(
        reason.startswith("demand_clock:only_")
        for reason in result["measurement"]["invalid_because"]
    )


def test_real_demand_reaches_continue_even_before_the_clock_elapses(tmp_path):
    """CONTINUE is decided first, so a genuine early signal is never masked."""
    db_path = _make_db(tmp_path)
    for index in range(report.KILL_THRESHOLD_ORGANIZATIONS):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    fresh = _measurable_root(tmp_path / "fresh", started="2027-01-01")

    result = _report(db_path, root=fresh)

    assert result["verdict"] == report.VERDICT_CONTINUE
    assert result["measurement"]["invalid_because"] == []


def test_the_threshold_itself_was_not_weakened(tmp_path):
    """Guards against 'fixing' validity by making KILL harder on the merits."""
    assert report.KILL_THRESHOLD_ORGANIZATIONS == 15
    db_path = _make_db(tmp_path)
    for index in range(report.KILL_THRESHOLD_ORGANIZATIONS - 1):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")
    # 14 keyed orgs plus a crowd of anonymous sources must still be KILL.
    for index in range(50):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, anon_ip_hash=f"anon-{index}")

    assert _report(db_path)["verdict"] == report.VERDICT_KILL


def test_the_live_repository_currently_satisfies_discoverability():
    """The shipped tree must actually meet what the gate demands."""
    unmet = sorted(
        name for name, met in report.evaluate_preconditions().items() if not met
    )
    assert unmet == [], f"discoverability preconditions unmet in-tree: {unmet}"


def test_rejected_requests_are_counted_but_never_folded_into_demand(tmp_path):
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            (ROOT / "migrations" / "0003_rejected_log.sql").read_text(encoding="utf-8")
        )
        for _ in range(3):
            conn.execute(
                "INSERT INTO rejected_log (observed_at_hour, reason_code, anon_ip_hash)"
                " VALUES (?, ?, ?)",
                (NOW - HOUR, "manifest_contract_invalid", "anon-0"),
            )
        conn.commit()
    finally:
        conn.close()

    result = _report(db_path)

    assert result["rejected_requests_by_reason"] == {"manifest_contract_invalid": 3}
    # A rejected request is evidence someone tried, not evidence of a served
    # need. It must never move a demand count or the verdict.
    assert result["distinct_keyed_organizations"] == 0
    assert result["distinct_approximate_anonymous_sources"] == 0


def test_a_database_without_the_rejected_table_is_an_empty_observation(tmp_path):
    """Pre-0003 databases must report {}, not crash the whole report."""
    db_path = _make_db(tmp_path)

    assert _report(db_path)["rejected_requests_by_reason"] == {}
