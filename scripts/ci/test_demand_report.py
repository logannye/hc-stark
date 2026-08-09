"""Tests for scripts/ci/demand_report.py against a real temporary SQLite file
built from the exact committed `demand_log` schema
(migrations/0001_demand_log.sql) -- not a hand-described approximation of it.

Also covers the two halves that make the 90-day verdict capable of firing at
all: `scripts/ci/d1_demand_export.py`, which is the only committed path from
remote D1 to the local file this report reads, and
`.github/workflows/demand-clock.yml`, which is the only thing that runs
either of them on a schedule.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
from pathlib import Path

import pytest

import d1_demand_export as export_module
import demand_report as report

ROOT = Path(__file__).resolve().parents[2]
DEMAND_LOG_MIGRATION = ROOT / "migrations" / "0001_demand_log.sql"
WORKFLOWS = ROOT / ".github" / "workflows"
DEMAND_CLOCK_WORKFLOW = WORKFLOWS / "demand-clock.yml"

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
    # Anonymous-only traffic: enough for the log to have observed something,
    # which is what the zero-rows precondition asks, while leaving the keyed
    # count -- the only input to the threshold -- at zero. Before that
    # precondition existed this case used a completely empty database, which
    # conflated "measured nobody" with "measured nothing".
    for index in range(3):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, anon_ip_hash=f"anon-{index}")
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
    # Anonymous rows so this stays a test of DISCOVERABILITY: with an empty
    # log the zero-rows precondition would also fire and the assertion below
    # about which preconditions are named would be checking the wrong one.
    for index in range(3):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, anon_ip_hash=f"anon-{index}")
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


# --- The empty-window precondition ------------------------------------
#
# An empty window and a dead write path are the same bytes. The report has
# to name the difference it cannot see rather than convert it into the most
# consequential verdict it emits.


def test_an_empty_window_is_invalid_rather_than_a_confident_kill(tmp_path):
    db_path = _make_db(tmp_path)

    result = _report(db_path)

    assert result["distinct_keyed_organizations"] == 0
    assert result["measurement"]["demand_log_rows_in_window"] == 0
    assert result["verdict"] == report.VERDICT_INVALID, (
        "zero recorded rows is indistinguishable from a dead write path; "
        "retiring the product on it would be retiring it on a bug"
    )
    assert "demand_log:zero_rows_in_window" in result["measurement"]["invalid_because"]


def test_one_observed_row_is_enough_to_make_the_window_decidable(tmp_path):
    """The precondition must not become a permanent excuse for never deciding.

    A single anonymous row proves the write path is alive; the verdict then
    goes back to being about the keyed count, which is still zero.
    """
    db_path = _make_db(tmp_path)
    _insert_row(db_path, observed_at_hour=NOW - HOUR, anon_ip_hash="anon-0")

    result = _report(db_path)

    assert result["measurement"]["demand_log_rows_in_window"] == 1
    assert result["measurement"]["invalid_because"] == []
    assert result["verdict"] == report.VERDICT_KILL


def test_rows_outside_the_window_do_not_vouch_for_the_window(tmp_path):
    """The precondition is about THIS period, not about the table ever
    having held anything.

    A log that recorded traffic in March and nothing since is exactly the
    shape a write path that broke in April leaves behind.
    """
    db_path = _make_db(tmp_path)
    stale_hour = ((NOW - 100 * DAY) // HOUR) * HOUR
    _insert_row(db_path, observed_at_hour=stale_hour, anon_ip_hash="anon-historic")

    result = _report(db_path)

    assert result["measurement"]["demand_log_rows_in_window"] == 0
    assert result["verdict"] == report.VERDICT_INVALID
    assert "demand_log:zero_rows_in_window" in result["measurement"]["invalid_because"]


def test_rejected_rows_alone_do_not_vouch_for_the_demand_write_path(tmp_path):
    """`rejected_log` is written by a different code path, so it can only
    prove that path is alive -- never that `logDemand` is."""
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            (ROOT / "migrations" / "0003_rejected_log.sql").read_text(encoding="utf-8")
        )
        conn.execute(
            "INSERT INTO rejected_log (observed_at_hour, reason_code, anon_ip_hash)"
            " VALUES (?, ?, ?)",
            (NOW - HOUR, "manifest_contract_invalid", "anon-0"),
        )
        conn.commit()
    finally:
        conn.close()

    result = _report(db_path)

    assert result["rejected_requests_by_reason"] == {"manifest_contract_invalid": 1}
    assert result["verdict"] == report.VERDICT_INVALID
    assert "demand_log:zero_rows_in_window" in result["measurement"]["invalid_because"]


def test_the_empty_window_precondition_never_masks_real_demand(tmp_path):
    """CONTINUE is still decided first; the new precondition only ever gates
    the KILL direction, exactly like the discoverability ones."""
    db_path = _make_db(tmp_path)
    for index in range(report.KILL_THRESHOLD_ORGANIZATIONS):
        _insert_row(db_path, observed_at_hour=NOW - HOUR, key_id=f"org-{index}")

    result = _report(db_path)

    assert result["verdict"] == report.VERDICT_CONTINUE
    assert result["measurement"]["invalid_because"] == []


# --- The scheduled trigger ---------------------------------------------
#
# `demand_report.py` was exercised by nothing but this file. No workflow in
# the repository carried a `schedule:` trigger of any kind, so on the day the
# window closed the kill/continue decision would simply never have been made.
# A report nothing runs is not a gate; it is a document.


def _workflow_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_a_scheduled_workflow_actually_runs_the_demand_report():
    """The defect this pins: coverage that exists but never executes."""
    scheduled = [
        path
        for path in sorted(WORKFLOWS.glob("*.yml"))
        # The invocation, not a mention: a workflow that merely names the
        # report in a comment runs nothing.
        if "python3 scripts/ci/demand_report.py" in _workflow_text(path)
        and "\n  schedule:" in _workflow_text(path)
    ]
    assert scheduled, (
        "no workflow both runs scripts/ci/demand_report.py and carries a "
        "schedule: trigger, so the 90-day verdict can never fire on its own"
    )


def test_the_demand_clock_workflow_exports_before_it_reports():
    """Reporting against a database nothing populated is the same non-result
    the report exists to refuse."""
    workflow = _workflow_text(DEMAND_CLOCK_WORKFLOW)
    assert "workflow_dispatch:" in workflow
    assert "cron:" in workflow
    export_at = workflow.index("python3 scripts/ci/d1_demand_export.py")
    report_at = workflow.index("python3 scripts/ci/demand_report.py")
    assert export_at < report_at
    assert "environment: tinyzkp-production" in workflow
    assert "CLOUDFLARE_API_TOKEN" in workflow
    assert "npm ci --prefix toolchains/cloudflare" in workflow


def test_the_demand_clock_workflow_fails_only_when_a_decision_is_due():
    """CONTINUE passes quietly, KILL fails, and MEASUREMENT_INVALID fails
    only after the window has elapsed.

    The last clause is the one worth pinning: MEASUREMENT_INVALID is the
    honest reading of every week before the clock elapses, and a workflow
    that failed on all of them would be a workflow nobody reads by the time
    it has something to say.
    """
    workflow = _workflow_text(DEMAND_CLOCK_WORKFLOW)
    for verdict in (
        report.VERDICT_CONTINUE,
        report.VERDICT_KILL,
        report.VERDICT_INVALID,
    ):
        assert f"{verdict})" in workflow
    assert 'test "$elapsed" -lt "$window"' in workflow
    assert "GITHUB_STEP_SUMMARY" in workflow
    assert "upload-artifact" in workflow


# --- The export path ----------------------------------------------------
#
# A broken export and genuine zero demand both look like "no rows". These
# tests pin that they never produce the same artifact: a broken export leaves
# NO database, which makes `demand_report.py --db` exit 1, while a genuinely
# empty remote log leaves a real database that reads as MEASUREMENT_INVALID.


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=(), returncode=returncode, stdout=stdout, stderr=""
    )


def _envelope(rows: list[dict]) -> str:
    """Wrangler's `d1 execute --json` output shape."""
    return json.dumps(
        [{"success": True, "meta": {"rows_read": len(rows)}, "results": rows}]
    )


def _remote_row(table: str, row_id: int, **overrides) -> dict:
    columns = next(
        columns for name, _, columns in export_module.EXPORTED_TABLES if name == table
    )
    row = {column: None for column in columns}
    row["id"] = row_id
    row["observed_at_hour"] = NOW - HOUR
    row.update(overrides)
    assert set(row) == set(columns)
    return row


def _fake_wrangler(
    *,
    tables: tuple[str, ...] = ("demand_log", "rejected_log"),
    demand: list[dict] | None = None,
    rejected: list[dict] | None = None,
    overcount: dict[str, int] | None = None,
    fail_on: str | None = None,
):
    """Stand-in for `wrangler d1 execute --remote --json`.

    Wrangler cannot run here (it needs a real Cloudflare credential), so the
    envelope it returns is reproduced exactly and the SQL this script emits is
    answered from in-memory tables.
    """
    stores = {"demand_log": demand or [], "rejected_log": rejected or []}
    extra = overcount or {}

    def runner(command, **_kwargs):
        sql = command[command.index("--command") + 1]
        if fail_on is not None and fail_on in sql:
            return _completed("", returncode=1)
        if "sqlite_master" in sql:
            return _completed(_envelope([{"name": name} for name in tables]))
        table = "demand_log" if "demand_log" in sql else "rejected_log"
        rows = stores[table]
        if "MAX(id)" in sql:
            return _completed(
                _envelope([{"max_id": max((row["id"] for row in rows), default=0)}])
            )
        if "COUNT(*)" in sql:
            return _completed(
                _envelope([{"row_count": len(rows) + extra.get(table, 0)}])
            )
        bounds = re.search(r"id > (\d+) AND id <= (\d+)", sql)
        assert bounds is not None, f"unexpected query: {sql}"
        lower, upper = (int(value) for value in bounds.groups())
        page = [row for row in rows if lower < row["id"] <= upper]
        return _completed(_envelope(page[: export_module.PAGE_ROWS]))

    return runner


def _run_export(tmp_path: Path, runner, *, output: Path | None = None) -> dict:
    node = tmp_path / "node"
    wrangler = tmp_path / "wrangler.js"
    node.write_text("", encoding="utf-8")
    wrangler.write_text("", encoding="utf-8")
    return export_module.export(
        output if output is not None else tmp_path / "export" / "demand_log.sqlite3",
        environment={
            "CLOUDFLARE_API_TOKEN": "t" * 40,
            "CLOUDFLARE_ACCOUNT_ID": "0" * 32,
        },
        node=node,
        wrangler=wrangler,
        runner=runner,
        now=NOW,
    )


def test_the_export_targets_the_database_the_worker_actually_writes_to():
    """Querying a different, empty database is the one failure that would
    look completely normal."""
    assert export_module.configured_database() == (
        export_module.DATABASE_NAME,
        export_module.DATABASE_ID,
    )


def test_a_repointed_binding_is_refused_before_any_query_runs(tmp_path):
    config = tmp_path / "wrangler.toml"
    config.write_text(
        'database_name = "tinyzkp-somewhere-else"\n'
        'database_id = "00000000-0000-0000-0000-000000000000"\n',
        encoding="utf-8",
    )
    node = tmp_path / "node"
    wrangler = tmp_path / "wrangler.js"
    node.write_text("", encoding="utf-8")
    wrangler.write_text("", encoding="utf-8")

    with pytest.raises(export_module.ExportError, match="no longer binds"):
        export_module.export(
            tmp_path / "demand_log.sqlite3",
            environment={
                "CLOUDFLARE_API_TOKEN": "t" * 40,
                "CLOUDFLARE_ACCOUNT_ID": "0" * 32,
            },
            node=node,
            wrangler=wrangler,
            runner=_fake_wrangler(),
            config=config,
            now=NOW,
        )


def test_a_successful_export_produces_a_database_the_report_can_read(tmp_path):
    demand = [
        _remote_row(
            "demand_log",
            index + 1,
            key_id=f"org-{index}",
            request_digest="digest-common",
            blocking_reason_codes=json.dumps(["unsupported_profile"]),
        )
        for index in range(15)
    ]
    rejected = [
        _remote_row("rejected_log", 1, reason_code="manifest_contract_invalid")
    ]

    summary = _run_export(tmp_path, _fake_wrangler(demand=demand, rejected=rejected))

    assert summary["rows_exported"] == {"demand_log": 15, "rejected_log": 1}
    assert summary["database_id"] == export_module.DATABASE_ID
    exported = Path(summary["output"])
    result = _report(exported)
    assert result["distinct_keyed_organizations"] == 15
    assert result["verdict"] == report.VERDICT_CONTINUE
    assert result["rejected_requests_by_reason"] == {"manifest_contract_invalid": 1}


def test_a_failed_export_leaves_no_database_to_misread_as_zero_demand(tmp_path):
    """THE load-bearing property. A stale database from a previous run would
    be read as a fresh measurement, and an empty one as a kill signal, so a
    failed export must leave neither."""
    output = tmp_path / "export" / "demand_log.sqlite3"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"stale database from a previous run")

    with pytest.raises(export_module.ExportError):
        _run_export(tmp_path, _fake_wrangler(fail_on="MAX(id)"), output=output)

    assert not output.exists(), (
        "a failed export must leave no database at all, so demand_report.py "
        "exits 1 instead of printing a confident zero"
    )
    assert list(output.parent.iterdir()) == [], "no partial file may survive either"


def test_a_truncated_export_is_rejected_rather_than_read_as_less_demand(tmp_path):
    """D1 caps response size, so silent truncation is the realistic way an
    export under-reports demand."""
    demand = [_remote_row("demand_log", index + 1) for index in range(3)]

    with pytest.raises(export_module.ExportError, match="of 5 rows"):
        _run_export(
            tmp_path,
            _fake_wrangler(demand=demand, overcount={"demand_log": 2}),
        )


def test_an_unmigrated_remote_database_is_a_loud_failure(tmp_path):
    """An unmigrated database answers every demand query with nothing, which
    is not the same as nobody calling."""
    with pytest.raises(export_module.ExportError, match="missing demand_log"):
        _run_export(tmp_path, _fake_wrangler(tables=("rate_limit_windows",)))


def test_remote_schema_drift_fails_instead_of_dropping_a_column(tmp_path):
    row = _remote_row("demand_log", 1)
    row.pop("blocking_reason_codes")

    with pytest.raises(export_module.ExportError, match="row shape differs"):
        _run_export(tmp_path, _fake_wrangler(demand=[row]))


def test_an_unsuccessful_wrangler_envelope_is_never_treated_as_no_rows():
    with pytest.raises(export_module.ExportError, match="unsuccessful statement"):
        export_module.parse_statement_results(
            json.dumps([{"success": False, "meta": {}, "results": []}])
        )
    with pytest.raises(export_module.ExportError, match="not valid JSON"):
        export_module.parse_statement_results("Authentication error [code: 10000]")
    with pytest.raises(export_module.ExportError, match="no output"):
        export_module.parse_statement_results("")


def test_a_malformed_credential_fails_before_the_database_is_replaced(tmp_path):
    output = tmp_path / "demand_log.sqlite3"
    node = tmp_path / "node"
    wrangler = tmp_path / "wrangler.js"
    node.write_text("", encoding="utf-8")
    wrangler.write_text("", encoding="utf-8")

    with pytest.raises(export_module.ExportError, match="CLOUDFLARE_API_TOKEN"):
        export_module.export(
            output,
            environment={"CLOUDFLARE_ACCOUNT_ID": "0" * 32},
            node=node,
            wrangler=wrangler,
            runner=_fake_wrangler(),
            now=NOW,
        )
    assert not output.exists()


def test_a_genuinely_empty_remote_log_is_distinguishable_from_a_broken_export(tmp_path):
    """The two states this whole path exists to keep apart, asserted side by
    side: an empty remote log yields a real database that reads as
    MEASUREMENT_INVALID, while a broken export yields no database at all."""
    summary = _run_export(tmp_path, _fake_wrangler())

    exported = Path(summary["output"])
    assert summary["rows_exported"] == {"demand_log": 0, "rejected_log": 0}
    assert exported.is_file()

    result = _report(exported)
    assert result["verdict"] == report.VERDICT_INVALID
    assert "demand_log:zero_rows_in_window" in result["measurement"]["invalid_because"]

    broken = tmp_path / "broken" / "demand_log.sqlite3"
    with pytest.raises(export_module.ExportError):
        _run_export(tmp_path, _fake_wrangler(fail_on="sqlite_master"), output=broken)
    assert not broken.exists()
    assert report.main(["--db", str(broken)]) == 1
