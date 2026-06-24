"""Tests for billing/usage_pg_tools.py."""

import json
import os
import sqlite3
import sys
from unittest.mock import patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import usage_pg_tools


def _make_usage_db(path):
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL UNIQUE,
            trace_length INTEGER NOT NULL,
            workload_id TEXT,
            duration_ms INTEGER NOT NULL,
            completed_at_ms INTEGER NOT NULL,
            billed INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE verify_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            completed_at_ms INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE failed_proofs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL UNIQUE,
            error TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            failed_at_ms INTEGER NOT NULL
        )
    """)
    conn.execute(
        "INSERT INTO usage_log "
        "(tenant_id, job_id, trace_length, workload_id, duration_ms, completed_at_ms, billed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("t_1", "job_old", 100, None, 7, 900, 0),
    )
    conn.execute(
        "INSERT INTO usage_log "
        "(tenant_id, job_id, trace_length, workload_id, duration_ms, completed_at_ms, billed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("t_1", "job_new", 250, "accumulator_step", 11, 1100, 1),
    )
    conn.execute(
        "INSERT INTO verify_log (tenant_id, duration_ms, completed_at_ms) VALUES (?, ?, ?)",
        ("t_1", 3, 1200),
    )
    conn.execute(
        "INSERT INTO failed_proofs (tenant_id, job_id, error, duration_ms, failed_at_ms) VALUES (?, ?, ?, ?, ?)",
        ("t_1", "job_fail", "boom", 5, 1300),
    )
    conn.commit()
    conn.close()


def test_sqlite_summary_respects_since_filter(tmp_path):
    db_path = str(tmp_path / "usage.sqlite")
    _make_usage_db(db_path)

    summary = usage_pg_tools.sqlite_summary(db_path, since_ms=1000)

    assert summary["usage_log"]["count"] == 1
    assert summary["usage_log"]["trace_length_sum"] == 250
    assert summary["usage_log"]["duration_ms_sum"] == 11
    assert summary["usage_log"]["billed_sum"] == 1
    assert summary["verify_log"]["count"] == 1
    assert summary["failed_proofs"]["count"] == 1


def test_compare_summaries_detects_drift():
    sqlite_data = {
        "usage_log": {
            "count": 2,
            "trace_length_sum": 350,
            "duration_ms_sum": 18,
            "time_min": 900,
            "time_max": 1100,
            "billed_sum": 1,
        },
        "verify_log": {
            "count": 1,
            "duration_ms_sum": 3,
            "time_min": 1200,
            "time_max": 1200,
        },
        "failed_proofs": {
            "count": 1,
            "duration_ms_sum": 5,
            "time_min": 1300,
            "time_max": 1300,
        },
    }
    pg_data = json.loads(json.dumps(sqlite_data))
    pg_data["usage_log"]["count"] = 1

    result = usage_pg_tools.compare_summaries(sqlite_data, pg_data)

    assert result["ok"] is False
    assert result["tables"]["usage_log"]["count"]["delta"] == -1
    assert result["tables"]["verify_log"]["count"]["delta"] == 0


def test_postgres_summary_parses_psql_json():
    payload = {
        "usage_log": {
            "count": 2,
            "trace_length_sum": 350,
            "duration_ms_sum": 18,
            "time_min": 900,
            "time_max": 1100,
            "billed_sum": 1,
        },
        "verify_log": {
            "count": 1,
            "duration_ms_sum": 3,
            "time_min": 1200,
            "time_max": 1200,
        },
        "failed_proofs": {
            "count": 1,
            "duration_ms_sum": 5,
            "time_min": 1300,
            "time_max": 1300,
        },
    }

    with patch.object(usage_pg_tools, "run_psql_query", return_value=json.dumps(payload)):
        summary = usage_pg_tools.postgres_summary("postgres://example")

    assert summary["usage_log"]["trace_length_sum"] == 350
    assert summary["failed_proofs"]["count"] == 1


def test_backfill_script_is_idempotent_for_proof_rows(tmp_path):
    db_path = str(tmp_path / "usage.sqlite")
    _make_usage_db(db_path)

    script, counts = usage_pg_tools.build_backfill_script(db_path, since_ms=1000)

    assert counts == {"usage_log": 1, "failed_proofs": 1}
    assert "COPY usage_log_import" in script
    assert "COPY failed_proofs_import" in script
    assert "ON CONFLICT (job_id) DO NOTHING" in script
    assert "verify_log" not in script
    assert "job_new" in script
    assert "job_old" not in script


def test_backfill_dry_run_prints_verify_log_skip(tmp_path, capsys):
    db_path = str(tmp_path / "usage.sqlite")
    _make_usage_db(db_path)
    parser = usage_pg_tools.build_parser()
    args = parser.parse_args(["--sqlite", db_path, "backfill", "--dry-run"])

    code = usage_pg_tools.cmd_backfill(args)

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["tables"]["usage_log"] == 2
    assert output["tables"]["failed_proofs"] == 1
    assert "verify_log" in output
    assert "skipped" in output["verify_log"]
