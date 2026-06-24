#!/usr/bin/env python3
"""Postgres migration helper for TinyZKP usage state.

This tool intentionally uses only the Python standard library plus the `psql`
CLI. It is meant for operators during the SQLite -> Postgres migration window:

    python3 billing/usage_pg_tools.py compare --since-ms <dual_write_start_ms>
    python3 billing/usage_pg_tools.py backfill --dry-run
    python3 billing/usage_pg_tools.py backfill --apply

Successful prove rows (`usage_log`) and failed prove rows (`failed_proofs`) are
safe to backfill idempotently because both tables have a unique `job_id`.
`verify_log` has no semantic event key, so this tool compares it but does not
backfill it; use a fresh Postgres cutover boundary for verify history.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


USAGE_DB_PATH = os.environ.get("HC_USAGE_DB_PATH", "/opt/hc-stark/data/usage.sqlite")
PG_URL = os.environ.get("HC_SERVER_PG_URL")
PSQL_BIN = os.environ.get("PSQL_BIN", "psql")


@dataclass(frozen=True)
class TableSpec:
    name: str
    time_column: str
    columns: tuple[str, ...]
    conflict_column: str | None
    summary_fields: tuple[tuple[str, str], ...]


USAGE_SPEC = TableSpec(
    name="usage_log",
    time_column="completed_at_ms",
    columns=(
        "tenant_id",
        "job_id",
        "trace_length",
        "workload_id",
        "duration_ms",
        "completed_at_ms",
        "billed",
    ),
    conflict_column="job_id",
    summary_fields=(
        ("count", "COUNT(*)"),
        ("trace_length_sum", "COALESCE(SUM(trace_length), 0)"),
        ("duration_ms_sum", "COALESCE(SUM(duration_ms), 0)"),
        ("time_min", "COALESCE(MIN(completed_at_ms), 0)"),
        ("time_max", "COALESCE(MAX(completed_at_ms), 0)"),
        ("billed_sum", "COALESCE(SUM(billed), 0)"),
    ),
)

VERIFY_SPEC = TableSpec(
    name="verify_log",
    time_column="completed_at_ms",
    columns=("tenant_id", "duration_ms", "completed_at_ms"),
    conflict_column=None,
    summary_fields=(
        ("count", "COUNT(*)"),
        ("duration_ms_sum", "COALESCE(SUM(duration_ms), 0)"),
        ("time_min", "COALESCE(MIN(completed_at_ms), 0)"),
        ("time_max", "COALESCE(MAX(completed_at_ms), 0)"),
    ),
)

FAILED_SPEC = TableSpec(
    name="failed_proofs",
    time_column="failed_at_ms",
    columns=("tenant_id", "job_id", "error", "duration_ms", "failed_at_ms"),
    conflict_column="job_id",
    summary_fields=(
        ("count", "COUNT(*)"),
        ("duration_ms_sum", "COALESCE(SUM(duration_ms), 0)"),
        ("time_min", "COALESCE(MIN(failed_at_ms), 0)"),
        ("time_max", "COALESCE(MAX(failed_at_ms), 0)"),
    ),
)

ALL_SPECS = (USAGE_SPEC, VERIFY_SPEC, FAILED_SPEC)
BACKFILL_SPECS = (USAGE_SPEC, FAILED_SPEC)


def _where_clause(spec: TableSpec, since_ms: int | None, until_ms: int | None) -> tuple[str, list[Any]]:
    predicates: list[str] = []
    args: list[Any] = []
    if since_ms is not None:
        predicates.append(f"{spec.time_column} >= ?")
        args.append(since_ms)
    if until_ms is not None:
        predicates.append(f"{spec.time_column} <= ?")
        args.append(until_ms)
    if not predicates:
        return "", args
    return " WHERE " + " AND ".join(predicates), args


def _pg_where_clause(spec: TableSpec, since_ms: int | None, until_ms: int | None) -> str:
    predicates: list[str] = []
    if since_ms is not None:
        predicates.append(f"{spec.time_column} >= {int(since_ms)}")
    if until_ms is not None:
        predicates.append(f"{spec.time_column} <= {int(until_ms)}")
    if not predicates:
        return ""
    return " WHERE " + " AND ".join(predicates)


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def sqlite_summary(path: str, since_ms: int | None = None, until_ms: int | None = None) -> dict[str, dict[str, int]]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    summary: dict[str, dict[str, int]] = {}
    try:
        for spec in ALL_SPECS:
            if not table_exists(conn, spec.name):
                summary[spec.name] = {field: 0 for field, _ in spec.summary_fields}
                continue
            where, args = _where_clause(spec, since_ms, until_ms)
            select = ", ".join(f"{expr} AS {field}" for field, expr in spec.summary_fields)
            row = conn.execute(f"SELECT {select} FROM {spec.name}{where}", args).fetchone()
            summary[spec.name] = {
                field: int(row[field] or 0)
                for field, _ in spec.summary_fields
            }
    finally:
        conn.close()
    return summary


def pg_summary_sql(since_ms: int | None = None, until_ms: int | None = None) -> str:
    parts: list[str] = []
    for spec in ALL_SPECS:
        where = _pg_where_clause(spec, since_ms, until_ms)
        fields = ", ".join(
            f"'{field}', ({expr})::bigint"
            for field, expr in spec.summary_fields
        )
        parts.append(f"'{spec.name}', (SELECT json_build_object({fields}) FROM {spec.name}{where})")
    return "SELECT json_build_object(" + ", ".join(parts) + ")::text;"


def run_psql_query(pg_url: str, sql: str) -> str:
    proc = subprocess.run(
        [PSQL_BIN, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", pg_url, "-c", sql],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "psql query failed")
    return proc.stdout.strip()


def run_psql_script(pg_url: str, script: str) -> None:
    proc = subprocess.run(
        [PSQL_BIN, "-X", "-v", "ON_ERROR_STOP=1", pg_url],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "psql script failed")


def postgres_summary(pg_url: str, since_ms: int | None = None, until_ms: int | None = None) -> dict[str, dict[str, int]]:
    raw = run_psql_query(pg_url, pg_summary_sql(since_ms, until_ms))
    data = json.loads(raw)
    return {
        table: {field: int(value or 0) for field, value in fields.items()}
        for table, fields in data.items()
    }


def compare_summaries(sqlite_data: dict[str, dict[str, int]], pg_data: dict[str, dict[str, int]]) -> dict[str, Any]:
    tables: dict[str, Any] = {}
    ok = True
    for spec in ALL_SPECS:
        sqlite_table = sqlite_data.get(spec.name, {})
        pg_table = pg_data.get(spec.name, {})
        fields: dict[str, Any] = {}
        for field, _ in spec.summary_fields:
            sqlite_value = int(sqlite_table.get(field, 0) or 0)
            pg_value = int(pg_table.get(field, 0) or 0)
            delta = pg_value - sqlite_value
            if delta != 0:
                ok = False
            fields[field] = {
                "sqlite": sqlite_value,
                "postgres": pg_value,
                "delta": delta,
            }
        tables[spec.name] = fields
    return {"ok": ok, "tables": tables}


def csv_for_table(path: str, spec: TableSpec, since_ms: int | None = None, until_ms: int | None = None) -> tuple[str, int]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    count = 0
    try:
        if not table_exists(conn, spec.name):
            return "", 0
        where, args = _where_clause(spec, since_ms, until_ms)
        column_list = ", ".join(spec.columns)
        for row in conn.execute(f"SELECT {column_list} FROM {spec.name}{where} ORDER BY rowid", args):
            writer.writerow([row[col] for col in spec.columns])
            count += 1
    finally:
        conn.close()
    return out.getvalue(), count


def _copy_block(spec: TableSpec, csv_data: str) -> str:
    if spec.conflict_column is None:
        raise ValueError(f"{spec.name} has no idempotent conflict column")
    columns = ", ".join(spec.columns)
    temp = f"{spec.name}_import"
    return "\n".join([
        f"CREATE TEMP TABLE {temp} (LIKE {spec.name} INCLUDING DEFAULTS);",
        f"COPY {temp} ({columns}) FROM STDIN WITH (FORMAT csv);",
        csv_data + r"\.",
        f"INSERT INTO {spec.name} ({columns})",
        f"SELECT {columns} FROM {temp}",
        f"ON CONFLICT ({spec.conflict_column}) DO NOTHING;",
        f"DROP TABLE {temp};",
    ])


def build_backfill_script(
    path: str,
    since_ms: int | None = None,
    until_ms: int | None = None,
) -> tuple[str, dict[str, int]]:
    blocks = ["BEGIN;"]
    counts: dict[str, int] = {}
    for spec in BACKFILL_SPECS:
        csv_data, count = csv_for_table(path, spec, since_ms, until_ms)
        counts[spec.name] = count
        blocks.append(_copy_block(spec, csv_data))
    blocks.append("COMMIT;")
    return "\n".join(blocks) + "\n", counts


def require_pg_url(value: str | None) -> str:
    if not value:
        raise SystemExit("HC_SERVER_PG_URL is required, or pass --pg-url")
    return value


def cmd_compare(args: argparse.Namespace) -> int:
    pg_url = require_pg_url(args.pg_url)
    sqlite_data = sqlite_summary(args.sqlite, args.since_ms, args.until_ms)
    pg_data = postgres_summary(pg_url, args.since_ms, args.until_ms)
    result = compare_summaries(sqlite_data, pg_data)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def cmd_summary(args: argparse.Namespace) -> int:
    if args.source == "sqlite":
        data = sqlite_summary(args.sqlite, args.since_ms, args.until_ms)
    else:
        data = postgres_summary(require_pg_url(args.pg_url), args.since_ms, args.until_ms)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_backfill(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.apply:
        raise SystemExit("pass --dry-run or --apply")
    if args.dry_run and args.apply:
        raise SystemExit("choose only one of --dry-run or --apply")

    script, counts = build_backfill_script(args.sqlite, args.since_ms, args.until_ms)
    result = {
        "action": "backfill",
        "mode": "dry_run" if args.dry_run else "apply",
        "sqlite": args.sqlite,
        "tables": counts,
        "verify_log": "skipped: no semantic idempotency key",
    }
    if args.dry_run:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    run_psql_script(require_pg_url(args.pg_url), script)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TinyZKP SQLite/Postgres usage migration helper")
    parser.add_argument("--sqlite", default=USAGE_DB_PATH, help="Path to usage.sqlite")
    parser.add_argument("--pg-url", default=PG_URL, help="Postgres URL; defaults to HC_SERVER_PG_URL")
    parser.add_argument("--since-ms", type=int, help="Only include rows at or after this millis timestamp")
    parser.add_argument("--until-ms", type=int, help="Only include rows at or before this millis timestamp")

    sub = parser.add_subparsers(dest="command", required=True)

    p_summary = sub.add_parser("summary", help="Print SQLite or Postgres usage summary")
    p_summary.add_argument("--source", choices=("sqlite", "postgres"), default="sqlite")
    p_summary.set_defaults(func=cmd_summary)

    p_compare = sub.add_parser("compare", help="Compare SQLite and Postgres usage summaries")
    p_compare.set_defaults(func=cmd_compare)

    p_backfill = sub.add_parser("backfill", help="Backfill idempotent usage rows into Postgres")
    p_backfill.add_argument("--dry-run", action="store_true", help="Report row counts without touching Postgres")
    p_backfill.add_argument("--apply", action="store_true", help="Apply the backfill using psql")
    p_backfill.set_defaults(func=cmd_backfill)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        code = args.func(args)
    except Exception as exc:
        print(f"usage_pg_tools: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
