#!/usr/bin/env python3
"""Postgres migration helper for TinyZKP tenant/auth state.

This tool uses only the Python standard library plus the `psql` CLI. It is
meant for the tenant-store phase of the SQLite -> Postgres migration:

    python3 billing/tenant_pg_tools.py init
    python3 billing/tenant_pg_tools.py backfill --dry-run
    python3 billing/tenant_pg_tools.py backfill --apply
    python3 billing/tenant_pg_tools.py compare

It mirrors the SQLite `tenant_store.py` schema into Postgres so API and MCP can
use `HC_SERVER_AUTH_PG_URL` for shared tenant/API-key authentication.
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
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TENANT_DB_PATH = os.environ.get("HC_TENANT_STORE_PATH", "/opt/hc-stark/data/tenant_store.sqlite")
PG_URL = os.environ.get("HC_SERVER_AUTH_PG_URL") or os.environ.get("HC_SERVER_PG_URL")
PSQL_BIN = os.environ.get("PSQL_BIN", "psql")
SCHEMA_SQL = (ROOT / "crates" / "hc-server" / "sql" / "tenant_auth_pg.sql").read_text()


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: tuple[str, ...]
    conflict_column: str
    update_columns: tuple[str, ...]
    summary_fields: tuple[tuple[str, str], ...]


TENANTS_SPEC = TableSpec(
    name="tenants",
    columns=(
        "tenant_id",
        "email",
        "api_key_hash",
        "api_key_prefix",
        "stripe_customer_id",
        "stripe_subscription_id",
        "stripe_subscription_item_id",
        "status",
        "plan",
        "attribution_source",
        "attribution_medium",
        "attribution_campaign",
        "attribution_platform",
        "attribution_use_case",
        "attribution_workflow",
        "attribution_intent",
        "attribution_landing_path",
        "attribution_referrer_host",
        "attribution_first_seen_at",
        "created_at_ms",
        "updated_at_ms",
    ),
    conflict_column="tenant_id",
    update_columns=(
        "email",
        "api_key_hash",
        "api_key_prefix",
        "stripe_customer_id",
        "stripe_subscription_id",
        "stripe_subscription_item_id",
        "status",
        "plan",
        "attribution_source",
        "attribution_medium",
        "attribution_campaign",
        "attribution_platform",
        "attribution_use_case",
        "attribution_workflow",
        "attribution_intent",
        "attribution_landing_path",
        "attribution_referrer_host",
        "attribution_first_seen_at",
        "updated_at_ms",
    ),
    summary_fields=(
        ("count", "COUNT(*)"),
        ("active_count", "COUNT(*) FILTER (WHERE status = 'active')"),
        ("suspended_count", "COUNT(*) FILTER (WHERE status = 'suspended')"),
        ("cancelled_count", "COUNT(*) FILTER (WHERE status = 'cancelled')"),
        ("free_count", "COUNT(*) FILTER (WHERE plan = 'free')"),
        ("paid_count", "COUNT(*) FILTER (WHERE plan <> 'free')"),
        ("updated_max", "COALESCE(MAX(updated_at_ms), 0)"),
    ),
)

PROCESSED_EVENTS_SPEC = TableSpec(
    name="processed_events",
    columns=("event_id", "processed_at_ms"),
    conflict_column="event_id",
    update_columns=(),
    summary_fields=(
        ("count", "COUNT(*)"),
        ("processed_max", "COALESCE(MAX(processed_at_ms), 0)"),
    ),
)

MAGIC_LINKS_SPEC = TableSpec(
    name="magic_links",
    columns=("token_hash", "tenant_id", "created_at_ms", "expires_at_ms", "used"),
    conflict_column="token_hash",
    update_columns=("tenant_id", "created_at_ms", "expires_at_ms", "used"),
    summary_fields=(
        ("count", "COUNT(*)"),
        ("unused_count", "COUNT(*) FILTER (WHERE used = 0)"),
        ("expires_max", "COALESCE(MAX(expires_at_ms), 0)"),
    ),
)

SESSIONS_SPEC = TableSpec(
    name="sessions",
    columns=("token_hash", "tenant_id", "created_at_ms", "expires_at_ms"),
    conflict_column="token_hash",
    update_columns=("tenant_id", "created_at_ms", "expires_at_ms"),
    summary_fields=(
        ("count", "COUNT(*)"),
        ("expires_max", "COALESCE(MAX(expires_at_ms), 0)"),
    ),
)

ALL_SPECS = (TENANTS_SPEC, PROCESSED_EVENTS_SPEC, MAGIC_LINKS_SPEC, SESSIONS_SPEC)


def require_pg_url(value: str | None) -> str:
    if not value:
        raise SystemExit("HC_SERVER_AUTH_PG_URL or HC_SERVER_PG_URL is required, or pass --pg-url")
    return value


def table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def sqlite_summary(path: str) -> dict[str, dict[str, int]]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    summary: dict[str, dict[str, int]] = {}
    try:
        for spec in ALL_SPECS:
            if not table_exists(conn, spec.name):
                summary[spec.name] = {field: 0 for field, _ in spec.summary_fields}
                continue
            row = _sqlite_summary_row(conn, spec)
            summary[spec.name] = {field: int(row[field] or 0) for field, _ in spec.summary_fields}
    finally:
        conn.close()
    return summary


def _sqlite_summary_row(conn: sqlite3.Connection, spec: TableSpec) -> sqlite3.Row:
    fields: list[str] = []
    for field, expr in spec.summary_fields:
        sqlite_expr = expr
        if "FILTER" in sqlite_expr:
            if field == "active_count":
                sqlite_expr = "SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)"
            elif field == "suspended_count":
                sqlite_expr = "SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END)"
            elif field == "cancelled_count":
                sqlite_expr = "SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END)"
            elif field == "free_count":
                sqlite_expr = "SUM(CASE WHEN plan = 'free' THEN 1 ELSE 0 END)"
            elif field == "paid_count":
                sqlite_expr = "SUM(CASE WHEN plan <> 'free' THEN 1 ELSE 0 END)"
            elif field == "unused_count":
                sqlite_expr = "SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END)"
        fields.append(f"{sqlite_expr} AS {field}")
    return conn.execute(f"SELECT {', '.join(fields)} FROM {spec.name}").fetchone()


def pg_summary_sql() -> str:
    parts: list[str] = []
    for spec in ALL_SPECS:
        fields = ", ".join(f"'{field}', ({expr})::bigint" for field, expr in spec.summary_fields)
        parts.append(f"'{spec.name}', (SELECT json_build_object({fields}) FROM {spec.name})")
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


def postgres_summary(pg_url: str) -> dict[str, dict[str, int]]:
    raw = run_psql_query(pg_url, pg_summary_sql())
    data = json.loads(raw)
    return {
        table: {field: int(value or 0) for field, value in fields.items()}
        for table, fields in data.items()
    }


def compare_summaries(sqlite_data: dict[str, dict[str, int]], pg_data: dict[str, dict[str, int]]) -> dict[str, Any]:
    ok = True
    tables: dict[str, Any] = {}
    for spec in ALL_SPECS:
        fields: dict[str, Any] = {}
        sqlite_table = sqlite_data.get(spec.name, {})
        pg_table = pg_data.get(spec.name, {})
        for field, _expr in spec.summary_fields:
            sqlite_value = int(sqlite_table.get(field, 0) or 0)
            pg_value = int(pg_table.get(field, 0) or 0)
            delta = pg_value - sqlite_value
            if delta != 0:
                ok = False
            fields[field] = {"sqlite": sqlite_value, "postgres": pg_value, "delta": delta}
        tables[spec.name] = fields
    return {"ok": ok, "tables": tables}


def csv_for_table(path: str, spec: TableSpec) -> tuple[str, int]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    count = 0
    try:
        if not table_exists(conn, spec.name):
            return "", 0
        existing_columns = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({spec.name})").fetchall()
        }
        select_columns = ", ".join(
            col if col in existing_columns else f"NULL AS {col}"
            for col in spec.columns
        )
        for row in conn.execute(f"SELECT {select_columns} FROM {spec.name} ORDER BY rowid"):
            writer.writerow([row[col] for col in spec.columns])
            count += 1
    finally:
        conn.close()
    return out.getvalue(), count


def _copy_block(spec: TableSpec, csv_data: str) -> str:
    columns = ", ".join(spec.columns)
    temp = f"{spec.name}_import"
    if spec.update_columns:
        updates = ", ".join(f"{col}=EXCLUDED.{col}" for col in spec.update_columns)
        conflict = f"ON CONFLICT ({spec.conflict_column}) DO UPDATE SET {updates};"
    else:
        conflict = f"ON CONFLICT ({spec.conflict_column}) DO NOTHING;"
    return "\n".join(
        [
            f"CREATE TEMP TABLE {temp} (LIKE {spec.name} INCLUDING DEFAULTS);",
            f"COPY {temp} ({columns}) FROM STDIN WITH (FORMAT csv);",
            csv_data + r"\.",
            f"INSERT INTO {spec.name} ({columns})",
            f"SELECT {columns} FROM {temp}",
            conflict,
            f"DROP TABLE {temp};",
        ]
    )


def build_backfill_script(path: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    blocks = ["BEGIN;"]
    for spec in ALL_SPECS:
        csv_data, count = csv_for_table(path, spec)
        counts[spec.name] = count
        blocks.append(_copy_block(spec, csv_data))
    blocks.append("COMMIT;")
    return "\n".join(blocks) + "\n", counts


def cmd_init(args: argparse.Namespace) -> int:
    run_psql_script(require_pg_url(args.pg_url), SCHEMA_SQL)
    print(json.dumps({"action": "init", "ok": True}, indent=2, sort_keys=True))
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    if args.source == "sqlite":
        data = sqlite_summary(args.sqlite)
    else:
        data = postgres_summary(require_pg_url(args.pg_url))
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    sqlite_data = sqlite_summary(args.sqlite)
    pg_data = postgres_summary(require_pg_url(args.pg_url))
    result = compare_summaries(sqlite_data, pg_data)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def cmd_backfill(args: argparse.Namespace) -> int:
    if not args.dry_run and not args.apply:
        raise SystemExit("pass --dry-run or --apply")
    if args.dry_run and args.apply:
        raise SystemExit("choose only one of --dry-run or --apply")

    script, counts = build_backfill_script(args.sqlite)
    result = {
        "action": "backfill",
        "mode": "dry_run" if args.dry_run else "apply",
        "sqlite": args.sqlite,
        "tables": counts,
    }
    if args.dry_run:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    run_psql_script(require_pg_url(args.pg_url), SCHEMA_SQL + "\n" + script)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TinyZKP SQLite/Postgres tenant migration helper")
    parser.add_argument("--sqlite", default=TENANT_DB_PATH, help="Path to tenant_store.sqlite")
    parser.add_argument("--pg-url", default=PG_URL, help="Postgres URL; defaults to HC_SERVER_AUTH_PG_URL or HC_SERVER_PG_URL")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize Postgres tenant/auth schema")
    p_init.set_defaults(func=cmd_init)

    p_summary = sub.add_parser("summary", help="Print SQLite or Postgres tenant summary")
    p_summary.add_argument("--source", choices=("sqlite", "postgres"), default="sqlite")
    p_summary.set_defaults(func=cmd_summary)

    p_compare = sub.add_parser("compare", help="Compare SQLite and Postgres tenant summaries")
    p_compare.set_defaults(func=cmd_compare)

    p_backfill = sub.add_parser("backfill", help="Backfill tenant/auth state into Postgres")
    p_backfill.add_argument("--dry-run", action="store_true", help="Report row counts without touching Postgres")
    p_backfill.add_argument("--apply", action="store_true", help="Apply the backfill using psql")
    p_backfill.set_defaults(func=cmd_backfill)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        code = args.func(args)
    except Exception as exc:
        print(f"tenant_pg_tools: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
