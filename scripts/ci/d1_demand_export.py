#!/usr/bin/env python3
"""Export the remote Cloudflare D1 `tinyzkp-estimator` tables into the local
SQLite file `scripts/ci/demand_report.py` reads.

Why this file exists. The 90-day kill criterion is measured by
`demand_report.py`, which opens a LOCAL SQLite file read-only. The rows it
needs are written by `site/_worker.js` into remote D1. Nothing committed
connected the two, so the report could only ever run against a database
somebody produced by hand -- which in practice meant it never ran against
production at all, and the pre-committed decision due at the close of the
window had no path to fire.

THE CORRECTNESS PROPERTY THIS FILE IS BUILT AROUND: a broken export must
never be mistakable for genuine zero demand. Both look like "no rows", and
confusing them means retiring the product on a bug rather than on a
measurement. Four mechanisms keep them apart, and every one fails LOUDLY:

  1. The destination file is deleted BEFORE any query runs and is recreated
     only by an atomic rename after every check below has passed. A failed
     export therefore leaves no database at all, and `demand_report.py --db`
     exits 1 with "no such database file" instead of printing a confident
     zero. A genuinely empty remote log, by contrast, still produces a real
     file -- so "export broke" and "nobody called" are different artifacts on
     disk, not the same one.
  2. The database is addressed by the exact UUID committed in
     `site/wrangler.toml`, and this script re-reads that file and refuses to
     run if the binding has been repointed. Querying a different (and
     therefore empty) database is the most plausible way to manufacture a
     false zero, and it is the one failure that would otherwise look
     completely normal.
  3. Both `demand_log` and `rejected_log` must already exist remotely. An
     unmigrated database answers every demand query with nothing, which is
     the same false zero wearing a different hat.
  4. Every table is counted before it is paged, and the page loop must return
     exactly that many rows. D1 caps response size, so a silently truncated
     result is the realistic way an export under-reports demand; a mismatch
     is an error, never a smaller number.

Row shape is checked against the committed migrations rather than trusted:
the local database is created by executing `migrations/0001_demand_log.sql`
and `migrations/0003_rejected_log.sql`, and every remote row must carry
exactly those columns. Remote schema drift fails here instead of quietly
dropping a column the report reads.

This script only ever SELECTs. It never writes to D1, and it stores nothing
the tables do not already hold -- the demand log is shape-only by
construction (see migrations/0001_demand_log.sql).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
WRANGLER_CONFIG = ROOT / "site" / "wrangler.toml"
# Installed by `npm ci --prefix toolchains/cloudflare`, which pins Wrangler
# 4.85.0 by lockfile integrity. The Pages deploy path materializes the same
# toolchain under /var/lib as root; this read-only report does not need that
# ceremony, but it must not fall back to an unpinned `npx wrangler` either.
DEFAULT_WRANGLER = (
    ROOT / "toolchains" / "cloudflare" / "node_modules" / "wrangler" / "bin" / "wrangler.js"
)

DATABASE_NAME = "tinyzkp-estimator"
DATABASE_ID = "ea4ad71c-6175-4a69-b106-02cc4af378ae"

SUMMARY_SCHEMA = "tinyzkp-d1-demand-export-v1"

# (table, committed migration, exact column set including the rowid key).
# `demand_report.py` reads `demand_log` for the verdict and `rejected_log`
# for the separately-reported rejection counts; both are exported so the
# local file is a faithful copy of what the report is entitled to see.
EXPORTED_TABLES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "demand_log",
        "0001_demand_log.sql",
        (
            "id",
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
        ),
    ),
    (
        "rejected_log",
        "0003_rejected_log.sql",
        ("id", "observed_at_hour", "reason_code", "key_id", "anon_ip_hash"),
    ),
)

ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")
DATABASE_NAME_LINE = re.compile(r'(?m)^\s*database_name\s*=\s*"([^"]*)"')
DATABASE_ID_LINE = re.compile(r'(?m)^\s*database_id\s*=\s*"([^"]*)"')

PAGE_ROWS = 2000
MAX_PAGES = 10_000
COMMAND_TIMEOUT = 300
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 4096
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class ExportError(ValueError):
    """The export failed a fail-closed invariant and produced no database."""


def configured_database(path: Path = WRANGLER_CONFIG) -> tuple[str, str]:
    """The `(database_name, database_id)` the deployed worker is bound to.

    Parsed with a regex rather than a TOML parser on purpose: `tomllib` is
    absent from the 3.9 interpreter this repository still has to run on, and
    the binding block is two literal lines whose exact text is already the
    thing under review.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ExportError(f"cannot read the Wrangler config: {path}") from error
    names = DATABASE_NAME_LINE.findall(text)
    identifiers = DATABASE_ID_LINE.findall(text)
    if len(names) != 1 or len(identifiers) != 1:
        raise ExportError(
            "Wrangler config does not declare exactly one D1 binding; refusing "
            "to guess which database the demand log lives in"
        )
    return names[0], identifiers[0]


def _executable(candidate: str | Path | None, program: str) -> Path:
    resolved = Path(candidate) if candidate is not None else None
    if resolved is None:
        found = shutil.which(program)
        if found is None:
            raise ExportError(f"required executable is not on PATH: {program}")
        resolved = Path(found)
    if not resolved.is_file():
        raise ExportError(f"required executable is missing: {resolved}")
    return resolved


def _wrangler_environment(
    environment: dict[str, str], node: Path, home: Path
) -> dict[str, str]:
    """A minimal environment for Wrangler, with the credential validated.

    A malformed or absent token makes Wrangler fail in ways that read like a
    query problem, so the shape is checked here where the message can say
    what is actually wrong.
    """
    token = environment.get("CLOUDFLARE_API_TOKEN", "")
    account = environment.get("CLOUDFLARE_ACCOUNT_ID", "")
    if (
        not 20 <= len(token) <= 512
        or token != token.strip()
        or any(character.isspace() for character in token)
    ):
        raise ExportError("CLOUDFLARE_API_TOKEN is missing or malformed")
    if ACCOUNT_ID.fullmatch(account) is None:
        raise ExportError("CLOUDFLARE_ACCOUNT_ID is missing or malformed")
    return {
        "PATH": os.pathsep.join((str(node.parent), TRUSTED_PATH)),
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_API_TOKEN": token,
        "CLOUDFLARE_ACCOUNT_ID": account,
    }


def wrangler_command(sql: str, *, node: Path, wrangler: Path) -> tuple[str, ...]:
    """The exact remote read command.

    The database is named by UUID, not by the friendly name: a name is
    resolved against whatever config happens to be in scope, and resolving to
    the wrong (empty) database is precisely the failure that would read as
    zero demand. `configured_database` has already proved this UUID is the one
    the deployed worker writes to.
    """
    return (
        str(node),
        str(wrangler),
        "d1",
        "execute",
        DATABASE_ID,
        "--remote",
        "--json",
        "--command",
        sql,
    )


def parse_statement_results(raw: str) -> list[dict[str, Any]]:
    """The single statement's rows from Wrangler's `--json` envelope."""
    text = (raw or "").strip()
    if not text:
        raise ExportError("Wrangler produced no output for a query")
    # Under `--json` Wrangler is expected to print nothing but the envelope,
    # but it has historically prefixed a progress banner. Skipping to the
    # first `[` tolerates that WITHOUT tolerating a partial document:
    # everything from that byte on still has to parse as one complete value.
    start = text.find("[")
    if start < 0:
        raise ExportError("Wrangler output contains no JSON array")
    try:
        payload = json.loads(text[start:])
    except json.JSONDecodeError as error:
        raise ExportError("Wrangler output is not valid JSON") from error
    if not isinstance(payload, list) or len(payload) != 1:
        raise ExportError("Wrangler returned other than one statement result")
    statement = payload[0]
    if not isinstance(statement, dict):
        raise ExportError("Wrangler statement result is not an object")
    if statement.get("success") is not True:
        raise ExportError("Wrangler reported an unsuccessful statement")
    if not isinstance(statement.get("meta"), dict):
        raise ExportError("Wrangler statement result carries no meta block")
    rows = statement.get("results")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ExportError("Wrangler statement result carries no row list")
    return rows


def _run_query(
    sql: str,
    *,
    node: Path,
    wrangler: Path,
    environment: dict[str, str],
    runner: Callable[..., "subprocess.CompletedProcess[str]"],
    timeout: int,
) -> list[dict[str, Any]]:
    command = wrangler_command(sql, node=node, wrangler=wrangler)
    try:
        completed = runner(
            command,
            cwd=str(ROOT),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExportError("the Wrangler query could not complete") from error
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode != 0:
        # The diagnostic is worth printing -- a weekly job the owner has to
        # debug from an email needs the provider's own message -- but the
        # token must never appear in a log, so it is redacted by value rather
        # than by guessing at a pattern.
        token = environment.get("CLOUDFLARE_API_TOKEN", "")
        diagnostic = f"{stdout}\n{stderr}"
        if token:
            diagnostic = diagnostic.replace(token, "***")
        print(
            "d1_demand_export: Wrangler exited "
            f"{completed.returncode}: {diagnostic[:MAX_DIAGNOSTIC_BYTES]}",
            file=sys.stderr,
        )
        raise ExportError("the Wrangler query failed")
    if len(stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES:
        raise ExportError("the Wrangler query emitted oversized output")
    return parse_statement_results(stdout)


def _non_negative_integer(
    rows: list[dict[str, Any]], column: str, description: str
) -> int:
    if len(rows) != 1:
        raise ExportError(f"{description} did not return exactly one row")
    value = rows[0].get(column)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExportError(f"{description} is not a non-negative integer")
    return value


def _fetch_table(
    table: str,
    columns: tuple[str, ...],
    *,
    query: Callable[[str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Every row of `table`, counted first and proved complete afterwards.

    Paging is keyset-based and bounded above by the maximum id observed
    BEFORE the count is taken. Rows the worker writes during the export get a
    higher id and are excluded from both the count and the pages, so ordinary
    concurrent traffic cannot make the two disagree. A disagreement therefore
    means rows were lost (a truncated response, or the retention pruner
    firing mid-export) -- which is reported as an error, never as a smaller
    demand figure.
    """
    max_id = _non_negative_integer(
        query(f"SELECT COALESCE(MAX(id), 0) AS max_id FROM {table}"),
        "max_id",
        f"{table} maximum id",
    )
    expected = _non_negative_integer(
        query(f"SELECT COUNT(*) AS row_count FROM {table} WHERE id <= {max_id}"),
        "row_count",
        f"{table} row count",
    )

    rows: list[dict[str, Any]] = []
    last_id = 0
    pages = 0
    while len(rows) < expected:
        pages += 1
        if pages > MAX_PAGES:
            raise ExportError(f"{table} export exceeded {MAX_PAGES} pages")
        page = query(
            f"SELECT * FROM {table} WHERE id > {last_id} AND id <= {max_id} "
            f"ORDER BY id LIMIT {PAGE_ROWS}"
        )
        if not page:
            break
        for row in page:
            if set(row) != set(columns):
                raise ExportError(
                    f"{table} row shape differs from the committed migration; "
                    "the report would silently read a column that no longer "
                    "means what it did"
                )
            row_id = row["id"]
            if isinstance(row_id, bool) or not isinstance(row_id, int) or row_id <= last_id:
                raise ExportError(f"{table} rows are not returned in ascending id order")
            last_id = row_id
        rows.extend(page)

    if len(rows) != expected:
        raise ExportError(
            f"{table} export returned {len(rows)} of {expected} rows; a partial "
            "export must never be reported as less demand"
        )
    return rows


def _storable(value: Any, table: str, column: str) -> Any:
    """A JSON value SQLite can hold, or a loud failure.

    D1 returns JSON, so a nested object or array here means the remote column
    no longer holds the scalar the migration declared.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise ExportError(f"{table}.{column} holds a value SQLite cannot store")


def _materialize(output: Path, exported: dict[str, list[dict[str, Any]]]) -> None:
    """Build the local database, then move it into place in one step.

    The rename is what makes a half-written export impossible to read: until
    it happens there is no file at `output` at all, and `demand_report.py`
    refuses to run rather than reporting zero.
    """
    scratch = output.with_name(f"{output.name}.partial-{os.getpid()}")
    scratch.unlink(missing_ok=True)
    conn = sqlite3.connect(scratch)
    try:
        for table, migration, columns in EXPORTED_TABLES:
            conn.executescript((MIGRATIONS / migration).read_text(encoding="utf-8"))
            placeholders = ", ".join("?" for _ in columns)
            conn.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                [
                    tuple(_storable(row[column], table, column) for column in columns)
                    for row in exported[table]
                ],
            )
        conn.commit()
    except sqlite3.Error as error:
        scratch.unlink(missing_ok=True)
        raise ExportError("the exported rows do not fit the committed schema") from error
    finally:
        conn.close()
    os.replace(scratch, output)


def export(
    output: Path,
    *,
    environment: dict[str, str] | None = None,
    node: str | Path | None = None,
    wrangler: str | Path | None = None,
    runner: Callable[..., "subprocess.CompletedProcess[str]"] = subprocess.run,
    timeout: int = COMMAND_TIMEOUT,
    config: Path = WRANGLER_CONFIG,
    now: int | None = None,
) -> dict[str, Any]:
    """Export the remote demand tables to `output` and describe what was read."""
    environment = dict(os.environ if environment is None else environment)
    now = int(time.time()) if now is None else now

    name, identifier = configured_database(config)
    if (name, identifier) != (DATABASE_NAME, DATABASE_ID):
        raise ExportError(
            "site/wrangler.toml no longer binds the reviewed demand database "
            f"({name}/{identifier}); exporting a different database would "
            "manufacture a false zero"
        )

    node_path = _executable(node, "node")
    wrangler_path = Path(wrangler) if wrangler is not None else DEFAULT_WRANGLER
    if not wrangler_path.is_file():
        raise ExportError(
            f"pinned Wrangler entrypoint is missing: {wrangler_path} "
            "(run `npm ci --prefix toolchains/cloudflare`)"
        )

    # Remove any stale database BEFORE the first query. Everything after this
    # point either completes and renames a fresh file into place, or leaves
    # nothing for the report to read.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="tinyzkp-d1-export-") as home:
        wrangler_environment = _wrangler_environment(
            environment, node_path, Path(home)
        )

        def query(sql: str) -> list[dict[str, Any]]:
            return _run_query(
                sql,
                node=node_path,
                wrangler=wrangler_path,
                environment=wrangler_environment,
                runner=runner,
                timeout=timeout,
            )

        present = {
            row.get("name")
            for row in query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        }
        missing = sorted(table for table, _, _ in EXPORTED_TABLES if table not in present)
        if missing:
            raise ExportError(
                "the remote database is missing " + ", ".join(missing) + "; an "
                "unmigrated database answers every demand query with nothing, "
                "which is not the same as nobody calling"
            )

        exported = {
            table: _fetch_table(table, columns, query=query)
            for table, _, columns in EXPORTED_TABLES
        }

    _materialize(output, exported)

    return {
        "schema": SUMMARY_SCHEMA,
        "schema_version": 1,
        "exported_at": now,
        "database_name": DATABASE_NAME,
        "database_id": DATABASE_ID,
        "output": str(output),
        # Total rows in each table, NOT a demand figure: the report applies
        # the trailing window and the keyed/anonymous split itself.
        "rows_exported": {table: len(rows) for table, rows in exported.items()},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write the exported SQLite file that demand_report.py --db reads",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        default=None,
        help="Optional path for the JSON export summary also printed to stdout",
    )
    parser.add_argument(
        "--node",
        default=None,
        help="Node executable to run Wrangler with; defaults to `node` on PATH",
    )
    parser.add_argument(
        "--wrangler",
        default=None,
        help=f"Wrangler entrypoint; defaults to {DEFAULT_WRANGLER}",
    )
    parser.add_argument("--timeout", type=int, default=COMMAND_TIMEOUT)
    args = parser.parse_args(argv)

    try:
        summary = export(
            args.output,
            node=args.node,
            wrangler=args.wrangler,
            timeout=args.timeout,
        )
    except ExportError as error:
        print(f"d1_demand_export: {error}", file=sys.stderr)
        return 1

    text = json.dumps(summary, indent=2, sort_keys=True)
    if args.summary_output is not None:
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.summary_output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
