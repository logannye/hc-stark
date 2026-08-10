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
import sqlite3
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
WRANGLER_CONFIG = ROOT / "site" / "wrangler.toml"

# The export talks to D1's REST API directly rather than shelling out to
# Wrangler. That is not a style preference; Wrangler cannot do this job.
#
# `wrangler d1 execute <database>` resolves its positional argument as a NAME
# or binding, never as a UUID. Given the UUID it lists the account's databases,
# finds nothing called "ea4ad71c-...", and reports:
#     Couldn't find DB with name 'ea4ad71c-6175-4a69-b106-02cc4af378ae'
# which reads like a missing database rather than an unsupported identifier.
# (Observed 2026-08-10 with a token that could both query AND list, so it is
# not a permissions problem, and widening the token does not fix it.)
#
# Passing the friendly name instead would work but reintroduces exactly the
# ambiguity this module refuses: a name resolves against whatever is in scope,
# and resolving to the wrong or empty database is the failure that would read
# as zero demand. The REST endpoint takes the UUID IN THE URL PATH, so the
# database is addressed unambiguously and no resolution step exists to go
# wrong. It also needs only D1 Read, and removes Node and the pinned Wrangler
# toolchain from this job entirely.
D1_QUERY_URL = (
    "https://api.cloudflare.com/client/v4"
    "/accounts/{account}/d1/database/{database}/query"
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


def _credentials(environment: dict[str, str]) -> tuple[str, str]:
    """The validated (token, account) pair.

    A malformed or absent credential makes the API fail in ways that read like
    a query problem -- Cloudflare answers both with a bare "Authentication
    error [code: 10000]" -- so the shape is checked here, where the message can
    say what is actually wrong.
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
    return token, account


def query_request(sql: str, *, account: str, token: str) -> "urllib.request.Request":
    """The exact remote read request.

    The database is addressed by UUID in the URL path, so there is no name to
    resolve and nothing that can silently select a different (empty) database.
    `configured_database` has already proved this UUID is the one the deployed
    worker writes to.
    """
    return urllib.request.Request(
        D1_QUERY_URL.format(account=account, database=DATABASE_ID),
        data=json.dumps({"sql": sql}).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "tinyzkp-demand-clock",
        },
    )


def parse_statement_results(raw: str) -> list[dict[str, Any]]:
    """The single statement's rows from D1's response envelope.

    Shape (identical to what `wrangler --json` used to print, which is why the
    validation below is unchanged from the Wrangler era):
        {"success": true, "errors": [], "result": [
            {"success": true, "meta": {...}, "results": [ {...}, ... ]}]}
    `raw` is the serialized `result` array, i.e. the inner list.
    """
    text = (raw or "").strip()
    if not text:
        raise ExportError("D1 returned no result for a query")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise ExportError("D1 result is not valid JSON") from error
    if not isinstance(payload, list) or len(payload) != 1:
        raise ExportError("D1 returned other than one statement result")
    statement = payload[0]
    if not isinstance(statement, dict):
        raise ExportError("D1 statement result is not an object")
    if statement.get("success") is not True:
        raise ExportError("D1 reported an unsuccessful statement")
    if not isinstance(statement.get("meta"), dict):
        raise ExportError("D1 statement result carries no meta block")
    rows = statement.get("results")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ExportError("D1 statement result carries no row list")
    return rows


def _run_query(
    sql: str,
    *,
    account: str,
    token: str,
    opener: Callable[..., Any],
    timeout: int,
) -> list[dict[str, Any]]:
    request = query_request(sql, account=account, token=token)
    try:
        with opener(request, timeout=timeout) as response:
            body = response.read(MAX_COMMAND_OUTPUT_BYTES + 1)
    except urllib.error.HTTPError as error:
        # Cloudflare returns its error envelope in the BODY of a 4xx, so the
        # useful diagnostic is only available by reading the failed response.
        body = error.read(MAX_DIAGNOSTIC_BYTES)
        detail = body.decode("utf-8", "replace") if body else ""
        # The token must never reach a log, and it is not echoed back by the
        # API -- but redact by value anyway rather than trust that.
        if token:
            detail = detail.replace(token, "***")
        print(
            f"d1_demand_export: D1 returned HTTP {error.code}: "
            f"{detail[:MAX_DIAGNOSTIC_BYTES]}",
            file=sys.stderr,
        )
        raise ExportError("the D1 query failed") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ExportError("the D1 query could not complete") from error

    if len(body) > MAX_COMMAND_OUTPUT_BYTES:
        raise ExportError("the D1 query emitted oversized output")
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportError("D1 response is not valid JSON") from error
    if not isinstance(envelope, dict) or envelope.get("success") is not True:
        errors = ""
        if isinstance(envelope, dict):
            errors = json.dumps(envelope.get("errors"))[:MAX_DIAGNOSTIC_BYTES]
        print(f"d1_demand_export: D1 reported {errors}", file=sys.stderr)
        raise ExportError("the D1 query failed")
    return parse_statement_results(json.dumps(envelope.get("result")))


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
    opener: Callable[..., Any] = urllib.request.urlopen,
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

    token, account = _credentials(environment)

    # Remove any stale database BEFORE the first query. Everything after this
    # point either completes and renames a fresh file into place, or leaves
    # nothing for the report to read.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)

    # No sandbox temporary directory any more: it existed only to give Wrangler
    # an isolated HOME so it could not read or write the caller's Wrangler
    # state. An HTTPS request has no such ambient state to isolate.
    def query(sql: str) -> list[dict[str, Any]]:
        return _run_query(
            sql,
            account=account,
            token=token,
            opener=opener,
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
    parser.add_argument("--timeout", type=int, default=COMMAND_TIMEOUT)
    args = parser.parse_args(argv)

    try:
        summary = export(args.output, timeout=args.timeout)
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
