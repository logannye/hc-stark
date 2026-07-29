#!/usr/bin/env python3
"""Fail CI when the worker writes anything the privacy notice does not disclose.

The defect this exists to prevent has already happened once. Phase 1b added a
D1 database, a `demand_log` table, and a key-minting endpoint, and shipped
them while `site/privacy.html` still said the site "contains no ... event
collector, customer account, proof API, or TinyZKP analytics database". The
copy was not maliciously wrong; it was simply never wired to the code, so
nothing could notice it had become false.

So this gate binds three artifacts together and fails if they disagree:

    migrations/*.sql   -- what tables and columns EXIST
    site/_worker.js    -- what the worker actually WRITES
    site/privacy-disclosure-v1.json -- what we have DISCLOSED

A new column in `demand_log` now breaks the build until someone names it in
the manifest, and the manifest points at the section of `site/privacy.html`
that has to describe it. Listing a column here is not itself the disclosure --
it is the receipt that the disclosure was considered.

The check runs in both directions. Undisclosed writes are the dangerous
direction; stale manifest entries are the direction that quietly erodes trust
in the gate, so they fail too.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "migrations"
WORKER = ROOT / "site" / "_worker.js"
MANIFEST = ROOT / "site" / "privacy-disclosure-v1.json"
PRIVACY = ROOT / "site" / "privacy.html"

# The exact sentence that was live and false. Kept verbatim as a regression
# tripwire: if it ever reappears, something reverted the disclosure.
RETIRED_DENIAL = "no custom contact form, event collector, customer account"

CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*?)\n\)\s*;",
    re.DOTALL | re.IGNORECASE,
)
INSERT_RE = re.compile(r"INSERT\s+INTO\s+(\w+)\s*\(([^)]*)\)", re.IGNORECASE)
UPDATE_RE = re.compile(r"UPDATE\s+(\w+)\s+SET\s+(\w+)", re.IGNORECASE)
SALT_LITERAL_RE = re.compile(r"IP_HASH_SALT\s*=\s*[\"'`]")


def _columns_from_ddl(body: str) -> set[str]:
    """First identifier of each top-level line in a CREATE TABLE body."""
    columns: set[str] = set()
    for raw in body.splitlines():
        line = raw.strip().rstrip(",")
        if not line or line.startswith("--"):
            continue
        head = line.split()[0]
        # Table-level constraints, not columns.
        if head.upper() in {"PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"}:
            continue
        columns.add(head)
    return columns


def parse_migrations() -> dict[str, set[str]]:
    tables: dict[str, set[str]] = {}
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        for name, body in CREATE_TABLE_RE.findall(text):
            tables.setdefault(name, set()).update(_columns_from_ddl(body))
    return tables


def parse_worker_writes() -> dict[str, set[str]]:
    """Every (table, column) the worker can write, from INSERT and UPDATE."""
    text = WORKER.read_text(encoding="utf-8")
    writes: dict[str, set[str]] = {}
    for table, column_blob in INSERT_RE.findall(text):
        columns = {c.strip() for c in column_blob.split(",") if c.strip()}
        writes.setdefault(table, set()).update(columns)
    for table, column in UPDATE_RE.findall(text):
        writes.setdefault(table, set()).add(column)
    return writes


def load_manifest() -> dict[str, object]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("privacy disclosure manifest root must be an object")
    return data


def manifest_tables(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    entries = manifest.get("tables")
    if not isinstance(entries, list):
        raise ValueError("manifest 'tables' must be a list")
    result: dict[str, dict[str, object]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"tables[{index}] must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"tables[{index}].name must be a non-empty string")
        if name in result:
            raise ValueError(f"duplicate table entry: {name}")
        result[name] = entry
    return result


def check(
    *,
    migrations: dict[str, set[str]],
    writes: dict[str, set[str]],
    manifest: dict[str, object],
    privacy_html: str,
    worker_js: str,
) -> list[str]:
    failures: list[str] = []
    declared = manifest_tables(manifest)

    # 1. The dangerous direction: writes we have not disclosed.
    for table in sorted(writes):
        entry = declared.get(table)
        if entry is None:
            failures.append(
                f"site/_worker.js writes to table {table!r}, which is absent from "
                f"site/privacy-disclosure-v1.json -- disclose it in "
                f"site/privacy.html and add it to the manifest before shipping"
            )
            continue
        columns = entry.get("columns")
        if not isinstance(columns, dict):
            failures.append(f"tables[{table}].columns must be an object")
            continue
        undisclosed = sorted(writes[table] - set(columns))
        if undisclosed:
            failures.append(
                f"site/_worker.js writes undisclosed column(s) "
                f"{undisclosed} to {table!r}; every column written must be "
                f"named in the manifest and covered by site/privacy.html"
            )

    # 2. The erosion direction: manifest entries that no longer match the DDL.
    #    A manifest describing tables that do not exist is not a disclosure,
    #    it is decoration, and it makes the gate look more binding than it is.
    for table, entry in sorted(declared.items()):
        actual = migrations.get(table)
        if actual is None:
            failures.append(
                f"manifest declares table {table!r}, which no migration creates"
            )
            continue
        columns = entry.get("columns")
        if not isinstance(columns, dict):
            continue
        phantom = sorted(set(columns) - actual)
        if phantom:
            failures.append(
                f"manifest declares column(s) {phantom} on {table!r} that the "
                f"migrations do not create"
            )
        missing = sorted(actual - set(columns))
        if missing:
            failures.append(
                f"table {table!r} has column(s) {missing} that the manifest "
                f"does not describe"
            )

    # 3. Every manifest table must point at a real anchor in the notice, so
    #    "disclosed" cannot degrade into "listed in a JSON file nobody reads".
    for table, entry in sorted(declared.items()):
        anchor = entry.get("disclosed_in")
        if not isinstance(anchor, str) or not anchor:
            failures.append(f"tables[{table}].disclosed_in must name a privacy.html anchor")
            continue
        if f'id="{anchor}"' not in privacy_html:
            failures.append(
                f"tables[{table}].disclosed_in={anchor!r} does not match any "
                f"id= anchor in site/privacy.html"
            )

    # 4. The notice must actually link the manifest.
    if "privacy-disclosure-v1.json" not in privacy_html:
        failures.append("site/privacy.html must link site/privacy-disclosure-v1.json")

    # 5. The retired denial must never come back.
    if RETIRED_DENIAL in privacy_html:
        failures.append(
            "site/privacy.html contains the retired denial "
            f"({RETIRED_DENIAL!r}); it was false from Phase 1b onward"
        )

    # 6. Honesty about the IP hash must track the code. While the salt is a
    #    source literal, the manifest must admit the hash is reversible. If
    #    someone later moves the salt to a real secret, this fails and forces
    #    the claim to be revisited deliberately rather than left understated.
    limits = manifest.get("identifier_limitations")
    ip = limits.get("anon_ip_hash") if isinstance(limits, dict) else None
    if not isinstance(ip, dict):
        failures.append("manifest must document identifier_limitations.anon_ip_hash")
    else:
        salt_is_literal = bool(SALT_LITERAL_RE.search(worker_js))
        if salt_is_literal and (ip.get("salt_is_secret") is not False or ip.get("reversible") is not True):
            failures.append(
                "IP_HASH_SALT is a source literal, so the manifest must record "
                "salt_is_secret=false and reversible=true"
            )
        if not salt_is_literal and ip.get("salt_is_secret") is not True:
            failures.append(
                "IP_HASH_SALT is no longer a source literal -- revisit "
                "identifier_limitations.anon_ip_hash and the privacy copy"
            )

    # 7. Retention must be stated, and must not claim enforcement without code.
    retention = manifest.get("retention")
    if not isinstance(retention, dict) or "enforced" not in retention:
        failures.append("manifest must document retention.enforced")

    return failures


def main(argv: list[str]) -> int:
    try:
        migrations = parse_migrations()
        writes = parse_worker_writes()
        manifest = load_manifest()
        failures = check(
            migrations=migrations,
            writes=writes,
            manifest=manifest,
            privacy_html=PRIVACY.read_text(encoding="utf-8"),
            worker_js=WORKER.read_text(encoding="utf-8"),
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"privacy disclosure gate failed to run: {error}", file=sys.stderr)
        return 2

    if failures:
        print("privacy disclosure gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    written = sum(len(columns) for columns in writes.values())
    print(
        f"PASS privacy disclosure gate "
        f"({len(writes)} written tables, {written} written columns disclosed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
