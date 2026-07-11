#!/usr/bin/env python3
"""Durable, local storage for recovery-period evaluation applications.

The public intake path deliberately has no outbound-email dependency. Records
are written synchronously to an owner-only SQLite database and reviewed with
``billing/evaluation_intake.py``.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import sqlite3
import stat
from pathlib import Path
from typing import Any


DEFAULT_PATH = "/opt/hc-stark/data/evaluation_applications.sqlite"
VALID_STATUSES = {"new", "qualified", "declined", "contracting", "closed"}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _path(path: str | os.PathLike[str] | None = None) -> Path:
    return Path(path or os.environ.get("HC_EVALUATION_STORE_PATH", DEFAULT_PATH))


def _require_owner_only(path: Path, mode: int, *, kind: str) -> None:
    path.chmod(mode)
    info = path.stat(follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) != mode:
        raise PermissionError(f"{kind} permissions must be {mode:o}: {path}")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise PermissionError(f"{kind} must be owned by the service user: {path}")


def _prepare_private_path(db_path: Path) -> None:
    parent = db_path.parent
    if parent.exists() and parent.is_symlink():
        raise PermissionError(f"evaluation store directory must not be a symlink: {parent}")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent.is_dir():
        raise PermissionError(f"evaluation store parent is not a directory: {parent}")
    _require_owner_only(parent, 0o700, kind="evaluation store directory")

    if db_path.is_symlink():
        raise PermissionError(f"evaluation store must not be a symlink: {db_path}")
    if db_path.exists() and not db_path.is_file():
        raise PermissionError(f"evaluation store must be a regular file: {db_path}")


def open_db(path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    db_path = _path(path)
    _prepare_private_path(db_path)

    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evaluation_applications (
                application_id TEXT PRIMARY KEY,
                submitted_at TEXT NOT NULL,
                retention_deadline TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('new', 'qualified', 'declined', 'contracting', 'closed')
                ),
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                qualification_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evaluation_status_submitted "
            "ON evaluation_applications(status, submitted_at)"
        )
        conn.commit()
        _require_owner_only(db_path, 0o600, kind="evaluation store")
    except Exception:
        conn.close()
        raise
    return conn


def create_application(
    *,
    name: str,
    email: str,
    category: str,
    message: str,
    qualification: dict[str, str],
    path: str | os.PathLike[str] | None = None,
    now: dt.datetime | None = None,
) -> str:
    submitted = now or _utc_now()
    retention_deadline = submitted + dt.timedelta(days=365)
    application_id = "eval_" + secrets.token_hex(12)
    canonical_qualification = json.dumps(
        qualification,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    with open_db(path) as conn:
        conn.execute(
            """
            INSERT INTO evaluation_applications (
                application_id, submitted_at, retention_deadline, status,
                name, email, category, message, qualification_json, updated_at
            ) VALUES (?, ?, ?, 'new', ?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                _iso(submitted),
                _iso(retention_deadline),
                name,
                email,
                category,
                message,
                canonical_qualification,
                _iso(submitted),
            ),
        )
    return application_id


def _record(row: sqlite3.Row, *, include_contact: bool) -> dict[str, Any]:
    qualification = json.loads(row["qualification_json"])
    result: dict[str, Any] = {
        "application_id": row["application_id"],
        "submitted_at": row["submitted_at"],
        "retention_deadline": row["retention_deadline"],
        "status": row["status"],
        "category": row["category"],
        "company": qualification.get("company", ""),
        "stack": qualification.get("stack", ""),
        "workload": qualification.get("workload", ""),
        "logical_rows": qualification.get("logical_rows", ""),
        "current_memory": qualification.get("current_memory", ""),
        "target_ram": qualification.get("target_ram", ""),
    }
    if include_contact:
        result.update(
            {
                "name": row["name"],
                "email": row["email"],
                "message": row["message"],
                "qualification": qualification,
            }
        )
    return result


def list_applications(
    *,
    status: str | None = None,
    include_contact: bool = False,
    path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    if status is not None and status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    query = "SELECT * FROM evaluation_applications"
    params: tuple[str, ...] = ()
    if status:
        query += " WHERE status = ?"
        params = (status,)
    query += " ORDER BY submitted_at ASC"
    with open_db(path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_record(row, include_contact=include_contact) for row in rows]


def get_application(
    application_id: str,
    *,
    include_contact: bool = False,
    path: str | os.PathLike[str] | None = None,
) -> dict[str, Any] | None:
    with open_db(path) as conn:
        row = conn.execute(
            "SELECT * FROM evaluation_applications WHERE application_id = ?",
            (application_id,),
        ).fetchone()
    return None if row is None else _record(row, include_contact=include_contact)


def set_status(
    application_id: str,
    status: str,
    *,
    path: str | os.PathLike[str] | None = None,
    now: dt.datetime | None = None,
) -> bool:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    updated_at = _iso(now or _utc_now())
    with open_db(path) as conn:
        cursor = conn.execute(
            "UPDATE evaluation_applications SET status = ?, updated_at = ? "
            "WHERE application_id = ?",
            (status, updated_at, application_id),
        )
    return cursor.rowcount == 1


def expired_ids(
    *,
    path: str | os.PathLike[str] | None = None,
    now: dt.datetime | None = None,
) -> list[str]:
    cutoff = _iso(now or _utc_now())
    with open_db(path) as conn:
        rows = conn.execute(
            "SELECT application_id FROM evaluation_applications "
            "WHERE retention_deadline <= ? ORDER BY application_id",
            (cutoff,),
        ).fetchall()
    return [row["application_id"] for row in rows]


def purge_expired(
    *,
    path: str | os.PathLike[str] | None = None,
    now: dt.datetime | None = None,
) -> int:
    cutoff = _iso(now or _utc_now())
    with open_db(path) as conn:
        cursor = conn.execute(
            "DELETE FROM evaluation_applications WHERE retention_deadline <= ?",
            (cutoff,),
        )
    return cursor.rowcount


def consume_readiness_probe(
    application_id: str,
    nonce: str,
    *,
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """Verify and delete one non-PII end-to-end intake probe."""
    if not application_id.startswith("eval_") or not nonce.startswith("probe_"):
        return False
    expected_message = f"TinyZKP automated contact readiness probe {nonce}"
    with open_db(path) as conn:
        row = conn.execute(
            "SELECT name, category, message, qualification_json "
            "FROM evaluation_applications WHERE application_id = ?",
            (application_id,),
        ).fetchone()
        if row is None:
            return False
        try:
            qualification = json.loads(row["qualification_json"])
        except json.JSONDecodeError:
            return False
        if (
            row["name"] != "TinyZKP readiness probe"
            or row["category"] != "General Inquiry"
            or row["message"] != expected_message
            or qualification.get("intent") != "automated_readiness_probe"
            or qualification.get("contact_method") != "github"
            or qualification.get("contact_handle") != "https://tinyzkp.com/status"
        ):
            return False
        cursor = conn.execute(
            "DELETE FROM evaluation_applications WHERE application_id = ?",
            (application_id,),
        )
    return cursor.rowcount == 1
