import datetime as dt
import os
import stat
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import evaluation_store


NOW = dt.datetime(2026, 7, 10, 12, 0, tzinfo=dt.timezone.utc)


def _create(path, *, now=NOW):
    return evaluation_store.create_application(
        name="Proving Lead",
        email="lead@example.com",
        category="Design Partner",
        message="Reproduce with a public generator.",
        qualification={
            "company": "Example ZK",
            "stack": "Plonky3 0.6.1",
            "workload": "Poseidon2 AIR",
            "logical_rows": "1048576",
            "current_memory": "OOM at 16 GiB",
            "target_ram": "2 GiB",
        },
        path=path,
        now=now,
    )


def test_create_is_durable_owner_only_and_redacted_by_default(tmp_path):
    path = tmp_path / "private" / "applications.sqlite"
    application_id = _create(path)

    assert application_id.startswith("eval_")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    records = evaluation_store.list_applications(path=path)
    assert records[0]["application_id"] == application_id
    assert records[0]["company"] == "Example ZK"
    assert "email" not in records[0]
    assert "message" not in records[0]

    full = evaluation_store.get_application(
        application_id,
        include_contact=True,
        path=path,
    )
    assert full["email"] == "lead@example.com"
    assert full["qualification"]["workload"] == "Poseidon2 AIR"


def test_status_and_retention_purge(tmp_path):
    path = tmp_path / "applications.sqlite"
    application_id = _create(path)

    assert evaluation_store.set_status(application_id, "qualified", path=path, now=NOW)
    assert evaluation_store.list_applications(status="qualified", path=path)[0][
        "application_id"
    ] == application_id
    assert evaluation_store.expired_ids(path=path, now=NOW) == []

    after_deadline = NOW + dt.timedelta(days=366)
    assert evaluation_store.expired_ids(path=path, now=after_deadline) == [application_id]
    assert evaluation_store.purge_expired(path=path, now=after_deadline) == 1
    assert evaluation_store.get_application(application_id, path=path) is None


def test_invalid_status_fails_closed(tmp_path):
    path = tmp_path / "applications.sqlite"
    application_id = _create(path)
    try:
        evaluation_store.set_status(application_id, "emailed", path=path)
    except ValueError as exc:
        assert "invalid status" in str(exc)
    else:
        raise AssertionError("invalid status must be rejected")
