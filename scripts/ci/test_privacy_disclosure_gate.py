"""Tests for the privacy disclosure gate.

Every test below except the first is a NEGATIVE test: it perturbs one input
and asserts the gate fails. That is the whole point. This repository has
already shipped a gate that was silently broken for three commits
(`plonky3_compatibility_gate.py`) and one that was orphaned and failing
unobserved (`offer_metadata_check.py`), so a gate whose failure path has
never been exercised is not evidence of anything.
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
from typing import Any

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import privacy_disclosure_gate as gate  # noqa: E402


@pytest.fixture
def live() -> dict[str, Any]:
    """The real repository state, as the gate sees it."""
    return {
        "migrations": gate.parse_migrations(),
        "writes": gate.parse_worker_writes(),
        "manifest": gate.load_manifest(),
        "privacy_html": gate.PRIVACY.read_text(encoding="utf-8"),
        "worker_js": gate.WORKER.read_text(encoding="utf-8"),
    }


def test_repository_state_passes(live: dict[str, Any]) -> None:
    assert gate.check(**live) == []


def test_the_parser_actually_found_the_real_tables(live: dict[str, Any]) -> None:
    """Guards against a regex that silently matches nothing.

    Every assertion below would hold vacuously if `parse_worker_writes`
    returned an empty dict, which is exactly how a gate rots into a no-op.
    """
    writes = live["writes"]
    assert set(writes) == {
        "rate_limit_windows",
        "demand_log",
        "rejected_log",
        "estimator_keys",
        "keyed_rate_limit_windows",
    }
    assert "anon_ip_hash" in writes["demand_log"]
    assert "key_hash" in writes["estimator_keys"]
    assert "reason_code" in writes["rejected_log"]


def test_undisclosed_column_fails(live: dict[str, Any]) -> None:
    """The load-bearing case: a new column shipped without disclosure."""
    live["migrations"] = copy.deepcopy(live["migrations"])
    live["writes"] = copy.deepcopy(live["writes"])
    live["migrations"]["demand_log"].add("caller_user_agent")
    live["writes"]["demand_log"].add("caller_user_agent")

    failures = gate.check(**live)

    assert any("caller_user_agent" in failure for failure in failures), failures


def test_undisclosed_table_fails(live: dict[str, Any]) -> None:
    live["migrations"] = copy.deepcopy(live["migrations"])
    live["writes"] = copy.deepcopy(live["writes"])
    live["migrations"]["contact_submissions"] = {"email", "message"}
    live["writes"]["contact_submissions"] = {"email", "message"}

    failures = gate.check(**live)

    assert any("contact_submissions" in failure for failure in failures), failures


def test_manifest_describing_a_nonexistent_column_fails(live: dict[str, Any]) -> None:
    """Stale manifests make the gate look more binding than it is."""
    live["manifest"] = copy.deepcopy(live["manifest"])
    tables = {entry["name"]: entry for entry in live["manifest"]["tables"]}
    tables["demand_log"]["columns"]["column_that_was_removed"] = "stale entry"

    failures = gate.check(**live)

    assert any("column_that_was_removed" in failure for failure in failures), failures


def test_column_added_to_schema_but_not_manifest_fails(live: dict[str, Any]) -> None:
    live["migrations"] = copy.deepcopy(live["migrations"])
    live["migrations"]["estimator_keys"].add("contact_email")

    failures = gate.check(**live)

    assert any("contact_email" in failure for failure in failures), failures


def test_manifest_pointing_at_a_missing_anchor_fails(live: dict[str, Any]) -> None:
    """Disclosure must land in the notice, not just in a JSON file."""
    live["manifest"] = copy.deepcopy(live["manifest"])
    tables = {entry["name"]: entry for entry in live["manifest"]["tables"]}
    tables["demand_log"]["disclosed_in"] = "section-that-does-not-exist"

    failures = gate.check(**live)

    assert any("section-that-does-not-exist" in failure for failure in failures), failures


def test_unlinked_manifest_fails(live: dict[str, Any]) -> None:
    live["privacy_html"] = live["privacy_html"].replace("privacy-disclosure-v1.json", "")

    failures = gate.check(**live)

    assert any("must link" in failure for failure in failures), failures


def test_the_retired_denial_cannot_come_back(live: dict[str, Any]) -> None:
    live["privacy_html"] += (
        "<p>The site contains no custom contact form, event collector, "
        "customer account, proof API, or TinyZKP analytics database.</p>"
    )

    failures = gate.check(**live)

    assert any("retired denial" in failure for failure in failures), failures


def test_understating_the_ip_hash_limitation_fails(live: dict[str, Any]) -> None:
    """While the salt is public, the manifest may not claim anonymity."""
    live["manifest"] = copy.deepcopy(live["manifest"])
    live["manifest"]["identifier_limitations"]["anon_ip_hash"]["reversible"] = False

    failures = gate.check(**live)

    assert any("reversible=true" in failure for failure in failures), failures


def test_moving_the_salt_to_a_secret_forces_a_manifest_revisit(
    live: dict[str, Any],
) -> None:
    """A genuine improvement must still be reflected, not silently inherited."""
    live["worker_js"] = live["worker_js"].replace(
        'const IP_HASH_SALT = "tinyzkp-v1-estimate-ip-hash-salt";',
        "const IP_HASH_SALT = env.IP_HASH_SALT;",
    )

    failures = gate.check(**live)

    assert any("no longer a source literal" in failure for failure in failures), failures


def test_missing_retention_statement_fails(live: dict[str, Any]) -> None:
    live["manifest"] = copy.deepcopy(live["manifest"])
    del live["manifest"]["retention"]

    failures = gate.check(**live)

    assert any("retention.enforced" in failure for failure in failures), failures


def test_manifest_json_is_strictly_valid() -> None:
    """The published artifact must parse for third parties, not just for us."""
    raw = gate.MANIFEST.read_text(encoding="utf-8")
    assert json.loads(raw)
    assert raw.endswith("\n")
