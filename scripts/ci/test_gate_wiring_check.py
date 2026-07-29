"""Tests for the gate wiring check.

Two of these exist because writing this gate produced exactly the bugs the
gate is meant to catch — it reported coverage it could not justify, twice,
for two different reasons. Both are pinned below.
"""

from __future__ import annotations

import pathlib
import sys

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gate_wiring_check as gate  # noqa: E402


def test_repository_state_passes() -> None:
    scripts = gate.candidate_scripts()
    covered = gate.reachable(scripts)
    assert gate.check(scripts, covered, gate.load_allowlist()) == []


def test_the_scanner_actually_found_the_scripts() -> None:
    """Every other assertion is vacuous if this returns an empty dict."""
    scripts = gate.candidate_scripts()
    assert len(scripts) > 100
    assert "scripts/ci/gate_wiring_check.py" in scripts
    assert "scripts/ci/privacy_disclosure_gate.py" in scripts


def test_a_test_filename_does_not_cover_its_subject() -> None:
    """`X.py` is a substring of `test_X.py`.

    A plain substring match reported that `recovery_reconciliation_invariants.py`
    was wired because CI runs `test_recovery_reconciliation_invariants.py` --
    so every script with a matching test looked covered by the mere existence
    of that test, whether or not anything ran the script.
    """
    assert gate._mentions("thing.py", "python3 scripts/ci/thing.py")
    assert not gate._mentions("thing.py", "pytest scripts/ci/test_thing.py")
    assert not gate._mentions("thing.py", "another_thing.py")


def test_prose_does_not_count_as_wiring() -> None:
    """This module's own docstring names example scripts.

    Before `_code_only`, those mentions marked the named scripts -- and
    everything they in turn named -- as reachable from CI, when no workflow
    ran any of them. A gate that says "covered" about something CI never
    executes is the failure it exists to prevent.
    """
    code = gate._code_only('"""Runs production_launch_preflight.py."""\nx = 1\n')
    assert "production_launch_preflight.py" not in code

    code = gate._code_only("# see production_launch_preflight.py\nx = 1\n")
    assert "production_launch_preflight.py" not in code

    code = gate._code_only('subprocess.run(["production_launch_preflight.py"])\n')
    assert "production_launch_preflight.py" in code


def test_an_imported_module_is_reached() -> None:
    """Shared libraries carry no `.py` in an import statement."""
    assert gate._mentions("strict_json.py", "import strict_json")
    assert gate._mentions("strict_json.py", "from strict_json import loads")
    assert not gate._mentions("strict_json.py", "import strict_json_other")


def test_an_unclassified_script_fails(tmp_path) -> None:
    scripts = {"scripts/ci/brand_new_gate.py": tmp_path / "brand_new_gate.py"}
    failures = gate.check(scripts, covered=set(), allowlist={})
    assert any("brand_new_gate.py" in f for f in failures), failures


def test_an_exemption_without_a_reason_fails(tmp_path, monkeypatch) -> None:
    allowlist = tmp_path / "manual-gates.txt"
    allowlist.write_text("scripts/ci/something.py\n", encoding="utf-8")
    monkeypatch.setattr(gate, "ALLOWLIST", allowlist)
    with pytest.raises(ValueError, match="needs a reason"):
        gate.load_allowlist()


def test_a_stale_exemption_fails() -> None:
    """An entry that became reachable must be removed, not left to rot."""
    existing = "scripts/ci/gate_wiring_check.py"
    failures = gate.check(
        scripts={existing: gate.ROOT / existing},
        covered={existing},
        allowlist={existing: "manual for now"},
    )
    assert any("now reachable" in f for f in failures), failures


def test_an_exemption_for_a_deleted_file_fails() -> None:
    failures = gate.check(
        scripts={},
        covered=set(),
        allowlist={"scripts/ci/deleted.py": "gone"},
    )
    assert any("does not exist" in f for f in failures), failures


def test_every_allowlist_entry_states_a_reason() -> None:
    allowlist = gate.load_allowlist()
    assert allowlist, "the allowlist should not be empty while retired-stack scripts remain"
    for path, reason in allowlist.items():
        assert len(reason) > 20, f"{path} needs a real reason, got {reason!r}"


def test_the_dead_offer_metadata_gate_is_gone() -> None:
    """Orphaned AND failing on every run, for a retired plan model."""
    assert not (gate.ROOT / "scripts" / "ci" / "offer_metadata_check.py").exists()
