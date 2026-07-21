"""The recovery-era payment sync is retained only as fail-closed history."""

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "marketing" / "sync_stripe_checkout_pipeline.py"
spec = importlib.util.spec_from_file_location("sync_stripe_checkout_pipeline", MODULE_PATH)
sync = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = sync
spec.loader.exec_module(sync)


def test_retired_sync_fails_before_file_or_network_access(tmp_path, monkeypatch, capsys):
    calls = []

    def unexpected_call(**kwargs):
        calls.append(kwargs)
        raise AssertionError("retired sync must not contact a payment provider")

    monkeypatch.setattr(sync.stripe_checkout_monitor, "collect_checkout_summary", unexpected_call)
    missing_state = tmp_path / "does-not-exist.json"

    assert sync.main(["--state", str(missing_state), "--dry-run"]) == 2
    assert calls == []
    assert not missing_state.exists()
    assert "retired" in capsys.readouterr().err


def test_retirement_notice_routes_to_current_guard_contracts():
    notice = sync.RETIREMENT_NOTICE.lower()

    assert "legacy checkout pipeline sync" in notice
    assert "guard revenue-readiness ledger" in notice
    assert "canonical launch-state" in notice
    assert "lemon squeezy" in notice
