"""The recovery-era payment readiness runner is retained fail closed."""

import importlib.util
import sys
from pathlib import Path


BILLING_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = BILLING_DIR / "stripe_revenue_readiness.py"
sys.path.insert(0, str(BILLING_DIR))
spec = importlib.util.spec_from_file_location("stripe_revenue_readiness", MODULE_PATH)
readiness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = readiness
spec.loader.exec_module(readiness)


def test_retired_runner_fails_before_profile_or_subprocess_access(monkeypatch, capsys):
    monkeypatch.setattr(
        readiness,
        "run_readiness",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("retired runner must not execute steps")),
    )

    assert readiness.main(["--sync-pipeline", "--setup-catalog", "full"]) == 2
    assert "retired" in capsys.readouterr().err


def test_retirement_notice_routes_to_current_guard_contracts():
    notice = readiness.RETIREMENT_NOTICE.lower()

    assert "legacy payment-readiness runner" in notice
    assert "guard-launch-state-v2.json" in notice
    assert "lemon squeezy" in notice
