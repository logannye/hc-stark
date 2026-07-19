import json

import launch_gate_audit as audit


def test_retired_audit_always_fails_closed(capsys):
    assert audit.main([]) == 1
    assert "RETIRED" in capsys.readouterr().err


def test_retired_audit_never_reports_skipped_success(capsys):
    assert audit.main(["--json"]) == 1
    record = json.loads(capsys.readouterr().out)
    assert record == {
        "schema_version": 1,
        "status": "retired",
        "code": "retired_hosted_launch_audit",
        "replacement": "python3 scripts/ci/guard_launch_gate.py --check",
        "passed": 0,
        "skipped": 0,
        "failed": 1,
    }
