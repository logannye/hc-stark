import json
from pathlib import Path
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import guard_launch_gate as gate  # noqa: E402


def valid_config() -> dict:
    return {
        "schema_version": 1,
        "release": "tinyzkp-guard-v1",
        "status": "blocked",
        "checkout_enabled": False,
        "gate_status": {
            name: {"status": "blocked", "evidence": []}
            for name in sorted(gate.REQUIRED_GATES)
        },
        "blocking_gates": sorted(gate.REQUIRED_GATES),
        "policy": "fail closed",
    }


def test_repository_gate_is_valid_and_blocked() -> None:
    config = gate.load_config(gate.DEFAULT_CONFIG)
    assert gate.validate(config) == []
    assert gate.validate(config, require_ready=True) == [
        "TinyZKP Guard commercial launch is not ready"
    ]


def test_blocked_gate_cannot_enable_checkout() -> None:
    config = valid_config()
    config["checkout_enabled"] = True
    assert "checkout cannot be enabled while launch status is blocked" in gate.validate(config)


def test_ready_gate_must_enable_checkout() -> None:
    config = valid_config()
    config["status"] = "ready"
    assert "ready status requires checkout_enabled=true" in gate.validate(config)


def test_passed_gate_requires_evidence_and_is_removed_from_blocking_list() -> None:
    config = valid_config()
    name = "engine_release_ready"
    config["gate_status"][name] = {"status": "passed", "evidence": []}
    config["blocking_gates"].remove(name)
    assert f"passed gate {name} requires reviewed evidence" in gate.validate(config)

    config["gate_status"][name]["evidence"] = ["release/evidence/engine-v1.json"]
    assert gate.validate(config) == []


def test_ready_requires_every_evidenced_gate_to_pass() -> None:
    config = valid_config()
    config["status"] = "ready"
    config["checkout_enabled"] = True
    assert "ready status requires every gate to pass" in gate.validate(config)


def test_gate_set_is_exact() -> None:
    config = valid_config()
    config["blocking_gates"] = config["blocking_gates"][:-1] + ["invented"]
    errors = gate.validate(config)
    assert any(message.startswith("unknown blocking gates:") for message in errors)
    assert "blocking_gates must exactly match non-passed gate_status entries" in errors


def test_loader_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    try:
        gate.load_config(path)
    except ValueError as exc:
        assert "must be an object" in str(exc)
    else:
        raise AssertionError("expected invalid document to fail")
