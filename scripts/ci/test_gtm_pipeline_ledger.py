import csv
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


execution_renderer = load_module("render_gtm_execution_ledger_for_pipeline_test", "scripts/marketing/render_gtm_execution_ledger.py")
renderer = load_module("render_gtm_pipeline_ledger", "scripts/marketing/render_gtm_pipeline_ledger.py")
checker = load_module("gtm_pipeline_ledger_check", "scripts/ci/gtm_pipeline_ledger_check.py")


def execution_payload():
    return execution_renderer.render_ledger(
        pricing=json.loads((ROOT / "site" / "pricing.json").read_text(encoding="utf-8")),
        commerce=json.loads((ROOT / "site" / "commerce.json").read_text(encoding="utf-8")),
        release=json.loads((ROOT / "site" / "release.json").read_text(encoding="utf-8")),
        launch_state=json.loads((ROOT / "release" / "guard-launch-state-v2.json").read_text(encoding="utf-8")),
    )


def write_pipeline(root: Path, execution=None, state=None, payload=None):
    execution = execution or execution_payload()
    state = state or renderer.normalize_state(execution, None)
    payload = payload or renderer.render_pipeline(execution, state)
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    (generated / "gtm_execution_ledger.json").write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")
    (root / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    outputs = renderer.expected_outputs(payload)
    for suffix, content in outputs.items():
        (generated / f"gtm_pipeline_ledger.{suffix}").write_text(content, encoding="utf-8")
    return execution, state, payload


def test_state_is_only_a_bounded_schedule_overlay():
    execution = execution_payload()
    state = renderer.normalize_state(execution, None)
    first_id = execution["tasks"][0]["task_id"]
    state["tasks"][first_id]["next_action_at"] = "2026-07-22"

    synced = renderer.normalize_state(execution, state)

    assert synced["schema_version"] == 2
    assert set(synced["tasks"]) == {task["task_id"] for task in execution["tasks"]}
    assert synced["tasks"][first_id] == {"next_action_at": "2026-07-22"}
    assert "stage" not in synced["tasks"][first_id]
    assert "actual_revenue_cents" not in synced["tasks"][first_id]


def test_pipeline_mirrors_gate_status_without_forecast_or_revenue():
    execution = execution_payload()
    state = renderer.normalize_state(execution, None)

    payload = renderer.render_pipeline(execution, state)

    assert payload["summary"]["blocking_records"] == len(execution["tasks"])
    assert payload["summary"]["revenue_evidence_claimed"] is False
    assert payload["summary"]["recorded_revenue_cents"] == 0
    assert {record["task_id"] for record in payload["records"]} == {task["task_id"] for task in execution["tasks"]}
    assert all(record["status"] == "blocked" for record in payload["records"])
    serialized = json.dumps(payload).lower()
    for marker in ("pipeline_value_cents", "probability_percent", "actual_revenue_cents", "primary_cta", "stripe", "pilot", "signup", "mcp"):
        assert marker not in serialized


def test_pipeline_renderer_rejects_false_revenue_in_execution_input():
    execution = execution_payload()
    execution["business_state"]["revenue_evidence_claimed"] = True
    execution["business_state"]["recorded_revenue_cents"] = 999_900
    state = renderer.normalize_state(execution, None)

    try:
        renderer.render_pipeline(execution, state)
    except ValueError as exc:
        assert "must not claim revenue evidence" in str(exc)
    else:
        raise AssertionError("false revenue in execution input must fail pipeline rendering")


def test_renderer_check_detects_stale_outputs(tmp_path):
    execution = execution_payload()
    generated = tmp_path / "marketing" / "generated"
    generated.mkdir(parents=True)
    execution_path = generated / "gtm_execution_ledger.json"
    state_path = tmp_path / "marketing" / "gtm_pipeline_state.json"
    execution_path.write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")
    args = [
        "--execution-ledger", str(execution_path),
        "--state", str(state_path),
        "--json-output", str(generated / "gtm_pipeline_ledger.json"),
        "--csv-output", str(generated / "gtm_pipeline_ledger.csv"),
        "--md-output", str(generated / "gtm_pipeline_ledger.md"),
        "--sync-state",
    ]
    assert renderer.main(args) == 0
    assert renderer.main(args + ["--check"]) == 0
    (generated / "gtm_pipeline_ledger.md").write_text("stale", encoding="utf-8")
    assert renderer.main(args + ["--check"]) == 1


def test_checker_accepts_bounded_guard_pipeline(tmp_path):
    execution, _, _ = write_pipeline(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]
    rows = list(csv.DictReader((tmp_path / "marketing" / "generated" / "gtm_pipeline_ledger.csv").read_text().splitlines()))
    assert len(rows) == len(execution["tasks"])
    assert set(rows[0]) == set(renderer.CSV_COLUMNS)


def test_checker_rejects_legacy_sales_state_fields(tmp_path):
    execution, state, _ = write_pipeline(tmp_path)
    first_id = execution["tasks"][0]["task_id"]
    state["tasks"][first_id]["stage"] = "won"
    state["tasks"][first_id]["actual_revenue_cents"] = 500_000
    (tmp_path / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "legacy sales stage" in failures
    assert "may contain only next_action_at" in failures


def test_checker_rejects_free_form_state_fields(tmp_path):
    execution, state, _ = write_pipeline(tmp_path)
    first_id = execution["tasks"][0]["task_id"]
    state["tasks"][first_id]["notes"] = "Use a retired route to collect demand."
    (tmp_path / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "may contain only next_action_at" in failures


def test_checker_rejects_extra_top_level_state_fields(tmp_path):
    _, state, _ = write_pipeline(tmp_path)
    state["actual_revenue_cents"] = 999_900
    state["customer_notes"] = "paid annual customer"
    (tmp_path / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "pipeline state may contain only" in failures


def test_renderer_and_checker_reject_duplicate_state_keys_before_hidden_data(tmp_path, capsys):
    execution, state, _ = write_pipeline(tmp_path)
    state_path = tmp_path / "marketing" / "gtm_pipeline_state.json"
    state_path.write_text(
        "{"
        f'"schema_version":2,"mode":{json.dumps(state["mode"])},'
        f'"updated_at":{json.dumps(state["updated_at"])},'
        f'"operator_rules":{json.dumps(state["operator_rules"])},'
        '"tasks":{"hidden":{"actual_revenue_cents":999900}},'
        f'"tasks":{json.dumps(state["tasks"])}'
        "}\n",
        encoding="utf-8",
    )
    generated = tmp_path / "marketing" / "generated"
    args = [
        "--execution-ledger",
        str(generated / "gtm_execution_ledger.json"),
        "--state",
        str(state_path),
        "--json-output",
        str(generated / "gtm_pipeline_ledger.json"),
        "--csv-output",
        str(generated / "gtm_pipeline_ledger.csv"),
        "--md-output",
        str(generated / "gtm_pipeline_ledger.md"),
        "--check",
    ]

    assert renderer.main(args) == 1
    assert "duplicate JSON key: tasks" in capsys.readouterr().err
    failures = "\n".join(
        check.detail for check in checker.validate(tmp_path) if check.status == "FAIL"
    )
    assert "duplicate JSON key: tasks" in failures
    assert len(execution["tasks"]) == len(state["tasks"])


def test_checker_rejects_tampered_pipeline_csv_and_markdown(tmp_path):
    write_pipeline(tmp_path)
    generated = tmp_path / "marketing" / "generated"
    csv_path = generated / "gtm_pipeline_ledger.csv"
    md_path = generated / "gtm_pipeline_ledger.md"
    csv_path.write_text(csv_path.read_text(encoding="utf-8").replace(",blocked,", ",passed,"), encoding="utf-8")
    markdown = md_path.read_text(encoding="utf-8")
    md_path.write_text("\n".join(line for line in markdown.splitlines() if not line.startswith("| [")) + "\n", encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "CSV must exactly match" in failures
    assert "markdown must exactly match" in failures


def test_checker_rejects_extra_pipeline_revenue_and_customer_fields(tmp_path):
    _, _, payload = write_pipeline(tmp_path)
    payload["booked_revenue_cents"] = 999_900
    payload["records"][0]["customer"] = "paid annual customer"
    generated = tmp_path / "marketing" / "generated"
    (generated / "gtm_pipeline_ledger.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    outputs = renderer.expected_outputs(payload)
    (generated / "gtm_pipeline_ledger.csv").write_text(outputs["csv"], encoding="utf-8")
    (generated / "gtm_pipeline_ledger.md").write_text(outputs["md"], encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "root fields must exactly match" in failures
    assert "record fields must exactly match" in failures
