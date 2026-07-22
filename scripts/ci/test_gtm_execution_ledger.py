import csv
import copy
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


renderer = load_module("render_gtm_execution_ledger", "scripts/marketing/render_gtm_execution_ledger.py")
checker = load_module("gtm_execution_ledger_check", "scripts/ci/gtm_execution_ledger_check.py")


def sources():
    return {
        "pricing": json.loads((ROOT / "site" / "pricing.json").read_text(encoding="utf-8")),
        "commerce": json.loads((ROOT / "site" / "commerce.json").read_text(encoding="utf-8")),
        "release": json.loads((ROOT / "site" / "release.json").read_text(encoding="utf-8")),
        "launch_state": json.loads((ROOT / "release" / "guard-launch-state-v2.json").read_text(encoding="utf-8")),
    }


def write_sources(root: Path, values=None):
    values = values or sources()
    paths = {
        "pricing": root / "site" / "pricing.json",
        "commerce": root / "site" / "commerce.json",
        "release": root / "site" / "release.json",
        "launch_state": root / "release" / "guard-launch-state-v2.json",
    }
    for name, path in paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(values[name], indent=2) + "\n", encoding="utf-8")
    return paths


def write_ledger(root: Path, payload=None):
    values = sources()
    write_sources(root, values)
    payload = payload or renderer.render_ledger(**values)
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    outputs = renderer.expected_outputs(payload)
    for suffix, content in outputs.items():
        (generated / f"gtm_execution_ledger.{suffix}").write_text(content, encoding="utf-8")
    return payload


def test_renderer_derives_only_current_guard_gate_tasks():
    payload = renderer.render_ledger(**sources())

    launch = sources()["launch_state"]
    assert payload["schema_version"] == 2
    assert payload["generated_from"] == renderer.SOURCE_PATHS
    assert payload["business_state"]["merchant_provider"] == "lemon_squeezy"
    assert payload["business_state"]["revenue_evidence_claimed"] is False
    assert payload["business_state"]["recorded_revenue_cents"] == 0
    assert len(payload["tasks"]) == len(launch["gate_status"])
    assert {task["gate"] for task in payload["tasks"]} == set(launch["gate_status"])
    assert set(renderer.GATE_METADATA) == set(launch["gate_status"])
    assert not {
        "three_external_workloads",
        "two_standard_annual_customers",
        "five_unaided_installs",
    } & {task["gate"] for task in payload["tasks"]}
    legal = next(task for task in payload["tasks"] if task["gate"] == "legal_terms_approved")
    assert legal["owner"] == "owner"
    assert "LN Holdings owner approval" in legal["next_action"]
    rehearsal = next(
        task
        for task in payload["tasks"]
        if task["gate"] == "release_rehearsal_within_budget"
    )
    assert "technical build" in rehearsal["next_action"]
    assert "budget" not in rehearsal["next_action"].lower()
    assert all(task["status"] == "blocked" for task in payload["tasks"])
    assert all("primary_cta" not in task and "secondary_cta" not in task for task in payload["tasks"])
    serialized = json.dumps(payload).lower()
    for marker in ("stripe", "pilot", "signup", "mcp", "live_monitoring"):
        assert marker not in serialized


def test_renderer_fails_closed_on_cross_source_drift():
    values = sources()
    values["commerce"] = copy.deepcopy(values["commerce"])
    values["commerce"]["checkout_enabled"] = True

    try:
        renderer.render_ledger(**values)
    except ValueError as exc:
        assert "checkout_enabled must agree" in str(exc)
    else:
        raise AssertionError("source drift should fail rendering")


def test_renderer_rejects_live_sales_while_gates_are_blocked():
    values = sources()
    for source_name in ("pricing", "commerce", "release", "launch_state"):
        values[source_name] = copy.deepcopy(values[source_name])
        values[source_name]["sales_state"] = "live"
        values[source_name]["checkout_enabled"] = True
        values[source_name]["launch_state"] = "qualified"
        values[source_name]["commerce_state"] = "public_live"

    try:
        renderer.render_ledger(**values)
    except ValueError as exc:
        assert "qualified launch cannot retain blocking gates" in str(exc)
    else:
        raise AssertionError("blocked gates must prevent a live revenue ledger")


def test_renderer_rejects_passed_gate_without_bound_evidence():
    values = sources()
    for source_name in ("release", "launch_state"):
        values[source_name] = copy.deepcopy(values[source_name])
        values[source_name]["gate_status"]["engine_release_ready"]["status"] = "passed"
        values[source_name]["gate_status"]["engine_release_ready"]["reason_code"] = None
        values[source_name]["blocking_gates"].remove("engine_release_ready")

    try:
        renderer.render_ledger(**values)
    except ValueError as exc:
        assert "passed status requires bound evidence" in str(exc)
    else:
        raise AssertionError("passed gates without evidence must fail rendering")


def test_renderer_rejects_malformed_evidence_reference():
    values = sources()
    for source_name in ("release", "launch_state"):
        values[source_name] = copy.deepcopy(values[source_name])
        values[source_name]["gate_status"]["engine_release_ready"]["status"] = "passed"
        values[source_name]["gate_status"]["engine_release_ready"]["reason_code"] = None
        values[source_name]["gate_status"]["engine_release_ready"]["evidence"] = [{}]
        values[source_name]["blocking_gates"].remove("engine_release_ready")

    try:
        renderer.render_ledger(**values)
    except ValueError as exc:
        assert "evidence reference 0 has invalid fields" in str(exc)
    else:
        raise AssertionError("malformed evidence must fail rendering")


def test_passed_gate_with_null_reason_and_bound_evidence_survives_full_check(tmp_path):
    values = sources()
    reference = {
        "path": "release/evidence/engine-release.json",
        "sha256": "a" * 64,
        "signature_path": "release/evidence/engine-release.sigstore.json",
        "signature_sha256": "b" * 64,
        "signer_id": "release-owner",
        "purpose": "engine-release-ready",
    }
    for source_name in ("release", "launch_state"):
        values[source_name] = copy.deepcopy(values[source_name])
        gate = values[source_name]["gate_status"]["engine_release_ready"]
        gate["status"] = "passed"
        gate["reason_code"] = None
        gate["evidence"] = [copy.deepcopy(reference)]
        values[source_name]["blocking_gates"].remove("engine_release_ready")

    payload = renderer.render_ledger(**values)
    task = next(task for task in payload["tasks"] if task["gate"] == "engine_release_ready")
    assert task["status"] == "passed"
    assert task["reason_code"] == ""

    write_sources(tmp_path, values)
    generated = tmp_path / "marketing" / "generated"
    generated.mkdir(parents=True)
    for suffix, content in renderer.expected_outputs(payload).items():
        (generated / f"gtm_execution_ledger.{suffix}").write_text(
            content, encoding="utf-8"
        )
    assert not [check for check in checker.validate(tmp_path) if check.status == "FAIL"]


def test_renderer_rejects_live_sales_without_approved_merchant_legal_and_portal():
    values = sources()
    valid_reference = {
        "path": "release/evidence/example.json",
        "sha256": "a" * 64,
        "signature_path": "release/evidence/example.sigstore.json",
        "signature_sha256": "b" * 64,
        "signer_id": "release-owner",
        "purpose": "guard-launch-gate",
    }
    for source_name in ("pricing", "commerce", "release", "launch_state"):
        values[source_name] = copy.deepcopy(values[source_name])
        values[source_name]["sales_state"] = "live"
        values[source_name]["checkout_enabled"] = True
        values[source_name]["launch_state"] = "qualified"
        values[source_name]["commerce_state"] = "public_live"
    for source_name in ("release", "launch_state"):
        values[source_name]["blocking_gates"] = []
        for gate in values[source_name]["gate_status"].values():
            gate["status"] = "passed"
            gate["reason_code"] = None
            gate["evidence"] = [copy.deepcopy(valid_reference)]

    try:
        renderer.render_ledger(**values)
    except ValueError as exc:
        assert "live customer portal" in str(exc)
    else:
        raise AssertionError("unapproved live commerce must fail rendering")


def test_renderer_check_detects_stale_outputs(tmp_path):
    paths = write_sources(tmp_path)
    generated = tmp_path / "marketing" / "generated"
    args = [
        "--pricing", str(paths["pricing"]),
        "--commerce", str(paths["commerce"]),
        "--release", str(paths["release"]),
        "--launch-state", str(paths["launch_state"]),
        "--json-output", str(generated / "gtm_execution_ledger.json"),
        "--csv-output", str(generated / "gtm_execution_ledger.csv"),
        "--md-output", str(generated / "gtm_execution_ledger.md"),
    ]
    assert renderer.main(args) == 0
    assert renderer.main(args + ["--check"]) == 0
    (generated / "gtm_execution_ledger.md").write_text("stale", encoding="utf-8")
    assert renderer.main(args + ["--check"]) == 1


def test_checker_accepts_current_guard_ledger(tmp_path):
    payload = write_ledger(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]
    rows = list(csv.DictReader((tmp_path / "marketing" / "generated" / "gtm_execution_ledger.csv").read_text().splitlines()))
    assert len(rows) == len(payload["tasks"])
    assert set(rows[0]) == set(renderer.CSV_COLUMNS)


def test_checker_rejects_revenue_or_retired_cta_claim(tmp_path):
    payload = write_ledger(tmp_path)
    payload["business_state"]["recorded_revenue_cents"] = 500_000
    payload["business_state"]["revenue_evidence_claimed"] = True
    payload["tasks"][0]["primary_cta"] = "https://tinyzkp.com/signup"
    (tmp_path / "marketing" / "generated" / "gtm_execution_ledger.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "retired account funnel" in failures
    assert "must not claim recorded revenue" in failures


def test_checker_rejects_noncanonical_gate_status(tmp_path):
    payload = write_ledger(tmp_path)
    payload["tasks"][0]["status"] = "passed"
    (tmp_path / "marketing" / "generated" / "gtm_execution_ledger.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "status must match canonical launch state" in failures


def test_checker_rejects_extra_revenue_and_customer_fields(tmp_path):
    payload = write_ledger(tmp_path)
    payload["booked_revenue_cents"] = 999_900
    payload["tasks"][0]["customer"] = "paid annual customer"
    payload["tasks"][0]["revenue_cents"] = 999_900
    generated = tmp_path / "marketing" / "generated"
    (generated / "gtm_execution_ledger.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    outputs = renderer.expected_outputs(payload)
    (generated / "gtm_execution_ledger.csv").write_text(outputs["csv"], encoding="utf-8")
    (generated / "gtm_execution_ledger.md").write_text(outputs["md"], encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "root fields must exactly match" in failures
    assert "task 0 fields must exactly match" in failures


def test_checker_rejects_tampered_csv_and_markdown(tmp_path):
    write_ledger(tmp_path)
    generated = tmp_path / "marketing" / "generated"
    csv_path = generated / "gtm_execution_ledger.csv"
    md_path = generated / "gtm_execution_ledger.md"
    csv_path.write_text(csv_path.read_text(encoding="utf-8").replace(",blocked,", ",passed,"), encoding="utf-8")
    markdown = md_path.read_text(encoding="utf-8")
    md_path.write_text("\n".join(line for line in markdown.splitlines() if not line.startswith("| [")) + "\n", encoding="utf-8")

    failures = "\n".join(check.detail for check in checker.validate(tmp_path) if check.status == "FAIL")

    assert "CSV must exactly match" in failures
    assert "markdown must exactly match" in failures
