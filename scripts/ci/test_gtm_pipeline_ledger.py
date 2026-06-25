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


renderer = load_module("render_gtm_pipeline_ledger", "scripts/marketing/render_gtm_pipeline_ledger.py")
checker = load_module("gtm_pipeline_ledger_check", "scripts/ci/gtm_pipeline_ledger_check.py")


def execution_task(index: int = 1):
    return {
        "task_id": f"outbound_send.{index:02d}.agent-{index}",
        "channel": "founder_outbound",
        "task_type": "manual_email",
        "status": "ready_after_manual_contact_research",
        "owner": "founder",
        "target": f"Agent {index}",
        "due_date": "2026-06-29",
        "follow_up_date": "2026-07-06",
        "primary_cta": f"https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow=agent-{index}",
        "secondary_cta": f"https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow=agent-{index}",
        "source_artifact": "marketing/generated/outbound_send_queue.md",
        "evidence_command": "python3 scripts/ci/outbound_send_queue_check.py",
        "evidence_url": "",
        "completed_at": "",
        "next_action": "Research exactly one founder and send one human email.",
        "blocker": "Requires manual contact research.",
    }


def execution_payload(count: int = checker.MIN_RECORDS):
    tasks = [
        {
            "task_id": "revenue.pilot_checkout_launch",
            "channel": "revenue",
            "task_type": "live_checkout_verification",
            "status": "ready_for_live_verification",
            "owner": "founder",
            "target": "$5K Production Pilot checkout",
            "due_date": "2026-06-25",
            "follow_up_date": "",
            "primary_cta": "https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout",
            "secondary_cta": "https://tinyzkp.com/contact?category=Paid%20Pilot&source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_contact",
            "source_artifact": "site/functions/api/create-pilot-checkout.js",
            "evidence_command": "python3 scripts/ci/production_launch_preflight.py --live",
            "evidence_url": "",
            "completed_at": "",
            "next_action": "Deploy and verify pilot checkout.",
            "blocker": "Requires Cloudflare Pages deploy access and live STRIPE_SECRET_KEY; inline price_data is available.",
        },
        {
            "task_id": "revenue.stripe_catalog_hygiene",
            "channel": "revenue",
            "task_type": "stripe_catalog_audit",
            "status": "external_secret_required",
            "owner": "founder",
            "target": "Current Stripe product and price catalog",
            "due_date": "2026-06-25",
            "follow_up_date": "",
            "primary_cta": "https://tinyzkp.com/pricing?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_signup",
            "secondary_cta": "https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout",
            "source_artifact": "billing/setup_stripe_products.sh",
            "evidence_command": "python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe --strict-catalog",
            "evidence_url": "",
            "completed_at": "",
            "next_action": "Run billing/setup_stripe_products.sh with write-capable Stripe access.",
            "blocker": "Requires a write-capable live Stripe API key or CLI profile.",
        }
    ]
    tasks.extend(execution_task(index) for index in range(1, count - 1))
    return {"tasks": tasks}


def write_pipeline(root: Path, execution=None, state=None):
    execution = execution or execution_payload()
    state = state or renderer.normalize_state(execution, None)
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True)
    (generated / "gtm_execution_ledger.json").write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")
    (root / "marketing").mkdir(exist_ok=True)
    (root / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    payload = renderer.render_pipeline(execution, state)
    (generated / "gtm_pipeline_ledger.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (generated / "gtm_pipeline_ledger.csv").write_text(renderer.render_csv(payload), encoding="utf-8")
    (generated / "gtm_pipeline_ledger.md").write_text(renderer.render_markdown(payload), encoding="utf-8")
    return execution, state, payload


def test_sync_state_preserves_manual_fields():
    execution = execution_payload()
    state = renderer.normalize_state(execution, None)
    first_outbound = "outbound_send.01.agent-1"
    state["tasks"][first_outbound]["stage"] = "sent"
    state["tasks"][first_outbound]["evidence_url"] = "https://mail.example/thread/1"
    state["tasks"][first_outbound]["last_action_at"] = "2026-06-29"

    synced = renderer.normalize_state(execution, state)

    assert synced["tasks"][first_outbound]["stage"] == "sent"
    assert synced["tasks"][first_outbound]["evidence_url"] == "https://mail.example/thread/1"
    assert synced["tasks"]["revenue.pilot_checkout_launch"]["stage"] == "ready_to_verify"
    assert synced["tasks"]["revenue.stripe_catalog_hygiene"]["stage"] == "blocked_external_secret"


def test_renderer_uses_stage_aware_next_actions():
    task = {
        "task_id": "mcp_submission.directory",
        "channel": "mcp_distribution",
        "task_type": "directory_submission",
        "status": "manual_submission_required",
        "owner": "founder",
        "target": "Directory",
        "due_date": "",
        "primary_cta": "https://tinyzkp.com/signup?source=directory&medium=mcp_directory&platform=directory&intent=mcp_install",
        "secondary_cta": "https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install",
        "source_artifact": "marketing/generated/mcp_submissions/directory.md",
        "evidence_command": "python3 scripts/monitoring/gtm_distribution_monitor.py --offline",
        "evidence_url": "",
        "completed_at": "",
        "next_action": "Submit marketing/generated/mcp_submissions/directory.md through the target account or PR flow.",
        "blocker": "Requires account access.",
    }
    state_entry = renderer.default_state_entry(task)
    state_entry["stage"] = "submitted"
    state_entry["evidence_url"] = "https://example.com/submission/1"

    record = renderer.pipeline_record(task, state_entry)

    assert record["next_action"].startswith("Follow up on Directory review")
    assert "Submit marketing/generated" not in record["next_action"]

    revenue_task = execution_payload()["tasks"][0]
    revenue_state = renderer.default_state_entry(revenue_task)
    revenue_state["stage"] = "live_monitoring"
    revenue_record = renderer.pipeline_record(revenue_task, revenue_state)
    assert revenue_record["probability_percent"] == 30
    assert revenue_record["next_action"].startswith("Monitor pilot checkout starts")

    catalog_task = execution_payload()["tasks"][1]
    catalog_state = renderer.default_state_entry(catalog_task)
    catalog_record = renderer.pipeline_record(catalog_task, catalog_state)
    assert catalog_record["stage"] == "blocked_external_secret"
    assert catalog_record["pipeline_value_cents"] == 0


def test_renderer_check_detects_stale_outputs(tmp_path):
    execution = execution_payload()
    state = renderer.normalize_state(execution, None)
    generated = tmp_path / "marketing" / "generated"
    generated.mkdir(parents=True)
    execution_path = generated / "gtm_execution_ledger.json"
    state_path = tmp_path / "marketing" / "gtm_pipeline_state.json"
    execution_path.write_text(json.dumps(execution), encoding="utf-8")

    args = [
        "--execution-ledger",
        str(execution_path),
        "--state",
        str(state_path),
        "--json-output",
        str(generated / "gtm_pipeline_ledger.json"),
        "--csv-output",
        str(generated / "gtm_pipeline_ledger.csv"),
        "--md-output",
        str(generated / "gtm_pipeline_ledger.md"),
        "--sync-state",
    ]
    assert renderer.main(args) == 0
    assert renderer.main(args + ["--check"]) == 0
    (generated / "gtm_pipeline_ledger.md").write_text("stale", encoding="utf-8")
    assert renderer.main(args + ["--check"]) == 1


def test_pipeline_checker_accepts_initial_no_pii_pipeline(tmp_path):
    write_pipeline(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]
    rows = list(csv.DictReader((tmp_path / "marketing" / "generated" / "gtm_pipeline_ledger.csv").read_text().splitlines()))
    assert len(rows) == checker.MIN_RECORDS
    assert rows[0]["stage"] == "ready_to_verify"


def test_pipeline_checker_rejects_personal_email_in_state(tmp_path):
    execution, state, _ = write_pipeline(tmp_path)
    state["tasks"]["outbound_send.01.agent-1"]["notes"] = "Email founder@example.com tomorrow"
    (tmp_path / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "must not include personal email addresses" in failed


def test_pipeline_checker_rejects_won_without_revenue_and_evidence(tmp_path):
    execution, state, _ = write_pipeline(tmp_path)
    state["tasks"]["outbound_send.01.agent-1"]["stage"] = "won"
    state["tasks"]["outbound_send.01.agent-1"]["completed_at"] = ""
    state["tasks"]["outbound_send.01.agent-1"]["evidence_url"] = ""
    state["tasks"]["outbound_send.01.agent-1"]["actual_revenue_cents"] = 0
    (tmp_path / "marketing" / "gtm_pipeline_state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "requires evidence_url" in failed
    assert "requires actual_revenue_cents" in failed
