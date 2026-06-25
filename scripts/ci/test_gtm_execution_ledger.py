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


renderer = load_module("render_gtm_execution_ledger", "scripts/marketing/render_gtm_execution_ledger.py")
checker = load_module("gtm_execution_ledger_check", "scripts/ci/gtm_execution_ledger_check.py")


def mcp_targets(count: int = checker.MIN_MCP_TASKS):
    targets = []
    for index in range(count):
        target_id = "smithery" if index == 0 else f"directory_{index}"
        source = "smithery_mcp" if index == 0 else f"directory_{index}"
        platform = "smithery" if index == 0 else f"directory_{index}"
        status = "active" if index == 0 else ("submission_ready" if index == 1 else "target")
        targets.append(
            {
                "id": target_id,
                "name": f"Directory {index}",
                "status": status,
                "kind": "mcp_directory",
                "source": source,
                "platform": platform,
                "listing_url": "https://example.com/tinyzkp" if status == "active" else "",
                "submission_url": f"https://example.com/submit/{target_id}",
                "signup_url": f"https://tinyzkp.com/signup?source={source}&medium=mcp_directory&platform={platform}&intent=mcp_install",
                "install_command": "claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com",
                "required_markers": ["TinyZKP", "Proof Receipts"],
            }
        )
    return {
        "generated_at": "2026-06-25",
        "positioning": {
            "one_liner": "Proof receipts for agent actions.",
            "data_boundary": "Do not put secrets, private customer data, or API keys into receipts.",
        },
        "canonical_assets": [],
        "targets": targets,
    }


def outbound_row(index: int):
    slug = f"agent-{index}"
    return {
        "rank": index,
        "target_id": f"yc_{slug}",
        "company": f"Agent {index}",
        "send_date": "2026-06-29",
        "follow_up_date": "2026-07-06",
        "contact_role": "Founder, platform lead, or agent product owner",
        "contact_name": "",
        "contact_email": "",
        "reply_type": "",
        "outcome": "",
        "primary_cta": f"https://tinyzkp.com/fit?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=find_route&workflow={slug}",
        "secondary_cta": f"https://tinyzkp.com/pilot?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&intent=paid_pilot_checkout&workflow={slug}",
    }


def outbound_queue(count: int = checker.MIN_OUTBOUND_TASKS):
    return {
        "source_generated_at": "2026-06-25T17:53:19+00:00",
        "queue": [outbound_row(index) for index in range(1, count + 1)],
    }


def openai_submission():
    return {
        "signup_url": "https://tinyzkp.com/signup?source=openai_chatgpt_app&medium=chatgpt_app&platform=openai&intent=mcp_install",
        "agent_offer_url": "https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=openai_chatgpt_app&medium=chatgpt_app&platform=openai&intent=agent_offer",
    }


def write_inputs(root: Path):
    (root / "marketing" / "generated").mkdir(parents=True)
    (root / "marketing" / "mcp_distribution_targets.json").write_text(json.dumps(mcp_targets()), encoding="utf-8")
    (root / "marketing" / "generated" / "outbound_send_queue.json").write_text(json.dumps(outbound_queue()), encoding="utf-8")
    (root / "marketing" / "openai_chatgpt_app_submission.json").write_text(json.dumps(openai_submission()), encoding="utf-8")


def write_ledger(root: Path, payload: dict | None = None):
    payload = payload or renderer.render_ledger(
        mcp_targets=mcp_targets(),
        outbound_queue=outbound_queue(),
        openai_submission=openai_submission(),
    )
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True)
    (generated / "gtm_execution_ledger.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (generated / "gtm_execution_ledger.csv").write_text(renderer.render_csv(payload), encoding="utf-8")
    (generated / "gtm_execution_ledger.md").write_text(renderer.render_markdown(payload), encoding="utf-8")
    return payload


def test_renderer_builds_revenue_directory_app_and_outbound_tasks():
    payload = renderer.render_ledger(
        mcp_targets=mcp_targets(),
        outbound_queue=outbound_queue(),
        openai_submission=openai_submission(),
    )

    assert payload["generated_at"] == "2026-06-25"
    assert payload["summary"]["total_tasks"] == 21
    assert payload["summary"]["outbound_manual_sends"] == checker.MIN_OUTBOUND_TASKS
    task_ids = {task["task_id"] for task in payload["tasks"]}
    assert "revenue.pilot_checkout_launch" in task_ids
    assert "revenue.stripe_catalog_hygiene" in task_ids
    assert "agent_app.openai_chatgpt_app_submission" in task_ids
    assert any(task_id.startswith("outbound_send.01.") for task_id in task_ids)
    assert all("source=" in task["primary_cta"] for task in payload["tasks"])


def test_renderer_check_detects_stale_outputs(tmp_path):
    write_inputs(tmp_path)
    json_out = tmp_path / "marketing" / "generated" / "gtm_execution_ledger.json"
    csv_out = tmp_path / "marketing" / "generated" / "gtm_execution_ledger.csv"
    md_out = tmp_path / "marketing" / "generated" / "gtm_execution_ledger.md"

    args = [
        "--mcp-targets",
        str(tmp_path / "marketing" / "mcp_distribution_targets.json"),
        "--outbound-queue",
        str(tmp_path / "marketing" / "generated" / "outbound_send_queue.json"),
        "--openai-submission",
        str(tmp_path / "marketing" / "openai_chatgpt_app_submission.json"),
        "--json-output",
        str(json_out),
        "--csv-output",
        str(csv_out),
        "--md-output",
        str(md_out),
    ]
    assert renderer.main(args) == 0
    assert renderer.main(args + ["--check"]) == 0

    md_out.write_text("stale", encoding="utf-8")
    assert renderer.main(args + ["--check"]) == 1


def test_gtm_execution_ledger_check_accepts_generated_ledger(tmp_path):
    write_ledger(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]
    rows = list(csv.DictReader((tmp_path / "marketing" / "generated" / "gtm_execution_ledger.csv").read_text().splitlines()))
    assert len(rows) == 21
    assert rows[0]["task_id"] == "revenue.pilot_checkout_launch"
    assert rows[1]["task_id"] == "revenue.stripe_catalog_hygiene"


def test_gtm_execution_ledger_check_rejects_untagged_cta(tmp_path):
    payload = write_ledger(tmp_path)
    payload["tasks"][0]["primary_cta"] = "https://tinyzkp.com/pilot"
    (tmp_path / "marketing" / "generated" / "gtm_execution_ledger.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "must include source" in failed


def test_gtm_execution_ledger_check_rejects_completion_without_evidence(tmp_path):
    payload = write_ledger(tmp_path)
    payload["tasks"][1]["status"] = "submitted"
    payload["tasks"][1]["evidence_url"] = ""
    payload["tasks"][1]["completed_at"] = ""
    (tmp_path / "marketing" / "generated" / "gtm_execution_ledger.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "requires evidence_url and completed_at" in failed
