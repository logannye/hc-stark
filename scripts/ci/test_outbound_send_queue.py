import csv
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


renderer = load_module("render_outbound_send_queue", "scripts/marketing/render_outbound_send_queue.py")
checker = load_module("outbound_send_queue_check", "scripts/ci/outbound_send_queue_check.py")


def target(index: int = 1):
    slug = f"agent-{index}"
    base = f"https://tinyzkp.com/{{path}}?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&workflow={slug}"
    return {
        "id": f"yc_{slug}",
        "company": f"Agent {index}",
        "website": f"https://agent-{index}.example",
        "yc_url": f"https://www.ycombinator.com/companies/{slug}",
        "score": 20 + index,
        "recommended_route": "paid_pilot" if index == 1 else "platform_rollout",
        "signals": ["agent", "workflow", "audit"] if index == 1 else ["agent", "workflow"],
        "one_liner": "AI agents for consequential workflow automation",
        "fit_reason": "Receipt consequential agent workflow state changes so recipients can verify the transition",
        "tracked_urls": {
            "learn": base.format(path="") + "&intent=learn",
            "fit": base.format(path="fit") + "&intent=find_route",
            "calculator": base.format(path="calculator") + "&intent=calculator",
            "pilot": base.format(path="pilot") + "&intent=paid_pilot_checkout",
            "signup": base.format(path="signup") + "&intent=api_key",
        },
        "email_draft": {
            "subject": f"verifiable receipts for Agent {index}?",
        },
    }


def source_payload(count: int = checker.MIN_QUEUE_TARGETS):
    return {
        "generated_at": "2026-06-25T17:53:19+00:00",
        "campaign": "yc_agent_outbound",
        "targets": [target(index) for index in range(1, count + 1)],
    }


def write_queue(root: Path, payload: dict | None = None):
    payload = payload or renderer.render_queue(source_payload(), limit=checker.MIN_QUEUE_TARGETS)
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True)
    (generated / "outbound_send_queue.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (generated / "outbound_send_queue.csv").write_text(renderer.render_csv(payload), encoding="utf-8")
    (generated / "outbound_send_queue.md").write_text(renderer.render_markdown(payload), encoding="utf-8")
    return payload


def test_renderer_builds_manual_first_wave_queue():
    queue = renderer.render_queue(source_payload(), limit=10)

    assert queue["send_window"]["first_send_date"] == "2026-06-29"
    assert queue["send_window"]["first_follow_up_date"] == "2026-07-06"
    assert len(queue["queue"]) == 10
    first = queue["queue"][0]
    assert first["contact_email"] == ""
    assert first["contact_research_status"] == "needs_manual_founder_or_engineering_contact"
    assert first["primary_cta"].endswith("intent=paid_pilot_checkout")
    assert "source=founder_outbound" in first["body"]
    assert first["mailto_template"].startswith("mailto:?")
    assert "will not follow up again" in first["follow_up_body"]
    labels = {item["label"] for item in first["research_urls"]}
    assert {"YC profile", "Company website", "Founder/engineering web search", "LinkedIn people search"} <= labels
    assert all(item["url"].startswith("https://") for item in first["research_urls"])


def test_renderer_check_detects_stale_outputs(tmp_path):
    source = source_payload()
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps(source), encoding="utf-8")
    json_out = tmp_path / "queue.json"
    csv_out = tmp_path / "queue.csv"
    md_out = tmp_path / "queue.md"

    exit_code = renderer.main([
        "--targets",
        str(targets),
        "--json-output",
        str(json_out),
        "--csv-output",
        str(csv_out),
        "--md-output",
        str(md_out),
        "--first-send-date",
        "2026-06-29",
    ])
    assert exit_code == 0
    assert renderer.main([
        "--targets",
        str(targets),
        "--json-output",
        str(json_out),
        "--csv-output",
        str(csv_out),
        "--md-output",
        str(md_out),
        "--first-send-date",
        "2026-06-29",
        "--check",
    ]) == 0

    md_out.write_text("stale", encoding="utf-8")
    assert renderer.main([
        "--targets",
        str(targets),
        "--json-output",
        str(json_out),
        "--csv-output",
        str(csv_out),
        "--md-output",
        str(md_out),
        "--first-send-date",
        "2026-06-29",
        "--check",
    ]) == 1


def test_outbound_send_queue_check_accepts_contact_safe_queue(tmp_path):
    write_queue(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]
    csv_path = tmp_path / "marketing" / "generated" / "outbound_send_queue.csv"
    rows = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
    assert len(rows) == checker.MIN_QUEUE_TARGETS
    assert rows[0]["contact_email"] == ""
    assert "Founder/engineering web search" in rows[0]["research_urls"]


def test_outbound_send_queue_check_rejects_personal_emails(tmp_path):
    payload = write_queue(tmp_path)
    payload["queue"][0]["contact_email"] = "founder@example.com"
    generated = tmp_path / "marketing" / "generated"
    (generated / "outbound_send_queue.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "contact fields must be blank" in failed


def test_outbound_send_queue_check_rejects_unbalanced_markdown_fences(tmp_path):
    write_queue(tmp_path)
    md_path = tmp_path / "marketing" / "generated" / "outbound_send_queue.md"
    md_path.write_text(md_path.read_text(encoding="utf-8") + "\n```text\nunterminated\n", encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "markdown code fences must be balanced" in failed


def test_first_send_date_can_be_overridden():
    queue = renderer.render_queue(source_payload(), limit=2, first_send_date=date(2026, 7, 1))

    assert queue["send_window"]["first_send_date"] == "2026-07-01"
    assert queue["send_window"]["first_follow_up_date"] == "2026-07-08"
