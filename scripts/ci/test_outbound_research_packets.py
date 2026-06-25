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


enricher = load_module("enrich_outbound_research", "scripts/marketing/enrich_outbound_research.py")
checker = load_module("outbound_research_packets_check", "scripts/ci/outbound_research_packets_check.py")
syncer = load_module("sync_outbound_research_pipeline", "scripts/marketing/sync_outbound_research_pipeline.py")


def queue_row(index: int = 1):
    slug = f"agent-{index}"
    base = f"https://tinyzkp.com/{{path}}?source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&workflow={slug}"
    return {
        "target_id": f"yc_{slug}",
        "company": f"Agent {index}",
        "website": f"https://agent-{index}.example",
        "yc_url": f"https://www.ycombinator.com/companies/{slug}",
        "recommended_route": "paid_pilot" if index == 1 else "platform_rollout",
        "contact_research_status": "needs_manual_founder_or_engineering_contact",
        "contact_role": "Founder, head of engineering, or workflow owner",
        "primary_cta": base.format(path="pilot") + "&intent=paid_pilot_checkout",
        "secondary_cta": base.format(path="calculator") + "&intent=calculator",
        "research_urls": [
            {"label": "YC profile", "url": f"https://www.ycombinator.com/companies/{slug}", "purpose": "Confirm company fit."},
            {"label": "Company website", "url": f"https://agent-{index}.example", "purpose": "Confirm positioning."},
            {"label": "Founder/engineering web search", "url": f"https://www.google.com/search?q=Agent+{index}+founder", "purpose": "Find one contact."},
            {"label": "LinkedIn people search", "url": f"https://www.linkedin.com/search/results/people/?keywords=Agent+{index}", "purpose": "Cross-check role."},
        ],
    }


def queue_payload(count: int = checker.MIN_PACKETS):
    return {
        "source_campaign": "yc_agent_outbound",
        "source_generated_at": "2026-06-25T00:00:00+00:00",
        "queue": [queue_row(index) for index in range(1, count + 1)],
    }


def write_packets(root: Path, payload: dict | None = None):
    payload = payload or enricher.build_packets(queue_payload(), limit=checker.MIN_PACKETS, timeout=0.01, offline=True)
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True)
    (generated / "outbound_research_packets.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (generated / "outbound_research_packets.md").write_text(enricher.render_markdown(payload), encoding="utf-8")
    return payload


def test_generator_filters_mailto_links_and_redacts_description_email():
    html = """
    <html>
      <head>
        <title>Agent Co</title>
        <meta name="description" content="Email founder@example.com for details">
      </head>
      <body>
        <a href="mailto:founder@example.com">Email us</a>
        <a href="/contact">Contact</a>
        <a href="/about">Team</a>
        <a href="/pricing">Pricing</a>
      </body>
    </html>
    """
    parser = enricher.HeadParser("https://agent.example")
    parser.feed(html)
    summary = enricher.PageSummary(
        url="https://agent.example",
        status="ok",
        title=parser.title,
        description=parser.description,
        contact_urls=enricher.classify_links("https://agent.example", parser.links, enricher.CONTACT_WORDS),
        about_urls=enricher.classify_links("https://agent.example", parser.links, enricher.ABOUT_WORDS),
        product_urls=enricher.classify_links("https://agent.example", parser.links, enricher.PRODUCT_WORDS),
    )

    assert "founder@example.com" not in summary.description
    assert summary.contact_urls == ("https://agent.example/contact",)
    assert summary.about_urls == ("https://agent.example/about",)
    assert summary.product_urls == ("https://agent.example/pricing",)


def test_checker_accepts_contact_safe_packets(tmp_path):
    write_packets(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]


def test_checker_rejects_emails_and_mailto(tmp_path):
    payload = write_packets(tmp_path)
    payload["packets"][0]["homepage"]["description"] = "founder@example.com"
    payload["packets"][0]["public_company_links"]["contact"] = ["mailto:founder@example.com"]
    generated = tmp_path / "marketing" / "generated"
    (generated / "outbound_research_packets.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "must not include email addresses" in failed
    assert "must not include mailto links" in failed or "must be an HTTPS URL" in failed


def test_generator_check_validates_existing_outputs(tmp_path):
    payload = enricher.build_packets(queue_payload(), limit=checker.MIN_PACKETS, timeout=0.01, offline=True)
    json_out = tmp_path / "packets.json"
    md_out = tmp_path / "packets.md"
    enricher.write_outputs(payload, json_out, md_out)

    assert enricher.main(["--json-output", str(json_out), "--md-output", str(md_out), "--check"]) == 0

    md_out.write_text(md_out.read_text(encoding="utf-8") + "\nmailto:founder@example.com\n", encoding="utf-8")
    assert enricher.main(["--json-output", str(json_out), "--md-output", str(md_out), "--check"]) == 1


def test_pipeline_sync_marks_company_research_ready_without_pii():
    packets = enricher.build_packets(queue_payload(), limit=2, timeout=0.01, offline=True)
    state = {
        "schema_version": 1,
        "updated_at": "2026-06-25",
        "privacy_rules": ["Do not commit personal email addresses."],
        "tasks": {
            "outbound_send.01.agent-1": {
                "stage": "needs_contact_research",
                "last_action_at": "",
                "next_action_at": "",
                "evidence_url": "",
                "completed_at": "",
                "reply_type": "",
                "outcome": "",
                "actual_revenue_cents": 0,
                "loss_reason": "",
                "notes": "",
            }
        },
    }

    synced, updated = syncer.sync_state(state, packets, action_date="2026-06-25")

    assert updated == 1
    entry = synced["tasks"]["outbound_send.01.agent-1"]
    assert entry["stage"] == "company_research_ready"
    assert entry["last_action_at"] == "2026-06-25"
    assert "outbound_research_packets.md" in entry["notes"]
    assert "@" not in entry["notes"]


def test_pipeline_sync_check_detects_stale_state(tmp_path):
    packets = enricher.build_packets(queue_payload(), limit=1, timeout=0.01, offline=True)
    packets_path = tmp_path / "packets.json"
    state_path = tmp_path / "state.json"
    packets_path.write_text(json.dumps(packets, indent=2) + "\n", encoding="utf-8")
    state = {
        "schema_version": 1,
        "updated_at": "2026-06-25",
        "privacy_rules": ["Do not commit personal email addresses."],
        "tasks": {
            "outbound_send.01.agent-1": {
                "stage": "needs_contact_research",
                "last_action_at": "",
                "next_action_at": "",
                "evidence_url": "",
                "completed_at": "",
                "reply_type": "",
                "outcome": "",
                "actual_revenue_cents": 0,
                "loss_reason": "",
                "notes": "",
            }
        },
    }
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    assert syncer.main(["--packets", str(packets_path), "--state", str(state_path), "--date", "2026-06-25", "--check"]) == 1
    assert syncer.main(["--packets", str(packets_path), "--state", str(state_path), "--date", "2026-06-25"]) == 0
    assert syncer.main(["--packets", str(packets_path), "--state", str(state_path), "--date", "2026-06-25", "--check"]) == 0
