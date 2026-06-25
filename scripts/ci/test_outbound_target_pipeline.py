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


generator = load_module("generate_outbound_targets", "scripts/marketing/generate_outbound_targets.py")
checker = load_module("outbound_targets_check", "scripts/ci/outbound_targets_check.py")


def company_page(companies):
    payload = {
        "component": "ycdc_new/pages/Companies/company_list_page/CompanyListPage",
        "props": {"companies": companies},
    }
    escaped = json.dumps(payload).replace('"', "&quot;")
    return f'<div data-page="{escaped}"></div>'


def test_generator_extracts_scores_and_renders_source_tagged_targets():
    html = company_page(
        [
            {
                "_type": "company",
                "slug": "audit-agent",
                "name": "Audit Agent",
                "batch_name": "w26",
                "one_liner": "AI agents for audit workflow automation",
                "website": "https://audit-agent.example",
                "long_description": "Autonomous agents reconcile finance workflows and keep audit trails for customers.",
                "tags": ["artificial-intelligence", "developer-tools", "b2b"],
                "team_size": 4,
                "year_founded": 2026,
                "location": "San Francisco, CA, USA",
                "linkedin_url": "",
                "twitter_url": "",
                "github_url": "",
                "ycdc_company_url": "/companies/audit-agent",
            },
            {
                "_type": "company",
                "slug": "photo-fun",
                "name": "Photo Fun",
                "batch_name": "s2019",
                "one_liner": "Consumer photo filters",
                "website": "https://photo.example",
                "long_description": "A consumer social photo app.",
                "tags": ["consumer"],
                "team_size": 30,
                "year_founded": 2019,
                "location": "Remote",
                "linkedin_url": "",
                "twitter_url": "",
                "github_url": "",
                "ycdc_company_url": "/companies/photo-fun",
            },
            {
                "_type": "company",
                "slug": "missing-site-agent",
                "name": "Missing Site Agent",
                "batch_name": "w26",
                "one_liner": "AI agents for audit workflow automation",
                "website": "",
                "long_description": "Autonomous agents reconcile finance workflows and keep audit trails.",
                "tags": ["artificial-intelligence", "developer-tools", "b2b"],
                "team_size": 3,
                "year_founded": 2026,
                "location": "Remote",
                "linkedin_url": "",
                "twitter_url": "",
                "github_url": "",
                "ycdc_company_url": "/companies/missing-site-agent",
            },
        ]
    )

    companies = generator.companies_from_html("https://www.ycombinator.com/companies/industry/ai", html)
    assert [company.slug for company in companies] == ["audit-agent", "photo-fun"]
    scored = []
    for company in companies:
        score, signals = generator.score_company(company)
        if score >= generator.MIN_SCORE:
            scored.append(generator.target_record(company, score, signals, "yc_agent_outbound"))

    assert [target["id"] for target in scored] == ["yc_audit-agent"]
    target = scored[0]
    assert target["recommended_route"] in {"paid_pilot", "platform_rollout"}
    assert "source=founder_outbound" in target["tracked_urls"]["pilot"]
    assert target["contact_research_status"] == "needs_manual_founder_or_engineering_contact"
    assert "audit" in target["fit_reason"].lower() or "receipt" in target["fit_reason"].lower()


def write_valid_catalog(root: Path, count: int = checker.MIN_TARGETS):
    generated = root / "marketing" / "generated"
    generated.mkdir(parents=True)
    targets = []
    for i in range(count):
        company_slug = f"agent-{i}"
        base_query = f"source=founder_outbound&medium=email&platform=direct&campaign=yc_agent_outbound&workflow={company_slug}"
        targets.append(
            {
                "id": f"yc_{company_slug}",
                "company": f"Agent {i}",
                "website": f"https://agent-{i}.example",
                "yc_url": f"https://www.ycombinator.com/companies/{company_slug}",
                "source_url": "https://www.ycombinator.com/companies/industry/ai",
                "batch": "w26",
                "team_size": 5,
                "year_founded": 2026,
                "location": "San Francisco, CA, USA",
                "tags": ["artificial-intelligence", "developer-tools"],
                "one_liner": "AI agent workflow automation",
                "score": 12,
                "signals": ["agent", "workflow"],
                "recommended_route": "paid_pilot",
                "contact_research_status": "needs_manual_founder_or_engineering_contact",
                "fit_reason": "Receipt consequential agent workflow state changes.",
                "tracked_urls": {
                    "learn": f"https://tinyzkp.com/?{base_query}&intent=learn",
                    "fit": f"https://tinyzkp.com/fit?{base_query}&intent=find_route",
                    "calculator": f"https://tinyzkp.com/calculator?{base_query}&intent=calculator",
                    "pilot": f"https://tinyzkp.com/pilot?{base_query}&intent=paid_pilot_checkout",
                    "signup": f"https://tinyzkp.com/signup?{base_query}&intent=api_key",
                },
                "email_draft": {
                    "subject": f"verifiable receipts for Agent {i}?",
                    "first_line": "I looked at Agent.",
                    "hook": "Receipt consequential agent workflow state changes.",
                },
            }
        )
    payload = {
        "generated_at": "2026-06-25T00:00:00+00:00",
        "campaign": "yc_agent_outbound",
        "source_urls": ["https://www.ycombinator.com/companies/industry/ai"],
        "targets": targets,
    }
    (generated / "outbound_targets.json").write_text(json.dumps(payload), encoding="utf-8")
    (generated / "outbound_targets.md").write_text(
        "# TinyZKP Founder Outbound Targets\n\nsource=founder_outbound\n\n## Operating Rules\n",
        encoding="utf-8",
    )


def test_outbound_target_check_accepts_contact_safe_catalog(tmp_path):
    write_valid_catalog(tmp_path)

    checks = checker.validate(tmp_path)

    assert not [check for check in checks if check.status == "FAIL"]


def test_outbound_target_check_rejects_personal_emails(tmp_path):
    write_valid_catalog(tmp_path)
    path = tmp_path / "marketing" / "generated" / "outbound_targets.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["targets"][0]["contact_email"] = "founder@example.com"
    path.write_text(json.dumps(payload), encoding="utf-8")

    checks = checker.validate(tmp_path)

    failed = "\n".join(check.detail for check in checks if check.status == "FAIL")
    assert "must not include personal email addresses" in failed
