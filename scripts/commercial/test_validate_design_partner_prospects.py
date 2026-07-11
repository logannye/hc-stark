import copy
import json
from pathlib import Path

import validate_design_partner_prospects as prospects


ROOT = Path(__file__).resolve().parents[2]
DOSSIER = ROOT / "commercial/research/design-partner-prospects.no-email.json"
SUMMARY = ROOT / "commercial/research/design-partner-prospects.no-email.md"


def load_dossier():
    return json.loads(DOSSIER.read_text(encoding="utf-8"))


def test_checked_in_dossier_is_valid_and_summary_is_generated_from_it():
    payload = load_dossier()
    assert prospects.validate(payload) == []
    assert prospects.render_markdown(payload) == SUMMARY.read_text(encoding="utf-8")


def test_requires_exactly_ten_unique_blocked_organization_records():
    payload = load_dossier()
    payload["prospects"].pop()
    payload["prospects"][0]["status"] = "ready_for_outreach"
    payload["prospects"][1]["public_repo"] = payload["prospects"][0]["public_repo"]
    failures = prospects.validate(payload)
    assert any("exactly 10" in failure for failure in failures)
    assert any("status must be" in failure for failure in failures)
    assert any("public_repo must be unique" in failure for failure in failures)


def test_rejects_address_like_data_and_unreviewed_routes():
    payload = copy.deepcopy(load_dossier())
    payload["prospects"][0]["fit_hypothesis"] = "Contact operator@example.invalid"
    payload["prospects"][1]["public_non_email_route"]["kind"] = "direct_message"
    payload["prospects"][1]["public_non_email_route"]["url"] = "https://example.com/contact"
    failures = prospects.validate(payload)
    assert any("address-like" in failure for failure in failures)
    assert any("kind is unsupported" in failure for failure in failures)
    assert any("HTTPS GitHub URL" in failure for failure in failures)


def test_rejects_message_sent_or_canary_bypass():
    payload = load_dossier()
    payload["policy"]["messages_sent"] = True
    payload["policy"]["outreach_blocker"] = "none"
    payload["prospects"][0]["public_non_email_route"]["use_policy"] = "Use now."
    failures = prospects.validate(payload)
    assert "policy.messages_sent must be false" in failures
    assert "policy.outreach_blocker must be live_no_email_canary" in failures
    assert any("must remain blocked until the canary" in failure for failure in failures)
