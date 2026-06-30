import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "marketing" / "sync_stripe_checkout_pipeline.py"
spec = importlib.util.spec_from_file_location("sync_stripe_checkout_pipeline", MODULE_PATH)
sync = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = sync
spec.loader.exec_module(sync)


def _execution():
    return {
        "tasks": [
            {
                "task_id": "revenue.pilot_checkout_launch",
                "channel": "revenue",
                "task_type": "live_checkout_verification",
                "status": "completed",
                "owner": "founder",
                "target": "$5K Production Pilot checkout",
                "due_date": "2026-06-25",
                "follow_up_date": "",
                "primary_cta": "https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout",
                "secondary_cta": "https://tinyzkp.com/contact?category=Paid%20Pilot&source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_contact",
                "source_artifact": "site/functions/api/create-pilot-checkout.js",
                "evidence_command": "python3 scripts/ci/production_launch_preflight.py --live",
                "evidence_url": "https://tinyzkp.com/api/create-pilot-checkout",
                "completed_at": "",
                "next_action": "Monitor pilot checkout starts and completed payments.",
                "blocker": "None; live route uses inline price_data.",
            }
        ]
    }


def _state():
    return {
        "schema_version": 1,
        "updated_at": "2026-06-25",
        "privacy_rules": [
            "Do not commit personal email addresses, phone numbers, private CRM notes, API keys, or customer secrets.",
            "Use evidence URLs, public listing URLs, task IDs, and aggregate outcomes instead of personal contact details.",
            "Record actual revenue only after Stripe, invoice, or signed-contract evidence exists.",
        ],
        "tasks": {
            "revenue.pilot_checkout_launch": {
                "stage": "live_monitoring",
                "last_action_at": "2026-06-25",
                "next_action_at": "2026-06-26",
                "evidence_url": "https://tinyzkp.com/api/create-pilot-checkout",
                "completed_at": "",
                "reply_type": "",
                "outcome": "",
                "actual_revenue_cents": 0,
                "loss_reason": "",
                "notes": "No buyer yet.",
            }
        },
    }


def _stripe_payload(payment_status="paid", status="complete"):
    return {
        "has_more": False,
        "data": [
            {
                "id": "cs_live_secret",
                "customer": "cus_live_secret",
                "customer_email": "buyer@example.com",
                "customer_details": {"email": "buyer@example.com"},
                "payment_intent": "pi_live_secret",
                "url": "https://checkout.stripe.com/c/pay/cs_live_secret",
                "status": status,
                "payment_status": payment_status,
                "amount_total": 500_000,
                "currency": "usd",
                "mode": "payment",
                "created": 1_782_403_200,
                "metadata": {
                    "plan": "production_pilot",
                    "source": "pricing_commercial",
                    "medium": "site",
                    "platform": "website",
                    "intent": "paid_pilot_checkout",
                    "workflow": "sensitive customer workflow",
                },
            }
        ],
    }


def _write_inputs(tmp_path, payload):
    generated = tmp_path / "marketing" / "generated"
    generated.mkdir(parents=True)
    execution_path = generated / "gtm_execution_ledger.json"
    state_path = tmp_path / "marketing" / "gtm_pipeline_state.json"
    payload_path = tmp_path / "stripe.json"
    execution_path.write_text(json.dumps(_execution(), indent=2) + "\n", encoding="utf-8")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(_state(), indent=2) + "\n", encoding="utf-8")
    payload_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return execution_path, state_path, payload_path, generated


def test_sync_state_records_paid_pilot_without_pii(tmp_path):
    execution_path, state_path, payload_path, generated = _write_inputs(tmp_path, _stripe_payload())

    assert sync.main(
        [
            "--from-json",
            str(payload_path),
            "--state",
            str(state_path),
            "--execution-ledger",
            str(execution_path),
            "--json-output",
            str(generated / "gtm_pipeline_ledger.json"),
            "--csv-output",
            str(generated / "gtm_pipeline_ledger.csv"),
            "--md-output",
            str(generated / "gtm_pipeline_ledger.md"),
            "--synced-at",
            "2026-06-25",
        ]
    ) == 0

    state_text = state_path.read_text(encoding="utf-8")
    ledger_text = (generated / "gtm_pipeline_ledger.json").read_text(encoding="utf-8")
    combined = state_text + ledger_text
    state = json.loads(state_text)
    entry = state["tasks"]["revenue.pilot_checkout_launch"]

    assert entry["stage"] == "won"
    assert entry["completed_at"] == "2026-06-25"
    assert entry["actual_revenue_cents"] == 500_000
    assert entry["evidence_url"] == "https://dashboard.stripe.com/payments"
    assert "production_pilot_paid=1" in entry["notes"]
    assert "buyer@example.com" not in combined
    assert "cs_live_secret" not in combined
    assert "cus_live_secret" not in combined
    assert "pi_live_secret" not in combined
    assert "checkout.stripe.com" not in combined
    assert "sensitive customer workflow" not in combined


def test_sync_state_does_not_lower_existing_revenue_when_lookback_has_no_paid_pilot():
    state = _state()
    entry = state["tasks"]["revenue.pilot_checkout_launch"]
    entry["stage"] = "won"
    entry["completed_at"] = "2026-06-24"
    entry["actual_revenue_cents"] = 500_000
    summary = sync.summary_from_payload(_stripe_payload(payment_status="unpaid", status="expired"), lookback_hours=168)

    updated, updated_entry = sync.sync_state(state, summary, synced_at="2026-06-25")

    assert updated_entry["stage"] == "won"
    assert updated_entry["completed_at"] == "2026-06-24"
    assert updated_entry["actual_revenue_cents"] == 500_000
    assert updated["updated_at"] == "2026-06-25"


def test_summary_from_payload_excludes_monitoring_canary_revenue():
    payload = _stripe_payload()
    session = payload["data"][0]
    session["metadata"]["source"] = "api_health_audit"
    session["metadata"]["medium"] = "monitoring"
    session["metadata"]["intent"] = "paid_pilot_checkout_canary"

    summary = sync.summary_from_payload(payload, lookback_hours=168)

    assert summary["sessions"] == 0
    assert summary["paid"] == 0
    assert summary["production_pilot_starts"] == 0
    assert summary["production_pilot_paid"] == 0
    assert summary["paid_amount_by_currency"] == {}
    assert summary["excluded_monitoring_sessions"] == 1


def test_live_sync_passes_api_account_source_to_monitor(tmp_path, monkeypatch):
    execution_path, state_path, _payload_path, generated = _write_inputs(tmp_path, _stripe_payload())
    calls = []
    summary = sync.summary_from_payload(_stripe_payload(), lookback_hours=168)

    def fake_collect(**kwargs):
        calls.append(kwargs)
        return summary

    monkeypatch.setattr(sync.stripe_checkout_monitor, "collect_checkout_summary", fake_collect)
    monkeypatch.setattr(sync.stripe_checkout_monitor, "summary_to_dict", lambda value: value)

    assert sync.main(
        [
            "--state",
            str(state_path),
            "--execution-ledger",
            str(execution_path),
            "--json-output",
            str(generated / "gtm_pipeline_ledger.json"),
            "--csv-output",
            str(generated / "gtm_pipeline_ledger.csv"),
            "--md-output",
            str(generated / "gtm_pipeline_ledger.md"),
            "--account-source",
            "api",
            "--stripe-api-key-env",
            "STRIPE_SECRET_KEY",
            "--dry-run",
            "--json",
        ]
    ) == 0

    assert calls
    assert calls[0]["account_source"] == "api"
    assert calls[0]["stripe_api_key_env"] == "STRIPE_SECRET_KEY"
