import importlib.util
import json
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "monitoring" / "daily_growth_decision.py"
spec = importlib.util.spec_from_file_location("daily_growth_decision", MODULE_PATH)
decision = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = decision
spec.loader.exec_module(decision)


def monitor_payload(**revenue_overrides):
    revenue = {
        "tenant_db_exists": True,
        "usage_db_exists": True,
        "accounts": 0,
        "active_accounts": 0,
        "monthly_active_accounts": 0,
        "activated_accounts": 0,
        "paid_accounts": 0,
        "free_accounts": 0,
        "total_proofs": 0,
        "monthly_proofs": 0,
        "paid_proofs": 0,
        "compute_trace_steps": 0,
        "estimated_base_mrr": 0,
        "estimated_usage_revenue_cents": 0,
        "top_sources": [],
    }
    revenue.update(revenue_overrides)
    return {
        "ok": True,
        "summary": {"passed": 12, "warned": 0, "failed": 0},
        "checks": [],
        "revenue": revenue,
        "stripe_checkout": None,
        "action_labels": [],
    }


def test_snapshot_handles_missing_prior_and_zero_denominators(tmp_path):
    snapshot = decision.build_daily_snapshot(
        monitor_payload(),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["metrics"]["adoption_rate"] == 0.0
    assert snapshot["metrics"]["paid_rate"] == 0.0
    assert snapshot["metrics"]["new_accounts"] == 0
    assert snapshot["authority"] == "implement_safe_experiment_or_report_blocker"
    assert snapshot["deltas"]["day"]["accounts"] is None
    assert snapshot["deltas"]["seven_day"]["accounts"] is None
    assert snapshot["previous_experiment_evaluation"]["status"] == "no_prior_experiment"

    path = decision.write_snapshot(tmp_path, snapshot)
    assert path == tmp_path / "2026-06-28.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["date"] == "2026-06-28"


def test_snapshot_computes_day_and_seven_day_deltas():
    prior = [
        {
            "date": "2026-06-21",
            "metrics": {"accounts": 3, "activated_accounts": 1, "paid_accounts": 0, "total_proofs": 4},
        },
        {
            "date": "2026-06-27",
            "metrics": {"accounts": 5, "activated_accounts": 2, "paid_accounts": 0, "total_proofs": 7},
        },
    ]
    snapshot = decision.build_daily_snapshot(
        monitor_payload(accounts=8, activated_accounts=4, paid_accounts=1, total_proofs=12),
        pipeline_state={"tasks": {}},
        prior_snapshots=prior,
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["metrics"]["new_accounts"] == 3
    assert snapshot["deltas"]["day"]["accounts"] == 3
    assert snapshot["deltas"]["day"]["activated_accounts"] == 2
    assert snapshot["deltas"]["seven_day"]["accounts"] == 5
    assert snapshot["deltas"]["seven_day"]["total_proofs"] == 8


def test_previous_experiment_evaluation_marks_activation_success():
    prior = [
        {
            "date": "2026-06-27",
            "metrics": {"accounts": 10, "activated_accounts": 1, "adoption_rate": 0.1},
            "selected_experiment": {"id": "activation_first_proof", "title": "Move new accounts to first proof"},
            "pipeline": {"due_count": 0},
        }
    ]
    snapshot = decision.build_daily_snapshot(
        monitor_payload(accounts=10, activated_accounts=3, paid_accounts=0, total_proofs=3),
        pipeline_state={"tasks": {}},
        prior_snapshots=prior,
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["previous_experiment_evaluation"]["status"] == "succeeded"
    assert snapshot["previous_experiment_evaluation"]["experiment_id"] == "activation_first_proof"


def test_growth_data_wiring_reports_repo_implementation_pending_deploy():
    snapshot = decision.build_daily_snapshot(
        monitor_payload(tenant_db_exists=False, usage_db_exists=False),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["selected_experiment"]["id"] == "growth_data_wiring"
    assert snapshot["implementation"]["status"] == "implemented_in_repo_pending_deploy"
    assert "production host cron" in snapshot["implementation"]["action"]


def test_experiment_prioritizes_paid_conversion_when_activation_exists():
    snapshot = decision.build_daily_snapshot(
        monitor_payload(
            accounts=10,
            active_accounts=10,
            monthly_active_accounts=6,
            activated_accounts=8,
            paid_accounts=0,
            free_accounts=10,
            total_proofs=22,
            monthly_proofs=12,
            top_sources=[
                {
                    "source": "smithery_mcp",
                    "medium": "mcp_directory",
                    "platform": "smithery",
                    "accounts": 8,
                    "activated_accounts": 7,
                    "monthly_active_accounts": 6,
                    "paid_accounts": 0,
                    "total_proofs": 20,
                    "paid_proofs": 0,
                }
            ],
        ),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["selected_experiment"]["id"] == "pilot_paid_conversion"
    assert snapshot["implementation"]["status"] == "agent_can_implement_repo_local_or_ledger_change"
    assert "paid customer" in snapshot["main_bottleneck"].lower()


def test_experiment_falls_back_to_activation_when_first_proof_is_blocked():
    snapshot = decision.build_daily_snapshot(
        monitor_payload(
            accounts=10,
            active_accounts=10,
            activated_accounts=1,
            paid_accounts=0,
            free_accounts=10,
            total_proofs=1,
        ),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )

    assert snapshot["selected_experiment"]["id"] == "activation_first_proof"
    assert "activation" in snapshot["main_bottleneck"].lower()


def test_report_redacts_pii_and_stripe_identifiers():
    payload = monitor_payload(
        accounts=1,
        active_accounts=1,
        activated_accounts=1,
        paid_accounts=0,
        free_accounts=1,
        total_proofs=1,
        top_sources=[
            {
                "source": "secret@example.com",
                "medium": "tzk_live_abcdef1234567890",
                "platform": "checkout",
                "accounts": 1,
                "activated_accounts": 1,
                "monthly_active_accounts": 0,
                "paid_accounts": 0,
                "total_proofs": 1,
                "paid_proofs": 0,
            }
        ],
    )
    payload["checks"] = [
        {
            "status": "FAIL",
            "category": "Stripe checkout",
            "name": "live checkout query",
            "detail": "cs_live_1234567890 for buyer@example.com at https://checkout.stripe.com/c/pay/cs_live_1234567890",
        }
    ]
    payload["summary"]["failed"] = 1

    snapshot = decision.build_daily_snapshot(
        payload,
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 6, 28),
        generated_at_ms=1_000,
    )
    rendered = json.dumps(snapshot) + decision.render_markdown(snapshot)

    assert "secret@example.com" not in rendered
    assert "buyer@example.com" not in rendered
    assert "cs_live_1234567890" not in rendered
    assert "tzk_live_abcdef1234567890" not in rendered
    assert "checkout.stripe.com" not in rendered
    assert "[redacted-email]" in rendered
    assert "[redacted-id]" in rendered


def test_cli_ingests_monitor_json_and_writes_snapshot(tmp_path, capsys):
    monitor_json = tmp_path / "monitor.json"
    monitor_json.write_text(
        json.dumps(monitor_payload(accounts=2, activated_accounts=2, paid_accounts=1, total_proofs=4)),
        encoding="utf-8",
    )
    exit_code = decision.main(
        [
            "--from-monitor-json",
            str(monitor_json),
            "--snapshot-dir",
            str(tmp_path / "snapshots"),
            "--pipeline-state",
            str(tmp_path / "missing-pipeline.json"),
            "--date",
            "2026-06-28",
            "--json",
        ]
    )

    assert exit_code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["snapshot"]["selected_experiment"]["id"] == "paid_expansion"
    assert Path(out["snapshot_path"]).exists()
