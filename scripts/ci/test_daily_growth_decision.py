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
    assert snapshot["autonomy_policy"]["north_star"] == "paid_customers"
    assert snapshot["funnel"]["next_missing_stage"] == "acquisition"
    assert snapshot["safe_action_queue"][0]["permission"] == "allowed_without_approval"
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


def test_funnel_rollup_surfaces_activation_and_paid_dropoffs():
    snapshot = decision.build_daily_snapshot(
        monitor_payload(
            accounts=11,
            activated_accounts=2,
            paid_accounts=0,
            total_proofs=5,
            top_sources=[
                {
                    "source": "unknown",
                    "medium": "",
                    "platform": "",
                    "accounts": 11,
                    "activated_accounts": 2,
                    "paid_accounts": 0,
                    "total_proofs": 5,
                }
            ],
        ),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 7, 1),
        generated_at_ms=1_000,
    )

    assert snapshot["funnel"]["next_missing_stage"] == "activation_rate"
    assert snapshot["funnel"]["dropoffs"]["accounts_without_successful_proof"] == 9
    assert snapshot["funnel"]["dropoffs"]["activated_without_paid_evidence"] == 2
    assert snapshot["funnel"]["rates"]["account_to_activation"] == 0.1818
    assert "No MCP, SDK, CLI, or package source adoption" in " ".join(snapshot["funnel"]["instrumentation_gaps"])


def test_safe_action_queue_marks_revenue_actions_as_approval_gated():
    snapshot = decision.build_daily_snapshot(
        monitor_payload(
            accounts=10,
            activated_accounts=8,
            paid_accounts=0,
            free_accounts=10,
            total_proofs=22,
        ),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 7, 1),
        generated_at_ms=1_000,
    )

    assert snapshot["selected_experiment"]["id"] == "pilot_paid_conversion"
    queue = {item["id"]: item for item in snapshot["safe_action_queue"]}
    assert queue["implement_selected_safe_experiment"]["permission"] == "allowed_without_approval"
    assert queue["request_revenue_action_approval"]["permission"] == "requires_explicit_approval"
    assert queue["do_not_claim_paid_traction"]["permission"] == "hard_guard"


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


def test_experiment_ledger_redacts_and_replaces_same_day_entry(tmp_path):
    snapshot = decision.build_daily_snapshot(
        monitor_payload(accounts=1, activated_accounts=1, paid_accounts=0, total_proofs=1),
        pipeline_state={"tasks": {}},
        prior_snapshots=[],
        snapshot_date=date(2026, 7, 1),
        generated_at_ms=1_000,
    )
    snapshot["selected_experiment"]["action"] = (
        "Follow up with buyer@example.com about cs_live_1234567890 at "
        "https://checkout.stripe.com/c/pay/cs_live_1234567890"
    )
    ledger_path = tmp_path / "growth_experiment_ledger.json"

    decision.write_experiment_ledger(ledger_path, snapshot)
    decision.write_experiment_ledger(ledger_path, snapshot)
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    rendered = json.dumps(payload)

    assert len(payload["entries"]) == 1
    assert payload["entries"][0]["experiment_id"] == snapshot["selected_experiment"]["id"]
    assert "buyer@example.com" not in rendered
    assert "cs_live_1234567890" not in rendered
    assert "checkout.stripe.com" not in rendered


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
    assert Path(out["experiment_ledger_path"]).exists()


def test_cli_no_write_snapshot_skips_experiment_ledger(tmp_path, capsys):
    monitor_json = tmp_path / "monitor.json"
    monitor_json.write_text(json.dumps(monitor_payload(accounts=1)), encoding="utf-8")
    ledger_path = tmp_path / "ledger.json"

    exit_code = decision.main(
        [
            "--from-monitor-json",
            str(monitor_json),
            "--snapshot-dir",
            str(tmp_path / "snapshots"),
            "--experiment-ledger",
            str(ledger_path),
            "--pipeline-state",
            str(tmp_path / "missing-pipeline.json"),
            "--date",
            "2026-07-01",
            "--no-write-snapshot",
            "--json",
        ]
    )

    assert exit_code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["snapshot_path"] is None
    assert out["experiment_ledger_path"] is None
    assert not ledger_path.exists()
