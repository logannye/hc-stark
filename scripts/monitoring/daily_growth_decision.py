#!/usr/bin/env python3
"""Create the daily TinyZKP growth scorecard, experiment, and implementation policy."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SNAPSHOT_DIR = Path(os.environ.get("TINYZKP_GROWTH_SNAPSHOT_DIR", "/opt/hc-stark/data/growth_snapshots"))
DEFAULT_PIPELINE_STATE = ROOT / "marketing" / "gtm_pipeline_state.json"

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET_RE = re.compile(
    r"\b(?:sk|rk|pk|whsec|tzk|acct|cs|cus|sub|si|pi|price|prod|evt|ch|in|pm)_(?:live|test)?[A-Za-z0-9_=-]{6,}\b"
)
STRIPE_CHECKOUT_URL_RE = re.compile(r"https://checkout\.stripe\.com/[^\s)\"']+")

METRIC_KEYS = (
    "accounts",
    "new_accounts",
    "active_accounts",
    "active_30d_accounts",
    "activated_accounts",
    "paid_accounts",
    "free_accounts",
    "total_proofs",
    "monthly_proofs",
    "paid_proofs",
    "estimated_base_mrr",
    "estimated_usage_revenue_cents",
    "stripe_paid_sessions",
    "stripe_pilot_paid_sessions",
    "stripe_paid_revenue_cents",
    "stack_accounts",
    "stack_activated_accounts",
    "stack_paid_accounts",
)

STACK_SOURCE_TERMS = (
    "mcp",
    "sdk",
    "cli",
    "package",
    "pypi",
    "npm",
    "crates",
    "smithery",
    "registry",
    "cursor",
    "claude",
    "openai",
)


@dataclass(frozen=True)
class ExperimentCandidate:
    id: str
    title: str
    score: int
    hypothesis: str
    target_segment: str
    action: str
    success_metric: str
    measurement_window: str
    stop_condition: str
    reason: str


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _now_ms() -> int:
    return int(time.time() * 1000)


def _today_utc() -> date:
    return datetime.now(timezone.utc).date()


def _parse_date(value: str | None) -> date:
    return date.fromisoformat(value) if value else _today_utc()


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _money(cents: int) -> str:
    return f"${cents / 100:.2f}"


def _delta_fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value}"


def redact_text(value: str) -> str:
    value = STRIPE_CHECKOUT_URL_RE.sub("[redacted-checkout-url]", value)
    value = EMAIL_RE.sub("[redacted-email]", value)
    return SECRET_RE.sub("[redacted-id]", value)


def sanitize_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [sanitize_obj(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_obj(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_obj(item) for key, item in value.items()}
    return value


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def _load_monitor_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.from_monitor_json:
        return load_json(Path(args.from_monitor_json))

    monitor = _load_module(
        "gtm_growth_monitor_for_daily_decision",
        ROOT / "scripts" / "monitoring" / "gtm_growth_monitor.py",
    )
    monitor_argv = [
        "--tenant-db",
        str(args.tenant_db),
        "--usage-db",
        str(args.usage_db),
        "--timeout",
        str(args.timeout),
    ]
    monitor_argv.append("--live" if args.live else "--offline")
    if args.stripe_checkout:
        monitor_argv.append("--stripe-checkout")
        monitor_argv.extend(["--stripe-bin", args.stripe_bin])
        if args.stripe_project_name:
            monitor_argv.extend(["--stripe-project-name", args.stripe_project_name])
        if args.stripe_checkout_test_mode:
            monitor_argv.append("--stripe-checkout-test-mode")
        monitor_argv.extend(["--stripe-checkout-limit", str(args.stripe_checkout_limit)])
        monitor_argv.extend(["--stripe-checkout-max-pages", str(args.stripe_checkout_max_pages)])
        monitor_argv.extend(["--stripe-checkout-lookback-hours", str(args.stripe_checkout_lookback_hours)])
        monitor_argv.extend(["--stripe-expected-display-name", args.stripe_expected_display_name])
        if args.stripe_skip_account_check:
            monitor_argv.append("--stripe-skip-account-check")
    monitor_args = monitor.build_parser().parse_args(monitor_argv)
    result = monitor.run_monitor(monitor_args)
    return monitor._json_result(result)


def _paid_revenue_cents(stripe_checkout: dict[str, Any] | None) -> int:
    if not isinstance(stripe_checkout, dict):
        return 0
    paid_amount = stripe_checkout.get("paid_amount_by_currency", {}) or {}
    if not isinstance(paid_amount, dict):
        return 0
    return sum(_safe_int(cents) for cents in paid_amount.values())


def _source_is_stack(source: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(source.get(key, "") or "").lower()
        for key in ("source", "medium", "platform")
    )
    return any(term in haystack for term in STACK_SOURCE_TERMS)


def extract_metrics(
    monitor_payload: dict[str, Any],
    *,
    previous_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    revenue = monitor_payload.get("revenue", {}) or {}
    sources = revenue.get("top_sources", []) if isinstance(revenue.get("top_sources"), list) else []
    stripe_checkout = monitor_payload.get("stripe_checkout")
    stripe_checkout = stripe_checkout if isinstance(stripe_checkout, dict) else None

    accounts = _safe_int(revenue.get("accounts"))
    activated = _safe_int(revenue.get("activated_accounts"))
    paid = _safe_int(revenue.get("paid_accounts"))
    stack_sources = [source for source in sources if isinstance(source, dict) and _source_is_stack(source)]
    previous_accounts = _safe_int((previous_metrics or {}).get("accounts")) if previous_metrics else None
    new_accounts = max(accounts - previous_accounts, 0) if previous_accounts is not None else 0

    metrics = {
        "accounts": accounts,
        "new_accounts": new_accounts,
        "active_accounts": _safe_int(revenue.get("active_accounts")),
        "active_30d_accounts": _safe_int(revenue.get("monthly_active_accounts")),
        "activated_accounts": activated,
        "paid_accounts": paid,
        "free_accounts": _safe_int(revenue.get("free_accounts")),
        "total_proofs": _safe_int(revenue.get("total_proofs")),
        "monthly_proofs": _safe_int(revenue.get("monthly_proofs")),
        "paid_proofs": _safe_int(revenue.get("paid_proofs")),
        "estimated_base_mrr": _safe_int(revenue.get("estimated_base_mrr")),
        "estimated_usage_revenue_cents": _safe_int(revenue.get("estimated_usage_revenue_cents")),
        "stripe_paid_sessions": _safe_int(stripe_checkout.get("paid") if stripe_checkout else 0),
        "stripe_pilot_paid_sessions": _safe_int(stripe_checkout.get("production_pilot_paid") if stripe_checkout else 0),
        "stripe_paid_revenue_cents": _paid_revenue_cents(stripe_checkout),
        "stack_accounts": sum(_safe_int(source.get("accounts")) for source in stack_sources),
        "stack_activated_accounts": sum(_safe_int(source.get("activated_accounts")) for source in stack_sources),
        "stack_paid_accounts": sum(_safe_int(source.get("paid_accounts")) for source in stack_sources),
    }
    metrics["adoption_rate"] = _rate(metrics["activated_accounts"], metrics["accounts"])
    metrics["paid_rate"] = _rate(metrics["paid_accounts"], metrics["accounts"])
    metrics["stack_adoption_rate"] = _rate(metrics["stack_activated_accounts"], metrics["stack_accounts"])
    return metrics


def _snapshot_date(snapshot: dict[str, Any]) -> date | None:
    try:
        return date.fromisoformat(str(snapshot.get("date") or ""))
    except ValueError:
        return None


def load_prior_snapshots(snapshot_dir: Path, snapshot_date: date) -> list[dict[str, Any]]:
    if not snapshot_dir.exists():
        return []
    snapshots: list[dict[str, Any]] = []
    for path in sorted(snapshot_dir.glob("*.json")):
        try:
            current = date.fromisoformat(path.stem)
        except ValueError:
            continue
        if current >= snapshot_date:
            continue
        try:
            payload = load_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if _snapshot_date(payload) is not None:
            snapshots.append(payload)
    return sorted(snapshots, key=lambda item: str(item.get("date") or ""))


def _latest_snapshot(snapshots: list[dict[str, Any]]) -> dict[str, Any] | None:
    return snapshots[-1] if snapshots else None


def _seven_day_baseline(snapshots: list[dict[str, Any]], snapshot_date: date) -> dict[str, Any] | None:
    target = snapshot_date - timedelta(days=7)
    eligible = [
        snapshot
        for snapshot in snapshots
        if (_snapshot_date(snapshot) is not None and _snapshot_date(snapshot) <= target)
    ]
    return eligible[-1] if eligible else None


def _metric_delta(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, int | None]:
    baseline_metrics = baseline.get("metrics", {}) if baseline else {}
    deltas: dict[str, int | None] = {}
    for key in METRIC_KEYS:
        if not baseline_metrics or key not in baseline_metrics:
            deltas[key] = None
        else:
            deltas[key] = _safe_int(current.get(key)) - _safe_int(baseline_metrics.get(key))
    return deltas


def _metric_value(snapshot: dict[str, Any], key: str) -> int:
    return _safe_int((snapshot.get("metrics", {}) or {}).get(key))


def _combined_paid(metrics: dict[str, Any]) -> int:
    return _safe_int(metrics.get("paid_accounts")) + _safe_int(metrics.get("stripe_paid_sessions"))


def _repo_has_daily_growth_cron() -> bool:
    wrapper_path = ROOT / "scripts" / "monitoring" / "daily_growth_decision_cron.sh"
    wrapper_marker = "scripts/monitoring/daily_growth_decision.py"
    cron_marker = "scripts/monitoring/daily_growth_decision_cron.sh"
    if not wrapper_path.exists() or wrapper_marker not in wrapper_path.read_text(encoding="utf-8"):
        return False
    return all(
        (ROOT / path).exists() and cron_marker in (ROOT / path).read_text(encoding="utf-8")
        for path in ("deploy/hetzner/deploy.sh", "deploy/hetzner/setup.sh")
    )


def summarize_pipeline(state: dict[str, Any] | None, snapshot_date: date) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {"exists": False, "stage_counts": {}, "due_tasks": [], "actual_revenue_cents": 0}
    tasks = state.get("tasks")
    if not isinstance(tasks, dict):
        return {"exists": False, "stage_counts": {}, "due_tasks": [], "actual_revenue_cents": 0}

    stage_counts: dict[str, int] = {}
    due_tasks: list[str] = []
    actual_revenue_cents = 0
    for task_id, task in sorted(tasks.items()):
        if not isinstance(task, dict):
            continue
        stage = str(task.get("stage") or "unknown")
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
        actual_revenue_cents += _safe_int(task.get("actual_revenue_cents"))
        next_action_at = str(task.get("next_action_at") or "")
        if next_action_at:
            try:
                if date.fromisoformat(next_action_at) <= snapshot_date:
                    due_tasks.append(str(task_id))
            except ValueError:
                continue

    return {
        "exists": True,
        "stage_counts": stage_counts,
        "due_tasks": due_tasks[:12],
        "due_count": len(due_tasks),
        "actual_revenue_cents": actual_revenue_cents,
    }


def evaluate_previous_experiment(
    prior_snapshots: list[dict[str, Any]],
    current_metrics: dict[str, Any],
    current_gaps: list[str],
    current_pipeline: dict[str, Any],
) -> dict[str, Any]:
    previous = _latest_snapshot(prior_snapshots)
    if not previous:
        return {
            "status": "no_prior_experiment",
            "experiment_id": "",
            "title": "",
            "evidence": "No prior daily snapshot exists yet.",
        }

    selected = previous.get("selected_experiment", {}) or {}
    experiment_id = str(selected.get("id") or "")
    title = str(selected.get("title") or "")
    prior_metrics = previous.get("metrics", {}) or {}
    prior_pipeline = previous.get("pipeline", {}) or {}

    if experiment_id == "growth_data_wiring":
        missing_store_gap = any("database is missing" in gap for gap in current_gaps)
        repo_ready = _repo_has_daily_growth_cron()
        if not missing_store_gap:
            status = "succeeded"
            evidence = "The current run can read canonical tenant and usage stores."
        elif repo_ready:
            status = "implemented_pending_external_verification"
            evidence = (
                "The repo has the production cron wiring for daily snapshots, but this local run still cannot read "
                "/opt/hc-stark/data tenant and usage stores."
            )
        else:
            status = "needs_implementation"
            evidence = "The daily growth decision cron is not present in the production deployment templates."
    elif experiment_id == "acquisition_baseline":
        status = "succeeded" if _safe_int(current_metrics.get("accounts")) > _safe_int(prior_metrics.get("accounts")) else "inconclusive"
        evidence = (
            f"Accounts moved from {_safe_int(prior_metrics.get('accounts'))} "
            f"to {_safe_int(current_metrics.get('accounts'))}."
        )
    elif experiment_id == "activation_first_proof":
        activation_delta = _safe_int(current_metrics.get("activated_accounts")) - _safe_int(prior_metrics.get("activated_accounts"))
        rate_delta = _safe_float(current_metrics.get("adoption_rate")) - _safe_float(prior_metrics.get("adoption_rate"))
        status = "succeeded" if activation_delta >= 2 or rate_delta >= 0.10 else "inconclusive"
        evidence = f"Activated accounts changed by {activation_delta}; adoption rate changed by {rate_delta * 100:.1f} points."
    elif experiment_id == "pilot_paid_conversion":
        current_paid = _combined_paid(current_metrics)
        prior_paid = _combined_paid(prior_metrics)
        status = "succeeded" if current_paid > prior_paid else "inconclusive"
        evidence = f"Paid customer evidence moved from {prior_paid} to {current_paid}."
    elif experiment_id == "paid_expansion":
        paid_delta = _safe_int(current_metrics.get("paid_accounts")) - _safe_int(prior_metrics.get("paid_accounts"))
        proof_delta = _safe_int(current_metrics.get("paid_proofs")) - _safe_int(prior_metrics.get("paid_proofs"))
        mrr_delta = _safe_int(current_metrics.get("estimated_base_mrr")) - _safe_int(prior_metrics.get("estimated_base_mrr"))
        status = "succeeded" if paid_delta > 0 or proof_delta > 0 or mrr_delta > 0 else "inconclusive"
        evidence = f"Paid accounts delta={paid_delta}, paid proofs delta={proof_delta}, base MRR delta=${mrr_delta}."
    elif experiment_id == "stack_adoption_attribution":
        current_stack = _safe_int(current_metrics.get("stack_accounts"))
        prior_stack = _safe_int(prior_metrics.get("stack_accounts"))
        status = "succeeded" if current_stack > prior_stack else "inconclusive"
        evidence = f"Stack-attributed accounts moved from {prior_stack} to {current_stack}."
    elif experiment_id == "pipeline_followup":
        current_due = _safe_int(current_pipeline.get("due_count"))
        prior_due = _safe_int(prior_pipeline.get("due_count"))
        status = "succeeded" if current_due < prior_due else "inconclusive"
        evidence = f"Due GTM pipeline tasks moved from {prior_due} to {current_due}."
    else:
        status = "unknown_experiment"
        evidence = "The prior experiment id is not recognized by the evaluator."

    return {
        "status": status,
        "experiment_id": experiment_id,
        "title": title,
        "evidence": evidence,
        "prior_date": previous.get("date", ""),
    }


def implementation_plan_for(candidate: dict[str, Any], gaps: list[str]) -> dict[str, Any]:
    experiment_id = str(candidate.get("id") or "")
    if experiment_id == "growth_data_wiring":
        if _repo_has_daily_growth_cron():
            status = "implemented_in_repo_pending_deploy"
            action = (
                "Deploy or push the current repo changes so the production host cron runs "
                "daily_growth_decision_cron.sh against /opt/hc-stark/data and writes non-repo snapshots."
            )
        else:
            status = "agent_can_implement_repo_change"
            action = (
                "Add daily_growth_decision.py to the production cron templates after the existing 09:45 GTM monitor, "
                "then test the script with --no-write-snapshot."
            )
        return {
            "status": status,
            "automation_policy": "implement_safe_repo_local_changes; report external deploy blockers",
            "action": action,
            "verification": "Next memo succeeds when tenant and usage store gaps disappear in production.",
        }

    if experiment_id in {"activation_first_proof", "pilot_paid_conversion", "paid_expansion", "stack_adoption_attribution", "acquisition_baseline"}:
        return {
            "status": "agent_can_implement_repo_local_or_ledger_change",
            "automation_policy": "make a small safe repo-local change, run focused tests, and report any external blockers",
            "action": str(candidate.get("action") or ""),
            "verification": str(candidate.get("success_metric") or ""),
        }

    if experiment_id == "pipeline_followup":
        return {
            "status": "agent_can_attempt_public_no_pii_followup",
            "automation_policy": "only use public/no-PII evidence; do not send customer messages or use private contact data",
            "action": str(candidate.get("action") or ""),
            "verification": str(candidate.get("success_metric") or ""),
        }

    return {
        "status": "needs_human_review",
        "automation_policy": "do_not_execute_unknown_experiment",
        "action": str(candidate.get("action") or ""),
        "verification": str(candidate.get("success_metric") or ""),
    }


def data_gaps(monitor_payload: dict[str, Any], pipeline_summary: dict[str, Any]) -> list[str]:
    revenue = monitor_payload.get("revenue", {}) or {}
    gaps: list[str] = []
    if not revenue.get("tenant_db_exists"):
        gaps.append("Tenant database is missing; account, attribution, and paid-plan counts are unavailable.")
    if not revenue.get("usage_db_exists"):
        gaps.append("Usage database is missing; proof activation and 30-day activity counts are unavailable.")
    if monitor_payload.get("stripe_checkout") is None:
        gaps.append("Stripe checkout summary was not included; paid checkout conversion is based on tenant and usage stores only.")
    if not pipeline_summary.get("exists"):
        gaps.append("GTM pipeline state is missing; outbound and directory follow-up counts are unavailable.")
    failed = _safe_int((monitor_payload.get("summary", {}) or {}).get("failed"))
    if failed:
        gaps.append(f"GTM monitor reported {failed} failing check(s); inspect monitor action labels before trusting trends.")
    return gaps


def _candidate(
    candidate_id: str,
    title: str,
    score: int,
    hypothesis: str,
    target_segment: str,
    action: str,
    success_metric: str,
    measurement_window: str,
    stop_condition: str,
    reason: str,
) -> ExperimentCandidate:
    return ExperimentCandidate(
        id=candidate_id,
        title=title,
        score=score,
        hypothesis=hypothesis,
        target_segment=target_segment,
        action=action,
        success_metric=success_metric,
        measurement_window=measurement_window,
        stop_condition=stop_condition,
        reason=reason,
    )


def rank_experiments(
    metrics: dict[str, Any],
    *,
    gaps: list[str],
    pipeline_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    accounts = _safe_int(metrics.get("accounts"))
    activated = _safe_int(metrics.get("activated_accounts"))
    paid = _safe_int(metrics.get("paid_accounts"))
    activation_rate = _safe_float(metrics.get("adoption_rate"))
    stripe_paid = _safe_int(metrics.get("stripe_paid_sessions"))
    stack_accounts = _safe_int(metrics.get("stack_accounts"))
    due_count = _safe_int(pipeline_summary.get("due_count"))

    candidates: list[ExperimentCandidate] = []
    if any("database is missing" in gap for gap in gaps):
        candidates.append(
            _candidate(
                "growth_data_wiring",
                "Fix production growth data wiring",
                99,
                "A complete tenant and usage snapshot will make every later growth experiment measurable.",
                "Internal growth instrumentation",
                "Verify the daily job can read production tenant and usage stores, then rerun the growth decision report.",
                "Tomorrow's memo includes account, activation, proof, and paid-plan counts with no missing-store gap.",
                "1 day",
                "Stop once the memo has complete production inputs; do not change customer-facing behavior.",
                "Reliable measurement is the highest leverage blocker when canonical stores are absent.",
            )
        )

    if accounts == 0:
        candidates.append(
            _candidate(
                "acquisition_baseline",
                "Create one measurable acquisition path",
                88,
                "A single tracked acquisition path will show whether current distribution can produce first accounts.",
                "MCP/package visitors and agent developers",
                "Pick the strongest listed channel and add one manual, tracked CTA path into signup or pilot checkout.",
                "At least one new attributed account appears in the next daily snapshot.",
                "3 days",
                "Stop if the path creates no attributed account after three daily snapshots.",
                "No accounts are recorded yet, so acquisition needs the first measurable signal.",
            )
        )

    if accounts > 0 and activation_rate < 0.35:
        candidates.append(
            _candidate(
                "activation_first_proof",
                "Move new accounts to first proof",
                92,
                "Reducing time-to-first-proof will create more qualified users for paid conversion.",
                "Signed-up accounts without a completed proof",
                "Review the signup/account path and recommend one friction reduction or lifecycle nudge toward the first successful proof.",
                "Activation rate rises by at least 10 percentage points or two more accounts complete a proof.",
                "7 days",
                "Stop if proof failures or support replies show the blocker is technical rather than messaging.",
                "Activation is below the 35% threshold and paid conversion depends on proof success.",
            )
        )

    if activated > 0 and paid + stripe_paid == 0:
        paid_conversion_score = 95 if activation_rate >= 0.35 else 82
        candidates.append(
            _candidate(
                "pilot_paid_conversion",
                "Convert activated users to Production Pilot",
                paid_conversion_score,
                "Activated users have seen the product value and are the highest intent path to first revenue.",
                "Activated free tenants and top proof-producing sources",
                "Recommend one Production Pilot conversion touch: pricing CTA, checkout follow-up, or targeted outbound from the top activated source.",
                "At least one paid checkout session, paid tenant, or signed pilot opportunity is recorded.",
                "7 days",
                "Stop if activated users decline because the production proof workflow is not yet credible.",
                "Paid customers are the north-star metric and there are activated non-paying users to convert.",
            )
        )

    if activated > 0 and paid + stripe_paid > 0:
        candidates.append(
            _candidate(
                "paid_expansion",
                "Expand the proven paid path",
                86,
                "The channel that already generated paid evidence is the safest place to compound revenue.",
                "Top paid source and similar accounts",
                "Recommend one narrowly scoped expansion of the paid source: follow-up, case-study CTA, or package listing update.",
                "Paid accounts, MRR estimate, or paid proofs increase in a daily snapshot.",
                "7 days",
                "Stop if the source stops producing paid proof usage for seven days.",
                "Existing paid evidence should be reinforced before adding broader acquisition work.",
            )
        )

    if stack_accounts == 0 and accounts > 0:
        candidates.append(
            _candidate(
                "stack_adoption_attribution",
                "Improve MCP/package stack adoption",
                74,
                "More explicit MCP, SDK, and CLI adoption paths will improve attribution and integration intent.",
                "Developers arriving from package registries, MCP directories, and CLI docs",
                "Recommend one stack-specific CTA or directory follow-up that lands users directly in signup or first proof.",
                "At least one account is attributed to an MCP, SDK, CLI, or package source.",
                "7 days",
                "Stop if attribution stays unknown and fix source tagging before more channel work.",
                "Accounts exist, but no stack-adoption source is visible in the canonical summary.",
            )
        )

    if due_count > 0:
        candidates.append(
            _candidate(
                "pipeline_followup",
                "Clear one due GTM follow-up",
                68 + min(due_count, 10),
                "A due marketplace, outbound, or revenue task may be blocking qualified pipeline.",
                "Due GTM pipeline tasks",
                "Recommend the single due follow-up most likely to create a pilot start or accepted distribution listing.",
                "One due task moves to submitted, live_monitoring, won, or a dated next action.",
                "1 day",
                "Stop if the task requires private contact data or external credentials not available to the operator.",
                f"{due_count} GTM pipeline task(s) are due for action.",
            )
        )

    if not candidates:
        candidates.append(
            _candidate(
                "revenue_quality_review",
                "Review the highest quality revenue signal",
                60,
                "A daily review of the strongest source will keep the experiment loop tied to revenue quality.",
                "Highest paid or activated source",
                "Recommend one small improvement to the source with the best paid, activation, or proof signal.",
                "The selected source improves paid accounts, activated accounts, or paid proofs.",
                "7 days",
                "Stop if the selected source has no measurable movement after seven days.",
                "No severe bottleneck was detected, so optimize the strongest observed source.",
            )
        )

    return [
        sanitize_obj(candidate.__dict__)
        for candidate in sorted(candidates, key=lambda item: (item.score, item.id), reverse=True)
    ]


def working_well(monitor_payload: dict[str, Any], metrics: dict[str, Any]) -> list[str]:
    items: list[str] = []
    summary = monitor_payload.get("summary", {}) or {}
    passed = _safe_int(summary.get("passed"))
    if passed:
        items.append(f"GTM surface health has {passed} passing check(s).")
    if _safe_int(metrics.get("activated_accounts")):
        items.append(
            f"{metrics['activated_accounts']} account(s) have completed proofs; adoption rate is {metrics['adoption_rate'] * 100:.1f}%."
        )
    if _safe_int(metrics.get("active_30d_accounts")) or _safe_int(metrics.get("monthly_proofs")):
        items.append(
            f"30-day usage shows {metrics['active_30d_accounts']} active account(s) and {metrics['monthly_proofs']} proof(s)."
        )
    if _safe_int(metrics.get("paid_accounts")) or _safe_int(metrics.get("stripe_paid_sessions")):
        items.append(
            f"Revenue evidence exists: {metrics['paid_accounts']} paid tenant(s), {metrics['stripe_paid_sessions']} paid checkout session(s)."
        )

    sources = ((monitor_payload.get("revenue", {}) or {}).get("top_sources", []) or [])[:3]
    if sources:
        best = max(
            (source for source in sources if isinstance(source, dict)),
            key=lambda source: (
                _safe_int(source.get("paid_accounts")),
                _safe_int(source.get("activated_accounts")),
                _safe_int(source.get("total_proofs")),
                _safe_int(source.get("accounts")),
            ),
            default=None,
        )
        if best:
            items.append(
                "Best visible source: "
                f"{best.get('source', 'unknown')} / {best.get('medium', '-')} / {best.get('platform', '-')} "
                f"with {best.get('accounts', 0)} account(s), {best.get('activated_accounts', 0)} activated, "
                f"and {best.get('paid_accounts', 0)} paid."
            )

    return items or ["Baseline monitoring is in place, but no adoption or revenue signal is visible yet."]


def main_bottleneck(metrics: dict[str, Any], gaps: list[str]) -> str:
    if any("database is missing" in gap for gap in gaps):
        return "Measurement: canonical production tenant or usage stores are unavailable to the daily decision job."
    if _safe_int(metrics.get("accounts")) == 0:
        return "Acquisition: no accounts are recorded yet."
    if _safe_int(metrics.get("activated_accounts")) == 0:
        return "Activation: accounts exist, but none have completed a proof."
    if _safe_float(metrics.get("adoption_rate")) < 0.35:
        return "Activation: fewer than 35% of accounts have completed a proof."
    if _safe_int(metrics.get("paid_accounts")) + _safe_int(metrics.get("stripe_paid_sessions")) == 0:
        return "Paid conversion: activated users exist, but no paid customer evidence is recorded."
    if _safe_int(metrics.get("stack_accounts")) == 0:
        return "Stack adoption attribution: account sources do not show MCP, SDK, CLI, or package adoption yet."
    return "Revenue expansion: paid evidence exists, so the next bottleneck is compounding the best source."


def build_daily_snapshot(
    monitor_payload: dict[str, Any],
    *,
    pipeline_state: dict[str, Any] | None = None,
    prior_snapshots: list[dict[str, Any]] | None = None,
    snapshot_date: date | None = None,
    generated_at_ms: int | None = None,
) -> dict[str, Any]:
    snapshot_date = snapshot_date or _today_utc()
    generated_at_ms = generated_at_ms if generated_at_ms is not None else _now_ms()
    prior_snapshots = prior_snapshots or []
    previous = _latest_snapshot(prior_snapshots)
    previous_metrics = previous.get("metrics", {}) if previous else None
    metrics = extract_metrics(monitor_payload, previous_metrics=previous_metrics)
    seven_day = _seven_day_baseline(prior_snapshots, snapshot_date)
    pipeline_summary = summarize_pipeline(pipeline_state, snapshot_date)
    gaps = data_gaps(monitor_payload, pipeline_summary)
    candidates = rank_experiments(metrics, gaps=gaps, pipeline_summary=pipeline_summary)

    previous_evaluation = evaluate_previous_experiment(prior_snapshots, metrics, gaps, pipeline_summary)
    implementation = implementation_plan_for(candidates[0], gaps)

    snapshot = {
        "schema_version": 1,
        "date": snapshot_date.isoformat(),
        "generated_at_ms": generated_at_ms,
        "north_star": "paid_customers",
        "authority": "implement_safe_experiment_or_report_blocker",
        "metrics": metrics,
        "deltas": {
            "day": _metric_delta(metrics, previous),
            "seven_day": _metric_delta(metrics, seven_day),
        },
        "monitor_summary": sanitize_obj(monitor_payload.get("summary", {}) or {}),
        "sources": sanitize_obj(((monitor_payload.get("revenue", {}) or {}).get("top_sources", []) or [])[:10]),
        "stripe_checkout": sanitize_obj(monitor_payload.get("stripe_checkout")),
        "pipeline": sanitize_obj(pipeline_summary),
        "working_well": working_well(monitor_payload, metrics),
        "main_bottleneck": main_bottleneck(metrics, gaps),
        "data_gaps": gaps,
        "previous_experiment_evaluation": previous_evaluation,
        "experiment_candidates": candidates,
        "selected_experiment": candidates[0],
        "implementation": implementation,
    }
    return sanitize_obj(snapshot)


def write_snapshot(snapshot_dir: Path, snapshot: dict[str, Any]) -> Path:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    path = snapshot_dir / f"{snapshot['date']}.json"
    path.write_text(json.dumps(sanitize_obj(snapshot), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def render_markdown(snapshot: dict[str, Any]) -> str:
    metrics = snapshot["metrics"]
    day = snapshot["deltas"]["day"]
    seven_day = snapshot["deltas"]["seven_day"]
    selected = snapshot["selected_experiment"]
    previous = snapshot.get("previous_experiment_evaluation", {}) or {}
    implementation = snapshot.get("implementation", {}) or {}
    candidates = snapshot.get("experiment_candidates", [])
    rejected = [candidate for candidate in candidates if candidate.get("id") != selected.get("id")][:3]
    pipeline = snapshot.get("pipeline", {}) or {}

    rows = [
        f"# TinyZKP Daily Growth Decision - {snapshot['date']}",
        "",
        "## Scorecard",
        f"- Accounts: {metrics['accounts']} (day {_delta_fmt(day['accounts'])}, 7d {_delta_fmt(seven_day['accounts'])})",
        f"- New accounts: {metrics['new_accounts']}",
        f"- Activated accounts: {metrics['activated_accounts']} ({metrics['adoption_rate'] * 100:.1f}%)",
        f"- 30d active accounts: {metrics['active_30d_accounts']}; 30d proofs: {metrics['monthly_proofs']}",
        f"- Paid customers: {metrics['paid_accounts']} ({metrics['paid_rate'] * 100:.1f}%); paid proofs: {metrics['paid_proofs']}",
        f"- Estimated base MRR: ${metrics['estimated_base_mrr']}; usage revenue: {_money(metrics['estimated_usage_revenue_cents'])}",
        f"- Stripe paid sessions: {metrics['stripe_paid_sessions']}; Stripe paid revenue: {_money(metrics['stripe_paid_revenue_cents'])}",
        f"- Stack adoption proxy: {metrics['stack_accounts']} account(s), {metrics['stack_activated_accounts']} activated, {metrics['stack_paid_accounts']} paid",
        "",
        "## What Is Working",
    ]
    rows.extend(f"- {item}" for item in snapshot.get("working_well", []))
    rows.extend(
        [
            "",
        "## Main Bottleneck",
        f"- {snapshot['main_bottleneck']}",
        "",
        "## Previous Experiment",
        f"- Status: {previous.get('status', 'unknown')}",
        f"- Experiment: {previous.get('title') or previous.get('experiment_id') or '-'}",
        f"- Evidence: {previous.get('evidence', '-')}",
        "",
        "## Today's Experiment",
        f"- Title: {selected['title']}",
            f"- Hypothesis: {selected['hypothesis']}",
            f"- Target segment: {selected['target_segment']}",
            f"- Action: {selected['action']}",
            f"- Success metric: {selected['success_metric']}",
            f"- Measurement window: {selected['measurement_window']}",
            f"- Stop condition: {selected['stop_condition']}",
            f"- Why this one: {selected['reason']}",
            f"- Implementation status: {implementation.get('status', 'unknown')}",
            f"- Automation policy: {implementation.get('automation_policy', 'unknown')}",
            f"- Implementation action: {implementation.get('action', '-')}",
            f"- Verification: {implementation.get('verification', '-')}",
        ]
    )
    if rejected:
        rows.append("")
        rows.append("## Other Candidates Considered")
        rows.extend(
            f"- {candidate['title']} (score {candidate['score']}): {candidate['reason']}"
            for candidate in rejected
        )
    rows.extend(
        [
            "",
            "## Pipeline And Data Gaps",
            f"- Due GTM pipeline tasks: {pipeline.get('due_count', 0)}",
            f"- Pipeline actual revenue evidence: {_money(_safe_int(pipeline.get('actual_revenue_cents')))}",
        ]
    )
    gaps = snapshot.get("data_gaps", [])
    if gaps:
        rows.extend(f"- {gap}" for gap in gaps)
    else:
        rows.append("- No critical data gaps detected.")
    return redact_text("\n".join(rows) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-monitor-json", type=Path, help="Read a gtm_growth_monitor --json payload from disk")
    parser.add_argument("--tenant-db", default="/opt/hc-stark/data/tenant_store.sqlite", help="Path to tenant_store.sqlite")
    parser.add_argument("--usage-db", default="/opt/hc-stark/data/usage.sqlite", help="Path to usage.sqlite")
    parser.add_argument("--snapshot-dir", type=Path, default=DEFAULT_SNAPSHOT_DIR, help="Directory for daily JSON snapshots")
    parser.add_argument("--pipeline-state", type=Path, default=DEFAULT_PIPELINE_STATE, help="No-PII GTM pipeline state JSON")
    parser.add_argument("--date", help="Snapshot date in YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--no-write-snapshot", action="store_true", help="Generate the memo without writing the snapshot JSON")
    parser.add_argument("--json", action="store_true", help="Emit the snapshot and memo as JSON")
    parser.add_argument("--live", action="store_true", help="Include live public funnel checks in the underlying monitor")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout for live checks")
    parser.add_argument("--stripe-checkout", action="store_true", help="Include live Stripe Checkout summary via the underlying monitor")
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument("--stripe-checkout-test-mode", action="store_true", help="Use Stripe test mode for checkout summary")
    parser.add_argument("--stripe-checkout-limit", type=int, default=100, help="Checkout sessions per Stripe page")
    parser.add_argument("--stripe-checkout-max-pages", type=int, default=3, help="Maximum Stripe pages to read")
    parser.add_argument("--stripe-checkout-lookback-hours", type=float, default=168, help="Trailing checkout window")
    parser.add_argument(
        "--stripe-expected-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", "TinyZKP"),
        help="Required substring in the active Stripe CLI display_name",
    )
    parser.add_argument("--stripe-skip-account-check", action="store_true", help="Skip Stripe account-context validation")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    snapshot_date = _parse_date(args.date)
    monitor_payload = _load_monitor_payload(args)
    try:
        pipeline_state = load_json(args.pipeline_state)
    except (OSError, json.JSONDecodeError):
        pipeline_state = None
    prior_snapshots = load_prior_snapshots(args.snapshot_dir, snapshot_date)
    snapshot = build_daily_snapshot(
        monitor_payload,
        pipeline_state=pipeline_state,
        prior_snapshots=prior_snapshots,
        snapshot_date=snapshot_date,
    )
    snapshot_path = None
    if not args.no_write_snapshot:
        snapshot_path = write_snapshot(args.snapshot_dir, snapshot)
    memo = render_markdown(snapshot)
    if args.json:
        payload = {"snapshot": snapshot, "memo": memo, "snapshot_path": str(snapshot_path) if snapshot_path else None}
        print(json.dumps(sanitize_obj(payload), indent=2, sort_keys=True))
    else:
        print(memo, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
