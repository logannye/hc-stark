#!/usr/bin/env python3
"""Render the GTM execution ledger from checked-in distribution artifacts.

The ledger does not submit forms, send email, or scrape contacts. It turns the
remaining account/manual GTM work into a source-tagged task queue with evidence
fields so operators can execute the launch without losing attribution or
marking revenue work complete without proof.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MCP_TARGETS = ROOT / "marketing" / "mcp_distribution_targets.json"
DEFAULT_OUTBOUND_QUEUE = ROOT / "marketing" / "generated" / "outbound_send_queue.json"
DEFAULT_OPENAI_SUBMISSION = ROOT / "marketing" / "openai_chatgpt_app_submission.json"
DEFAULT_JSON = ROOT / "marketing" / "generated" / "gtm_execution_ledger.json"
DEFAULT_CSV = ROOT / "marketing" / "generated" / "gtm_execution_ledger.csv"
DEFAULT_MD = ROOT / "marketing" / "generated" / "gtm_execution_ledger.md"

TASK_COLUMNS = [
    "task_id",
    "channel",
    "task_type",
    "status",
    "owner",
    "target",
    "due_date",
    "follow_up_date",
    "primary_cta",
    "secondary_cta",
    "submission_url",
    "source_artifact",
    "evidence_command",
    "evidence_url",
    "completed_at",
    "next_action",
    "blocker",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def source_date(mcp_targets: dict[str, Any], outbound_queue: dict[str, Any]) -> str:
    value = str(outbound_queue.get("source_generated_at") or "").split("T", 1)[0]
    return value or str(mcp_targets.get("generated_at") or "")


def revenue_task(generated_at: str) -> dict[str, str]:
    return {
        "task_id": "revenue.pilot_checkout_launch",
        "channel": "revenue",
        "task_type": "live_checkout_verification",
        "status": "completed",
        "owner": "founder",
        "target": "$5K Production Pilot checkout",
        "due_date": generated_at,
        "follow_up_date": "",
        "primary_cta": "https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout",
        "secondary_cta": "https://tinyzkp.com/contact?category=Paid%20Pilot&source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_contact",
        "submission_url": "",
        "source_artifact": "site/functions/api/create-pilot-checkout.js",
        "evidence_command": "python3 scripts/ci/production_launch_preflight.py --live",
        "evidence_url": "https://tinyzkp.com/api/create-pilot-checkout",
        "completed_at": generated_at,
        "next_action": "Monitor pilot checkout starts, completed payments, and paid-pilot contact fallbacks; record revenue only after Stripe or invoice evidence exists.",
        "blocker": "None; live route uses inline price_data when STRIPE_PRICE_ID_PILOT is absent.",
    }


def stripe_catalog_task(generated_at: str) -> dict[str, str]:
    return {
        "task_id": "revenue.stripe_catalog_hygiene",
        "channel": "revenue",
        "task_type": "stripe_catalog_audit",
        "status": "external_secret_required",
        "owner": "founder",
        "target": "Current Stripe product and price catalog",
        "due_date": generated_at,
        "follow_up_date": "",
        "primary_cta": "https://tinyzkp.com/pricing?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_signup",
        "secondary_cta": "https://tinyzkp.com/pilot?source=gtm_execution_ledger&medium=ops&platform=direct&intent=paid_pilot_checkout",
        "submission_url": "",
        "source_artifact": "billing/setup_stripe_products.sh",
        "evidence_command": "python3 billing/stripe_revenue_ops_audit.py --stripe-bin /opt/homebrew/bin/stripe --strict-catalog",
        "evidence_url": "",
        "completed_at": "",
        "next_action": "Switch the local Stripe CLI to the LN Holdings account used for TinyZKP, confirm billing/stripe_account_context_check.py passes, then run bash billing/setup_stripe_products.sh --stripe-cli --stripe-bin /opt/homebrew/bin/stripe --push-cloudflare with write-capable live access and rerun the strict revenue-ops audit.",
        "blocker": "Requires the LN Holdings Stripe account used for TinyZKP plus write-capable live API key or CLI profile; the current local CLI profile reports display_name='Galen Health' and is not authoritative for TinyZKP catalog or revenue evidence.",
    }


def mcp_status(target: dict[str, Any]) -> str:
    if target.get("status") == "active":
        return "active_listing_monitor"
    if target.get("status") == "submitted":
        return "submitted"
    if target.get("status") == "submission_ready":
        return "ready_for_manual_submission"
    return "manual_submission_required"


def mcp_task(target: dict[str, Any]) -> dict[str, str]:
    target_id = str(target["id"])
    status = mcp_status(target)
    listing_url = str(target.get("listing_url") or "")
    return {
        "task_id": f"mcp_submission.{target_id}",
        "channel": "mcp_distribution",
        "task_type": "directory_submission",
        "status": status,
        "owner": "founder",
        "target": str(target["name"]),
        "due_date": "",
        "follow_up_date": "",
        "primary_cta": str(target["signup_url"]),
        "secondary_cta": "https://tinyzkp.com/mcp?source=gtm_execution_ledger&medium=ops&platform=direct&intent=mcp_install",
        "submission_url": str(target["submission_url"]),
        "source_artifact": f"marketing/generated/mcp_submissions/{target_id}.md",
        "evidence_command": "python3 scripts/monitoring/gtm_distribution_monitor.py --offline",
        "evidence_url": listing_url,
        "completed_at": str(target.get("completed_at") or ""),
        "next_action": (
            "Monitor accepted listing for current copy and source-tagged CTA."
            if status == "active_listing_monitor"
            else f"Follow up on {target['name']} review, then update the public listing URL when accepted."
            if status == "submitted"
            else f"Submit marketing/generated/mcp_submissions/{target_id}.md through the target account or PR flow."
        ),
        "blocker": (
            ""
            if status == "active_listing_monitor"
            else "Awaiting directory review or merge."
            if status == "submitted"
            else "Requires account access or a manual PR/submission flow."
        ),
    }


def openai_task(submission: dict[str, Any], generated_at: str) -> dict[str, str]:
    return {
        "task_id": "agent_app.openai_chatgpt_app_submission",
        "channel": "agent_app_distribution",
        "task_type": "app_review_submission",
        "status": "ready_for_manual_submission",
        "owner": "founder",
        "target": "OpenAI ChatGPT app review",
        "due_date": generated_at,
        "follow_up_date": "",
        "primary_cta": str(submission["signup_url"]),
        "secondary_cta": str(submission["agent_offer_url"]),
        "submission_url": "https://platform.openai.com",
        "source_artifact": "marketing/openai_chatgpt_app_submission.json",
        "evidence_command": "python3 scripts/ci/openai_chatgpt_app_check.py",
        "evidence_url": "",
        "completed_at": "",
        "next_action": "Submit the ChatGPT app prototype with widget URL, MCP endpoint, screenshots, and review prompts.",
        "blocker": "Requires OpenAI Platform Dashboard account access and reviewer submission.",
    }


def outbound_task(row: dict[str, Any]) -> dict[str, str]:
    rank = int(row["rank"])
    target_id = str(row["target_id"]).removeprefix("yc_")
    return {
        "task_id": f"outbound_send.{rank:02d}.{target_id}",
        "channel": "founder_outbound",
        "task_type": "manual_email",
        "status": "ready_after_manual_contact_research",
        "owner": "founder",
        "target": str(row["company"]),
        "due_date": str(row["send_date"]),
        "follow_up_date": str(row["follow_up_date"]),
        "primary_cta": str(row["primary_cta"]),
        "secondary_cta": str(row["secondary_cta"]),
        "submission_url": "",
        "source_artifact": "marketing/generated/outbound_send_queue.md",
        "evidence_command": "python3 scripts/ci/outbound_send_queue_check.py",
        "evidence_url": "",
        "completed_at": "",
        "next_action": f"Research exactly one {row['contact_role']} and send one human email from the generated draft.",
        "blocker": "Requires manual contact research; contact name and email are intentionally blank before the founder selects a recipient.",
        "contact_role": str(row["contact_role"]),
        "contact_name": str(row.get("contact_name") or ""),
        "contact_email": str(row.get("contact_email") or ""),
        "reply_type": str(row.get("reply_type") or ""),
        "outcome": str(row.get("outcome") or ""),
    }


def render_ledger(
    *,
    mcp_targets: dict[str, Any],
    outbound_queue: dict[str, Any],
    openai_submission: dict[str, Any],
) -> dict[str, Any]:
    generated_at = source_date(mcp_targets, outbound_queue)
    tasks: list[dict[str, str]] = [revenue_task(generated_at), stripe_catalog_task(generated_at)]
    tasks.extend(mcp_task(target) for target in mcp_targets.get("targets", []))
    tasks.append(openai_task(openai_submission, generated_at))
    tasks.extend(outbound_task(row) for row in outbound_queue.get("queue", []))

    manual_statuses = {
        "external_secret_required",
        "ready_for_live_verification",
        "manual_submission_required",
        "ready_for_manual_submission",
        "ready_after_manual_contact_research",
    }
    return {
        "generated_at": generated_at,
        "generated_from": [
            "marketing/mcp_distribution_targets.json",
            "marketing/generated/outbound_send_queue.json",
            "marketing/openai_chatgpt_app_submission.json",
        ],
        "manual_rules": [
            "Do not mark a task complete until completed_at and evidence_url are filled.",
            "Do not automate cold outbound email sends.",
            "Do not add personal email addresses to generated artifacts.",
            "Preserve every source-tagged TinyZKP CTA URL when submitting or sending.",
            "Record accepted listing URLs, sent dates, replies, and paid-pilot outcomes back into this ledger or the source system after manual action.",
        ],
        "summary": {
            "total_tasks": len(tasks),
            "manual_required": sum(1 for task in tasks if task["status"] in manual_statuses),
            "active_monitors": sum(1 for task in tasks if task["status"] == "active_listing_monitor"),
            "outbound_manual_sends": sum(1 for task in tasks if task["channel"] == "founder_outbound"),
        },
        "tasks": tasks,
    }


def render_csv(payload: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TASK_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for task in payload["tasks"]:
        writer.writerow(task)
    return buffer.getvalue()


def render_markdown(payload: dict[str, Any]) -> str:
    tasks = payload["tasks"]
    lines = [
        "# TinyZKP GTM Execution Ledger",
        "",
        f"Generated from checked-in GTM artifacts dated `{payload['generated_at']}`.",
        "",
        "This ledger is the operator queue for revenue-critical work that still requires account access, manual review, or founder contact research. It deliberately does not contain personal email addresses and does not send messages.",
        "",
        "## Manual Rules",
        "",
    ]
    lines.extend(f"- {rule}" for rule in payload["manual_rules"])
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total tasks: {payload['summary']['total_tasks']}",
            f"- Manual/account-required tasks: {payload['summary']['manual_required']}",
            f"- Active listing monitors: {payload['summary']['active_monitors']}",
            f"- Founder outbound sends queued: {payload['summary']['outbound_manual_sends']}",
            "",
            "## Revenue Binding",
            "",
        ]
    )
    revenue = [task for task in tasks if task["channel"] == "revenue"]
    lines.extend(task_card(task) for task in revenue)
    lines.extend(["", "## MCP Directory Submissions", ""])
    lines.extend(task_card(task) for task in tasks if task["channel"] == "mcp_distribution")
    lines.extend(["", "## Agent App Submission", ""])
    lines.extend(task_card(task) for task in tasks if task["channel"] == "agent_app_distribution")
    lines.extend(["", "## Founder Outbound Sends", ""])
    lines.extend(task_card(task) for task in tasks if task["channel"] == "founder_outbound")
    return "\n".join(lines).rstrip() + "\n"


def task_card(task: dict[str, str]) -> str:
    details = [
        f"### {task['task_id']} — {task['target']}",
        "",
        f"- Status: `{task['status']}`",
        f"- Owner: {task['owner']}",
        f"- Type: `{task['task_type']}`",
    ]
    if task.get("due_date"):
        details.append(f"- Due date: {task['due_date']}")
    if task.get("follow_up_date"):
        details.append(f"- Follow-up date: {task['follow_up_date']}")
    details.extend(
        [
            f"- Primary CTA: {task['primary_cta']}",
            f"- Secondary CTA: {task['secondary_cta']}",
        ]
    )
    if task.get("submission_url"):
        details.append(f"- Submission URL: {task['submission_url']}")
    details.extend(
        [
            f"- Source artifact: `{task['source_artifact']}`",
            f"- Evidence command: `{task['evidence_command']}`",
        ]
    )
    if task.get("evidence_url"):
        details.append(f"- Evidence URL: {task['evidence_url']}")
    details.append(f"- Next action: {task['next_action']}")
    if task.get("blocker"):
        details.append(f"- Blocker: {task['blocker']}")
    return "\n".join(details)


def expected_outputs(payload: dict[str, Any]) -> dict[Path, str]:
    return {
        Path("json"): json.dumps(payload, indent=2) + "\n",
        Path("csv"): render_csv(payload),
        Path("md"): render_markdown(payload),
    }


def check_outputs(expected: dict[Path, str], paths: dict[Path, Path]) -> list[str]:
    failures: list[str] = []
    for key, path in paths.items():
        if not path.is_file():
            failures.append(f"missing generated GTM execution ledger file: {path}")
            continue
        if path.read_text(encoding="utf-8") != expected[key]:
            failures.append(f"stale generated GTM execution ledger file: {path}")
    return failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-targets", type=Path, default=DEFAULT_MCP_TARGETS)
    parser.add_argument("--outbound-queue", type=Path, default=DEFAULT_OUTBOUND_QUEUE)
    parser.add_argument("--openai-submission", type=Path, default=DEFAULT_OPENAI_SUBMISSION)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--csv-output", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--md-output", type=Path, default=DEFAULT_MD)
    parser.add_argument("--check", action="store_true", help="Fail if generated ledger files are stale")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    payload = render_ledger(
        mcp_targets=load_json(args.mcp_targets),
        outbound_queue=load_json(args.outbound_queue),
        openai_submission=load_json(args.openai_submission),
    )
    expected = expected_outputs(payload)
    paths = {
        Path("json"): args.json_output,
        Path("csv"): args.csv_output,
        Path("md"): args.md_output,
    }

    if args.check:
        failures = check_outputs(expected, paths)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        if failures:
            print(f"\n{len(failures)} GTM execution ledger file(s) are stale.", file=sys.stderr)
            return 1
        print("PASS GTM execution ledger is current")
        return 0

    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    for key, content in expected.items():
        paths[key].write_text(content, encoding="utf-8")
    print(f"Wrote GTM execution ledger with {len(payload['tasks'])} task(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
