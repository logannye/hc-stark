#!/usr/bin/env python3
"""Sync outbound research packet progress into the no-PII GTM pipeline state."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKETS = ROOT / "marketing" / "generated" / "outbound_research_packets.json"
DEFAULT_STATE = ROOT / "marketing" / "gtm_pipeline_state.json"


def today_iso() -> str:
    return date.today().isoformat()


def next_business_day(start: date) -> date:
    candidate = start + timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)
    return candidate


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def packet_note(packet: dict[str, Any]) -> str:
    links = packet.get("public_company_links") if isinstance(packet.get("public_company_links"), dict) else {}
    homepage = packet.get("homepage") if isinstance(packet.get("homepage"), dict) else {}
    counts = {
        "contact": len(links.get("contact") or []),
        "about": len(links.get("about") or []),
        "product": len(links.get("product") or []),
    }
    return (
        "Company-level outbound research packet generated in "
        "marketing/generated/outbound_research_packets.md; "
        f"homepage_status={homepage.get('status') or 'unknown'}, "
        f"company_research_status={packet.get('company_research_status') or 'unknown'}, "
        f"public_link_counts=contact:{counts['contact']},about:{counts['about']},product:{counts['product']}. "
        "No personal emails, phone numbers, private CRM notes, or mailto links are stored; manually identify exactly one founder or engineering owner before sending."
    )


def sync_state(state: dict[str, Any], packets_payload: dict[str, Any], *, action_date: str) -> tuple[dict[str, Any], int]:
    tasks = state.get("tasks")
    if not isinstance(tasks, dict):
        raise ValueError("pipeline state tasks must be an object")
    next_action_at = next_business_day(date.fromisoformat(action_date)).isoformat()
    updated = 0
    for packet in packets_payload.get("packets") or []:
        target_id = str(packet.get("target_id") or "")
        if not target_id.startswith("yc_"):
            continue
        slug = target_id.removeprefix("yc_")
        task_prefix = f"outbound_send."
        matching_ids = [
            task_id
            for task_id in tasks
            if task_id.startswith(task_prefix) and task_id.endswith(f".{slug}")
        ]
        for task_id in matching_ids:
            entry = tasks[task_id]
            if not isinstance(entry, dict):
                continue
            if entry.get("stage") == "needs_contact_research":
                entry["stage"] = "company_research_ready"
            entry["last_action_at"] = action_date
            entry["next_action_at"] = next_action_at
            entry["notes"] = packet_note(packet)
            updated += 1
    state["updated_at"] = action_date
    return state, updated


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=Path, default=DEFAULT_PACKETS)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--date", default=today_iso())
    parser.add_argument("--check", action="store_true", help="Validate that state already reflects all packets")
    args = parser.parse_args(argv)

    try:
        packets = load_json(args.packets)
        state = load_json(args.state)
        # Date-tolerant --check: reproduce the committed state's own action date
        # so freshness ignores wall-clock drift (the check may run on CI's UTC
        # day, not the day the state was last synced) while still catching real
        # content drift (stage transitions, notes, task set). Write mode keeps
        # stamping the actual action date (default today).
        action_date = str(state.get("updated_at") or args.date) if args.check else args.date
        synced, updated = sync_state(state, packets, action_date=action_date)
    except Exception as exc:
        print(f"FAIL outbound research pipeline sync - {exc}", file=sys.stderr)
        return 1

    if args.check:
        current = load_json(args.state)
        expected = json.dumps(synced, indent=2, sort_keys=True)
        actual = json.dumps(current, indent=2, sort_keys=True)
        if expected != actual:
            print("FAIL outbound research pipeline sync - state is stale", file=sys.stderr)
            return 1
        print(f"PASS outbound research pipeline state is current for {updated} task(s)")
        return 0

    args.state.write_text(json.dumps(synced, indent=2) + "\n", encoding="utf-8")
    print(f"Synced outbound research packets into GTM pipeline state: updated={updated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
