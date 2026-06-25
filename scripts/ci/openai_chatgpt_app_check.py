#!/usr/bin/env python3
"""Validate TinyZKP ChatGPT app prototype and submission metadata."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SUBMISSION = ROOT / "marketing" / "openai_chatgpt_app_submission.json"
PROTOTYPE_DOC = ROOT / "marketing" / "OPENAI_CHATGPT_APP_PROTOTYPE.md"
WIDGET = ROOT / "site" / "apps" / "tinyzkp-receipt-widget.html"


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def _display(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _contains(path: Path, markers: list[str], name: str, root: Path) -> list[Check]:
    if not path.exists():
        return [Check("FAIL", name, f"{path} is missing")]
    text = path.read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in text]
    if missing:
        return [Check("FAIL", name, f"missing markers: {', '.join(missing)}")]
    return [Check("PASS", name, f"{_display(path, root)} contains required markers")]


def validate(root: Path = ROOT) -> list[Check]:
    submission = root / SUBMISSION.relative_to(ROOT)
    prototype_doc = root / PROTOTYPE_DOC.relative_to(ROOT)
    widget = root / WIDGET.relative_to(ROOT)
    checks: list[Check] = []

    checks.extend(
        _contains(
            prototype_doc,
            [
                "https://developers.openai.com/apps-sdk",
                "https://developers.openai.com/apps-sdk/build/mcp-server",
                "https://developers.openai.com/apps-sdk/deploy/submission",
                "source=openai_chatgpt_app",
                "human confirmation",
            ],
            "prototype doc",
            root,
        )
    )
    checks.extend(
        _contains(
            widget,
            [
                "tools/call",
                "ui/notifications/tool-result",
                "verify_proof",
                "prove_template",
                "source=openai_chatgpt_app",
                "Default receipts are transparent",
            ],
            "receipt widget",
            root,
        )
    )

    if not submission.exists():
        checks.append(Check("FAIL", "submission metadata", f"{submission} is missing"))
        return checks

    try:
        data = json.loads(submission.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        checks.append(Check("FAIL", "submission metadata", f"invalid JSON: {exc}"))
        return checks

    required_pairs = {
        "mcp_server_url": "https://mcp.tinyzkp.com",
        "streamable_http_endpoint": "https://mcp.tinyzkp.com/mcp",
        "widget_url": "https://tinyzkp.com/apps/tinyzkp-receipt-widget.html",
        "privacy_policy_url": "https://tinyzkp.com/privacy",
        "terms_url": "https://tinyzkp.com/terms",
        "human_confirmation_required": True,
    }
    missing_pairs = [
        f"{key}={value}"
        for key, value in required_pairs.items()
        if data.get(key) != value
    ]
    required_tools = {"list_templates", "describe_template", "prove_template", "poll_job", "get_proof_summary", "verify_proof"}
    tools = set(data.get("tools") or [])
    if not required_tools.issubset(tools):
        missing_pairs.append("tools include " + ", ".join(sorted(required_tools - tools)))
    if "source=openai_chatgpt_app" not in str(data.get("signup_url", "")):
        missing_pairs.append("source-tagged signup_url")
    if len(data.get("test_prompts") or []) < 5:
        missing_pairs.append("at least five test prompts")
    if len(data.get("official_docs_references") or []) < 5:
        missing_pairs.append("official docs references")

    if missing_pairs:
        checks.append(Check("FAIL", "submission metadata", "missing or incorrect: " + ", ".join(missing_pairs)))
    else:
        checks.append(Check("PASS", "submission metadata", "ChatGPT app metadata is review-ready"))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} OpenAI app check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll OpenAI app prototype checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
