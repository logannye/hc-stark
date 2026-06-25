#!/usr/bin/env python3
"""Validate manual GTM launch assets before community/outbound distribution."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

ASSETS = {
    Path("marketing/HN_LAUNCH.md"): [
        "source=hn_launch",
        "platform=hacker_news",
        "prove_template",
        "verify_proof",
    ],
    Path("marketing/X_THREAD.md"): [
        "source=x_launch_thread",
        "platform=x",
    ],
    Path("marketing/OUTBOUND_EMAIL.md"): [
        "source=founder_outbound",
        "medium=email",
        "intent=calculator",
    ],
    Path("marketing/INTEGRATION_CURSOR.md"): [
        "source=cursor_community_post",
        "prove_template",
        "poll_job",
        "verify_proof",
    ],
    Path("marketing/INTEGRATION_LANGCHAIN.md"): [
        "source=langchain_integration_post",
        "accumulator_step",
        "verified={result.ok}",
    ],
}

FORBIDDEN_MARKERS = [
    "prove_status",
    "submit_workload",
    "workload_status",
    "list_jobs",
    "list_programs",
    "describe_program",
    "zero-knowledge proofs as a native tool call",
    "100 proofs/month free forever",
    "10K free verify calls/month",
]

BARE_CONVERSION_URL_RE = re.compile(
    r"https://tinyzkp\.com/(?:signup|try|docs|contact|calculator)(?!\?)"
)


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def validate(root: Path = ROOT) -> list[Check]:
    checks: list[Check] = []
    for rel_path, required_markers in ASSETS.items():
        path = root / rel_path
        if not path.exists():
            checks.append(Check("FAIL", str(rel_path), "missing file"))
            continue
        text = path.read_text(encoding="utf-8")
        missing = [marker for marker in required_markers if marker not in text]
        forbidden = [marker for marker in FORBIDDEN_MARKERS if marker in text]
        bare_urls = sorted(set(BARE_CONVERSION_URL_RE.findall(text)))
        if missing or forbidden or bare_urls:
            details: list[str] = []
            if missing:
                details.append("missing markers: " + ", ".join(missing))
            if forbidden:
                details.append("forbidden stale markers: " + ", ".join(forbidden))
            if bare_urls:
                details.append("untagged conversion URLs: " + ", ".join(bare_urls))
            checks.append(Check("FAIL", str(rel_path), "; ".join(details)))
        else:
            checks.append(Check("PASS", str(rel_path), "manual distribution asset is source-tagged and current"))
    return checks


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    checks = validate(root)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} manual distribution asset check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll manual distribution asset checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
