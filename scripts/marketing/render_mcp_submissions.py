#!/usr/bin/env python3
"""Render MCP directory submission drafts from the GTM target catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGETS = ROOT / "marketing" / "mcp_distribution_targets.json"
DEFAULT_OUT_DIR = ROOT / "marketing" / "generated" / "mcp_submissions"


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _target_file(target: dict) -> Path:
    return Path(f"{target['id']}.md")


def render_target(config: dict, target: dict) -> str:
    positioning = config["positioning"]
    listing_url = target.get("listing_url") or "Not published yet"
    required_markers = ", ".join(target.get("required_markers") or [])
    tags = "mcp, agents, proof-receipts, stark, verification, audit, developer-tools, security, api"

    return f"""# TinyZKP MCP Submission: {target['name']}

Status: `{target['status']}`
Kind: `{target['kind']}`
Submission URL: {target['submission_url']}
Current listing: {listing_url}

## Directory Fields

Name: TinyZKP

One-line description: {positioning['one_liner']}

Website / CTA: {target['signup_url']}

Hosted MCP endpoint: {positioning['hosted_endpoint']}

Install command:

```bash
{target['install_command']}
```

Tags: {tags}

## Short Description

TinyZKP gives agents and backend workflows a native MCP tool for minting
transparent STARK state-transition receipts. Agents can prove that a supported
workflow advanced from an initial state to a final state by declared steps, then
hand the receipt to another human, service, or agent for independent
verification without replaying the producer system.

## Boundaries

- {positioning['proof_boundary']}
- {positioning['data_boundary']}
- Free signup includes evaluation receipts and no credit card.
- Optional `Authorization: Bearer tzk_...` unlocks account-scoped limits.
- Verification is free and can be performed by humans, services, or agents.

## Source-Tagged Signup URL

{target['signup_url']}

## Submission Checklist

- Use the hosted endpoint exactly: `{positioning['hosted_endpoint']}`
- Include the install command exactly as written above.
- Include the source-tagged signup URL, not a generic homepage URL.
- Include the transparent-receipt warning from the Boundaries section.
- After publication, update `marketing/mcp_distribution_targets.json` with the
  live listing URL and set `status` to `active`.
- Run `python3 scripts/monitoring/gtm_distribution_monitor.py`.

## Required Listing Markers

{required_markers}
"""


def render_index(config: dict) -> str:
    rows = [
        "| Target | Status | Source | Submission Draft | Signup URL |",
        "|---|---|---|---|---|",
    ]
    for target in config["targets"]:
        file = _target_file(target)
        rows.append(
            f"| {target['name']} | `{target['status']}` | `{target['source']}` | "
            f"[{file.name}](./{file.name}) | {target['signup_url']} |"
        )

    return (
        "# TinyZKP MCP Submission Drafts\n\n"
        "Generated from `marketing/mcp_distribution_targets.json` by "
        "`scripts/marketing/render_mcp_submissions.py`.\n\n"
        "Do not hand-edit these drafts. Update the target catalog or renderer, then run:\n\n"
        "```bash\n"
        "python3 scripts/marketing/render_mcp_submissions.py\n"
        "```\n\n"
        + "\n".join(rows)
        + "\n"
    )


def render_all(config: dict) -> dict[Path, str]:
    outputs = {Path("index.md"): render_index(config)}
    for target in config["targets"]:
        outputs[_target_file(target)] = render_target(config, target)
    return outputs


def write_outputs(outputs: dict[Path, str], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for file, content in outputs.items():
        (out_dir / file).write_text(content, encoding="utf-8")


def check_outputs(outputs: dict[Path, str], out_dir: Path) -> list[str]:
    failures: list[str] = []
    for file, expected in outputs.items():
        path = out_dir / file
        if not path.exists():
            failures.append(f"missing generated submission: {path}")
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            failures.append(f"stale generated submission: {path}")
    expected_files = set(outputs)
    for path in sorted(out_dir.glob("*.md")):
        rel_path = path.relative_to(out_dir)
        if rel_path not in expected_files:
            failures.append(f"obsolete generated submission: {path}")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--check", action="store_true", help="Fail if generated drafts are stale")
    args = parser.parse_args(argv)

    config = load_config(args.targets)
    outputs = render_all(config)

    if args.check:
        failures = check_outputs(outputs, args.out_dir)
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        if failures:
            print(f"\n{len(failures)} MCP submission draft(s) are stale.", file=sys.stderr)
            return 1
        print("PASS MCP submission drafts are current")
        return 0

    write_outputs(outputs, args.out_dir)
    print(f"Wrote {len(outputs)} MCP submission draft(s) to {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
