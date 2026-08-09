#!/usr/bin/env python3
"""Fail when a runbook describes a system that no longer exists.

In a business whose target ops envelope is under two hours a month, a runbook
that confidently describes a deleted system costs more than a missing one: the
operator follows it, and loses an hour to `systemctl stop hc-stark` on a box
that was decommissioned. Prose alone cannot hold that line -- three runbooks
described the retired hosted stack as live operator procedure for months, and
one of them said so in its own status line.

So every file in `docs/runbooks/` must be explicitly classified here as either
HISTORICAL (retired system, carries the established retirement banner) or LIVE
(describes something that actually runs). An unclassified file fails: adding a
runbook is therefore a deliberate declaration of which one it is, and a system
that gets retired cannot quietly leave its runbook reading as procedure.

The banner wording is the convention already established by
`docs/runbooks/2026-06-04-stop-the-bleeding-deploy.md`, not a new invention.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOKS = "docs/runbooks"

# The exact sentence fragment the 2026-06-04 tombstone established. Matching a
# literal rather than a regex keeps the convention one string, so a reader
# grepping for it finds every retired runbook.
BANNER = "must not be executed"

# Runbooks for systems that were deleted. Each must carry the banner.
HISTORICAL = (
    "2026-06-04-stop-the-bleeding-deploy.md",
    "2026-06-23-reconciliation-deploy.md",
    "deploy_2026-04-28.md",
    "deploy_docker_compose.md",
    "expedited-revenue-launch.md",
    "guard_commerce_setup.md",
    "public-beta-launch.md",
    "restore.md",
)

# Runbooks describing something that actually runs, or a still-binding
# obligation. These must NOT read as procedure for the retired hosted stack.
LIVE = (
    "cloudflare_pages_release.md",
    "external_listing_retraction.md",
    "incident_response.md",
    "legacy_retirement_notice.md",
    "production_operations.md",
    "release_provenance.md",
    "retired_host_migration.md",
)

# Operator commands that only make sense against the deleted hosted stack. A
# LIVE runbook containing one of these is the exact defect this gate exists to
# catch: an executable instruction for a machine that is gone.
#
# These are COMMANDS, deliberately, not product names. A LIVE runbook may name
# a retired system in prose -- explaining what was retired is how a reader is
# kept from going looking for it -- so matching on e.g. "Lemon Squeezy" would
# punish exactly the honesty this gate is trying to enforce.
RETIRED_OPERATOR_MARKERS = (
    "docker compose up",
    "docker compose build",
    "systemctl start hc-stark",
    "systemctl stop hc-stark",
    "systemctl start hc-billing-webhook",
    "systemctl stop hc-billing-webhook",
)

# The current-production runbook is not merely required to exist: it is
# required to still name the load-bearing facts. Gutting it back to a
# description would pass a bare existence check while restoring the original
# defect -- nothing in docs/runbooks/ documenting what actually runs.
CURRENT_RUNBOOK = "production_operations.md"
CURRENT_RUNBOOK_MARKERS = (
    "ea4ad71c-6175-4a69-b106-02cc4af378ae",  # the real D1 database id
    "tinyzkp-estimator",
    "site/_worker.js",
    "/v1/estimate",
    "/v1/keys",
    "tinyzkp-uptime-probe",
    "ALERT_STATE",
    "deploy-site.yml",
    "deploy-uptime-probe.yml",
    "demand_report.py",
    "RETENTION_DAYS",
    "estimator_keys",
    # The four hard-won gotchas, each anchored on a phrase that cannot survive
    # the rule being deleted.
    "reject the deploy",
    "d1_databases",
    "skipping",
    "persist across",
)

# Incident-response text that has to keep naming the live paging path. It is
# the one LIVE runbook that is mostly historical, so it needs a positive
# requirement, not just the absence of retired commands.
LIVE_CROSS_REFERENCE = ("incident_response.md",)


def check(root: pathlib.Path) -> list[str]:
    failures: list[str] = []
    directory = root / RUNBOOKS
    if not directory.is_dir():
        return [f"missing {RUNBOOKS}/"]

    present = sorted(p.name for p in directory.glob("*.md"))
    classified = set(HISTORICAL) | set(LIVE)

    for name in present:
        if name not in classified:
            failures.append(
                f"{RUNBOOKS}/{name} is not classified in runbook_currency_check.py: "
                "add it to HISTORICAL (retired system, needs the banner) or LIVE"
            )
    for name in sorted(classified):
        if name not in present:
            failures.append(f"{RUNBOOKS}/{name} is classified but missing")

    for name in HISTORICAL:
        path = directory / name
        if not path.is_file():
            continue
        if BANNER not in path.read_text(encoding="utf-8", errors="replace"):
            failures.append(
                f"{RUNBOOKS}/{name} describes a retired system but lacks the "
                f'retirement banner ("{BANNER}")'
            )

    for name in LIVE:
        path = directory / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in RETIRED_OPERATOR_MARKERS:
            if marker in text:
                failures.append(
                    f"{RUNBOOKS}/{name} is classified LIVE but contains a retired-stack "
                    f"operator instruction: {marker}"
                )

    current = directory / CURRENT_RUNBOOK
    if not current.is_file():
        failures.append(
            f"{RUNBOOKS}/{CURRENT_RUNBOOK} is missing: nothing in {RUNBOOKS}/ "
            "documents the system that actually runs"
        )
    else:
        text = current.read_text(encoding="utf-8", errors="replace")
        failures.extend(
            f"{RUNBOOKS}/{CURRENT_RUNBOOK} missing marker: {marker}"
            for marker in CURRENT_RUNBOOK_MARKERS
            if marker not in text
        )

    for name in LIVE_CROSS_REFERENCE:
        path = directory / name
        if path.is_file() and CURRENT_RUNBOOK not in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            failures.append(
                f"{RUNBOOKS}/{name} does not point at {CURRENT_RUNBOOK}: an "
                "incident would start from the retired stack's instructions"
            )

    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args(argv)
    failures = check(args.root)
    if failures:
        print("Runbook currency check failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("runbook currency: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
