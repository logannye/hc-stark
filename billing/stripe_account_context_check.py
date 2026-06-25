#!/usr/bin/env python3
"""Verify that the active Stripe CLI profile is the expected TinyZKP account."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


DEFAULT_EXPECTED_DISPLAY_NAME = "TinyZKP"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "stripe" / "config.toml"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
STRIPE_SECRET_RE = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[^\s'\"}]+")
STRIPE_ID_RE = re.compile(r"\b(?:acct|cs|cus|pi|sub|price|prod|mtr|req)_[A-Za-z0-9_*]{8,}\b")
ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*$")
SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")


@dataclass(frozen=True)
class AccountContext:
    project_name: str = ""
    display_name: str = ""
    account_id: str = ""


@dataclass(frozen=True)
class AccountCheckResult:
    status: str
    name: str
    detail: str
    display_name: str = ""
    project_name: str = ""


def redact(text: object) -> str:
    value = EMAIL_RE.sub("[redacted-email]", str(text))
    value = STRIPE_SECRET_RE.sub("[redacted-key]", value)
    return STRIPE_ID_RE.sub("[redacted-id]", value)


def _clean_value(raw: str) -> str:
    value = raw.strip().rstrip(",")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value.strip("'\"")


def _parse_config_fields(text: str) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    top_level: dict[str, str] = {}
    sections: dict[str, dict[str, str]] = {}
    current_section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        section = SECTION_RE.match(stripped)
        if section:
            current_section = section.group(1)
            sections.setdefault(current_section, {})
            continue
        assignment = ASSIGNMENT_RE.match(stripped)
        if not assignment:
            continue
        key, raw_value = assignment.groups()
        target = sections.setdefault(current_section, {}) if current_section else top_level
        target[key] = _clean_value(raw_value)
    return top_level, sections


def parse_config(text: str) -> AccountContext:
    top_level, sections = _parse_config_fields(text)
    project_name = top_level.get("project-name") or top_level.get("project_name") or ""
    section = sections.get(project_name) if project_name else None
    if section is None:
        section = next((fields for fields in sections.values() if fields.get("display_name")), {})

    return AccountContext(
        project_name=project_name,
        display_name=section.get("display_name") or section.get("display-name") or "",
        account_id=section.get("account_id") or section.get("account-id") or "",
    )


def parse_profiles(text: str) -> list[AccountContext]:
    _top_level, sections = _parse_config_fields(text)
    profiles: list[AccountContext] = []
    for project_name, section in sections.items():
        display_name = section.get("display_name") or section.get("display-name") or ""
        account_id = section.get("account_id") or section.get("account-id") or ""
        if display_name or account_id:
            profiles.append(AccountContext(project_name=project_name, display_name=display_name, account_id=account_id))
    return profiles


def load_profiles(config_path: Path = DEFAULT_CONFIG_PATH) -> list[AccountContext]:
    try:
        return parse_profiles(config_path.read_text(encoding="utf-8"))
    except OSError:
        return []


def display_name_matches(display_name: str, expected_display_name: str) -> bool:
    expected = expected_display_name.strip().lower()
    actual = display_name.strip().lower()
    return bool(expected and actual and expected in actual)


def discover_profile(
    *,
    expected_display_name: str = DEFAULT_EXPECTED_DISPLAY_NAME,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> AccountCheckResult:
    expected = expected_display_name.strip()
    if not expected:
        return AccountCheckResult("FAIL", "profile discovery", "expected Stripe display name is empty")
    profiles = load_profiles(config_path)
    matches = [profile for profile in profiles if display_name_matches(profile.display_name, expected)]
    if len(matches) == 1:
        profile = matches[0]
        return AccountCheckResult(
            "PASS",
            "profile discovery",
            f"found Stripe CLI profile '{profile.project_name}' with display_name '{profile.display_name}'",
            display_name=profile.display_name,
            project_name=profile.project_name,
        )
    available = ", ".join(
        f"{profile.project_name}='{profile.display_name or '-'}'"
        for profile in profiles
    ) or "none"
    if not matches:
        return AccountCheckResult(
            "FAIL",
            "profile discovery",
            f"no local Stripe CLI profile display_name matches '{expected}'; available profiles: {available}",
        )
    return AccountCheckResult(
        "FAIL",
        "profile discovery",
        f"multiple local Stripe CLI profiles match '{expected}'; pass --stripe-project-name explicitly",
    )


def run_check(
    *,
    stripe_bin: str = "stripe",
    stripe_project_name: str = "",
    expected_display_name: str = DEFAULT_EXPECTED_DISPLAY_NAME,
    timeout: int = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> AccountCheckResult:
    expected = expected_display_name.strip()
    if not expected:
        return AccountCheckResult("FAIL", "account context", "expected Stripe display name is empty")

    command = [stripe_bin, "config", "--list", "--color", "off"]
    if stripe_project_name:
        command.extend(["--project-name", stripe_project_name])
    try:
        completed = runner(
            tuple(command),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return AccountCheckResult("FAIL", "account context", redact(exc))
    except subprocess.TimeoutExpired:
        return AccountCheckResult("FAIL", "account context", f"stripe config timed out after {timeout}s")

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    if completed.returncode != 0:
        detail = redact(output) or f"stripe config exited with {completed.returncode}"
        return AccountCheckResult("FAIL", "account context", detail[:600])

    context = parse_config(output)
    if not context.display_name:
        return AccountCheckResult(
            "FAIL",
            "account context",
            "Stripe CLI config does not expose a display_name; run stripe login or verify the selected profile",
            project_name=context.project_name,
        )
    if display_name_matches(context.display_name, expected):
        detail = f"configured Stripe CLI display_name '{context.display_name}' matches expected '{expected}'"
        if context.project_name:
            detail += f" (project: {context.project_name})"
        return AccountCheckResult(
            "PASS",
            "account context",
            detail,
            display_name=context.display_name,
            project_name=context.project_name,
        )

    detail = (
        f"configured Stripe CLI display_name '{context.display_name}' does not match expected '{expected}'; "
        "switch to the TinyZKP Stripe profile with stripe login, or set "
        "TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME only if the account was intentionally renamed"
    )
    if context.project_name:
        detail += f" (project: {context.project_name})"
    return AccountCheckResult(
        "FAIL",
        "account context",
        detail,
        display_name=context.display_name,
        project_name=context.project_name,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripe-bin", default="stripe", help="Stripe CLI executable path")
    parser.add_argument("--stripe-project-name", default="", help="Optional Stripe CLI project profile name")
    parser.add_argument("--config-path", type=Path, default=DEFAULT_CONFIG_PATH, help="Stripe CLI config path for local profile discovery")
    parser.add_argument("--list-profiles", action="store_true", help="List local Stripe CLI profile names and display names without secrets")
    parser.add_argument("--discover-profile", action="store_true", help="Find the local Stripe CLI profile matching --expected-display-name")
    parser.add_argument(
        "--expected-display-name",
        default=os.environ.get("TINYZKP_STRIPE_EXPECTED_DISPLAY_NAME", DEFAULT_EXPECTED_DISPLAY_NAME),
        help="Required substring in the active Stripe CLI display_name",
    )
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def print_text(result: AccountCheckResult) -> None:
    print(f"{result.status:<4} Stripe CLI: {result.name} - {result.detail}")


def safe_profile_dict(profile: AccountContext) -> dict[str, str]:
    return {"project_name": profile.project_name, "display_name": profile.display_name}


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.list_profiles:
        profiles = [safe_profile_dict(profile) for profile in load_profiles(args.config_path)]
        if args.json:
            print(json.dumps({"profiles": profiles}, indent=2))
        else:
            if profiles:
                for profile in profiles:
                    print(f"{profile['project_name']}: {profile['display_name'] or '-'}")
            else:
                print("No local Stripe CLI profiles found.")
        return 0

    if args.discover_profile:
        result = discover_profile(expected_display_name=args.expected_display_name, config_path=args.config_path)
        if args.json:
            print(json.dumps({"result": asdict(result)}, indent=2))
        else:
            print_text(result)
        return 0 if result.status == "PASS" else 1

    result = run_check(
        stripe_bin=args.stripe_bin,
        stripe_project_name=args.stripe_project_name,
        expected_display_name=args.expected_display_name,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps({"result": asdict(result)}, indent=2))
    else:
        print_text(result)
    return 0 if result.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
