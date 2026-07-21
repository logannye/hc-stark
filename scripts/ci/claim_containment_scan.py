#!/usr/bin/env python3
"""Reject unsupported production claims outside labeled research/history."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
ACTIVE_FILES = (Path("README.md"),)
ACTIVE_TREES = (Path("site"), Path("release"))
ACTIVE_SUFFIXES = {".md", ".html", ".json", ".jsonld", ".txt"}
LEGACY_LABEL_RE = re.compile(
    r"(?:legacy research|historical archive).*not production evidence|"
    r"superseded plan.*not active release guidance",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(
    r"\b(?:do not|does not|must not|no)\b.{0,100}\bclaim\b|"
    r"\bnot (?:a |an )?(?:production |unconditional )?(?:claim|guarantee|"
    r"zero[- ]knowledge|unique)|"
    r"\bout of scope\b|"
    r"\bbefore any .*claim is advertised\b|"
    r"\bremove every instance\b|"
    r"\bcorrect claims\b|"
    r"\bresearch lineage\b",
    re.IGNORECASE,
)
UNSUPPORTED = {
    "square-root production behavior": re.compile(
        r"(?:\bO\s*[\(\[]?\s*(?:sqrt|√)|\bO\s*\(\s*√|"
        r"\bsquare[- ]root\b)",
        re.IGNORECASE,
    ),
    "zero-knowledge privacy": re.compile(
        r"\bzero[- ]knowledge\b", re.IGNORECASE
    ),
    "uniqueness or only-system capability": re.compile(
        r"\b(?:the\s+)?only\s+(?:production\s+)?"
        r"(?:system|prover|implementation|tool)\b|"
        r"\bunique(?:ly)?\s+(?:production\s+)?"
        r"(?:system|prover|implementation|tool|capabilit(?:y|ies))\b",
        re.IGNORECASE,
    ),
    "shipping implementation claim": re.compile(
        r"\bshipping\s+(?:CLI|implementation|prover|system)\b",
        re.IGNORECASE,
    ),
    "production-readiness claim": re.compile(
        r"\b(?:production[- ]ready|ready for production)\b",
        re.IGNORECASE,
    ),
}


def candidate_files(root: Path) -> list[tuple[Path, bool]]:
    files: dict[Path, bool] = {}
    for relative in ACTIVE_FILES:
        path = root / relative
        if path.is_file():
            files[path] = False
    for relative in ACTIVE_TREES:
        base = root / relative
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in ACTIVE_SUFFIXES:
                files[path] = False
    docs = root / "docs"
    if docs.is_dir():
        for path in docs.rglob("*.md"):
            files[path] = True
    return sorted(files.items())


def scan(root: Path) -> list[str]:
    errors: list[str] = []
    for path, is_documentation in candidate_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.relative_to(root)}: cannot read UTF-8: {exc}")
            continue
        labeled_legacy = "archive" in path.relative_to(root).parts or bool(
            LEGACY_LABEL_RE.search("\n".join(text.splitlines()[:12]))
        )
        lines = text.splitlines()
        for line_number, line in enumerate(lines, start=1):
            context = " ".join(
                lines[max(0, line_number - 2) : min(len(lines), line_number + 1)]
            )
            for label, pattern in UNSUPPORTED.items():
                if pattern.search(line) is None:
                    continue
                if is_documentation and labeled_legacy:
                    continue
                if NEGATION_RE.search(context):
                    continue
                errors.append(
                    f"{path.relative_to(root)}:{line_number}: "
                    f"unsupported {label}"
                )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    errors = scan(args.root.resolve())
    if errors:
        for error in errors:
            print(f"claim containment: FAIL: {error}", file=sys.stderr)
        return 1
    print("claim containment: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
