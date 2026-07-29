#!/usr/bin/env python3
"""Fail CI when a check script is neither reachable from CI nor declared manual.

Three separate incidents motivate this:

  * `plonky3_compatibility_gate.py` was silently broken for three commits --
    it required a literal that had been moved, so it passed by checking
    nothing.
  * `offer_metadata_check.py` was referenced by no workflow AND failed on
    every run (it requires `site/.well-known/tinyzkp-offers.json`, which
    does not exist, and validates a free/developer/pro/scale/compute plan
    model that was retired with the hosted stack). Nobody noticed, because
    nothing ran it.
  * The privacy notice, the Guard withdrawal, and the MCP listings each went
    stale because the thing that would have caught them was not wired.

The failure mode is always the same: a repository that *looks* like it has
coverage. This gate makes "is it actually run?" a question with a committed
answer for every script.

Reachability is TRANSITIVE, not just direct mention. Most check scripts here
are legitimately invoked by an orchestrator (`production_launch_preflight.py`,
`guard_pages_launch_preflight.py`, `sdk_contract_gate.sh`) rather than named
in a workflow, and a gate that ignored that would produce a wall of false
positives and promptly be ignored itself. A script is covered when it is:

  1. named in a `.github/workflows/*.yml` file, or
  2. named by any file that is itself covered (orchestrators, shell wrappers,
     and the pytest modules CI runs), or
  3. explicitly listed in `scripts/manual-gates.txt` with a reason.

Anything else fails. The allowlist is checked in both directions: an entry
that has since become reachable, or that names a file that no longer exists,
also fails -- otherwise the allowlist quietly becomes the place where dead
scripts go to look accounted for.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ALLOWLIST = ROOT / "scripts" / "manual-gates.txt"

SCANNED_DIRS = (
    "scripts/ci",
    "scripts/commercial",
    "scripts/deploy",
    "scripts/release",
    "scripts/monitoring",
    "scripts/marketing",
    "scripts/benchmark",
)
SUFFIXES = (".py", ".sh", ".mjs")


def candidate_scripts() -> dict[str, pathlib.Path]:
    """Every executable check script, keyed by repo-relative path."""
    scripts: dict[str, pathlib.Path] = {}
    for relative in SCANNED_DIRS:
        directory = ROOT / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            if path.name.startswith("__init__"):
                continue
            scripts[path.relative_to(ROOT).as_posix()] = path
    return scripts


_DOCSTRING_RE = re.compile(r'"""..*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
_COMMENT_RE = re.compile(r"(?m)#.*$")


def _text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _code_only(text: str) -> str:
    """Strip docstrings and comments before looking for invocations.

    Without this the check is self-referential and reports false coverage:
    THIS module's own docstring names `production_launch_preflight.py` and
    `sdk_contract_gate.sh` as examples, which marked both -- and everything
    they in turn name -- as reachable from CI, when no workflow runs either.
    A gate that says "covered" about something CI never executes is the exact
    failure it exists to prevent, so prose must not count as wiring.
    """
    return _COMMENT_RE.sub("", _DOCSTRING_RE.sub("", text))


def _mentions(name: str, text: str) -> bool:
    """Whether `text` names this exact script.

    The boundary matters more than it looks. A plain substring test reports
    that `recovery_reconciliation_invariants.py` is wired because CI runs
    `test_recovery_reconciliation_invariants.py` -- every script whose name
    is embedded in its own test's filename would be marked covered by the
    mere existence of that test. That is a gate reporting coverage it cannot
    justify, which is the thing this module exists to stop.
    """
    if re.search(rf"(?<![\w-]){re.escape(name)}", text) is not None:
        return True
    # A Python module imported by a covered script is reached too, and an
    # import statement carries no `.py` suffix -- `strict_json.py` is used
    # everywhere as `import strict_json`. Without this, shared library
    # modules look orphaned and get pushed into the manual allowlist, which
    # is both wrong and the fastest way to make the allowlist meaningless.
    if name.endswith(".py"):
        stem = re.escape(name[:-3])
        if re.search(rf"(?m)^\s*(?:import\s+{stem}\b|from\s+{stem}\s+import)", text):
            return True
    return False


def reachable(scripts: dict[str, pathlib.Path]) -> set[str]:
    """Transitive closure of 'named by something CI runs'."""
    workflow_text = "\n".join(
        _code_only(_text(path)) for path in sorted(WORKFLOWS.glob("*.yml"))
    )
    covered = {
        relative
        for relative, path in scripts.items()
        if _mentions(path.name, workflow_text)
    }
    # Fixed point: anything named by a covered file is itself covered.
    changed = True
    while changed:
        changed = False
        frontier = "\n".join(
            _code_only(_text(scripts[relative])) for relative in covered
        )
        for relative, path in scripts.items():
            if relative in covered:
                continue
            if _mentions(path.name, frontier):
                covered.add(relative)
                changed = True
    return covered


def load_allowlist() -> dict[str, str]:
    """`path  # reason` per line; blank lines and full-line comments ignored."""
    entries: dict[str, str] = {}
    if not ALLOWLIST.is_file():
        return entries
    for number, raw in enumerate(ALLOWLIST.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, _, reason = line.partition("#")
        path = path.strip()
        reason = reason.strip()
        if not reason:
            raise ValueError(
                f"{ALLOWLIST.name}:{number}: '{path}' needs a reason after '#' -- "
                "an unexplained exemption is how a dead gate hides"
            )
        entries[path] = reason
    return entries


def check(
    scripts: dict[str, pathlib.Path],
    covered: set[str],
    allowlist: dict[str, str],
) -> list[str]:
    failures: list[str] = []

    for relative in sorted(scripts):
        if relative in covered or relative in allowlist:
            continue
        failures.append(
            f"{relative} is run by no workflow, no covered script, and no test, "
            f"and is not listed in scripts/manual-gates.txt -- wire it, delete "
            f"it, or declare it manual with a reason"
        )

    for relative, reason in sorted(allowlist.items()):
        if not (ROOT / relative).is_file():
            failures.append(
                f"scripts/manual-gates.txt lists {relative}, which does not exist"
            )
        elif relative in covered:
            failures.append(
                f"scripts/manual-gates.txt still exempts {relative}, but it is "
                f"now reachable from CI -- remove the exemption ({reason})"
            )

    return failures


def main(argv: list[str]) -> int:
    try:
        scripts = candidate_scripts()
        covered = reachable(scripts)
        allowlist = load_allowlist()
        failures = check(scripts, covered, allowlist)
    except (OSError, ValueError) as error:
        print(f"gate wiring check failed to run: {error}", file=sys.stderr)
        return 2

    if failures:
        print("gate wiring check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        f"PASS gate wiring check ({len(covered)} reachable, "
        f"{len(allowlist)} declared manual, {len(scripts)} total)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
