#!/usr/bin/env python3
"""Fail CI when the SERVED robots.txt disagrees with the declared crawler policy.

Every other robots-related check in this repository reads `site/robots.txt`
from the working tree. That file is six lines long and allows everything. The
file Cloudflare actually serves at https://tinyzkp.com/robots.txt is 2070 bytes
and disallows nine of the largest AI crawlers, because a zone-level "Managed
content" block is injected ahead of our committed lines by the edge. No
repository gate could ever observe that, so the block survived from whenever it
was switched on until it was found by hand.

That is not a cosmetic drift. `site/llms.txt` is written specifically to court
agent traffic, and `release/demand-clock-v1.json` starts a 90-day clock whose
kill criterion is computed from the traffic that discovery generates. A
KILL_THRESHOLD_MET verdict produced while the edge is turning those agents away
would be measuring the edge configuration, not the market -- the most expensive
possible way to be wrong about this project.

WHY A DECLARATION FILE AND NOT "live must equal repo"
-----------------------------------------------------
Blocking AI crawlers is a legitimate thing for an owner to want. A gate that
simply asserted `live == repo` would be asserting a policy preference it has no
standing to hold, and the first time the owner deliberately turned a block on
they would silence the gate to get their build green -- which is how a gate
becomes decoration. So the intended policy lives in a committed declaration,
`release/live-crawler-policy-v1.json`, and this gate fails when live disagrees
with the DECLARATION in either direction:

  * live blocks an agent the declaration does not sanction  -> INJECTED_BLOCK
    (the edge, a Cloudflare setting change, or a third party decided something
    the repository never agreed to)
  * live fails to block an agent the declaration sanctions   -> UNENFORCED_BLOCK
    (the declaration describes an intent production is not carrying out)

The repository copy is folded in as the floor: anything `site/robots.txt`
already disallows is expected to be disallowed live too, without needing to be
restated in the declaration. So the declaration means precisely "blocks that
exist at the edge, on purpose, beyond what we committed" -- and its empty state
is the honest default of "we block nobody the repository does not block".

Content-Signal is checked on the same terms. `ai-train=no, use=reference` is a
machine-readable restriction with the same commercial consequence as a
Disallow, and Cloudflare injects it in the same block, so exempting it would
leave the gate half blind.

WHY IT DOES NOT SIMPLY FAIL CLOSED ON A FETCH ERROR
---------------------------------------------------
Two bad options and neither is acceptable on its own. Failing the build on any
network hiccup makes a red build meaningless and trains everyone to re-run it;
passing silently when the fetch fails is the "check whose false branch is safe"
antipattern that has already cost this repository nine dark checks in one
audit -- a gate that cannot report is worth less than no gate, because it also
consumes the attention that would have gone to a real one.

The resolution is that unreachable is a THIRD state, not an alias for either:

  exit 0   PASS         live agrees with the declaration
  exit 1   DRIFT        live disagrees -- always fatal, on every trigger
  exit 75  UNREACHABLE  three attempts with backoff all failed

Exit 75 (EX_TEMPFAIL) is fatal by default. `--tolerate-unreachable` downgrades
it to a GitHub Actions `::warning::` annotation plus a job-summary row and exit
0, and CI passes that flag ONLY on `pull_request` events. A contributor must
not be blocked by a transient DNS failure on a change that has nothing to do
with the site; the `push` build on `main` is the run that speaks for production,
and there unreachable stays fatal. The downgraded path is still loud -- an
annotation on the run and a line in the job summary -- so "we have not been able
to see production for a week" cannot look like "production is fine".
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[2]
REPO_ROBOTS = ROOT / "site" / "robots.txt"
DECLARATION = ROOT / "release" / "live-crawler-policy-v1.json"

DEFAULT_URL = "https://tinyzkp.com/robots.txt"

# Three attempts over roughly ten seconds. Long enough to ride out a single
# failed TLS handshake or a CDN node rotating; short enough that a genuinely
# unreachable origin is reported inside one CI step rather than by timeout.
FETCH_ATTEMPTS = 3
FETCH_BACKOFF_SECONDS = (2.0, 5.0)
FETCH_TIMEOUT_SECONDS = 15.0

# A plain, honest identifier. Cloudflare varies robots.txt by nothing today,
# but announcing a crawler-shaped agent would risk measuring a bot-managed
# response rather than the one a real crawler receives.
USER_AGENT = "tinyzkp-live-robots-policy-gate/1 (+https://tinyzkp.com)"

EXIT_PASS = 0
EXIT_DRIFT = 1
EXIT_UNREACHABLE = 75  # EX_TEMPFAIL

_DIRECTIVE_RE = re.compile(r"^([A-Za-z-]+)\s*:\s*(.*)$")


class Unreachable(Exception):
    """The live robots.txt could not be read after every attempt."""


def parse_robots(text: str) -> dict[str, dict[str, object]]:
    """Group a robots.txt into `{lowercased user-agent: {allow, disallow, signals}}`.

    Groups are merged by agent name, per RFC 9309 section 2.2.1: production
    serves TWO `User-agent: *` records (Cloudflare's, then ours), and a parser
    that kept only the first or only the last would report a different policy
    than a real crawler applies. Consecutive `User-agent` lines share one rule
    block, which is how the injected block would express a multi-agent rule if
    Cloudflare ever collapsed it.
    """
    groups: dict[str, dict[str, object]] = {}
    current: list[str] = []
    # A `User-agent` line after a rule line starts a NEW group rather than
    # extending the previous agent list; this flag is what distinguishes the
    # two cases.
    saw_rule = False

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _DIRECTIVE_RE.match(line)
        if match is None:
            continue
        field = match.group(1).lower()
        value = match.group(2).strip()

        if field == "user-agent":
            if saw_rule:
                current = []
                saw_rule = False
            agent = value.lower()
            if agent:
                current.append(agent)
                groups.setdefault(
                    agent, {"allow": set(), "disallow": set(), "signals": set()}
                )
            continue

        if field not in {"allow", "disallow", "content-signal"}:
            # Sitemap and Host are site-wide, not per-group, and carry no
            # crawl permission. They are deliberately out of scope.
            continue

        saw_rule = True
        for agent in current:
            bucket = groups[agent]
            if field == "allow":
                bucket["allow"].add(value)  # type: ignore[union-attr]
            elif field == "disallow":
                bucket["disallow"].add(value)  # type: ignore[union-attr]
            else:
                bucket["signals"].add(value)  # type: ignore[union-attr]

    return groups


def blocked_agents(groups: dict[str, dict[str, object]]) -> set[str]:
    """Agents shut out of the whole site.

    `Disallow: /` with no `Allow: /` in the same merged group. An empty
    `Disallow:` means "no restriction" and is correctly ignored, because the
    empty string is not `/`.
    """
    blocked = set()
    for agent, rules in groups.items():
        disallow = rules["disallow"]
        allow = rules["allow"]
        if "/" in disallow and "/" not in allow:  # type: ignore[operator]
            blocked.add(agent)
    return blocked


def content_signals(groups: dict[str, dict[str, object]]) -> dict[str, set[str]]:
    return {
        agent: set(rules["signals"])  # type: ignore[arg-type]
        for agent, rules in groups.items()
        if rules["signals"]
    }


def fetch_live(url: str) -> str:
    """Read the served robots.txt, retrying before declaring it unreachable."""
    last_error: Exception | None = None
    for attempt in range(FETCH_ATTEMPTS):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise urllib.error.HTTPError(
                        url, response.status, "unexpected status", response.headers, None
                    )
                return response.read().decode("utf-8", errors="replace")
        except Exception as error:  # noqa: BLE001 -- every transport failure is one state
            last_error = error
            if attempt + 1 < FETCH_ATTEMPTS:
                time.sleep(FETCH_BACKOFF_SECONDS[attempt])
    raise Unreachable(f"{url}: {last_error}")


def load_declaration(path: pathlib.Path) -> tuple[set[str], dict[str, set[str]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    agents = document.get("intentionally_disallowed_user_agents", [])
    if not isinstance(agents, list) or not all(isinstance(a, str) for a in agents):
        raise ValueError(
            f"{path.name}: intentionally_disallowed_user_agents must be a list of strings"
        )
    signals_raw = document.get("content_signal_by_user_agent", {})
    if not isinstance(signals_raw, dict):
        raise ValueError(f"{path.name}: content_signal_by_user_agent must be an object")
    signals: dict[str, set[str]] = {}
    for agent, value in signals_raw.items():
        if not isinstance(value, str):
            raise ValueError(f"{path.name}: content signal for {agent!r} must be a string")
        signals[agent.lower()] = {value}
    return {agent.lower() for agent in agents}, signals


def _emit_warning(message: str) -> None:
    """Make a non-green, non-fatal outcome impossible to scroll past.

    An annotation alone is easy to miss in a long log, and a job summary alone
    is easy to never open, so this writes both.
    """
    print(f"::warning title=Live robots.txt unreachable::{message}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(
                "### Live robots.txt policy gate: UNREACHABLE\n\n"
                f"{message}\n\n"
                "Production crawler policy was NOT verified on this run.\n"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--repo-robots", type=pathlib.Path, default=REPO_ROBOTS)
    parser.add_argument("--declaration", type=pathlib.Path, default=DECLARATION)
    parser.add_argument(
        "--live-file",
        type=pathlib.Path,
        default=None,
        help="Read the 'live' document from a file instead of the network (tests only).",
    )
    parser.add_argument(
        "--tolerate-unreachable",
        action="store_true",
        help=(
            "Downgrade an unreachable production origin from fatal to a visible "
            "warning. CI passes this on pull_request events only."
        ),
    )
    args = parser.parse_args(argv)

    repo_groups = parse_robots(args.repo_robots.read_text(encoding="utf-8"))
    declared_agents, declared_signals = load_declaration(args.declaration)

    if args.live_file is not None:
        live_text = args.live_file.read_text(encoding="utf-8")
    else:
        try:
            live_text = fetch_live(args.url)
        except Unreachable as error:
            message = (
                f"could not read {args.url} after {FETCH_ATTEMPTS} attempts: {error}"
            )
            if args.tolerate_unreachable:
                _emit_warning(message)
                print(f"UNREACHABLE (tolerated): {message}")
                return EXIT_PASS
            print(f"UNREACHABLE: {message}", file=sys.stderr)
            return EXIT_UNREACHABLE

    live_groups = parse_robots(live_text)

    repo_blocked = blocked_agents(repo_groups)
    live_blocked = blocked_agents(live_groups)
    # The repository copy is the floor: a block we committed needs no separate
    # declaration entry, so the declaration stays a list of edge-only decisions.
    expected_blocked = repo_blocked | declared_agents

    injected = sorted(live_blocked - expected_blocked)
    unenforced = sorted(expected_blocked - live_blocked)

    repo_signals = content_signals(repo_groups)
    live_signals = content_signals(live_groups)
    expected_signals: dict[str, set[str]] = {
        agent: set(values) for agent, values in repo_signals.items()
    }
    for agent, values in declared_signals.items():
        expected_signals.setdefault(agent, set()).update(values)

    signal_drift: list[str] = []
    for agent in sorted(set(expected_signals) | set(live_signals)):
        expected = expected_signals.get(agent, set())
        observed = live_signals.get(agent, set())
        if expected != observed:
            signal_drift.append(
                f"  user-agent {agent!r}: live={sorted(observed) or ['(none)']} "
                f"declared={sorted(expected) or ['(none)']}"
            )

    print(f"live robots.txt: {args.url} ({len(live_text.encode('utf-8'))} bytes)")
    print(f"  repository disallows at root : {sorted(repo_blocked) or ['(none)']}")
    print(f"  declaration sanctions        : {sorted(declared_agents) or ['(none)']}")
    print(f"  live disallows at root       : {sorted(live_blocked) or ['(none)']}")

    if not injected and not unenforced and not signal_drift:
        print("PASS: served crawler policy matches release/live-crawler-policy-v1.json")
        return EXIT_PASS

    print("", file=sys.stderr)
    print("DRIFT: the served crawler policy is not the declared one.", file=sys.stderr)
    if injected:
        print(
            "\nINJECTED_BLOCK -- live blocks agents neither the repository nor the\n"
            "declaration sanctions. Something outside this repository (a Cloudflare\n"
            "zone setting, most likely 'Managed robots.txt' / AI crawler control) is\n"
            "turning traffic away that release/demand-clock-v1.json is counting:",
            file=sys.stderr,
        )
        for agent in injected:
            print(f"  - {agent}", file=sys.stderr)
    if unenforced:
        print(
            "\nUNENFORCED_BLOCK -- the declaration says these are blocked on purpose,\n"
            "but production serves no such rule. Either the edge setting was turned\n"
            "off or the declaration records an intent that never took effect:",
            file=sys.stderr,
        )
        for agent in unenforced:
            print(f"  - {agent}", file=sys.stderr)
    if signal_drift:
        print(
            "\nCONTENT_SIGNAL_DRIFT -- Content-Signal restricts commercial reuse as\n"
            "firmly as Disallow does, and is injected by the same mechanism:",
            file=sys.stderr,
        )
        for line in signal_drift:
            print(line, file=sys.stderr)
    print(
        "\nResolve by DECIDING, not by muting: either turn the edge setting off, or\n"
        "record the block in release/live-crawler-policy-v1.json so the choice is\n"
        "attributable. Reopening the crawlers means emptying that declaration AND\n"
        "changing the Cloudflare zone -- this gate stays red until both agree.",
        file=sys.stderr,
    )
    return EXIT_DRIFT


if __name__ == "__main__":
    raise SystemExit(main())
