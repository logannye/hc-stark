"""Tests for scripts/ci/live_robots_policy_gate.py.

The fixture in `LIVE_2026_08_09` is the byte-exact document Cloudflare served
at https://tinyzkp.com/robots.txt on the day the injection was found, not a
paraphrase of it. A hand-written approximation would let the parser drift away
from the real edge output -- which is the exact failure this gate exists to
catch, so it is not a shortcut worth taking here.

The network is never touched. The gate's `--live-file` switch feeds a document
in directly so every assertion is deterministic and offline; the fetch path
itself is exercised against real production by CI's own invocation of the gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import live_robots_policy_gate as gate


ROOT = Path(__file__).resolve().parents[2]

# The committed six lines: everything allowed, nothing disallowed.
REPO_ROBOTS = ROOT / "site" / "robots.txt"
DECLARATION = ROOT / "release" / "live-crawler-policy-v1.json"

CONTENT_SIGNAL_PREAMBLE = """# As a condition of accessing this website, you agree to abide by the following
# content signals:

# (a)  If a Content-Signal = yes, you may collect content for the corresponding
#      use.
# (b)  If a Content-Signal = no, you may not collect content for the
#      corresponding use.
# (c)  If the website operator does not include a Content-Signal for a
#      corresponding use, the website operator neither grants nor restricts
#      permission via Content-Signal with respect to the corresponding use.

# The content signals and their meanings are:

# search:   building a search index and providing search results (e.g., returning
#           hyperlinks and short excerpts from your website's contents). Search does not
#           include providing AI-generated search summaries.
# ai-input: inputting content into one or more AI models (e.g., retrieval
#           augmented generation, grounding, or other real-time taking of content for
#           generative AI search answers).
# ai-train: training or fine-tuning AI models.
# use:      how AI systems may consume the content (immediate, reference, or full).

# ANY RESTRICTIONS EXPRESSED VIA CONTENT SIGNALS ARE EXPRESS RESERVATIONS OF
# RIGHTS UNDER ARTICLE 4 OF THE EUROPEAN UNION DIRECTIVE 2019/790 ON COPYRIGHT
# AND RELATED RIGHTS IN THE DIGITAL SINGLE MARKET.

"""

CLOUDFLARE_BLOCK = """# BEGIN Cloudflare Managed content

User-agent: *
Content-Signal: search=yes,ai-train=no,use=reference
Allow: /

User-agent: Amazonbot
Disallow: /

User-agent: Applebot-Extended
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: CloudflareBrowserRenderingCrawler
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: GPTBot
Disallow: /

User-agent: meta-externalagent
Disallow: /

# END Cloudflare Managed Content
"""

REPO_TAIL = """
User-agent: *
Allow: /
# Retired hosted-service paths intentionally remain crawlable so search engines
# can observe their 410 responses and X-Robots-Tag retirement headers.

Sitemap: https://tinyzkp.com/sitemap.xml
Host: tinyzkp.com
"""

LIVE_2026_08_09 = CONTENT_SIGNAL_PREAMBLE + CLOUDFLARE_BLOCK + REPO_TAIL

INJECTED_AGENTS = [
    "Amazonbot",
    "Applebot-Extended",
    "Bytespider",
    "CCBot",
    "ClaudeBot",
    "CloudflareBrowserRenderingCrawler",
    "GPTBot",
    "Google-Extended",
    "meta-externalagent",
]


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _declaration(tmp_path: Path, agents: list[str], signals: dict[str, str]) -> Path:
    document = json.loads(DECLARATION.read_text(encoding="utf-8"))
    document["intentionally_disallowed_user_agents"] = agents
    document["content_signal_by_user_agent"] = signals
    return _write(tmp_path, "declaration.json", json.dumps(document, indent=2))


def _run(tmp_path: Path, live: str, agents: list[str], signals: dict[str, str]) -> int:
    return gate.main(
        [
            "--live-file",
            str(_write(tmp_path, "live-robots.txt", live)),
            "--repo-robots",
            str(REPO_ROBOTS),
            "--declaration",
            str(_declaration(tmp_path, agents, signals)),
        ]
    )


def test_fixture_reproduces_the_observed_production_document():
    """Pin the fixture to the size actually measured, so it cannot quietly rot.

    2070 bytes is what `curl` reported for https://tinyzkp.com/robots.txt on
    2026-08-09. If someone trims the fixture to "just the interesting part",
    this fails rather than letting the parser be tested against a document
    production never served.
    """
    assert len(LIVE_2026_08_09.encode("utf-8")) == 2070
    assert LIVE_2026_08_09.endswith("Host: tinyzkp.com\n")
    assert "# BEGIN Cloudflare Managed content" in LIVE_2026_08_09


def test_committed_repo_robots_blocks_nobody():
    """The premise of the whole gate: the repository copy is not the served one."""
    groups = gate.parse_robots(REPO_ROBOTS.read_text(encoding="utf-8"))
    assert gate.blocked_agents(groups) == set()
    assert gate.content_signals(groups) == {}


def test_merged_star_groups_are_not_read_as_the_last_one_wins():
    """Production serves TWO `User-agent: *` records; both must be applied.

    A parser that kept only the last group would silently drop the injected
    Content-Signal, and one that kept only the first would drop our own Allow.
    """
    groups = gate.parse_robots(LIVE_2026_08_09)
    assert groups["*"]["allow"] == {"/"}
    assert groups["*"]["signals"] == {"search=yes,ai-train=no,use=reference"}


def test_fails_on_the_real_production_document_with_an_empty_declaration(tmp_path):
    """The defect as found: nine edge-injected blocks nobody in the repo chose."""
    assert _run(tmp_path, LIVE_2026_08_09, [], {}) == gate.EXIT_DRIFT


def test_reports_every_injected_agent_not_just_the_first(tmp_path, capsys):
    _run(tmp_path, LIVE_2026_08_09, [], {})
    reported = capsys.readouterr().err
    for agent in INJECTED_AGENTS:
        assert agent.lower() in reported, agent
    assert "INJECTED_BLOCK" in reported


def test_passes_once_the_declaration_matches_the_served_document(tmp_path):
    assert (
        _run(
            tmp_path,
            LIVE_2026_08_09,
            INJECTED_AGENTS,
            {"*": "search=yes,ai-train=no,use=reference"},
        )
        == gate.EXIT_PASS
    )


def test_committed_declaration_describes_production_as_measured(tmp_path):
    """The file checked into the repo must match the live document, not an ideal.

    If someone empties the declaration to express the intent "reopen the
    crawlers" without changing the Cloudflare zone, this is the assertion that
    turns that aspiration back into a red build.
    """
    assert (
        gate.main(
            [
                "--live-file",
                str(_write(tmp_path, "live-robots.txt", LIVE_2026_08_09)),
                "--repo-robots",
                str(REPO_ROBOTS),
                "--declaration",
                str(DECLARATION),
            ]
        )
        == gate.EXIT_PASS
    )


def test_fails_in_the_other_direction_when_a_declared_block_is_not_served(tmp_path):
    """A declaration is a claim about production, so it fails when unsupported."""
    reopened = REPO_TAIL  # the zone setting turned off; repo lines only
    assert _run(tmp_path, reopened, ["GPTBot"], {}) == gate.EXIT_DRIFT


def test_unenforced_and_injected_are_reported_distinctly(tmp_path, capsys):
    _run(tmp_path, REPO_TAIL, ["GPTBot"], {})
    reported = capsys.readouterr().err
    assert "UNENFORCED_BLOCK" in reported
    assert "INJECTED_BLOCK" not in reported


def test_content_signal_drift_fails_even_when_no_agent_is_disallowed(tmp_path):
    """`ai-train=no` restricts reuse without disallowing a single crawler.

    Checking Disallow alone would let the most consequential half of the
    injected block through untouched.
    """
    signal_only = "User-agent: *\nContent-Signal: ai-train=no\nAllow: /\n"
    assert _run(tmp_path, signal_only, [], {}) == gate.EXIT_DRIFT
    assert _run(tmp_path, signal_only, [], {"*": "ai-train=no"}) == gate.EXIT_PASS


def test_empty_disallow_is_not_a_block(tmp_path):
    """`Disallow:` with no path grants full access; treating it as `/` inverts it."""
    permissive = "User-agent: GPTBot\nDisallow:\n" + REPO_TAIL
    assert _run(tmp_path, permissive, [], {}) == gate.EXIT_PASS


def test_repo_blocks_are_the_floor_and_need_no_declaration_entry(tmp_path):
    """A block we commit ourselves is already attributable, so it is expected live."""
    repo = _write(tmp_path, "repo-robots.txt", "User-agent: BadBot\nDisallow: /\n")
    live = _write(tmp_path, "live-robots.txt", "User-agent: BadBot\nDisallow: /\n")
    declaration = _declaration(tmp_path, [], {})
    assert (
        gate.main(
            [
                "--live-file",
                str(live),
                "--repo-robots",
                str(repo),
                "--declaration",
                str(declaration),
            ]
        )
        == gate.EXIT_PASS
    )


def test_repo_rule_missing_from_production_also_fails(tmp_path):
    """The edge dropping a rule we committed is drift too, not a happy accident."""
    repo = _write(tmp_path, "repo-robots.txt", "User-agent: BadBot\nDisallow: /\n")
    live = _write(tmp_path, "live-robots.txt", "User-agent: *\nAllow: /\n")
    declaration = _declaration(tmp_path, [], {})
    assert (
        gate.main(
            [
                "--live-file",
                str(live),
                "--repo-robots",
                str(repo),
                "--declaration",
                str(declaration),
            ]
        )
        == gate.EXIT_DRIFT
    )


def test_unreachable_is_fatal_by_default(tmp_path, monkeypatch):
    """The third state must not collapse into PASS on the run that speaks for main."""

    def _explode(url: str) -> str:
        raise gate.Unreachable(f"{url}: simulated transport failure")

    monkeypatch.setattr(gate, "fetch_live", _explode)
    exit_code = gate.main(
        [
            "--repo-robots",
            str(REPO_ROBOTS),
            "--declaration",
            str(_declaration(tmp_path, [], {})),
        ]
    )
    assert exit_code == gate.EXIT_UNREACHABLE
    assert exit_code not in (gate.EXIT_PASS, gate.EXIT_DRIFT)


def test_tolerated_unreachable_still_emits_a_visible_annotation(
    tmp_path, monkeypatch, capsys
):
    """A tolerated miss must never be indistinguishable from a verified pass."""

    def _explode(url: str) -> str:
        raise gate.Unreachable(f"{url}: simulated transport failure")

    monkeypatch.setattr(gate, "fetch_live", _explode)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    exit_code = gate.main(
        [
            "--tolerate-unreachable",
            "--repo-robots",
            str(REPO_ROBOTS),
            "--declaration",
            str(_declaration(tmp_path, [], {})),
        ]
    )
    assert exit_code == gate.EXIT_PASS
    stdout = capsys.readouterr().out
    assert "::warning" in stdout
    assert "UNREACHABLE" in stdout
    assert "PASS:" not in stdout
    assert "UNREACHABLE" in summary.read_text(encoding="utf-8")


def test_fetch_retries_before_declaring_unreachable(monkeypatch):
    """One failed handshake must not be reported as an unreachable origin."""
    attempts: list[int] = []

    def _fail(request, timeout):  # noqa: ANN001 -- urlopen's signature
        attempts.append(1)
        raise OSError("simulated connection reset")

    monkeypatch.setattr(gate.urllib.request, "urlopen", _fail)
    monkeypatch.setattr(gate.time, "sleep", lambda _seconds: None)
    with pytest.raises(gate.Unreachable):
        gate.fetch_live("https://example.invalid/robots.txt")
    assert len(attempts) == gate.FETCH_ATTEMPTS


def test_declaration_rejects_a_malformed_agent_list(tmp_path):
    path = _write(tmp_path, "bad.json", json.dumps({"intentionally_disallowed_user_agents": "GPTBot"}))
    with pytest.raises(ValueError):
        gate.load_declaration(path)
