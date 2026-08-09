#!/usr/bin/env python3
"""Fail when the site's head metadata sells a product that is not for sale.

WHY THIS GATE EXISTS
====================
A 2026-08-09 production sweep found that every body-copy surface on tinyzkp.com
correctly described the Guard subscription as withdrawn, while the homepage
``<title>``, ``meta[name=description]``, and every ``og:``/``twitter:`` tag still
sold it in the present tense:

    <title>TinyZKP Guard - Finish Plonky3 proof jobs within a RAM budget</title>

That is the single most-quoted text the site publishes. A search engine, a social
unfurl, and an LLM summariser all read the head and none of them read the body,
so the withdrawal had landed everywhere except the place it mattered most. This
is the same class of defect as the 2026-07-29 truthful-surfaces remediation: the
human-readable page was corrected and the machine-facing surface was not.

The governing rule in this repo is that a fix is not done when the surface is
corrected, only when a gate exists that fails if it drifts again. This is that
gate.

WHAT IT ASSERTS
===============
1. The homepage head must not name Guard at all. Every other page may - and
   several must, because ``guard.html``, ``eula.html``, ``terms.html`` and
   ``refunds.html`` exist precisely to document the withdrawn subscription. The
   homepage is different in kind: it is the canonical result for the query
   "TinyZKP", so whatever it names in its head becomes what TinyZKP *is*.
2. No page's head may carry purchase-intent or pending-launch phrasing while the
   SKU is withdrawn. "Not yet", "coming soon" and a quoted price each promise a
   launch that is not coming. site/llms.txt already forbids exactly this for
   agents; this extends the same rule to the tags agents actually read.
3. Every ``og:image``/``twitter:image`` must resolve to a file that exists in
   site/. A social card that 404s is the failure mode that replaced the previous
   card, and it is invisible from the page itself.

Assertions 1 and 2 are conditional on release/guard-sku-withdrawal-v1.json
recording the withdrawal, so revoking that record relaxes them in step with the
business decision rather than requiring a hand edit here. Assertion 3 is
unconditional.
"""

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
GUARD_SKU_WITHDRAWAL = ROOT / "release" / "guard-sku-withdrawal-v1.json"

HOMEPAGE = "index.html"

# Phrases that assert a purchase is possible or imminent no matter what else the
# sentence says. "Not yet" and "coming soon" promise a launch; a withdrawal is
# not a delay, so these fail unconditionally while the SKU is withdrawn.
HARD_PENDING_PHRASES = (
    "not yet",
    "coming soon",
    "pre-order",
    "preorder",
    "buy guard",
)

# These are only a problem when they stand alone. Naming the historical price, or
# the words "for sale", is honest and useful when the same sentence says the SKU
# is withdrawn - site/pricing.html's description does exactly that:
#   "...the withdrawn $499 monthly / $4,990 annual TinyZKP Guard subscription..."
# Failing that would push the site toward saying LESS about the withdrawal, which
# is the opposite of the intent. So these fail only in the absence of withdrawal
# language in the same value.
SOFT_PENDING_PHRASES = ("for sale",)
PRICE_RE = re.compile(r"\$\s?\d")
WITHDRAWAL_LANGUAGE = (
    "withdrawn",
    "withdrew",
    "no longer",
    "not sold",
    "discontinued",
    "retired",
)

METADATA_ATTRS = {
    ("meta", "description"),
    ("meta", "twitter:title"),
    ("meta", "twitter:description"),
    ("meta", "og:title"),
    ("meta", "og:description"),
}
IMAGE_KEYS = {"og:image", "twitter:image"}


def guard_sku_withdrawn() -> bool:
    """True when the Guard SKU is recorded as withdrawn.

    Absent or malformed record means NOT withdrawn. A parse failure must never
    silently *relax* this gate into passing, and it does not: a non-withdrawn
    reading turns assertions 1 and 2 off, which is the conservative direction
    only because a non-withdrawn SKU legitimately may be advertised. The
    withdrawal record is itself schema-checked by guard_launch_gate.py.
    """
    try:
        data = json.loads(GUARD_SKU_WITHDRAWAL.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get("withdrawn") is True


class HeadMetadata(HTMLParser):
    """Collect title text and the content of head-level meta tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_head = True
        self.in_title = False
        self.title = ""
        # key -> content, e.g. "og:title" -> "TinyZKP - ..."
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered == "body":
            self.in_head = False
        if not self.in_head:
            return
        if lowered == "title":
            self.in_title = True
            return
        if lowered != "meta":
            return
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        key = attrs_dict.get("name") or attrs_dict.get("property")
        if key:
            self.meta[key.lower()] = attrs_dict.get("content", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data


def head_metadata(path: Path) -> HeadMetadata:
    parser = HeadMetadata()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def check() -> list[str]:
    failures: list[str] = []
    withdrawn = guard_sku_withdrawn()
    pages = sorted(SITE.glob("*.html"))
    if not pages:
        return [f"no HTML pages found under {SITE}"]

    for path in pages:
        parsed = head_metadata(path)
        name = path.name
        # Only the tags a search engine or unfurl actually quotes.
        quoted: dict[str, str] = {"<title>": parsed.title.strip()}
        for key, content in parsed.meta.items():
            if ("meta", key) in METADATA_ATTRS:
                quoted[key] = content

        for key, value in quoted.items():
            if not value:
                continue
            lowered = value.lower()

            if withdrawn and name == HOMEPAGE and re.search(r"\bguard\b", lowered):
                failures.append(
                    f"{name} {key} names the withdrawn Guard SKU: {value!r}. The "
                    "homepage head is the canonical answer to 'what is TinyZKP'; "
                    "it must name what is actually offered."
                )

            if withdrawn:
                hit = [p for p in HARD_PENDING_PHRASES if p in lowered]
                if hit:
                    failures.append(
                        f"{name} {key} describes the withdrawn SKU as pending "
                        f"(contains {hit}): {value!r}. A withdrawal is not a delay."
                    )
                discloses = any(w in lowered for w in WITHDRAWAL_LANGUAGE)
                if not discloses:
                    soft = [p for p in SOFT_PENDING_PHRASES if p in lowered]
                    if soft:
                        failures.append(
                            f"{name} {key} implies the withdrawn SKU is purchasable "
                            f"(contains {soft}) without saying it is withdrawn: {value!r}"
                        )
                    if PRICE_RE.search(value):
                        failures.append(
                            f"{name} {key} quotes a price without saying the SKU is "
                            f"withdrawn: {value!r}"
                        )

        for key, content in parsed.meta.items():
            if key not in IMAGE_KEYS or not content:
                continue
            # Absolute site URLs and root-relative paths both resolve into site/.
            relative = content.split("tinyzkp.com", 1)[-1].lstrip("/")
            if not relative:
                failures.append(f"{name} {key} is empty")
                continue
            if not (SITE / relative).is_file():
                failures.append(
                    f"{name} {key} points at {content!r}, which does not exist in "
                    f"site/ - the social card would 404"
                )

    return failures


def main() -> int:
    failures = check()
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        print(f"\nsite metadata truth check: {len(failures)} failure(s)")
        return 1
    state = "withdrawn" if guard_sku_withdrawn() else "not withdrawn"
    pages = len(list(SITE.glob("*.html")))
    print(f"PASS site metadata truth check ({pages} pages, Guard SKU {state})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
