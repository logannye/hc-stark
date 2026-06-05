"""Marketing-site ↔ pricing.json parity lint (audit WEB-1).

The Rust/Python parity tests guard the rate sheet but NOT the marketing HTML, so
the homepage shipped a Developer "5,000 proofs/mo" quota and a Scale "1M trace
steps included" allotment — neither of which exists in pricing.json (paid plans
are usage-metered with a $-denominated monthly cap, no proof-count or
included-step quota). These tests fail on any such fabricated quota string so the
copy can't silently drift from the rate sheet again.
"""

import os
import re

import pytest

SITE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "site")
PAGES = ["index.html", "signup.html", "docs.html", "try.html", "compute.html", "welcome.html"]

# The only legitimate proof-count claim is the FREE tier's ≈100/mo, derived from
# free.monthly_cap_cents (500) / cheapest-tier price (5¢) = 100. Any other
# numeric "N proofs/mo" is a fabricated paid-tier quota.
_FREE_TIER_PROOF_COUNT = "100"
_PROOF_QUOTA_RE = re.compile(r"([\d,]+)\s*proofs?\s*(?:/|per)\s*(?:mo|month)", re.IGNORECASE)
# pricing.json has no "included trace steps" allotment for any plan.
_INCLUDED_STEPS_RE = re.compile(r"trace steps? included", re.IGNORECASE)


def _read(page):
    path = os.path.join(SITE_DIR, page)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("page", PAGES)
def test_no_fabricated_proof_count_quota(page):
    html = _read(page)
    if html is None:
        pytest.skip(f"{page} not present")
    offenders = [
        m.group(0)
        for m in _PROOF_QUOTA_RE.finditer(html)
        if m.group(1).replace(",", "") != _FREE_TIER_PROOF_COUNT
    ]
    assert not offenders, (
        f"{page} claims a proof-count quota not in pricing.json (paid plans are "
        f"usage-metered with a $-cap, not a proof quota): {offenders}"
    )


@pytest.mark.parametrize("page", PAGES)
def test_no_included_trace_steps_allotment(page):
    html = _read(page)
    if html is None:
        pytest.skip(f"{page} not present")
    offenders = _INCLUDED_STEPS_RE.findall(html)
    assert not offenders, (
        f"{page} claims 'trace steps included', but pricing.json has no included-"
        f"step allotment for any plan: {offenders}"
    )
