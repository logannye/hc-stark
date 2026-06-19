"""Marketing-site ↔ pricing.json parity lint (audit WEB-1).

The Rust/Python parity tests guard the rate sheet but NOT the marketing HTML, so
the homepage shipped a Developer "5,000 proofs/mo" quota and a Scale "1M trace
steps included" allotment — neither of which exists in pricing.json (paid plans
are usage-metered with a $-denominated monthly cap, no proof-count or
included-step quota). These tests fail on any such fabricated quota string so the
copy can't silently drift from the rate sheet again.
"""

import os
from pathlib import Path
import re

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SITE_DIR = REPO_ROOT / "site"
PAGES = [
    str(path.relative_to(SITE_DIR))
    for path in sorted(SITE_DIR.glob("*.html"))
    if path.name not in {"privacy.html", "terms.html"}
] + [
    str(path.relative_to(SITE_DIR))
    for path in sorted((SITE_DIR / "use-cases").glob("*.html"))
]

COPY_LINT_FILES = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "BUSINESS_GUIDE.md",
    REPO_ROOT / "deploy" / "server-card.json",
    REPO_ROOT / "clients" / "cli" / "README.md",
    REPO_ROOT / "clients" / "cli" / "package.json",
]
COPY_LINT_FILES += sorted((REPO_ROOT / "marketing").glob("*.md"))
COPY_LINT_FILES += sorted((REPO_ROOT / "skills" / "tinyzkp-proofs").glob("*.md"))
COPY_LINT_FILES += [SITE_DIR / page for page in PAGES]

# The only legitimate proof-count claim is the FREE tier's ≈100/mo, derived from
# free.monthly_cap_cents (500) / cheapest-tier price (5¢) = 100. Any other
# numeric "N proofs/mo" is a fabricated paid-tier quota.
_FREE_TIER_PROOF_COUNT = "100"
_PROOF_QUOTA_RE = re.compile(r"([\d,]+)\s*proofs?\s*(?:/|per)\s*(?:mo|month)", re.IGNORECASE)
# pricing.json has no "included trace steps" allotment for any plan.
_INCLUDED_STEPS_RE = re.compile(r"trace steps? included", re.IGNORECASE)


def _read(page):
    path = SITE_DIR / page
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


FORBIDDEN_COPY_PATTERNS = [
    ("six templates", re.compile(r"\bsix\s+proof\s+templates\b|\bsix\s+templates\b", re.IGNORECASE)),
    ("any computation", re.compile(r"\bany\s+computation\b", re.IGNORECASE)),
    ("default privacy claim", re.compile(r"without\s+(?:revealing|learning)", re.IGNORECASE)),
    ("production zkVM/zkML", re.compile(r"\bproduction\s+zk(?:vm|ml)\b", re.IGNORECASE)),
    ("EVM calldata", re.compile(r"\bEVM\s+calldata\b|\bcalldata\b", re.IGNORECASE)),
    ("unaudited range_proof", re.compile(r"\brange_proof\b", re.IGNORECASE)),
    ("unaudited hash_preimage", re.compile(r"\bhash_preimage\b", re.IGNORECASE)),
    ("unaudited policy_compliance", re.compile(r"\bpolicy_compliance\b", re.IGNORECASE)),
    ("unaudited data_integrity", re.compile(r"\bdata_integrity\b", re.IGNORECASE)),
    ("unaudited computation_attestation", re.compile(r"\bcomputation_attestation\b", re.IGNORECASE)),
    ("unaudited soundness-bit claim", re.compile(r"\b\d+\s*bits?\s+of\s+(?:soundness|security)\b", re.IGNORECASE)),
]


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


@pytest.mark.parametrize("path", COPY_LINT_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_public_copy_has_no_forbidden_overclaims(path):
    text = path.read_text(encoding="utf-8")
    offenders = []
    for label, pattern in FORBIDDEN_COPY_PATTERNS:
        matches = sorted(set(m.group(0) for m in pattern.finditer(text)))
        if matches:
            offenders.append(f"{label}: {matches}")
    assert not offenders, f"{path.relative_to(REPO_ROOT)} contains forbidden public-copy claims: {offenders}"
