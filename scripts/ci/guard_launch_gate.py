#!/usr/bin/env python3
"""Derive every public Guard launch state from digest-bound evidence.

The checked-in source remains deliberately blocked.  A qualified state can be
produced only when every gate points at a safe, strict-JSON evidence envelope
whose digest, release identity, age, kind, and gate-specific claims validate.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import strict_json  # noqa: E402
import guard_release_index  # noqa: E402


DEFAULT_SOURCE = ROOT / "release" / "guard-launch-evidence-v2.json"
DEFAULT_CONFIG = ROOT / "release" / "guard-launch-state-v2.json"
OUTPUTS = {
    "launch": DEFAULT_CONFIG,
    "candidate_authorization": ROOT
    / "release"
    / "guard-candidate-build-authorization-v1.json",
    "release": ROOT / "site" / "release.json",
    "commerce": ROOT / "site" / "commerce.json",
    "pricing": ROOT / "site" / "pricing.json",
    "discovery": ROOT / "site" / "discovery.json",
    "compatibility": ROOT / "site" / "compatibility.json",
    "offers": ROOT / "site" / "offers.jsonld",
    "release_channels": ROOT / "release" / "release-channels-v1.json",
    "site_release_channels": ROOT / "site" / "release-channels-v1.json",
}
EVIDENCE_PREFIX = PurePosixPath("release/evidence/guard-launch-v2")
PROFILE_ID = "tinyzkp-p3-goldilocks-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_THIRD_PARTY_NOTICES_BYTES = 4 * 1024 * 1024
REUSABLE_EVIDENCE_MAX_DAYS = 730
CURRENT_EVALUATION_MAX_AGE = timedelta(hours=24)
ARTIFACT_PUBLICATION_BLOCKER = "guard_artifact_published"
PRIOR_QUALIFIED_RELEASE_GATE = "prior_qualified_release"
AUTHORIZATION_POLICY = "owner_only_ga_v1"
QUALIFICATION_BASIS = "owner_attested"
SIGNING_TRUST_PATH = "release/guard-signing-trust-v1.json"
SIGNING_PUBLIC_KEY_PATH = "release/guard-signing-public-key.pem"
RELEASE_INDEX_NAME = "guard-release-index-v1.json"
RELEASE_INDEX_SIGNATURE_NAME = "guard-release-index-v1.json.sig"
RELEASE_INDEX_HANDOFF_NAME = "guard-release-index-revision-handoff-v1.json"
ARTIFACT_PUBLICATION_NAME = "guard-artifact-publication-v1.json"
ARTIFACT_PUBLICATION_BUNDLE_NAME = "guard-artifact-publication-v1.sigstore.json"
ARTIFACT_PUBLICATION_PURPOSE = "guard_launch:artifact_publication"
LEGAL_DOCUMENT_PATHS = {
    "eula_sha256": "legal/EULA.txt",
    "notices_sha256": "legal/THIRD-PARTY-NOTICES.txt",
    "terms_sha256": "site/terms.html",
    "privacy_sha256": "site/privacy.html",
    "refunds_sha256": "site/refunds.html",
}
LEGACY_RETIREMENT_NOTICE_PATH = "docs/runbooks/legacy_retirement_notice.md"
RECEIPT_DOWNLOAD_URL = "https://tinyzkp.com/releases"
GUARD_SKU_WITHDRAWAL = ROOT / "release" / "guard-sku-withdrawal-v1.json"


def _guard_sku_withdrawn(path: Path | None = None) -> bool:
    """True when the Guard SKU is recorded as withdrawn.

    Absent or malformed record means NOT withdrawn: this function must never
    silently withdraw a live SKU because a file failed to parse.
    """
    source = GUARD_SKU_WITHDRAWAL if path is None else path
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get("withdrawn") is True


ACQUISITION_ROUTES = (
    "/doctor",
    "/plonky3-out-of-memory",
    "/resumable-plonky3-prover",
    "/ssd-backed-plonky3-proving",
)
ACQUISITION_PAGES = {
    route: ROOT / "site" / f"{route.removeprefix('/')}.html"
    for route in ACQUISITION_ROUTES
}
LLMS_ACQUISITION_LINES = (
    "- Doctor: https://tinyzkp.com/doctor",
    "- Plonky3 out of memory: https://tinyzkp.com/plonky3-out-of-memory",
    "- Resumable Plonky3 prover: https://tinyzkp.com/resumable-plonky3-prover",
    "- SSD-backed Plonky3 proving: https://tinyzkp.com/ssd-backed-plonky3-proving",
)
LLMS_ACQUISITION_RECOMMENDATIONS = (
    "- Run the free doctor first, once the signed evaluation release is "
    "published: https://tinyzkp.com/doctor",
)
LLMS_STATUS_RE = re.compile(r"^Current status:.*$", re.MULTILINE)
LLMS_GUARD_AVAILABILITY_RE = re.compile(
    r"^- Guard (?:is|sales are|checkout is).*$", re.MULTILINE
)
CHECKOUT_CONTROL_RE = re.compile(
    r'(<a\b[^>]*\bdata-checkout="(?:annual|monthly)"[^>]*>)(.*?)(</a>)'
)
DOCTOR_STATUS_RE = re.compile(
    r'<div class="notice" data-doctor-status>.*?</div>'
)
LAUNCH_COPY_RE = re.compile(
    r'(<(?P<tag>div|p)\b(?=[^>]*\bdata-launch-copy="'
    r'(?P<key>[a-z0-9-]+)")[^>]*>).*?(</(?P=tag)>)',
    re.DOTALL,
)
BASE_SITEMAP_ROUTES = (
    "/",
    # The live product. Its absence here was not cosmetic: the demand
    # threshold in scripts/ci/demand_report.py counts callers of an endpoint
    # that search engines were never told about, which makes a zero reading
    # unattributable. See the achievability preconditions in that module.
    "/estimate",
    "/guard",
    "/compatibility",
    "/benchmarks",
    "/troubleshooting",
    "/pricing",
    "/docs",
    "/security",
    "/releases",
    "/support",
)
# Acquisition (SEO landing) routes are spliced in after the primary product
# pages and before the reference pages. Named rather than inlined so adding a
# primary page cannot silently reorder the acquisition block.
SITEMAP_ACQUISITION_SPLICE_INDEX = 5
ACQUISITION_ROBOTS_RE = re.compile(
    r'<meta name="robots" content="(?:noindex,nofollow|index,follow)" '
    r'data-guard-acquisition>'
)

GATE_POLICIES: dict[str, tuple[str, int]] = {
    "engine_release_ready": ("EngineReleaseEvidenceV1", 120),
    "guard_release_ready": ("GuardReleaseEvidenceV1", 120),
    "legal_terms_approved": ("LegalApprovalEvidenceV1", 365),
    "merchant_sandbox_lifecycle_passed": ("MerchantSandboxEvidenceV1", 90),
    "merchant_live_owner_smoke_passed": ("MerchantLiveSmokeEvidenceV1", 30),
    "legacy_obligations_resolved": ("LegacyResolutionEvidenceV1", 365),
    # Decommission is a signed point-in-time transition, not a renewable
    # assertion that forces the owner to recreate retired infrastructure facts.
    "hosted_infrastructure_decommissioned": ("DecommissionEvidenceV1", 3650),
    "release_rehearsal_within_budget": ("ReleaseRehearsalEvidenceV1", 90),
    PRIOR_QUALIFIED_RELEASE_GATE: ("PriorQualifiedReleaseEvidenceV1", 730),
}
CHANGE_CLASS_FRESH_GATES = {
    "proof_critical": frozenset(GATE_POLICIES),
    "guard_package_only": frozenset(
        {
            "guard_release_ready",
            "release_rehearsal_within_budget",
        }
    ),
    "site_legal_pricing": frozenset(
        {
            "legal_terms_approved",
            "merchant_sandbox_lifecycle_passed",
            "merchant_live_owner_smoke_passed",
            "release_rehearsal_within_budget",
        }
    ),
}
MUTABLE_FACT_FRESH_GATES = frozenset({"merchant_live_owner_smoke_passed"})
REQUIRED_GATES = frozenset(GATE_POLICIES) - {PRIOR_QUALIFIED_RELEASE_GATE}
BLOCKED_REASONS = {
    "engine_release_ready": "engine-release-evidence-missing",
    "guard_release_ready": "guard-release-evidence-missing",
    "legal_terms_approved": "legal-approval-missing",
    "merchant_sandbox_lifecycle_passed": "merchant-sandbox-evidence-missing",
    "merchant_live_owner_smoke_passed": "merchant-live-smoke-missing",
    "legacy_obligations_resolved": "legacy-resolution-evidence-missing",
    "hosted_infrastructure_decommissioned": "decommission-evidence-missing",
    "release_rehearsal_within_budget": "release-rehearsal-evidence-missing",
    PRIOR_QUALIFIED_RELEASE_GATE: "prior-qualified-release-evidence-missing",
    ARTIFACT_PUBLICATION_BLOCKER: "guard-artifact-publication-missing",
}
ADVISORY_ITEMS = frozenset(
    {
        "external_design_partner_integration",
        "five_unaided_installs",
        "implementation_review_no_high_findings",
        "independent_resource_reproduction",
        "plonky3_specialist_review",
        "three_external_workloads",
        "two_standard_annual_customers",
    }
)
LAUNCH_BLOCKERS = REQUIRED_GATES | {ARTIFACT_PUBLICATION_BLOCKER}
GATE_PURPOSES = {
    gate: f"guard_launch:{gate}" for gate in sorted(REQUIRED_GATES)
}
GATE_PURPOSES[PRIOR_QUALIFIED_RELEASE_GATE] = (
    f"guard_launch:{PRIOR_QUALIFIED_RELEASE_GATE}"
)
SALES_FREEZE_PURPOSE = "guard_launch:sales_freeze"
SALES_FREEZE_SIGNER_ID = "tinyzkp-owner-configuration-main"
INACTIVE_SALES_FREEZE = {
    "status": "inactive",
    "reason_code": "sales-not-frozen",
    "evidence": [],
}
MARKET_TRUST_PURPOSES = {
    "guard_market:doctor_evaluation_release",
    "guard_market:community_announcement",
    "guard_market:ecosystem_submission",
}
COMMERCE_STATES = {
    "unconfigured",
    "test_published",
    "test_verified",
    "live_hidden",
    "public_live",
    "sales_frozen",
}
MERCHANT_CATALOG_POLICY = {
    "monthly_price_usd": 499,
    "annual_price_usd": 4990,
    "annual_default": True,
    "annual_emphasized": True,
    "entitlement_mode": "lemon_squeezy_subscription_license_keys",
    "machine_activation_limit": None,
    "trials_allowed": False,
    "coupons_allowed": False,
    "usage_metering": False,
    "add_ons_allowed": False,
    "subscription_pause_offered": False,
    "enterprise_variants_allowed": False,
    "cancel_at_period_end": True,
    "portal_enabled": True,
    "dunning_enabled": True,
    "invoices_enabled": True,
}
REASON_ANCHORS = {
    "launch": "/releases#launch-blockers",
    "sales": "/pricing#sales-status",
    "portal": "/support#merchant-portal",
    "legal": "/terms#legal-status",
    "merchant": "/pricing#merchant-of-record-status",
    **{
        gate: f"/releases#gate-{gate.replace('_', '-')}"
        for gate in sorted(LAUNCH_BLOCKERS)
    },
}


class GateError(ValueError):
    """The evidence source or one of its referenced records is unsafe."""


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_records(records: list[tuple[str, bytes]], *, domain: str) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii") + b"\0")
    for name, payload in records:
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(str(len(payload)).encode("ascii") + b"\0")
        digest.update(payload)
    return digest.hexdigest()


def _normalized_site_html(payload: str) -> bytes:
    normalized = CHECKOUT_CONTROL_RE.sub(
        lambda match: match.group(1) + "__CHECKOUT_STATE__" + match.group(3),
        payload,
    )
    normalized = ACQUISITION_ROBOTS_RE.sub(
        '<meta name="robots" content="__ACQUISITION_STATE__" data-guard-acquisition>',
        normalized,
    )
    normalized = DOCTOR_STATUS_RE.sub(
        '<div class="notice" data-doctor-status>__DOCTOR_STATE__</div>',
        normalized,
    )
    normalized = LAUNCH_COPY_RE.sub(
        lambda match: (
            match.group(1)
            + f"__LAUNCH_COPY_{match.group('key')}__"
            + match.group(4)
        ),
        normalized,
    )
    return normalized.encode("utf-8")


def _normalized_site_file(path: Path) -> bytes:
    raw = path.read_bytes()
    if path.suffix == ".html":
        try:
            return _normalized_site_html(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise GateError(f"{path} is not UTF-8 HTML") from exc
    return raw


def _legal_document_sha256(root: Path, field: str) -> str:
    relative = LEGAL_DOCUMENT_PATHS[field]
    path, raw = _safe_fixed_file(
        root,
        relative,
        relative,
        maximum_bytes=(
            MAX_THIRD_PARTY_NOTICES_BYTES
            if field == "notices_sha256"
            else MAX_EVIDENCE_BYTES
        ),
    )
    if field in {"eula_sha256", "notices_sha256"}:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError(f"{relative} is not UTF-8") from error
        marker = (
            re.search(r"(?i)\b(?:unresolved|placeholder|todo|tbd)\b", text)
            if field == "eula_sha256"
            else re.search(
                r"(?im)^(?:unresolved|placeholder|todo|tbd)\b",
                text,
            )
        )
        if marker:
            raise GateError(f"{relative} still contains release-blocking markers")
    return sha256_bytes(_normalized_site_file(path))


def _eula_url(eula_sha256: str) -> str:
    if SHA256_RE.fullmatch(eula_sha256) is None:
        raise GateError("EULA URL requires an exact SHA-256")
    return f"https://tinyzkp.com/legal/{eula_sha256}/EULA.txt"


def _validate_eula_effective_date(root: Path, expected_release_date: str) -> None:
    relative = LEGAL_DOCUMENT_PATHS["eula_sha256"]
    _path, raw = _safe_fixed_file(root, relative, relative)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"{relative} is not UTF-8") from error
    matches = re.findall(r"(?m)^Effective Date: (\d{4}-\d{2}-\d{2})$", text)
    if len(matches) != 1:
        raise GateError(
            "owner-approved EULA must contain exactly one "
            "Effective Date: YYYY-MM-DD line"
        )
    try:
        parsed = datetime.strptime(matches[0], "%Y-%m-%d")
    except ValueError as error:
        raise GateError("owner-approved EULA effective date is invalid") from error
    if (
        parsed.strftime("%Y-%m-%d") != matches[0]
        or matches[0] != expected_release_date
    ):
        raise GateError(
            "owner-approved EULA effective date differs from legal release_date"
        )


def _validate_public_eula_tree(
    root: Path, *, current_sha256: str | None = None, current_bytes: bytes | None = None
) -> None:
    tree = root / "site" / "legal"
    if not tree.exists() and not tree.is_symlink():
        if current_sha256 is not None:
            raise GateError("current digest-addressed public EULA is unavailable")
        return
    metadata = tree.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise GateError("site/legal must be a real directory")
    observed: set[str] = set()
    for revision in tree.iterdir():
        revision_metadata = revision.lstat()
        digest = revision.name
        if (
            SHA256_RE.fullmatch(digest) is None
            or stat.S_ISLNK(revision_metadata.st_mode)
            or not stat.S_ISDIR(revision_metadata.st_mode)
        ):
            raise GateError("site/legal contains an invalid EULA revision path")
        entries = list(revision.iterdir())
        if len(entries) != 1 or entries[0].name != "EULA.txt":
            raise GateError("site/legal EULA revision inventory differs")
        document = entries[0]
        document_metadata = document.lstat()
        if (
            stat.S_ISLNK(document_metadata.st_mode)
            or not stat.S_ISREG(document_metadata.st_mode)
            or document_metadata.st_nlink != 1
        ):
            raise GateError("site/legal EULA revision is not a single-link file")
        raw = document.read_bytes()
        if not raw or sha256_bytes(raw) != digest:
            raise GateError("site/legal EULA revision digest differs")
        observed.add(digest)
    if current_sha256 is not None and (
        current_sha256 not in observed
        or current_bytes is None
        or (tree / current_sha256 / "EULA.txt").read_bytes() != current_bytes
    ):
        raise GateError("current digest-addressed public EULA bytes differ")


def _site_bundle_sha256(root: Path) -> str:
    site = root / "site"
    generated = {
        "commerce.json",
        "pricing.json",
        "discovery.json",
        "compatibility.json",
        "release.json",
        "offers.jsonld",
        "release-channels-v1.json",
        "sitemap.xml",
        "llms.txt",
        RELEASE_INDEX_NAME,
        RELEASE_INDEX_SIGNATURE_NAME,
        RELEASE_INDEX_HANDOFF_NAME,
        ARTIFACT_PUBLICATION_NAME,
        ARTIFACT_PUBLICATION_BUNDLE_NAME,
    }
    records: list[tuple[str, bytes]] = []
    if not site.is_dir():
        raise GateError("site source tree is unavailable for rehearsal binding")
    _validate_public_eula_tree(root)
    for path in sorted(site.rglob("*")):
        if path.is_symlink():
            raise GateError("site source tree contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(site).as_posix()
        if (
            relative in generated
            or relative.startswith("release-index-revisions/")
            or relative.startswith("artifact-publications/")
            or relative.startswith("legal/")
        ):
            continue
        records.append((relative, _normalized_site_file(path)))
    if not records:
        raise GateError("site source tree is empty")
    return _digest_records(records, domain="tinyzkp-site-source-v1")


def _reviewed_file_set_sha256(
    root: Path, paths: tuple[str, ...], *, domain: str
) -> str:
    records: list[tuple[str, bytes]] = []
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise GateError(f"reviewed release file is unavailable: {relative}")
        records.append((relative, path.read_bytes()))
    return _digest_records(records, domain=domain)


def _validate_published_index_files(
    root: Path, claims: dict[str, Any]
) -> dict[str, str]:
    original_index_sha = claims["release_index_sha256"]
    original_signature_sha = claims["release_index_signature_sha256"]
    stable_index = root / "site" / RELEASE_INDEX_NAME
    stable_signature = root / "site" / RELEASE_INDEX_SIGNATURE_NAME
    if stable_index.is_symlink() or not stable_index.is_file():
        raise GateError("published Guard release index index is unavailable")
    if stable_signature.is_symlink() or not stable_signature.is_file():
        raise GateError("published Guard release index signature is unavailable")
    index_sha = sha256_bytes(stable_index.read_bytes())
    signature_sha = sha256_bytes(stable_signature.read_bytes())
    locations = {
        "index": stable_index,
        "signature": stable_signature,
        "revision_index": (
            root
            / "site"
            / "release-index-revisions"
            / index_sha
            / RELEASE_INDEX_NAME
        ),
        "revision_signature": (
            root
            / "site"
            / "release-index-revisions"
            / index_sha
            / RELEASE_INDEX_SIGNATURE_NAME
        ),
    }
    expected = {
        "index": index_sha,
        "revision_index": index_sha,
        "signature": signature_sha,
        "revision_signature": signature_sha,
    }
    for label, path in locations.items():
        if path.is_symlink() or not path.is_file():
            raise GateError(f"published Guard release index {label} is unavailable")
        if sha256_bytes(path.read_bytes()) != expected[label]:
            raise GateError(f"published Guard release index {label} digest differs")
    if (
        locations["index"].read_bytes()
        != locations["revision_index"].read_bytes()
        or locations["signature"].read_bytes()
        != locations["revision_signature"].read_bytes()
    ):
        raise GateError("stable and immutable Guard release index bytes differ")
    public_key = root / SIGNING_PUBLIC_KEY_PATH
    if public_key.is_symlink() or not public_key.is_file():
        raise GateError("Guard signing public key is unavailable for release index")
    public_key_sha256 = sha256_bytes(public_key.read_bytes())
    revision_root = root / "site" / "release-index-revisions"
    if index_sha == original_index_sha:
        if signature_sha != original_signature_sha:
            raise GateError("published original Guard release index signature differs")
        if (root / "site" / RELEASE_INDEX_HANDOFF_NAME).exists():
            raise GateError("original Guard release index cannot contain a revision handoff")
    else:
        current_sha = index_sha
        visited: set[str] = set()
        while current_sha != original_index_sha:
            if current_sha in visited or len(visited) >= 1024:
                raise GateError("Guard release index revision chain is cyclic or oversized")
            visited.add(current_sha)
            directory = revision_root / current_sha
            handoff_path = directory / RELEASE_INDEX_HANDOFF_NAME
            signature_path = directory / RELEASE_INDEX_SIGNATURE_NAME
            current_path = directory / RELEASE_INDEX_NAME
            if any(
                path.is_symlink() or not path.is_file()
                for path in (handoff_path, signature_path, current_path)
            ):
                raise GateError("Guard release index revision chain is incomplete")
            try:
                current_value, current_raw = guard_release_index.load(
                    current_path, "revised Guard release index"
                )
                handoff_value, handoff_raw = guard_release_index.load(
                    handoff_path, "Guard release index revision handoff"
                )
            except guard_release_index.IndexError as exc:
                raise GateError(str(exc)) from exc
            prior_sha = handoff_value.get("prior_index_sha256")
            if not isinstance(prior_sha, str) or not SHA256_RE.fullmatch(prior_sha):
                raise GateError("Guard release index revision prior digest is invalid")
            prior_path = revision_root / prior_sha / RELEASE_INDEX_NAME
            if prior_path.is_symlink() or not prior_path.is_file():
                raise GateError("Guard release index revision prior is unavailable")
            try:
                prior_value, prior_raw = guard_release_index.load(
                    prior_path, "prior Guard release index"
                )
                handoff = guard_release_index.validate_handoff(
                    handoff_value,
                    prior_raw=prior_raw,
                    revised_raw=current_raw,
                    public_key_sha256=public_key_sha256,
                )
                guard_release_index.validate_transition(
                    prior_value, current_value, handoff
                )
            except guard_release_index.IndexError as exc:
                raise GateError(str(exc)) from exc
            if sha256_bytes(current_raw) != current_sha:
                raise GateError("Guard release index revision digest differs")
            if current_sha == index_sha:
                stable_handoff = root / "site" / RELEASE_INDEX_HANDOFF_NAME
                if (
                    stable_handoff.is_symlink()
                    or not stable_handoff.is_file()
                    or stable_handoff.read_bytes() != handoff_raw
                    or signature_path.read_bytes() != stable_signature.read_bytes()
                ):
                    raise GateError(
                        "stable Guard release index revision handoff differs"
                    )
            current_sha = prior_sha
        original_index = revision_root / original_index_sha / RELEASE_INDEX_NAME
        original_signature = (
            revision_root / original_index_sha / RELEASE_INDEX_SIGNATURE_NAME
        )
        if (
            original_index.is_symlink()
            or not original_index.is_file()
            or sha256_bytes(original_index.read_bytes()) != original_index_sha
            or original_signature.is_symlink()
            or not original_signature.is_file()
            or sha256_bytes(original_signature.read_bytes())
            != original_signature_sha
        ):
            raise GateError("original Guard release index chain anchor differs")
    return {
        "url": f"https://tinyzkp.com/{RELEASE_INDEX_NAME}",
        "signature_url": f"https://tinyzkp.com/{RELEASE_INDEX_SIGNATURE_NAME}",
        "sha256": index_sha,
        "signature_sha256": signature_sha,
        "immutable_revision_url": (
            "https://tinyzkp.com/release-index-revisions/"
            f"{index_sha}/{RELEASE_INDEX_NAME}"
        ),
        "immutable_revision_signature_url": (
            "https://tinyzkp.com/release-index-revisions/"
            f"{index_sha}/{RELEASE_INDEX_SIGNATURE_NAME}"
        ),
        "origin_release_url": claims["release_index_url"],
        "origin_release_sha256": original_index_sha,
        "origin_release_signature_url": claims[
            "release_index_signature_url"
        ],
        "origin_release_signature_sha256": original_signature_sha,
    }


def _validate_artifact_publication(
    root: Path,
    *,
    guard_claims: dict[str, Any] | None,
    engine_claims: dict[str, Any] | None,
    identity: dict[str, Any],
    trust_policy: dict[str, Any],
    prior_claim: dict[str, Any] | None,
    release_change_class: str,
    signature_runner: Callable[..., subprocess.CompletedProcess[str]],
    cosign_path: Path | None,
) -> dict[str, Any]:
    publication_path, publication_raw = _safe_fixed_file(
        root,
        f"site/{ARTIFACT_PUBLICATION_NAME}",
        f"site/{ARTIFACT_PUBLICATION_NAME}",
    )
    bundle_path, bundle_raw = _safe_fixed_file(
        root,
        f"site/{ARTIFACT_PUBLICATION_BUNDLE_NAME}",
        f"site/{ARTIFACT_PUBLICATION_BUNDLE_NAME}",
    )
    try:
        publication_value = strict_json.loads(publication_raw)
        bundle_value = strict_json.loads(bundle_raw)
    except ValueError as error:
        raise GateError(f"artifact publication evidence is not strict JSON: {error}") from error
    if not isinstance(bundle_value, dict):
        raise GateError("artifact publication Sigstore bundle must be an object")
    publication = exact_object(
        publication_value,
        {
            "schema_version",
            "document_type",
            "authorization_policy",
            "qualification_basis",
            "signer_id",
            "purpose",
            "publication_kind",
            "promotion_repository",
            "promotion_workflow",
            "promotion_run_id",
            "promotion_run_attempt",
            "promotion_source_sha",
            "workflow_source_sha",
            "prior_release_index_sha256",
            "published_at",
            "release_identity",
            "guard_release_tag",
            "artifact_url",
            "artifact_sha256",
            "channel_url",
            "channel_sha256",
            "release_index_url",
            "release_index_sha256",
            "release_index_signature_url",
            "release_index_signature_sha256",
            "guard_oci_reference",
            "guard_oci_digest",
            "engine_oci_reference",
            "engine_oci_digest",
            "anonymous_checks",
        },
        "GuardArtifactPublicationV1",
    )
    anonymous = exact_object(
        publication["anonymous_checks"],
        {
            "github_release_artifact",
            "github_release_channel",
            "github_release_index",
            "guard_oci_manifest",
            "engine_oci_manifest",
        },
        "GuardArtifactPublicationV1 anonymous_checks",
    )
    _all_true(
        anonymous,
        tuple(sorted(anonymous)),
        "GuardArtifactPublicationV1 anonymous_checks",
    )
    if (
        publication["schema_version"] != 1
        or publication["document_type"] != "GuardArtifactPublicationV1"
        or publication["authorization_policy"] != AUTHORIZATION_POLICY
        or publication["qualification_basis"] != QUALIFICATION_BASIS
        or publication["signer_id"] != "tinyzkp-artifact-publication-main"
        or publication["purpose"] != ARTIFACT_PUBLICATION_PURPOSE
        or publication["publication_kind"] not in {"initial_ga", "successor_ga"}
        or publication["promotion_repository"] != "logannye/hc-stark"
        or publication["promotion_workflow"]
        != ".github/workflows/promote-guard-release.yml"
        or not isinstance(publication["promotion_run_id"], str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", publication["promotion_run_id"])
        is None
        or not isinstance(publication["promotion_run_attempt"], int)
        or isinstance(publication["promotion_run_attempt"], bool)
        or publication["promotion_run_attempt"] < 1
        or not isinstance(publication["promotion_source_sha"], str)
        or GIT_SHA_RE.fullmatch(publication["promotion_source_sha"]) is None
        or not isinstance(publication["workflow_source_sha"], str)
        or GIT_SHA_RE.fullmatch(publication["workflow_source_sha"]) is None
        or publication["release_identity"] != identity
        or publication["guard_release_tag"]
        != f"guard-v{identity['guard_version']}"
        or re.fullmatch(r"[0-9a-f]{64}", publication["artifact_sha256"] or "")
        is None
        or re.fullmatch(r"[0-9a-f]{64}", publication["channel_sha256"] or "")
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", publication["release_index_sha256"] or ""
        )
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}", publication["release_index_signature_sha256"] or ""
        )
        is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", publication["guard_oci_digest"] or "")
        is None
        or publication["guard_oci_reference"]
        != f"ghcr.io/logannye/tinyzkp-guard@{publication['guard_oci_digest']}"
        or re.fullmatch(r"sha256:[0-9a-f]{64}", publication["engine_oci_digest"] or "")
        is None
        or publication["engine_oci_reference"]
        != f"ghcr.io/logannye/tinyzkp-engine@{publication['engine_oci_digest']}"
    ):
        raise GateError("artifact publication evidence identity differs")
    if (
        release_change_class in {"guard_package_only", "proof_critical"}
        and prior_claim is not None
    ):
        expected_prior_sha = (
            prior_claim["prior_release_index_sha256"]
        )
        if (
            publication["publication_kind"] != "successor_ga"
            or publication["prior_release_index_sha256"] != expected_prior_sha
        ):
            raise GateError("artifact publication predecessor binding differs")
    elif release_change_class != "retained_prior" and prior_claim is None:
        if (
            publication["publication_kind"] != "initial_ga"
            or publication["prior_release_index_sha256"] is not None
        ):
            raise GateError(
                "first artifact publication must be initial_ga with no predecessor"
            )
    if publication["publication_kind"] == "successor_ga":
        prior_sha = publication["prior_release_index_sha256"]
        if not isinstance(prior_sha, str) or SHA256_RE.fullmatch(prior_sha) is None:
            raise GateError("successor artifact publication predecessor is invalid")
        publication_index_relative = (
            "site/release-index-revisions/"
            f"{publication['release_index_sha256']}/{RELEASE_INDEX_NAME}"
        )
        _current_index_path, current_index_raw = _safe_fixed_file(
            root, publication_index_relative, publication_index_relative
        )
        prior_relative = (
            f"site/release-index-revisions/{prior_sha}/{RELEASE_INDEX_NAME}"
        )
        prior_index_path, prior_index_raw = _safe_fixed_file(
            root, prior_relative, prior_relative
        )
        if (
            sha256_bytes(current_index_raw) != publication["release_index_sha256"]
            or sha256_bytes(prior_index_raw) != prior_sha
        ):
            raise GateError("successor artifact publication index chain differs")
        try:
            current_index = strict_json.loads(current_index_raw)
            prior_index = strict_json.loads(prior_index_raw)
            guard_release_index.validate_successor(
                prior_index,
                current_index,
                expected_new_identity=current_index["current_release_identity"],
            )
        except (ValueError, KeyError, guard_release_index.IndexError) as error:
            raise GateError(
                f"successor artifact publication index chain differs: {error}"
            ) from error
    if guard_claims is not None and any(
        publication[field] != guard_claims[claim_field]
        for field, claim_field in {
            "artifact_url": "artifact_url",
            "artifact_sha256": "artifact_sha256",
            "channel_url": "channel_url",
            "channel_sha256": "channel_identity_sha256",
            "release_index_url": "release_index_url",
            "release_index_sha256": "release_index_sha256",
            "release_index_signature_url": "release_index_signature_url",
            "release_index_signature_sha256": "release_index_signature_sha256",
            "guard_oci_digest": "oci_digest",
        }.items()
    ):
        raise GateError("artifact publication differs from current Guard readiness")
    if engine_claims is not None and (
        publication["engine_oci_digest"] != engine_claims["engine_oci_digest"]
    ):
        raise GateError("artifact publication differs from current engine readiness")
    parse_timestamp(publication["published_at"], "artifact publication published_at")
    _verify_signature(
        claim=publication_path,
        bundle=bundle_path,
        signer_id=publication["signer_id"],
        purpose=publication["purpose"],
        workflow_source_sha=publication["workflow_source_sha"],
        trust_policy=trust_policy,
        runner=signature_runner,
        cosign_path=cosign_path,
    )
    publication_sha = sha256_bytes(publication_raw)
    immutable_root = root / "site" / "artifact-publications" / publication_sha
    immutable_record = immutable_root / ARTIFACT_PUBLICATION_NAME
    immutable_bundle = immutable_root / ARTIFACT_PUBLICATION_BUNDLE_NAME
    if (
        immutable_record.is_symlink()
        or not immutable_record.is_file()
        or immutable_record.read_bytes() != publication_raw
        or immutable_bundle.is_symlink()
        or not immutable_bundle.is_file()
        or immutable_bundle.read_bytes() != bundle_raw
    ):
        raise GateError("immutable artifact publication evidence differs")
    return {
        "record": publication,
        "reference": {
            "path": f"site/{ARTIFACT_PUBLICATION_NAME}",
            "sha256": publication_sha,
            "signature_path": f"site/{ARTIFACT_PUBLICATION_BUNDLE_NAME}",
            "signature_sha256": sha256_bytes(bundle_raw),
            "signer_id": publication["signer_id"],
            "purpose": publication["purpose"],
        },
    }


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(f"{label} must be an object")
    missing = keys - set(value)
    extra = set(value) - keys
    if missing or extra:
        raise GateError(
            f"{label} fields differ; missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return value


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise GateError(f"{label} must be second-precision UTC")
    return parsed


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = strict_json.loads(raw)
    except (OSError, ValueError) as exc:
        raise GateError(f"cannot read strict {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{label} must be an object")
    return value


def load_config(path: Path) -> dict[str, Any]:
    """Backward-compatible loader used by CI callers."""

    return load_json(path, "launch-state")


def _safe_evidence_file(root: Path, relative: str) -> tuple[Path, bytes]:
    if not isinstance(relative, str) or not relative:
        raise GateError("evidence path must be a non-empty string")
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or pure.parts[: len(EVIDENCE_PREFIX.parts)] != EVIDENCE_PREFIX.parts
        or pure.suffix != ".json"
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != relative
    ):
        raise GateError(
            f"evidence path must be a normalized JSON path below {EVIDENCE_PREFIX}"
        )
    path = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise GateError(f"evidence path is unavailable: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GateError(f"evidence path contains a symlink: {relative}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GateError(f"evidence must be a single-link regular file: {relative}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_EVIDENCE_BYTES:
        raise GateError(f"evidence size is invalid: {relative}")
    return path, path.read_bytes()


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GateError(f"{label} must be a non-negative integer")
    return value


def _all_true(claims: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    for field in fields:
        if claims.get(field) is not True:
            raise GateError(f"{label}.{field} must be true")


def _validate_catalog_policy(value: Any, label: str) -> dict[str, Any]:
    policy = exact_object(value, set(MERCHANT_CATALOG_POLICY), label)
    if policy != MERCHANT_CATALOG_POLICY:
        raise GateError(f"{label} differs from the locked Guard catalog policy")
    return policy


def _semantic_engine(claims: dict[str, Any]) -> None:
    required_true = {
        "official_verifier_acceptance",
        "proof_byte_equality",
        "resource_1m_target",
        "resource_16m_target",
        "fixed_host_matrix",
        "durable_recovery_matrix",
        "enospc_recovery",
        "fuzzing",
        "cli_smoke",
        "oci_smoke",
        "signed_artifacts",
        "checksums",
        "sbom",
        "provenance",
        "immutable_source_identity",
        "artifact_identity_bound",
    }
    exact_object(
        claims,
        {
            "backend_gate_status",
            "engine_release_tag",
            "engine_artifact_sha256",
            "engine_oci_digest",
            *required_true,
        },
        "engine evidence claims",
    )
    if claims["backend_gate_status"] != "qualified":
        raise GateError("engine evidence backend_gate_status must be qualified")
    if (
        not isinstance(claims["engine_release_tag"], str)
        or not re.fullmatch(r"backend-v[0-9A-Za-z.-]+", claims["engine_release_tag"])
    ):
        raise GateError("engine evidence engine_release_tag must be backend-v*")
    _all_true(claims, tuple(sorted(required_true)), "engine evidence claims")
    if not isinstance(claims["engine_artifact_sha256"], str) or not SHA256_RE.fullmatch(
        claims["engine_artifact_sha256"]
    ):
        raise GateError("engine evidence engine_artifact_sha256 must be a SHA-256")
    if not isinstance(claims["engine_oci_digest"], str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", claims["engine_oci_digest"]
    ):
        raise GateError("engine evidence engine_oci_digest must be a sha256 OCI digest")


def _semantic_guard(claims: dict[str, Any]) -> None:
    required_true = {
        "supervisor_protocol",
        "stdout_stderr_framing",
        "release_identity_enforcement",
        "signal_supervision",
        "orphan_prevention",
        "atomic_state",
        "canonical_doctor_plan_consumption",
        "diagnostics_redaction",
        "exact_release_checkpoint_lifecycle",
        "side_by_side_old_release_resume",
        "release_scoped_activation",
        "activated_release_offline",
        "cancelled_release_offline",
        "non_root_oci",
        "read_only_root",
        "network_none_after_activation",
        "ci_policy_operations",
        "signed_static_channel",
        "signed_release_index",
        "package_identity_parity",
        "artifact_identity_bound",
    }
    exact_object(
        claims,
        {
            "guard_channel_status",
            *required_true,
            "artifact_published",
            "artifact_url",
            "artifact_sha256",
            "oci_digest",
            "channel_url",
            "channel_identity_sha256",
            "release_index_url",
            "release_index_sha256",
            "release_index_signature_url",
            "release_index_signature_sha256",
            "channel_release_identity",
            "channel_guard_version",
            "channel_guard_source_sha",
            "channel_engine_source_sha",
            "channel_release_change_class",
            "channel_prior_qualified_release_identity",
            "channel_prior_release_index_sha256",
            "public_candidate_authorization_commit",
            "channel_compatibility_profile",
            "channel_artifact_sha256",
            "channel_oci_digest",
            "embedded_merchant_mode",
            "embedded_store_id",
            "embedded_product_id",
            "embedded_monthly_variant_id",
            "embedded_annual_variant_id",
            "embedded_catalog_policy",
            "embedded_release_date",
            "embedded_eula_sha256",
            "embedded_notices_sha256",
        },
        "Guard evidence claims",
    )
    if claims["guard_channel_status"] != "qualified":
        raise GateError("Guard evidence guard_channel_status must be qualified")
    if claims["artifact_published"] is not False:
        raise GateError(
            "Guard readiness evidence cannot claim publication; publication "
            "is derived from the imported signed release index"
        )
    if claims["embedded_merchant_mode"] != "live":
        raise GateError("Guard embedded merchant catalog must be live mode")
    _validate_catalog_policy(
        claims["embedded_catalog_policy"],
        "Guard evidence embedded_catalog_policy",
    )
    if claims["channel_release_change_class"] not in {
        "proof_critical",
        "guard_package_only",
    }:
        raise GateError("Guard channel release_change_class is invalid")
    prior_channel_fields = (
        claims["channel_prior_qualified_release_identity"],
        claims["channel_prior_release_index_sha256"],
    )
    if (prior_channel_fields[0] is None) != (prior_channel_fields[1] is None):
        raise GateError("Guard channel predecessor fields must both be set or absent")
    if prior_channel_fields[0] is not None and (
        not isinstance(prior_channel_fields[0], str)
        or not re.fullmatch(
            r"tinyzkp-guard/[A-Za-z0-9.+-]{1,512}", prior_channel_fields[0]
        )
        or not isinstance(prior_channel_fields[1], str)
        or not SHA256_RE.fullmatch(prior_channel_fields[1])
    ):
        raise GateError("Guard channel predecessor identity is malformed")
    if (
        not isinstance(claims["public_candidate_authorization_commit"], str)
        or not GIT_SHA_RE.fullmatch(
            claims["public_candidate_authorization_commit"]
        )
    ):
        raise GateError(
            "Guard evidence public_candidate_authorization_commit must be a Git SHA"
        )
    _all_true(claims, tuple(sorted(required_true)), "Guard evidence claims")
    _validate_https_url(
        claims["artifact_url"],
        "Guard artifact URL",
        required=True,
        allowed_hosts=("github.com", "githubusercontent.com"),
    )
    for field in (
        "artifact_sha256",
        "channel_identity_sha256",
        "release_index_sha256",
        "release_index_signature_sha256",
    ):
        if not isinstance(claims[field], str) or not SHA256_RE.fullmatch(claims[field]):
            raise GateError(f"Guard evidence {field} must be a SHA-256")
    try:
        embedded_release_date = datetime.strptime(
            claims["embedded_release_date"], "%Y-%m-%d"
        )
    except (TypeError, ValueError) as exc:
        raise GateError(
            "Guard evidence embedded_release_date must be YYYY-MM-DD"
        ) from exc
    if embedded_release_date.strftime("%Y-%m-%d") != claims[
        "embedded_release_date"
    ]:
        raise GateError("Guard evidence embedded_release_date must be YYYY-MM-DD")
    for field in ("embedded_eula_sha256", "embedded_notices_sha256"):
        if not isinstance(claims[field], str) or not SHA256_RE.fullmatch(
            claims[field]
        ):
            raise GateError(f"Guard evidence {field} must be a SHA-256")
    if (
        not isinstance(claims["oci_digest"], str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", claims["oci_digest"])
    ):
        raise GateError("Guard evidence oci_digest must be a sha256 OCI digest")
    _validate_https_url(
        claims["channel_url"],
        "Guard channel URL",
        required=True,
        allowed_hosts=("github.com", "githubusercontent.com"),
    )
    _validate_https_url(
        claims["release_index_url"],
        "Guard release index URL",
        required=True,
        allowed_hosts=("github.com", "githubusercontent.com"),
    )
    _validate_https_url(
        claims["release_index_signature_url"],
        "Guard release index signature URL",
        required=True,
        allowed_hosts=("github.com", "githubusercontent.com"),
    )


def _semantic_workloads(claims: dict[str, Any]) -> None:
    exact_object(
        claims,
        {
            "organizations",
            "workloads",
            "customer_specific_branches",
            "max_assistance_minutes",
            "max_workloads_per_organization",
            "public_adapter",
            "public_job_contract",
            "witness_data_transferred",
            "organizations_with_real_failure_problem",
            "minimum_documented_failure_cost_usd",
            "written_annual_price_acceptances",
        },
        "external-workload evidence claims",
    )
    if _positive_int(claims["organizations"], "organizations") != 3:
        raise GateError(
            "founding validation requires exactly three organizations"
        )
    if _positive_int(claims["workloads"], "workloads") != 3:
        raise GateError("founding validation requires exactly three workloads")
    if _positive_int(claims["customer_specific_branches"], "customer_specific_branches") != 0:
        raise GateError("customer-specific branches must be zero")
    if _positive_int(claims["max_assistance_minutes"], "max_assistance_minutes") > 240:
        raise GateError("external-workload assistance exceeds 240 minutes")
    if claims["max_workloads_per_organization"] != 1:
        raise GateError("external-workload evidence must cap one workload per organization")
    _all_true(
        claims,
        ("public_adapter", "public_job_contract"),
        "external-workload evidence claims",
    )
    if claims["witness_data_transferred"] is not False:
        raise GateError("external-workload evidence must record no witness transfer")
    if _positive_int(
        claims["organizations_with_real_failure_problem"],
        "organizations_with_real_failure_problem",
    ) != 3:
        raise GateError(
            "exactly three founding organizations require a real failure problem"
        )
    if _positive_int(
        claims["minimum_documented_failure_cost_usd"],
        "minimum_documented_failure_cost_usd",
    ) <= 4990:
        raise GateError("documented failure cost must materially exceed $4,990")
    if _positive_int(
        claims["written_annual_price_acceptances"],
        "written_annual_price_acceptances",
    ) < 2:
        raise GateError("two written standard-price acceptances are required")


def _semantic_customers(claims: dict[str, Any]) -> None:
    exact_object(
        claims,
        {
            "ordinary_paid_annual_subscriptions",
            "annual_price_usd",
            "ordinary_checkout",
            "cadence",
            "store_id",
            "product_id",
            "monthly_variant_id",
            "annual_variant_id",
            "catalog_policy",
        },
        "annual-customer evidence claims",
    )
    if _positive_int(
        claims["ordinary_paid_annual_subscriptions"],
        "ordinary_paid_annual_subscriptions",
    ) < 2:
        raise GateError("annual-customer evidence requires two paid subscriptions")
    if claims["annual_price_usd"] != 4990:
        raise GateError("annual-customer evidence must use the standard $4,990 price")
    _all_true(claims, ("ordinary_checkout",), "annual-customer evidence claims")
    if claims["cadence"] != "annual":
        raise GateError("founding paid subscriptions must be annual")
    _validate_catalog_policy(
        claims["catalog_policy"], "annual-customer catalog_policy"
    )


def _semantic_installs(
    claims: dict[str, Any], *, expected_machine_counts: frozenset[int]
) -> None:
    completed_steps = {
        "ordinary_purchase",
        "license_received",
        "artifact_downloaded",
        "artifact_signature_verified",
        "release_activated",
        "proof_produced",
        "official_verifier_accepted",
        "interruption_resumed",
        "ci_policy_passed",
        "portal_cancelled",
    }
    exact_object(
        claims,
        {
            "clean_machines",
            "verified_under_60_minutes",
            "median_minutes",
            *completed_steps,
        },
        "clean-machine evidence claims",
    )
    clean_machines = _positive_int(claims["clean_machines"], "clean_machines")
    if clean_machines not in expected_machine_counts:
        expected = " or ".join(str(value) for value in sorted(expected_machine_counts))
        raise GateError(
            f"clean-machine evidence requires exactly {expected} machines "
            "for this change class"
        )
    verified = _positive_int(
        claims["verified_under_60_minutes"], "verified_under_60_minutes"
    )
    if clean_machines == 5 and (verified < 4 or verified > 5):
        raise GateError(
            "verified-under-60 count must be four or five of the five journeys"
        )
    if clean_machines == 2 and verified != 2:
        raise GateError(
            "both Guard/package smoke journeys must verify under 60 minutes"
        )
    if _positive_int(claims["median_minutes"], "median_minutes") >= 30:
        raise GateError("clean-machine median must be under 30 minutes")
    _all_true(
        claims,
        tuple(sorted(completed_steps)),
        "clean-machine evidence claims",
    )


def _semantic_legal(claims: dict[str, Any]) -> None:
    approval_fields = {
        "seller_confirmed",
        "owner_approved",
        "eula",
        "third_party_notices",
        "privacy",
        "terms",
        "refunds",
    }
    exact_object(
        claims,
        {
            *approval_fields,
            "release_date",
            "eula_sha256",
            "notices_sha256",
            "terms_sha256",
            "privacy_sha256",
            "refunds_sha256",
        },
        "legal evidence claims",
    )
    _all_true(claims, tuple(sorted(approval_fields)), "legal evidence claims")
    try:
        release_date = datetime.strptime(claims["release_date"], "%Y-%m-%d")
    except (TypeError, ValueError) as exc:
        raise GateError("legal evidence release_date must be YYYY-MM-DD") from exc
    if release_date.strftime("%Y-%m-%d") != claims["release_date"]:
        raise GateError("legal evidence release_date must be YYYY-MM-DD")
    for field in (
        "eula_sha256",
        "notices_sha256",
        "terms_sha256",
        "privacy_sha256",
        "refunds_sha256",
    ):
        if not isinstance(claims[field], str) or not SHA256_RE.fullmatch(claims[field]):
            raise GateError(f"legal evidence {field} must be a SHA-256")


def _semantic_sandbox(claims: dict[str, Any]) -> None:
    fields = (
        "monthly",
        "annual",
        "decline",
        "renewal",
        "dunning",
        "portal",
        "cancellation",
        "resumption",
        "refund",
        "expiry",
        "receipt_delivered",
        "license_key_delivered",
        "terms_presented_before_payment",
        "terms_acceptance_required",
        "receipt_legal_binding_verified",
        "receipt_download_url",
        "eula_url",
        "eula_sha256",
        "terms_version",
        "mode",
        "store_id",
        "product_id",
        "monthly_variant_id",
        "annual_variant_id",
        "monthly_checkout_url",
        "annual_checkout_url",
        "portal_url",
        "store_hostname",
        "catalog_policy",
    )
    exact_object(claims, set(fields), "merchant sandbox evidence claims")
    _all_true(
        claims,
        tuple(
            field
            for field in fields
            if field
            not in {
                "mode",
                "store_id",
                "product_id",
                "monthly_variant_id",
                "annual_variant_id",
                "monthly_checkout_url",
                "annual_checkout_url",
                "portal_url",
                "store_hostname",
                "catalog_policy",
                "receipt_download_url",
                "eula_url",
                "eula_sha256",
                "terms_version",
            }
        ),
        "merchant sandbox evidence claims",
    )
    if claims["mode"] != "test":
        raise GateError("merchant sandbox evidence mode must be test")
    _validate_merchant_claim_urls(claims, "merchant sandbox evidence")
    _validate_catalog_policy(
        claims["catalog_policy"], "merchant sandbox catalog_policy"
    )
    _validate_merchant_legal_delivery(claims, "merchant sandbox evidence")


def _semantic_live(claims: dict[str, Any]) -> None:
    fields = (
        "monthly_variant_active",
        "annual_variant_active",
        "monthly_price_rendered",
        "annual_price_rendered",
        "checkout_rendered",
        "portal_configured",
        "license_keys_enabled",
        "receipt_delivery_configured",
        "license_key_delivery_configured",
        "terms_presented_before_payment",
        "terms_acceptance_required",
        "receipt_legal_binding_configured",
        "support_mailbox_configured",
        "support_delivery_verified",
        "support_owner_access_verified",
        "support_retention_configured",
        "support_intake_private",
        "support_contact",
        "receipt_download_url",
        "eula_url",
        "eula_sha256",
        "terms_version",
        "mode",
        "store_id",
        "product_id",
        "monthly_variant_id",
        "annual_variant_id",
        "monthly_checkout_url",
        "annual_checkout_url",
        "portal_url",
        "store_hostname",
        "catalog_policy",
    )
    exact_object(claims, set(fields), "merchant live-smoke evidence claims")
    _all_true(
        claims,
        (
            "monthly_variant_active",
            "annual_variant_active",
            "monthly_price_rendered",
            "annual_price_rendered",
            "checkout_rendered",
            "portal_configured",
            "license_keys_enabled",
            "receipt_delivery_configured",
            "license_key_delivery_configured",
            "terms_presented_before_payment",
            "terms_acceptance_required",
            "receipt_legal_binding_configured",
            "support_mailbox_configured",
            "support_delivery_verified",
            "support_owner_access_verified",
            "support_retention_configured",
            "support_intake_private",
        ),
        "merchant live-smoke evidence claims",
    )
    if claims["mode"] != "live":
        raise GateError("merchant owner live smoke must inspect live mode")
    _validate_merchant_claim_urls(claims, "merchant live-smoke evidence")
    _validate_catalog_policy(
        claims["catalog_policy"], "merchant live-smoke catalog_policy"
    )
    _validate_merchant_legal_delivery(claims, "merchant live-smoke evidence")
    if (
        not isinstance(claims["support_contact"], str)
        or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62})@tinyzkp\.com",
            claims["support_contact"],
        )
        is None
    ):
        raise GateError(
            "merchant live-smoke support_contact must be one private TinyZKP mailbox"
        )


def _validate_merchant_legal_delivery(claims: dict[str, Any], label: str) -> None:
    if claims["receipt_download_url"] != RECEIPT_DOWNLOAD_URL:
        raise GateError(f"{label} receipt download target differs")
    if (
        not isinstance(claims["eula_sha256"], str)
        or SHA256_RE.fullmatch(claims["eula_sha256"]) is None
        or claims["eula_url"] != _eula_url(claims["eula_sha256"])
    ):
        raise GateError(f"{label} exact EULA identity differs")
    try:
        parsed = datetime.strptime(claims["terms_version"], "%Y-%m-%d")
    except (TypeError, ValueError) as error:
        raise GateError(f"{label} terms_version must be YYYY-MM-DD") from error
    if parsed.strftime("%Y-%m-%d") != claims["terms_version"]:
        raise GateError(f"{label} terms_version must be YYYY-MM-DD")


def _validate_merchant_claim_urls(claims: dict[str, Any], label: str) -> None:
    monthly = _validate_checkout_url(
        claims["monthly_checkout_url"], f"{label} monthly checkout", required=True
    )
    annual = _validate_checkout_url(
        claims["annual_checkout_url"], f"{label} annual checkout", required=True
    )
    if monthly == annual:
        raise GateError(f"{label} monthly and annual checkout URLs must differ")
    monthly_host = _merchant_store_hostname(monthly, f"{label} monthly checkout")
    annual_host = _merchant_store_hostname(annual, f"{label} annual checkout")
    if monthly_host != annual_host or claims["store_hostname"] != monthly_host:
        raise GateError(f"{label} store hostname differs from checkout URLs")
    _validate_portal_url(
        claims["portal_url"],
        f"{label} portal URL",
        required=True,
        expected_store_hostname=monthly_host,
    )


def _semantic_legacy(claims: dict[str, Any]) -> None:
    exact_object(
        claims,
        {
            "identified_free_tenant_accounts",
            "external_free_tenant_accounts",
            "synthetic_test_tenant_accounts",
            "accounts_with_api_usage",
            "external_api_usage_accounts",
            "synthetic_api_usage_accounts",
            "external_accounts_with_billed_usage",
            "owner_only_legacy_tinyzkp_subscriptions_identified",
            "owner_only_legacy_tinyzkp_subscriptions_resolved",
            "owner_only_legacy_tinyzkp_price_usd",
            "owner_only_legacy_catalog_objects_disabled",
            "unrelated_stripe_catalog_objects_untouched",
            "synthetic_test_data_disposition_documented",
            "retirement_notices_required",
            "retirement_notices_sent",
            "external_api_usage_exports_resolved",
            "open_export_requests",
            "open_refund_or_credit_obligations",
            "customer_artifacts_pending_disposition",
            "unresolved_obligations",
            "statutory_records_retained",
            "retained_record_disposition_documented",
            "retirement_notice_template_sha256",
        },
        "legacy-resolution evidence claims",
    )
    counts = {
        field: _positive_int(claims[field], field)
        for field in (
            "identified_free_tenant_accounts",
            "external_free_tenant_accounts",
            "synthetic_test_tenant_accounts",
            "accounts_with_api_usage",
            "external_api_usage_accounts",
            "synthetic_api_usage_accounts",
            "external_accounts_with_billed_usage",
            "owner_only_legacy_tinyzkp_subscriptions_identified",
            "owner_only_legacy_tinyzkp_subscriptions_resolved",
            "owner_only_legacy_tinyzkp_price_usd",
            "retirement_notices_required",
            "retirement_notices_sent",
            "external_api_usage_exports_resolved",
            "open_export_requests",
            "open_refund_or_credit_obligations",
            "customer_artifacts_pending_disposition",
            "unresolved_obligations",
        )
    }
    if not (
        counts["external_free_tenant_accounts"]
        + counts["synthetic_test_tenant_accounts"]
        == counts["identified_free_tenant_accounts"]
        and counts["external_accounts_with_billed_usage"]
        <= counts["external_api_usage_accounts"]
        and counts["external_api_usage_accounts"]
        + counts["synthetic_api_usage_accounts"]
        == counts["accounts_with_api_usage"]
        <= counts["identified_free_tenant_accounts"]
        and counts["external_api_usage_accounts"]
        <= counts["external_free_tenant_accounts"]
        and counts["synthetic_api_usage_accounts"]
        <= counts["synthetic_test_tenant_accounts"]
    ):
        raise GateError("legacy account inventory counts are inconsistent")
    if (
        counts["retirement_notices_required"]
        != counts["external_free_tenant_accounts"]
        or counts["retirement_notices_sent"]
        != counts["retirement_notices_required"]
        or counts["external_api_usage_exports_resolved"]
        != counts["external_api_usage_accounts"]
    ):
        raise GateError("legacy notices and API-data export dispositions are incomplete")
    if (
        counts["owner_only_legacy_tinyzkp_subscriptions_identified"] != 2
        or counts["owner_only_legacy_tinyzkp_subscriptions_resolved"] != 2
        or counts["owner_only_legacy_tinyzkp_price_usd"] != 19
    ):
        raise GateError("the two owner-only TinyZKP $19 subscriptions are unresolved")
    for field in (
        "open_export_requests",
        "open_refund_or_credit_obligations",
        "customer_artifacts_pending_disposition",
        "unresolved_obligations",
    ):
        if counts[field] != 0:
            raise GateError(f"legacy {field} must be zero")
    if (
        not isinstance(claims["retirement_notice_template_sha256"], str)
        or SHA256_RE.fullmatch(claims["retirement_notice_template_sha256"]) is None
    ):
        raise GateError("legacy retirement notice template digest is invalid")
    _all_true(
        claims,
        (
            "owner_only_legacy_catalog_objects_disabled",
            "unrelated_stripe_catalog_objects_untouched",
            "synthetic_test_data_disposition_documented",
            "statutory_records_retained",
            "retained_record_disposition_documented",
        ),
        "legacy-resolution evidence claims",
    )


def _semantic_decommission(claims: dict[str, Any]) -> None:
    fields = (
        "production_servers",
        "databases",
        "queues",
        "workers",
        "pagers",
        "monitoring_services",
        "alerting_services",
        "backup_jobs",
        "unused_r2_buckets",
        "customer_artifacts_pending_deletion",
        "active_oauth_apps",
        "active_legacy_credentials",
    )
    exact_object(
        claims,
        {
            *fields,
            "retired_hosts",
            "retired_hosts_return_410",
            "writes_disabled",
            "jobs_disabled",
            "credentials_revoked",
            "records_retained",
            "observation_period_days_planned",
        },
        "decommission evidence claims",
    )
    for field in fields:
        if _positive_int(claims[field], field) != 0:
            raise GateError(f"decommission evidence {field} must be zero")
    _all_true(
        claims,
        (
            "retired_hosts_return_410",
            "writes_disabled",
            "jobs_disabled",
            "credentials_revoked",
            "records_retained",
        ),
        "decommission evidence claims",
    )
    if claims["retired_hosts"] != [
        "api.tinyzkp.com",
        "mcp.tinyzkp.com",
        "webhook.tinyzkp.com",
    ]:
        raise GateError(
            "decommission evidence must verify the exact three retired hostnames"
        )
    if _positive_int(
        claims["observation_period_days_planned"],
        "observation_period_days_planned",
    ) < 90:
        raise GateError("decommission evidence must plan at least 90 days of 410 monitoring")


def _semantic_rehearsal(claims: dict[str, Any]) -> None:
    base_fields = {
        "qualification_completed",
        "build_validation_passed",
        "deployment_rehearsed",
        "rollback_rehearsed",
        "release_artifact_identity_verified",
        "change_class",
    }
    site_fields = {
        "site_contract_tests_passed",
        "site_accessibility_tests_passed",
        "site_bundle_sha256",
        "deployment_plan_sha256",
        "rollback_plan_sha256",
    }
    if claims.get("change_class") == "site_legal_pricing":
        exact_object(
            claims,
            base_fields | site_fields,
            "release-rehearsal evidence claims",
        )
        _all_true(
            claims,
            (
                "site_contract_tests_passed",
                "site_accessibility_tests_passed",
            ),
            "site/legal/pricing rehearsal claims",
        )
        for field in (
            "site_bundle_sha256",
            "deployment_plan_sha256",
            "rollback_plan_sha256",
        ):
            if not isinstance(claims[field], str) or not SHA256_RE.fullmatch(
                claims[field]
            ):
                raise GateError(
                    f"site/legal/pricing rehearsal {field} must be a SHA-256"
                )
    else:
        exact_object(
            claims,
            base_fields,
            "release-rehearsal evidence claims",
        )
    _all_true(
        claims,
        (
            "qualification_completed",
            "build_validation_passed",
            "deployment_rehearsed",
            "rollback_rehearsed",
            "release_artifact_identity_verified",
        ),
        "release-rehearsal evidence claims",
    )
    if claims["change_class"] not in {
        "guard_package_only",
        "proof_critical",
        "site_legal_pricing",
    }:
        raise GateError("release rehearsal change_class is not a locked wire value")


def _semantic_prior_qualified_release(claims: dict[str, Any]) -> None:
    exact_object(
        claims,
        {
            "prior_launch_state",
            "prior_commerce_state",
            "prior_artifact_published",
            "prior_release_identity",
            "prior_qualified_release_identity",
            "prior_engine_artifact_sha256",
            "prior_release_tag",
            "prior_qualified_at",
            "prior_launch_evidence_sha256",
            "prior_guard_channel_sha256",
            "prior_guard_artifact_sha256",
            "prior_release_index_sha256",
            "prior_channel_url",
        },
        "prior-qualified-release evidence claims",
    )
    if (
        claims["prior_launch_state"] != "qualified"
        or claims["prior_commerce_state"] != "public_live"
        or claims["prior_artifact_published"] is not True
    ):
        raise GateError("prior release was not qualified, public, and published")
    prior_identity = _validate_identity(
        claims["prior_release_identity"], qualified=True
    )
    if claims["prior_release_tag"] != f"guard-v{prior_identity['guard_version']}":
        raise GateError("prior release tag differs from its release identity")
    parse_timestamp(
        claims["prior_qualified_at"], "prior release qualified_at"
    )
    for field in (
        "prior_launch_evidence_sha256",
        "prior_guard_channel_sha256",
        "prior_guard_artifact_sha256",
        "prior_engine_artifact_sha256",
        "prior_release_index_sha256",
    ):
        if not isinstance(claims[field], str) or not SHA256_RE.fullmatch(
            claims[field]
        ):
            raise GateError(f"prior release {field} must be a SHA-256")
    if claims["prior_qualified_release_identity"] != _expected_guard_release_identity(
        prior_identity, claims["prior_engine_artifact_sha256"]
    ):
        raise GateError("prior signed Guard release identity differs")
    _validate_https_url(
        claims["prior_channel_url"],
        "prior Guard channel URL",
        required=True,
        allowed_hosts=("github.com", "githubusercontent.com"),
    )


SEMANTIC_VALIDATORS: dict[str, Callable[[dict[str, Any]], None]] = {
    "engine_release_ready": _semantic_engine,
    "guard_release_ready": _semantic_guard,
    "legal_terms_approved": _semantic_legal,
    "merchant_sandbox_lifecycle_passed": _semantic_sandbox,
    "merchant_live_owner_smoke_passed": _semantic_live,
    "legacy_obligations_resolved": _semantic_legacy,
    "hosted_infrastructure_decommissioned": _semantic_decommission,
    "release_rehearsal_within_budget": _semantic_rehearsal,
    PRIOR_QUALIFIED_RELEASE_GATE: _semantic_prior_qualified_release,
}


def _validate_identity(identity: Any, *, qualified: bool) -> dict[str, Any]:
    value = exact_object(
        identity,
        {
            "guard_release",
            "guard_version",
            "guard_source_sha",
            "engine_source_sha",
            "compatibility_profile",
        },
        "release identity",
    )
    if value["guard_release"] != "tinyzkp-guard-v1":
        raise GateError("release identity guard_release must be tinyzkp-guard-v1")
    if value["compatibility_profile"] != PROFILE_ID:
        raise GateError(f"release identity compatibility_profile must be {PROFILE_ID}")
    if qualified:
        if not isinstance(value["guard_version"], str) or not SEMVER_RE.fullmatch(
            value["guard_version"]
        ):
            raise GateError("qualified Guard identity requires a semantic version")
        for field in ("guard_source_sha", "engine_source_sha"):
            if not isinstance(value[field], str) or not GIT_SHA_RE.fullmatch(value[field]):
                raise GateError(f"qualified Guard identity requires a 40-hex {field}")
    else:
        for field in ("guard_version", "guard_source_sha", "engine_source_sha"):
            if value[field] is not None:
                raise GateError(f"blocked prelaunch identity {field} must be null")
    return value


def _expected_guard_release_identity(
    identity: dict[str, Any], engine_artifact_sha256: str
) -> str:
    return (
        f"tinyzkp-guard/{identity['guard_version']}"
        f"+guard.{identity['guard_source_sha']}"
        f".engine.{identity['engine_source_sha']}"
        f".artifact.{engine_artifact_sha256}"
    )


def _validate_https_url(
    value: Any, label: str, *, required: bool, allowed_hosts: tuple[str, ...]
) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise GateError(f"{label} must be an HTTPS URL")
    if (
        not value
        or not value.isascii()
        or "\\" in value
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise GateError(f"{label} must be an unambiguous ASCII HTTPS URL")
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise GateError(f"{label} must be a well-formed HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not host
        or not host.isascii()
        or username is not None
        or password is not None
        or "#" in value
        or parsed.fragment
        or port not in {None, 443}
        or not any(host == allowed or host.endswith("." + allowed) for allowed in allowed_hosts)
    ):
        raise GateError(f"{label} must use an approved HTTPS merchant host")
    return value


def _merchant_store_hostname(value: str, label: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if host == "lemonsqueezy.com" or not host.endswith(".lemonsqueezy.com"):
        raise GateError(f"{label} must use the reviewed Lemon Squeezy store hostname")
    store_slug = host.removesuffix(".lemonsqueezy.com")
    if (
        store_slug in {"api", "app", "www"}
        or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", store_slug
        )
        is None
    ):
        raise GateError(f"{label} Lemon Squeezy store hostname is malformed")
    return host


def _validate_checkout_url(
    value: Any,
    label: str,
    *,
    required: bool,
    expected_terms_version: str | None = None,
    expected_guard_version: str | None = None,
) -> str | None:
    url = _validate_https_url(
        value,
        label,
        required=required,
        allowed_hosts=("lemonsqueezy.com",),
    )
    if url is None:
        return None
    parsed = urlparse(url)
    _merchant_store_hostname(url, label)
    if re.fullmatch(r"/checkout/buy/[A-Za-z0-9_-]{8,128}/?", parsed.path) is None:
        raise GateError(f"{label} must be a hosted /checkout/buy/... link")
    try:
        query = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError as exc:
        raise GateError(f"{label} custom data query is malformed") from exc
    expected_keys = {
        "checkout[custom][guard_version]",
        "checkout[custom][terms_version]",
    }
    if len(query) != len(expected_keys) or {key for key, _value in query} != expected_keys:
        raise GateError(
            f"{label} must contain only fixed terms_version and guard_version custom data"
        )
    custom = dict(query)
    if (
        not custom["checkout[custom][terms_version]"]
        or not custom["checkout[custom][guard_version]"]
    ):
        raise GateError(f"{label} checkout custom data cannot be empty")
    if expected_terms_version is not None and (
        custom["checkout[custom][terms_version]"] != expected_terms_version
    ):
        raise GateError(f"{label} terms_version differs from the reviewed legal version")
    if expected_guard_version is not None and (
        custom["checkout[custom][guard_version]"] != expected_guard_version
    ):
        raise GateError(f"{label} guard_version differs from the release identity")
    return url


def _validate_portal_url(
    value: Any,
    label: str,
    *,
    required: bool,
    expected_store_hostname: str | None,
) -> str | None:
    url = _validate_https_url(
        value,
        label,
        required=required,
        allowed_hosts=("lemonsqueezy.com",),
    )
    if url is None:
        return None
    parsed = urlparse(url)
    host = _merchant_store_hostname(url, label)
    if (
        parsed.path != "/billing"
        or "?" in url
        or "#" in url
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise GateError(f"{label} must be the generic unsigned /billing portal")
    if expected_store_hostname is not None and host != expected_store_hostname:
        raise GateError(f"{label} must use the same reviewed Lemon Squeezy store")
    return url


def _merchant_id(value: Any, label: str, *, required: bool) -> str | None:
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None
    ):
        raise GateError(f"{label} must be a bounded merchant identifier")
    return value


def _merchant_configuration(
    value: Any, label: str, *, mode: str, required: bool
) -> dict[str, Any]:
    keys = {
        "store_id",
        "product_id",
        "monthly_variant_id",
        "annual_variant_id",
        "monthly_checkout_url",
        "annual_checkout_url",
        "portal_url",
    }
    config = exact_object(value, keys, label)
    result = {
        field: _merchant_id(config[field], f"{label}.{field}", required=required)
        for field in ("store_id", "product_id", "monthly_variant_id", "annual_variant_id")
    }
    result["monthly_checkout_url"] = _validate_checkout_url(
        config["monthly_checkout_url"],
        f"{label}.monthly_checkout_url",
        required=required,
    )
    result["annual_checkout_url"] = _validate_checkout_url(
        config["annual_checkout_url"],
        f"{label}.annual_checkout_url",
        required=required,
    )
    if not required and any(item is not None for item in result.values()):
        raise GateError(f"{label} must be entirely null while unconfigured")
    if required and result["monthly_variant_id"] == result["annual_variant_id"]:
        raise GateError(f"{label} monthly and annual variant IDs must differ")
    if required:
        if result["monthly_checkout_url"] == result["annual_checkout_url"]:
            raise GateError(f"{label} monthly and annual checkout URLs must differ")
        monthly_host = _merchant_store_hostname(
            result["monthly_checkout_url"], f"{label}.monthly_checkout_url"
        )
        annual_host = _merchant_store_hostname(
            result["annual_checkout_url"], f"{label}.annual_checkout_url"
        )
        if monthly_host != annual_host:
            raise GateError(f"{label} checkout URLs must use one reviewed store")
        result["portal_url"] = _validate_portal_url(
            config["portal_url"],
            f"{label}.portal_url",
            required=True,
            expected_store_hostname=monthly_host,
        )
        result["store_hostname"] = monthly_host
    else:
        result["portal_url"] = _validate_portal_url(
            config["portal_url"],
            f"{label}.portal_url",
            required=False,
            expected_store_hostname=None,
        )
        result["store_hostname"] = None
    if not required and any(item is not None for item in result.values()):
        raise GateError(f"{label} must be entirely null while unconfigured")
    return result


def _safe_fixed_file(
    root: Path,
    relative: str,
    expected: str,
    *,
    maximum_bytes: int = MAX_EVIDENCE_BYTES,
) -> tuple[Path, bytes]:
    if relative != expected:
        raise GateError(f"trust policy path must be {expected}")
    pure = PurePosixPath(relative)
    path = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise GateError(f"trust policy is unavailable: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GateError("trust policy path contains a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GateError("trust policy must be a single-link regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum_bytes:
        raise GateError("trust policy size is invalid")
    return path, raw


def _load_trust_policy(
    root: Path,
    reference_value: Any,
    *,
    externally_trusted_sha256: str | None,
    expected_path: str = "release/guard-launch-trust-v1.json",
) -> dict[str, Any]:
    reference = exact_object(
        reference_value, {"path", "sha256"}, "trust_policy"
    )
    digest = reference["sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise GateError("trust policy SHA-256 is malformed")
    _path, raw = _safe_fixed_file(
        root, reference["path"], expected_path
    )
    if sha256_bytes(raw) != digest:
        raise GateError("trust policy digest does not match")
    if externally_trusted_sha256 is not None:
        if (
            not isinstance(externally_trusted_sha256, str)
            or not SHA256_RE.fullmatch(externally_trusted_sha256)
        ):
            raise GateError("external trust-policy SHA-256 is malformed")
        if digest != externally_trusted_sha256:
            raise GateError(
                "trust policy digest differs from the independently protected trust root"
            )
    try:
        value = strict_json.loads(raw)
    except ValueError as exc:
        raise GateError(f"trust policy is not strict JSON: {exc}") from exc
    policy = exact_object(
        value,
        {"schema_version", "document_type", "signers"},
        "GuardLaunchTrustV1",
    )
    if policy["schema_version"] != 1 or policy["document_type"] != "GuardLaunchTrustV1":
        raise GateError("trust policy schema/type is invalid")
    signers = policy["signers"]
    if not isinstance(signers, list):
        raise GateError("trust policy signers must be an array")
    ids: set[str] = set()
    for index, signer_value in enumerate(signers):
        signer = exact_object(
            signer_value,
            {
                "id",
                "purposes",
                "certificate_identity_regexp",
                "oidc_issuer",
            },
            f"trust signer {index}",
        )
        signer_id = signer["id"]
        purposes = signer["purposes"]
        if (
            not isinstance(signer_id, str)
            or not signer_id
            or len(signer_id) > 256
            or signer_id in ids
            or not isinstance(purposes, list)
            or not purposes
            or len(purposes) != len(set(purposes))
            or any(
                purpose
                not in set(GATE_PURPOSES.values())
                | MARKET_TRUST_PURPOSES
                | {ARTIFACT_PUBLICATION_PURPOSE, SALES_FREEZE_PURPOSE}
                for purpose in purposes
            )
            or not isinstance(signer["certificate_identity_regexp"], str)
            or not signer["certificate_identity_regexp"]
            or len(signer["certificate_identity_regexp"]) > 2048
            or not isinstance(signer["oidc_issuer"], str)
            or not signer["oidc_issuer"].startswith("https://")
            or len(signer["oidc_issuer"]) > 2048
        ):
            raise GateError(f"trust signer {index} is invalid")
        ids.add(signer_id)
    return policy


def _load_signing_trust(
    root: Path,
    *,
    externally_trusted_sha256: str | None,
) -> dict[str, Any]:
    _path, raw = _safe_fixed_file(root, SIGNING_TRUST_PATH, SIGNING_TRUST_PATH)
    policy_sha256 = sha256_bytes(raw)
    if externally_trusted_sha256 is not None:
        if (
            not isinstance(externally_trusted_sha256, str)
            or not SHA256_RE.fullmatch(externally_trusted_sha256)
        ):
            raise GateError("external signing-trust SHA-256 is malformed")
        if policy_sha256 != externally_trusted_sha256:
            raise GateError(
                "signing-trust digest differs from the independently protected root"
            )
    try:
        value = strict_json.loads(raw)
    except ValueError as exc:
        raise GateError(f"Guard signing trust is not strict JSON: {exc}") from exc
    policy = exact_object(
        value,
        {
            "schema_version",
            "document_type",
            "status",
            "public_key_path",
            "public_key_sha256",
        },
        "GuardSigningTrustV1",
    )
    if (
        policy["schema_version"] != 1
        or policy["document_type"] != "GuardSigningTrustV1"
        or policy["status"] not in {"unconfigured", "configured"}
        or policy["public_key_path"] != SIGNING_PUBLIC_KEY_PATH
    ):
        raise GateError("Guard signing trust schema/type/status/path is invalid")
    configured = policy["status"] == "configured"
    public_key_sha256 = policy["public_key_sha256"]
    if not configured:
        if public_key_sha256 is not None:
            raise GateError("unconfigured Guard signing trust cannot contain a key digest")
        return {
            **policy,
            "trust_policy_sha256": policy_sha256,
            "public_key_available": False,
        }
    if (
        not isinstance(public_key_sha256, str)
        or not SHA256_RE.fullmatch(public_key_sha256)
    ):
        raise GateError("configured Guard signing trust requires a public-key SHA-256")
    _key_path, key_raw = _safe_fixed_file(
        root, policy["public_key_path"], SIGNING_PUBLIC_KEY_PATH
    )
    if (
        sha256_bytes(key_raw) != public_key_sha256
        or not key_raw.startswith(b"-----BEGIN PUBLIC KEY-----\n")
        or not key_raw.rstrip().endswith(b"-----END PUBLIC KEY-----")
    ):
        raise GateError("canonical Guard signing public key differs from signing trust")
    return {
        **policy,
        "trust_policy_sha256": policy_sha256,
        "public_key_available": True,
    }


def _verify_signature(
    *,
    claim: Path,
    bundle: Path,
    signer_id: Any,
    purpose: str,
    trust_policy: dict[str, Any],
    workflow_source_sha: Any | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    cosign_path: Path | None = None,
) -> None:
    if workflow_source_sha is not None and (
        not isinstance(workflow_source_sha, str)
        or GIT_SHA_RE.fullmatch(workflow_source_sha) is None
    ):
        raise GateError("evidence workflow source SHA is malformed")
    matches = [
        signer
        for signer in trust_policy["signers"]
        if signer["id"] == signer_id and purpose in signer["purposes"]
    ]
    if len(matches) != 1:
        raise GateError("evidence signer is not allowlisted for the gate purpose")
    signer = matches[0]
    cosign = cosign_path or (
        Path(os.environ["TINYZKP_COSIGN"])
        if os.environ.get("TINYZKP_COSIGN")
        else Path(shutil.which("cosign") or "")
    )
    if not str(cosign) or not cosign.is_absolute():
        raise GateError("anchored cosign executable is unavailable")
    command = [
        str(cosign),
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity-regexp",
        signer["certificate_identity_regexp"],
        "--certificate-oidc-issuer",
        signer["oidc_issuer"],
    ]
    if workflow_source_sha is not None:
        command.extend(
            [
                "--certificate-github-workflow-sha",
                workflow_source_sha,
                "--certificate-github-workflow-ref",
                "refs/heads/main",
                "--certificate-github-workflow-repository",
                "logannye/hc-stark",
                "--certificate-github-workflow-trigger",
                "workflow_dispatch",
            ]
        )
    command.append(str(claim))
    try:
        with tempfile.TemporaryDirectory(prefix="tinyzkp-cosign-") as cosign_home:
            completed = runner(
                command,
                cwd=ROOT,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": cosign_home,
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError("detached evidence signature verification failed") from exc
    if completed.returncode != 0:
        raise GateError("detached evidence signature verification failed")


def _validate_sales_freeze(
    source: dict[str, Any],
    *,
    root: Path,
    identity: dict[str, Any],
    commerce_state: str,
    trust_policy: dict[str, Any],
    signature_runner: Callable[..., subprocess.CompletedProcess[str]],
    cosign_path: Path | None,
    current_time: datetime | None,
) -> dict[str, str] | None:
    record = exact_object(
        source["sales_freeze"],
        {"status", "reason_code", "evidence"},
        "sales_freeze",
    )
    if commerce_state != "sales_frozen":
        if record != INACTIVE_SALES_FREEZE:
            raise GateError("non-frozen launch source cannot contain sales-freeze evidence")
        return None
    if (
        record["status"] != "passed"
        or record["reason_code"] is not None
        or not isinstance(record["evidence"], list)
        or len(record["evidence"]) != 1
    ):
        raise GateError("sales_frozen requires one owner-signed freeze record")
    reference = exact_object(
        record["evidence"][0],
        {
            "path",
            "sha256",
            "signature_path",
            "signature_sha256",
            "signer_id",
            "purpose",
        },
        "sales-freeze evidence reference",
    )
    if (
        reference["signer_id"] != SALES_FREEZE_SIGNER_ID
        or reference["purpose"] != SALES_FREEZE_PURPOSE
        or not isinstance(reference["sha256"], str)
        or SHA256_RE.fullmatch(reference["sha256"]) is None
        or not isinstance(reference["signature_sha256"], str)
        or SHA256_RE.fullmatch(reference["signature_sha256"]) is None
        or not isinstance(reference["signature_path"], str)
        or not reference["signature_path"].endswith(".sigstore.json")
    ):
        raise GateError("sales-freeze evidence reference identity differs")
    path, raw = _safe_evidence_file(root, reference["path"])
    signature_path, signature_raw = _safe_evidence_file(
        root, reference["signature_path"]
    )
    if (
        sha256_bytes(raw) != reference["sha256"]
        or sha256_bytes(signature_raw) != reference["signature_sha256"]
    ):
        raise GateError("sales-freeze evidence bytes differ from their reference")
    try:
        envelope_value = strict_json.loads(raw)
        signature_value = strict_json.loads(signature_raw)
    except ValueError as error:
        raise GateError("sales-freeze evidence is not strict JSON") from error
    if not isinstance(signature_value, dict):
        raise GateError("sales-freeze signature bundle must be an object")
    envelope = exact_object(
        envelope_value,
        {
            "schema_version",
            "document_type",
            "authorization_policy",
            "qualification_basis",
            "signer_id",
            "purpose",
            "issued_at",
            "workflow_source_sha",
            "prior_source_sha256",
            "release_identity",
            "prior_commerce_state",
            "requested_commerce_state",
            "checkout_enabled",
            "preserve_customer_portal",
            "preserve_published_artifacts",
            "reason",
        },
        "GuardSalesFreezeEvidenceV1",
    )
    if (
        envelope["schema_version"] != 1
        or envelope["document_type"] != "GuardSalesFreezeEvidenceV1"
        or envelope["authorization_policy"] != AUTHORIZATION_POLICY
        or envelope["qualification_basis"] != QUALIFICATION_BASIS
        or envelope["signer_id"] != SALES_FREEZE_SIGNER_ID
        or envelope["purpose"] != SALES_FREEZE_PURPOSE
        or envelope["release_identity"] != identity
        or envelope["prior_commerce_state"] != "public_live"
        or envelope["requested_commerce_state"] != "sales_frozen"
        or envelope["checkout_enabled"] is not False
        or envelope["preserve_customer_portal"] is not True
        or envelope["preserve_published_artifacts"] is not True
        or envelope["reason"] != "owner_emergency_sales_freeze"
        or not isinstance(envelope["workflow_source_sha"], str)
        or GIT_SHA_RE.fullmatch(envelope["workflow_source_sha"]) is None
        or not isinstance(envelope["prior_source_sha256"], str)
        or SHA256_RE.fullmatch(envelope["prior_source_sha256"]) is None
    ):
        raise GateError("sales-freeze evidence contract differs")
    reconstructed = copy.deepcopy(source)
    reconstructed["requested_commerce_state"] = "public_live"
    reconstructed["sales_freeze"] = copy.deepcopy(INACTIVE_SALES_FREEZE)
    if sha256_bytes(canonical_bytes(reconstructed)) != envelope["prior_source_sha256"]:
        raise GateError("sales-freeze evidence does not bind the prior live source")
    issued_at = parse_timestamp(envelope["issued_at"], "sales-freeze issued_at")
    if current_time is not None and issued_at > current_time:
        raise GateError("sales-freeze evidence is future-dated")
    _verify_signature(
        claim=path,
        bundle=signature_path,
        signer_id=reference["signer_id"],
        purpose=SALES_FREEZE_PURPOSE,
        workflow_source_sha=envelope["workflow_source_sha"],
        trust_policy=trust_policy,
        runner=signature_runner,
        cosign_path=cosign_path,
    )
    return reference


def _evidence_policy(
    gate: str, release_change_class: str
) -> tuple[int, bool]:
    """Return the permitted age and whether evidence binds the exact release.

    Proof-critical and first-GA qualification remain exact and fresh. A
    Guard/package-only release may reuse facts whose engine/profile did not
    change, while the Guard package, activation journey, and rehearsal are
    release-specific. A site/legal/pricing release retains the exact software
    identity and reruns only its legal, merchant, site, and rollback gates.
    """

    _kind, default_max_age_days = GATE_POLICIES[gate]
    if gate == PRIOR_QUALIFIED_RELEASE_GATE:
        return default_max_age_days, True
    fresh_gates = CHANGE_CLASS_FRESH_GATES[release_change_class]
    exact_release = gate in fresh_gates or release_change_class != "guard_package_only"
    if gate in MUTABLE_FACT_FRESH_GATES:
        return default_max_age_days, exact_release
    if gate in fresh_gates:
        return default_max_age_days, True
    if release_change_class == "guard_package_only":
        return REUSABLE_EVIDENCE_MAX_DAYS, False
    # A site/legal/pricing change cannot change either software source
    # identity. Its reusable records therefore remain exact-release-bound.
    return REUSABLE_EVIDENCE_MAX_DAYS, True


def _validate_evidence_identity(
    evidence_identity_value: Any,
    identity: dict[str, Any],
    *,
    gate: str,
    release_change_class: str,
    exact_release: bool,
) -> None:
    evidence_identity = _validate_identity(
        evidence_identity_value, qualified=True
    )
    if exact_release:
        if evidence_identity != identity:
            raise GateError(f"{gate} evidence release identity differs")
        return
    # Guard/package-only reuse is allowed only across a Guard source/version
    # change. The engine and compatibility profile must be byte-for-byte the
    # same, and evidence cannot be imported from another product generation.
    for field in (
        "guard_release",
        "engine_source_sha",
        "compatibility_profile",
    ):
        if evidence_identity[field] != identity[field]:
            raise GateError(
                f"{gate} reusable evidence {field} differs from the "
                "candidate engine/profile identity"
            )


def _validate_gate_evidence(
    root: Path,
    gate: str,
    references: Any,
    identity: dict[str, Any],
    evaluated_at: datetime,
    trust_policy: dict[str, Any],
    merchant: dict[str, Any],
    legal: dict[str, Any],
    release_change_class: str,
    *,
    current_time: datetime | None,
    signature_runner: Callable[..., subprocess.CompletedProcess[str]],
    cosign_path: Path | None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    if (
        not isinstance(references, list)
        or not references
        or len(references) != len({json.dumps(item, sort_keys=True) for item in references})
    ):
        raise GateError(f"passed gate {gate} requires unique evidence references")
    expected_kind, _default_max_age_days = GATE_POLICIES[gate]
    max_age_days, exact_release_identity = _evidence_policy(
        gate, release_change_class
    )
    validated: list[dict[str, str]] = []
    observed_claims: dict[str, Any] | None = None
    for index, reference_value in enumerate(references):
        reference = exact_object(
            reference_value,
            {
                "path",
                "sha256",
                "signature_path",
                "signature_sha256",
                "signer_id",
                "purpose",
            },
            f"{gate} evidence reference {index}",
        )
        digest = reference["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise GateError(f"{gate} evidence reference SHA-256 is malformed")
        path, raw = _safe_evidence_file(root, reference["path"])
        if sha256_bytes(raw) != digest:
            raise GateError(f"{gate} evidence digest does not match {reference['path']}")
        signature_digest = reference["signature_sha256"]
        if (
            not isinstance(signature_digest, str)
            or not SHA256_RE.fullmatch(signature_digest)
        ):
            raise GateError(f"{gate} evidence signature SHA-256 is malformed")
        signature_path, signature_raw = _safe_evidence_file(
            root, reference["signature_path"]
        )
        if not reference["signature_path"].endswith(".sigstore.json"):
            raise GateError(f"{gate} evidence signature must be a Sigstore bundle")
        if sha256_bytes(signature_raw) != signature_digest:
            raise GateError(f"{gate} evidence signature digest does not match")
        try:
            signature_value = strict_json.loads(signature_raw)
        except ValueError as exc:
            raise GateError(f"{gate} evidence signature is not strict JSON: {exc}") from exc
        if not isinstance(signature_value, dict):
            raise GateError(f"{gate} evidence signature bundle must be an object")
        purpose = reference["purpose"]
        if purpose != GATE_PURPOSES[gate]:
            raise GateError(f"{gate} evidence purpose differs from the locked purpose")
        try:
            envelope = strict_json.loads(raw)
        except ValueError as exc:
            raise GateError(f"{gate} evidence is not strict JSON: {exc}") from exc
        envelope = exact_object(
            envelope,
            {
                "schema_version",
                "document_type",
                "authorization_policy",
                "qualification_basis",
                "evidence_kind",
                "gate",
                "result",
                "issued_at",
                "expires_at",
                "workflow_source_sha",
                "release_identity",
                "claims",
            },
            f"{gate} evidence envelope",
        )
        if (
            envelope["schema_version"] != 1
            or envelope["document_type"] != "GuardGateEvidenceV1"
            or envelope["authorization_policy"] != AUTHORIZATION_POLICY
            or envelope["qualification_basis"] != QUALIFICATION_BASIS
            or envelope["evidence_kind"] != expected_kind
            or envelope["gate"] != gate
            or envelope["result"] != "passed"
            or not isinstance(envelope["workflow_source_sha"], str)
            or GIT_SHA_RE.fullmatch(envelope["workflow_source_sha"]) is None
        ):
            raise GateError(f"{gate} evidence envelope type, kind, gate, or result differs")
        _verify_signature(
            claim=path,
            bundle=signature_path,
            signer_id=reference["signer_id"],
            purpose=purpose,
            workflow_source_sha=envelope["workflow_source_sha"],
            trust_policy=trust_policy,
            runner=signature_runner,
            cosign_path=cosign_path,
        )
        _validate_evidence_identity(
            envelope["release_identity"],
            identity,
            gate=gate,
            release_change_class=release_change_class,
            exact_release=exact_release_identity,
        )
        issued_at = parse_timestamp(envelope["issued_at"], f"{gate} evidence issued_at")
        expires_at = parse_timestamp(
            envelope["expires_at"], f"{gate} evidence expires_at"
        )
        if issued_at > evaluated_at:
            raise GateError(f"{gate} evidence is future-dated")
        if expires_at <= issued_at:
            raise GateError(f"{gate} evidence expiry must follow issuance")
        if evaluated_at > expires_at:
            raise GateError(f"{gate} evidence has expired")
        if expires_at - issued_at > timedelta(days=max_age_days):
            raise GateError(f"{gate} evidence validity exceeds {max_age_days} days")
        if evaluated_at - issued_at > timedelta(days=max_age_days):
            raise GateError(f"{gate} evidence is older than {max_age_days} days")
        if current_time is not None:
            if issued_at > current_time:
                raise GateError(f"{gate} evidence is future-dated at action time")
            if current_time > expires_at:
                raise GateError(f"{gate} evidence has expired at action time")
            if current_time - issued_at > timedelta(days=max_age_days):
                raise GateError(
                    f"{gate} evidence is older than {max_age_days} days at action time"
                )
        if not isinstance(envelope["claims"], dict):
            raise GateError(f"{gate} evidence claims must be an object")
        SEMANTIC_VALIDATORS[gate](envelope["claims"])
        if gate == "legal_terms_approved":
            for field in (
                "release_date",
                "eula_sha256",
                "notices_sha256",
                "terms_sha256",
                "privacy_sha256",
                "refunds_sha256",
            ):
                if envelope["claims"][field] != legal[field]:
                    raise GateError(
                        f"legal evidence {field} differs from the reviewed "
                        "document identity"
                    )
            for field in LEGAL_DOCUMENT_PATHS:
                if envelope["claims"][field] != _legal_document_sha256(
                    root, field
                ):
                    raise GateError(
                        f"legal evidence {field} differs from the actual "
                        "reviewed repository document"
                    )
        if gate == "legacy_obligations_resolved":
            _notice_path, notice_raw = _safe_fixed_file(
                root,
                LEGACY_RETIREMENT_NOTICE_PATH,
                LEGACY_RETIREMENT_NOTICE_PATH,
            )
            if (
                envelope["claims"]["retirement_notice_template_sha256"]
                != sha256_bytes(notice_raw)
            ):
                raise GateError(
                    "legacy retirement notice template differs from reviewed bytes"
                )
        if (
            gate == "release_rehearsal_within_budget"
            and release_change_class == "site_legal_pricing"
        ):
            expected_rehearsal = {
                "site_bundle_sha256": _site_bundle_sha256(root),
                "deployment_plan_sha256": _reviewed_file_set_sha256(
                    root,
                    (
                        ".github/workflows/deploy-site.yml",
                        "scripts/deploy/cloudflare_pages_release.py",
                        "docs/runbooks/cloudflare_pages_release.md",
                    ),
                    domain="tinyzkp-pages-deployment-v1",
                ),
                "rollback_plan_sha256": _reviewed_file_set_sha256(
                    root,
                    (
                        "scripts/deploy/cloudflare_pages_release.py",
                        "docs/runbooks/cloudflare_pages_release.md",
                    ),
                    domain="tinyzkp-pages-rollback-v1",
                ),
            }
            for field, expected in expected_rehearsal.items():
                if envelope["claims"][field] != expected:
                    raise GateError(
                        f"site/legal/pricing rehearsal {field} differs from "
                        "the actual reviewed deployable source"
                    )
        if gate == "guard_release_ready":
            channel_bindings = {
                "channel_release_identity": _expected_guard_release_identity(
                    identity, envelope["claims"]["artifact_sha256"]
                ),
                "channel_guard_version": identity["guard_version"],
                "channel_guard_source_sha": identity["guard_source_sha"],
                "channel_engine_source_sha": identity["engine_source_sha"],
                "channel_compatibility_profile": identity[
                    "compatibility_profile"
                ],
                "channel_artifact_sha256": envelope["claims"][
                    "artifact_sha256"
                ],
                "channel_oci_digest": envelope["claims"]["oci_digest"],
            }
            for field, expected in channel_bindings.items():
                if envelope["claims"][field] != expected:
                    raise GateError(
                        f"guard_release_ready evidence {field} differs from "
                        "the exact candidate artifact identity"
                    )
            embedded_catalog = {
                "embedded_store_id": merchant["live_configuration"]["store_id"],
                "embedded_product_id": merchant["live_configuration"][
                    "product_id"
                ],
                "embedded_monthly_variant_id": merchant["live_configuration"][
                    "monthly_variant_id"
                ],
                "embedded_annual_variant_id": merchant["live_configuration"][
                    "annual_variant_id"
                ],
            }
            for field, expected in embedded_catalog.items():
                if envelope["claims"][field] != expected:
                    raise GateError(
                        f"guard_release_ready evidence {field} differs from "
                        "the exact live merchant configuration"
                    )
            if (
                envelope["claims"]["embedded_catalog_policy"]
                != merchant["catalog_policy"]
            ):
                raise GateError(
                    "guard_release_ready embedded catalog policy differs "
                    "from the reviewed merchant policy"
                )
            legal_claims = {
                "embedded_release_date": legal["release_date"],
                "embedded_eula_sha256": legal["eula_sha256"],
                "embedded_notices_sha256": legal["notices_sha256"],
            }
            for field, expected in legal_claims.items():
                if envelope["claims"][field] != expected:
                    raise GateError(
                        f"guard_release_ready evidence {field} differs from "
                        "the reviewed legal document identity"
                    )
        if gate in {
            "merchant_sandbox_lifecycle_passed",
            "merchant_live_owner_smoke_passed",
            "two_standard_annual_customers",
        }:
            expected_configuration = (
                merchant["test_configuration"]
                if gate == "merchant_sandbox_lifecycle_passed"
                else merchant["live_configuration"]
            )
            expected_mode = (
                "test" if gate == "merchant_sandbox_lifecycle_passed" else "live"
            )
            if gate != "two_standard_annual_customers" and envelope["claims"]["mode"] != expected_mode:
                raise GateError(f"{gate} evidence mode differs from merchant configuration")
            if envelope["claims"]["catalog_policy"] != merchant["catalog_policy"]:
                raise GateError(f"{gate} catalog policy differs from merchant source")
            for field in (
                "store_id",
                "product_id",
                "monthly_variant_id",
                "annual_variant_id",
                "monthly_checkout_url",
                "annual_checkout_url",
                "portal_url",
                "store_hostname",
            ):
                if envelope["claims"][field] != expected_configuration[field]:
                    raise GateError(
                        f"{gate} evidence {field} differs from merchant configuration"
                    )
            expected_delivery = {
                "receipt_download_url": RECEIPT_DOWNLOAD_URL,
                "eula_url": _eula_url(legal["eula_sha256"]),
                "eula_sha256": legal["eula_sha256"],
                "terms_version": legal["release_date"],
            }
            for field, expected in expected_delivery.items():
                if envelope["claims"][field] != expected:
                    raise GateError(
                        f"{gate} evidence {field} differs from the exact "
                        "owner-approved agreement"
                    )
        if observed_claims is not None and envelope["claims"] != observed_claims:
            raise GateError(f"{gate} evidence references disagree semantically")
        observed_claims = envelope["claims"]
        validated.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest,
                "signature_path": signature_path.relative_to(root).as_posix(),
                "signature_sha256": signature_digest,
                "signer_id": reference["signer_id"],
                "purpose": purpose,
            }
        )
    if observed_claims is None:
        raise GateError(f"passed gate {gate} has no semantic claims")
    return validated, observed_claims


def derive(
    source: dict[str, Any],
    *,
    root: Path = ROOT,
    signature_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    cosign_path: Path | None = None,
    trusted_policy_sha256: str | None = None,
    trusted_signing_policy_sha256: str | None = None,
    current_time: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    source = exact_object(
        source,
        {
            "schema_version",
            "document_type",
            "authorization_policy",
            "qualification_basis",
            "evaluated_at",
            "release_identity",
            "trust_policy",
            "requested_commerce_state",
            "sales_freeze",
            "release_change_class",
            "prior_qualified_release",
            "merchant",
            "legal",
            "gates",
            "advisory_status",
        },
        "GuardLaunchEvidenceV2",
    )
    if source["schema_version"] != 2 or source["document_type"] != "GuardLaunchEvidenceV2":
        raise GateError("launch evidence must be GuardLaunchEvidenceV2 schema_version 2")
    if source["authorization_policy"] != AUTHORIZATION_POLICY:
        raise GateError(f"authorization_policy must be {AUTHORIZATION_POLICY}")
    if source["qualification_basis"] != QUALIFICATION_BASIS:
        raise GateError(f"qualification_basis must be {QUALIFICATION_BASIS}")
    advisory_status = exact_object(
        source["advisory_status"], set(ADVISORY_ITEMS), "advisory_status"
    )
    if any(value != "not_completed" for value in advisory_status.values()):
        raise GateError(
            "owner-only GA advisory status must remain transparent and not_completed"
        )
    evaluated = parse_timestamp(source["evaluated_at"], "evaluated_at")
    if current_time is not None:
        if current_time.tzinfo != timezone.utc:
            raise GateError("current release-gate time must be UTC")
        if evaluated > current_time:
            raise GateError("launch evaluated_at is future-dated")
        if current_time - evaluated > CURRENT_EVALUATION_MAX_AGE:
            raise GateError("launch evaluated_at is older than 24 hours")
    commerce_state = source["requested_commerce_state"]
    if commerce_state not in COMMERCE_STATES:
        raise GateError("requested_commerce_state is not a locked commerce state")
    release_change_class = source["release_change_class"]
    if release_change_class not in {
        "guard_package_only",
        "proof_critical",
        "site_legal_pricing",
    }:
        raise GateError("release_change_class is not a locked wire value")

    gates = exact_object(source["gates"], set(REQUIRED_GATES), "gates")
    any_passed = any(
        isinstance(value, dict) and value.get("status") == "passed"
        for value in gates.values()
    )
    all_passed = all(
        isinstance(value, dict) and value.get("status") == "passed"
        for value in gates.values()
    )
    identity = _validate_identity(
        source["release_identity"],
        qualified=any_passed or commerce_state != "unconfigured",
    )
    if any_passed and trusted_policy_sha256 is None:
        raise GateError(
            "passing evidence requires a protected trust-policy SHA-256"
        )
    trust_policy = _load_trust_policy(
        root,
        source["trust_policy"],
        externally_trusted_sha256=trusted_policy_sha256,
    )
    if any_passed and not trust_policy["signers"]:
        raise GateError("passing evidence requires at least one allowlisted signer")
    signing_trust = _load_signing_trust(
        root,
        externally_trusted_sha256=trusted_signing_policy_sha256,
    )
    sales_freeze_reference = _validate_sales_freeze(
        source,
        root=root,
        identity=identity,
        commerce_state=commerce_state,
        trust_policy=trust_policy,
        signature_runner=signature_runner,
        cosign_path=cosign_path,
        current_time=current_time,
    )

    merchant_source = exact_object(
        source["merchant"],
        {
            "provider",
            "approval_status",
            "portal_state",
            "portal_url",
            "catalog_policy",
            "test_configuration",
            "live_configuration",
        },
        "merchant",
    )
    if merchant_source["provider"] != "lemon_squeezy":
        raise GateError("merchant provider must be lemon_squeezy")
    _validate_catalog_policy(
        merchant_source["catalog_policy"], "merchant.catalog_policy"
    )
    if merchant_source["approval_status"] not in {"pending", "approved"}:
        raise GateError("merchant approval_status must be pending or approved")
    if merchant_source["portal_state"] not in {"unconfigured", "live"}:
        raise GateError("merchant portal_state must be unconfigured or live")
    test_required = commerce_state != "unconfigured"
    live_required = commerce_state in {"live_hidden", "public_live", "sales_frozen"}
    test_configuration = _merchant_configuration(
        merchant_source["test_configuration"],
        "merchant.test_configuration",
        mode="test",
        required=test_required,
    )
    live_configuration = _merchant_configuration(
        merchant_source["live_configuration"],
        "merchant.live_configuration",
        mode="live",
        required=live_required,
    )
    portal_live = merchant_source["portal_state"] == "live"
    checkout_store_hostname = (
        _merchant_store_hostname(
            live_configuration["monthly_checkout_url"],
            "merchant.live_configuration.monthly_checkout_url",
        )
        if live_configuration.get("monthly_checkout_url") is not None
        else None
    )
    portal_url = _validate_portal_url(
        merchant_source["portal_url"],
        "merchant portal URL",
        required=portal_live,
        expected_store_hostname=checkout_store_hostname,
    )
    if not portal_live and portal_url is not None:
        raise GateError("unconfigured portal cannot contain a portal URL")
    if live_required and portal_live and portal_url != live_configuration["portal_url"]:
        raise GateError(
            "merchant portal URL differs from the exact live configuration"
        )
    merchant = {
        **merchant_source,
        "test_configuration": test_configuration,
        "live_configuration": live_configuration,
        "portal_url": portal_url,
    }

    legal = exact_object(
        source["legal"],
        {
            "seller_status",
            "owner_approval_status",
            "release_date",
            "eula_sha256",
            "notices_sha256",
            "terms_sha256",
            "privacy_sha256",
            "refunds_sha256",
        },
        "legal",
    )
    if legal["seller_status"] not in {"unconfirmed", "confirmed"}:
        raise GateError("legal seller_status must be unconfirmed or confirmed")
    if legal["owner_approval_status"] not in {"not_approved", "approved"}:
        raise GateError(
            "legal owner_approval_status must be not_approved or approved"
        )
    legal_approved = (
        legal["seller_status"] == "confirmed"
        and legal["owner_approval_status"] == "approved"
    )
    if legal_approved:
        try:
            release_date = datetime.strptime(legal["release_date"], "%Y-%m-%d")
        except (TypeError, ValueError) as exc:
            raise GateError("approved legal release_date must be YYYY-MM-DD") from exc
        if release_date.strftime("%Y-%m-%d") != legal["release_date"]:
            raise GateError("approved legal release_date must be YYYY-MM-DD")
        for field in (
            "eula_sha256",
            "notices_sha256",
            "terms_sha256",
            "privacy_sha256",
            "refunds_sha256",
        ):
            if not isinstance(legal[field], str) or not SHA256_RE.fullmatch(
                legal[field]
            ):
                raise GateError(f"approved legal {field} must be a SHA-256")
            if legal[field] != _legal_document_sha256(root, field):
                raise GateError(
                    f"approved legal {field} differs from the actual repository bytes"
                )
        _validate_eula_effective_date(root, legal["release_date"])
    elif any(
        legal[field] is not None
        for field in (
            "release_date",
            "eula_sha256",
            "notices_sha256",
            "terms_sha256",
            "privacy_sha256",
            "refunds_sha256",
        )
    ):
        raise GateError(
            "unapproved legal state cannot declare reviewed document identity"
        )

    if live_required:
        for field in ("product_id", "monthly_variant_id", "annual_variant_id"):
            if test_configuration[field] == live_configuration[field]:
                raise GateError(
                    f"merchant test and live {field} must use distinct objects"
                )
        for configuration_name, configuration in (
            ("test_configuration", test_configuration),
            ("live_configuration", live_configuration),
        ):
            for cadence in ("monthly", "annual"):
                _validate_checkout_url(
                    configuration[f"{cadence}_checkout_url"],
                    f"merchant.{configuration_name}.{cadence}_checkout_url",
                    required=True,
                    expected_terms_version=legal["release_date"],
                    expected_guard_version=identity["guard_version"],
                )
        if len(
            {
                test_configuration["monthly_checkout_url"],
                test_configuration["annual_checkout_url"],
                live_configuration["monthly_checkout_url"],
                live_configuration["annual_checkout_url"],
            }
        ) != 4:
            raise GateError("merchant test and live checkout URLs must be distinct")

    prior_record = exact_object(
        source["prior_qualified_release"],
        {"status", "reason_code", "evidence"},
        "prior_qualified_release",
    )
    prior_claim: dict[str, Any] | None = None
    prior_evidence: list[dict[str, str]] = []
    if prior_record["status"] == "blocked":
        if (
            release_change_class != "proof_critical"
            or prior_record["reason_code"]
            != BLOCKED_REASONS[PRIOR_QUALIFIED_RELEASE_GATE]
            or prior_record["evidence"] != []
        ):
            raise GateError(
                f"{release_change_class} requires a signed prior qualified release"
            )
    elif prior_record["status"] == "passed":
        if prior_record["reason_code"] is not None:
            raise GateError("passed prior-qualified-release evidence has a reason")
        prior_evidence, prior_claim = _validate_gate_evidence(
            root,
            PRIOR_QUALIFIED_RELEASE_GATE,
            prior_record["evidence"],
            identity,
            evaluated,
            trust_policy,
            merchant,
            legal,
            release_change_class,
            current_time=current_time,
            signature_runner=signature_runner,
            cosign_path=cosign_path,
        )
        prior_identity = prior_claim["prior_release_identity"]
        if release_change_class == "guard_package_only":
            for field in (
                "guard_release",
                "engine_source_sha",
                "compatibility_profile",
            ):
                if prior_identity[field] != identity[field]:
                    raise GateError(
                        f"prior qualified release {field} differs from the "
                        "Guard/package candidate"
                    )
            if (
                prior_identity["guard_version"] == identity["guard_version"]
                or prior_identity["guard_source_sha"] == identity["guard_source_sha"]
            ):
                raise GateError(
                    "Guard/package reuse requires a distinct prior Guard release"
                )
        elif prior_identity != identity:
            if release_change_class == "site_legal_pricing":
                raise GateError(
                    "site/legal/pricing reuse requires the exact unchanged "
                    "software identity"
                )
        if prior_identity["guard_release"] != identity["guard_release"]:
            raise GateError("prior release belongs to another Guard product generation")
        if parse_timestamp(
            prior_claim["prior_qualified_at"], "prior release qualified_at"
        ) > evaluated:
            raise GateError("prior qualified release is future-dated")
    else:
        raise GateError("prior_qualified_release status must be blocked or passed")

    gate_status: dict[str, Any] = {}
    gate_claims: dict[str, dict[str, Any]] = {}
    blocking: list[str] = []
    for gate_name in sorted(REQUIRED_GATES):
        record = exact_object(
            gates[gate_name],
            {"status", "reason_code", "evidence"},
            f"gates.{gate_name}",
        )
        status = record["status"]
        if status not in {"blocked", "passed"}:
            raise GateError(f"gates.{gate_name}.status must be blocked or passed")
        if status == "blocked":
            if record["reason_code"] != BLOCKED_REASONS[gate_name]:
                raise GateError(
                    f"gates.{gate_name}.reason_code is not the locked reason"
                )
            if record["evidence"] != []:
                raise GateError(
                    f"blocked gate {gate_name} cannot cite passing evidence"
                )
            evidence: list[dict[str, str]] = []
            blocking.append(gate_name)
        else:
            if record["reason_code"] is not None:
                raise GateError(
                    f"passed gate {gate_name} must have reason_code=null"
                )
            evidence, claims = _validate_gate_evidence(
                root,
                gate_name,
                record["evidence"],
                identity,
                evaluated,
                trust_policy,
                merchant,
                legal,
                release_change_class,
                current_time=current_time,
                signature_runner=signature_runner,
                cosign_path=cosign_path,
            )
            gate_claims[gate_name] = claims
        gate_status[gate_name] = {
            "status": status,
            "reason_code": record["reason_code"],
            "reason_anchor": REASON_ANCHORS[gate_name],
            "evidence": evidence,
        }

    guard_claim = gate_claims.get("guard_release_ready")
    if guard_claim is not None and release_change_class != "site_legal_pricing":
        expected_prior_identity = (
            prior_claim["prior_qualified_release_identity"]
            if prior_claim is not None
            else None
        )
        expected_prior_index = (
            prior_claim["prior_release_index_sha256"]
            if prior_claim is not None
            else None
        )
        if (
            guard_claim["channel_release_change_class"]
            != release_change_class
            or guard_claim["channel_prior_qualified_release_identity"]
            != expected_prior_identity
            or guard_claim["channel_prior_release_index_sha256"]
            != expected_prior_index
        ):
            raise GateError(
                "Guard channel change class/predecessor differs from signed "
                "launch qualification"
            )
    stable_index = root / "site" / RELEASE_INDEX_NAME
    stable_signature = root / "site" / RELEASE_INDEX_SIGNATURE_NAME
    publication_record = root / "site" / ARTIFACT_PUBLICATION_NAME
    publication_bundle = root / "site" / ARTIFACT_PUBLICATION_BUNDLE_NAME
    publication_parts = (
        stable_index.exists()
        or stable_index.is_symlink()
        or stable_signature.exists()
        or stable_signature.is_symlink()
        or publication_record.exists()
        or publication_record.is_symlink()
        or publication_bundle.exists()
        or publication_bundle.is_symlink()
    )
    publication_material_present = all(
        path.exists() or path.is_symlink()
        for path in (
            stable_index,
            stable_signature,
            publication_record,
            publication_bundle,
        )
    )
    if publication_parts and not publication_material_present:
        raise GateError("artifact publication material is incomplete")
    engine_publication_claim = gate_claims.get("engine_release_ready")
    publication_matches_current = True
    publication_validation_identity = identity
    publication_validation_class = release_change_class
    if publication_material_present:
        publication_preview = load_json(
            publication_record, "GuardArtifactPublicationV1"
        )
        publication_matches_current = (
            publication_preview.get("release_identity") == identity
        )
        if not publication_matches_current:
            if (
                release_change_class not in {"guard_package_only", "proof_critical"}
                or commerce_state != "live_hidden"
                or prior_claim is None
                or publication_preview.get("release_identity")
                != prior_claim["prior_release_identity"]
            ):
                raise GateError(
                    "retained artifact publication does not match the signed prior release"
                )
            publication_validation_identity = prior_claim["prior_release_identity"]
            publication_validation_class = "retained_prior"
    if (
        publication_material_present
        and publication_matches_current
        and commerce_state != "sales_frozen"
        and (guard_claim is None or engine_publication_claim is None)
    ):
        raise GateError(
            "published Guard material lacks passed engine/Guard readiness"
        )
    publication_validation = None
    if publication_material_present:
        publication_validation = _validate_artifact_publication(
            root,
            guard_claims=guard_claim if publication_matches_current else None,
            engine_claims=(
                engine_publication_claim if publication_matches_current else None
            ),
            identity=publication_validation_identity,
            trust_policy=trust_policy,
            prior_claim=prior_claim,
            release_change_class=publication_validation_class,
            signature_runner=signature_runner,
            cosign_path=cosign_path,
        )
    published_identity_claims = (
        guard_claim
        if guard_claim is not None
        else (
            {
                "release_index_sha256": publication_validation["record"][
                    "release_index_sha256"
                ],
                "release_index_signature_sha256": publication_validation[
                    "record"
                ]["release_index_signature_sha256"],
                "release_index_url": publication_validation["record"][
                    "release_index_url"
                ],
                "release_index_signature_url": publication_validation[
                    "record"
                ]["release_index_signature_url"],
            }
            if publication_validation is not None
            else None
        )
    )
    latest_release_index = (
        _validate_published_index_files(root, published_identity_claims)
        if publication_material_present
        and publication_matches_current
        and (guard_claim is not None or commerce_state == "sales_frozen")
        else None
    )
    artifact_published = latest_release_index is not None
    published_record = (
        publication_validation["record"]
        if publication_validation is not None
        else None
    )
    gate_status[ARTIFACT_PUBLICATION_BLOCKER] = {
        "status": "passed" if artifact_published else "blocked",
        "reason_code": (
            None
            if artifact_published
            else BLOCKED_REASONS[ARTIFACT_PUBLICATION_BLOCKER]
        ),
        "reason_anchor": REASON_ANCHORS[ARTIFACT_PUBLICATION_BLOCKER],
        "evidence": (
            [publication_validation["reference"]]
            if artifact_published
            else []
        ),
    }
    if not artifact_published:
        blocking.append(ARTIFACT_PUBLICATION_BLOCKER)
    blocking.sort()
    launch_state = "qualified" if not blocking else "blocked"
    rehearsal_claim = gate_claims.get("release_rehearsal_within_budget")
    if (
        rehearsal_claim is not None
        and rehearsal_claim["change_class"] != release_change_class
    ):
        raise GateError(
            "signed release-rehearsal change_class differs from the launch source"
        )
    if (launch_state == "qualified") != (all_passed and artifact_published):
        raise GateError("derived launch state is internally inconsistent")
    merchant_ready = merchant["approval_status"] == "approved"
    legal_ready = legal_approved
    if commerce_state == "sales_frozen" and (
        not merchant_ready
        or not portal_live
        or gate_status["merchant_live_owner_smoke_passed"]["status"] != "passed"
    ):
        raise GateError(
            "sales_frozen requires approved merchant state, a live customer portal, "
            "retained live configuration, and prior live owner-smoke evidence"
        )
    if portal_live and not merchant_ready:
        raise GateError("live portal requires merchant approval")
    if commerce_state == "test_verified" and gate_status[
        "merchant_sandbox_lifecycle_passed"
    ]["status"] != "passed":
        raise GateError("test_verified requires current sandbox evidence")
    if commerce_state == "live_hidden":
        required_hidden = {
            "engine_release_ready",
            "legal_terms_approved",
            "merchant_sandbox_lifecycle_passed",
        }
        if (
            not merchant_ready
            or not legal_ready
            or not portal_live
            or any(gate_status[name]["status"] != "passed" for name in required_hidden)
        ):
            raise GateError(
                "live_hidden requires engine, legal, merchant sandbox, and portal evidence"
            )
    if commerce_state == "public_live" and (
        launch_state != "qualified"
        or not merchant_ready
        or not legal_ready
        or not portal_live
        or not signing_trust["public_key_available"]
    ):
        raise GateError(
            "public_live requires qualified launch, approved merchant/legal state, "
            "a live portal, and configured Guard signing trust"
        )
    # A withdrawal is a business decision, not a launch-gate state. It is
    # read from a committed record rather than derived, so that no amount of
    # passing launch evidence can put a withdrawn SKU back on sale without
    # someone deliberately revoking release/guard-sku-withdrawal-v1.json.
    #
    # `closed` and `frozen` both mean "not selling right now" and render as
    # schema.org/OutOfStock -- which tells every machine reader the product
    # is coming back. `withdrawn` is the state that renders as
    # schema.org/Discontinued. Without it the withdrawal could only ever land
    # in human-readable copy, which is exactly what happened.
    sku_withdrawn = _guard_sku_withdrawn()
    sales_state = (
        "withdrawn"
        if sku_withdrawn
        else "live"
        if commerce_state == "public_live"
        else "frozen"
        if commerce_state == "sales_frozen"
        else "closed"
    )
    # Fail closed and unconditionally: a withdrawn SKU is never purchasable,
    # whatever the merchant evidence says.
    checkout_enabled = commerce_state == "public_live" and not sku_withdrawn
    public_annual_url = (
        live_configuration["annual_checkout_url"] if checkout_enabled else None
    )
    public_monthly_url = (
        live_configuration["monthly_checkout_url"] if checkout_enabled else None
    )
    public_portal_url = portal_url if portal_live else None
    commerce_mode = (
        "test"
        if commerce_state in {"test_published", "test_verified"}
        else "live"
        if commerce_state in {"live_hidden", "public_live", "sales_frozen"}
        else "unconfigured"
    )
    public_merchant_config = (
        test_configuration
        if commerce_mode == "test"
        else live_configuration
        if commerce_mode == "live"
        else {
            "store_id": None,
            "product_id": None,
            "monthly_variant_id": None,
            "annual_variant_id": None,
            "store_hostname": None,
        }
    )
    source_sha = sha256_bytes(canonical_bytes(source))
    engine_claim = gate_claims.get("engine_release_ready")
    legal_claim = gate_claims.get("legal_terms_approved")
    live_smoke_claim = gate_claims.get("merchant_live_owner_smoke_passed")
    candidate_prerequisites = {
        "engine_release_ready",
        "legal_terms_approved",
        "merchant_sandbox_lifecycle_passed",
        "release_rehearsal_within_budget",
    }
    candidate_build_ready = (
        commerce_state == "live_hidden"
        and not artifact_published
        and guard_claim is None
        and merchant_ready
        and legal_ready
        and portal_live
        and signing_trust["public_key_available"]
        and engine_claim is not None
        and all(
            gate_status[name]["status"] == "passed"
            for name in candidate_prerequisites
        )
    )
    candidate_state = (
        "published"
        if artifact_published
        else "candidate_prepared"
        if guard_claim is not None
        else "authorized"
        if candidate_build_ready
        else "blocked"
    )
    candidate_authorization = {
        "schema_version": 1,
        "document_type": "GuardCandidateBuildAuthorizationV1",
        "authorization_policy": AUTHORIZATION_POLICY,
        "qualification_basis": QUALIFICATION_BASIS,
        "authorization_state": candidate_state,
        "authorization_scope": "prepare_signed_guard_draft_only",
        "commercial_release_authorized": False,
        "checkout_enabled": False,
        "public_gate_source_sha256": source_sha,
        "release_change_class": release_change_class,
        "prior_qualified_release": (
            {
                "release_identity": prior_claim[
                    "prior_qualified_release_identity"
                ],
                "release_index_sha256": prior_claim[
                    "prior_release_index_sha256"
                ],
            }
            if prior_claim is not None
            else None
        ),
        "public_candidate_authorization_commit": (
            guard_claim["public_candidate_authorization_commit"]
            if guard_claim is not None
            else None
        ),
        "release_identity": identity,
        "expected_public_candidate_tag": (
            f"guard-v{identity['guard_version']}"
            if identity["guard_version"] is not None
            else None
        ),
        "engine": (
            {
                "candidate_tag": engine_claim["engine_release_tag"],
                "source_sha": identity["engine_source_sha"],
                "public_contracts_git_revision": identity["engine_source_sha"],
                "artifact_sha256": engine_claim["engine_artifact_sha256"],
                "oci_digest": engine_claim["engine_oci_digest"],
            }
            if engine_claim is not None
            else None
        ),
        "compatibility_profile": identity["compatibility_profile"],
        "legal_artifacts": (
            {
                "release_date": legal_claim["release_date"],
                "eula_sha256": legal_claim["eula_sha256"],
                "eula_url": _eula_url(legal_claim["eula_sha256"]),
                "notices_sha256": legal_claim["notices_sha256"],
            }
            if legal_claim is not None
            else None
        ),
        "merchant_catalog": (
            {
                "merchant": "lemon_squeezy",
                "mode": "live",
                "store_id": live_configuration["store_id"],
                "product_id": live_configuration["product_id"],
                "monthly_variant_id": live_configuration["monthly_variant_id"],
                "annual_variant_id": live_configuration["annual_variant_id"],
                "monthly_checkout_url": live_configuration[
                    "monthly_checkout_url"
                ],
                "annual_checkout_url": live_configuration[
                    "annual_checkout_url"
                ],
                "customer_portal_url": live_configuration["portal_url"],
                "store_hostname": live_configuration["store_hostname"],
                "catalog_policy": merchant["catalog_policy"],
            }
            if live_configuration["store_id"] is not None
            else None
        ),
        "signing_trust": {
            "policy_path": SIGNING_TRUST_PATH,
            "policy_sha256": signing_trust["trust_policy_sha256"],
            "public_key_path": SIGNING_PUBLIC_KEY_PATH,
            "public_key_sha256": signing_trust["public_key_sha256"],
        },
        "reviewed_evidence": {
            "launch_evidence_sha256": source_sha,
            "launch_trust_policy_sha256": source["trust_policy"]["sha256"],
            "required_passed_gates": sorted(candidate_prerequisites),
            "advisory_status": advisory_status,
        },
        "remaining_launch_blockers": blocking,
    }
    market_clock_path = root / "release" / "guard-market-clock-v1.json"
    if market_clock_path.is_file():
        market_clock = load_json(market_clock_path, "GuardMarketClockV1")
        doctor_record = market_clock.get("doctor_evaluation_release")
        signed_doctor_identity = (
            doctor_record.get("identity")
            if isinstance(doctor_record, dict)
            and doctor_record.get("status") == "passed"
            else None
        )
        if signed_doctor_identity is not None and not isinstance(
            signed_doctor_identity, dict
        ):
            raise GateError("market clock doctor identity is invalid")
        market_clock_source_sha = market_clock.get("source_sha256")
        if not isinstance(market_clock_source_sha, str) or not SHA256_RE.fullmatch(
            market_clock_source_sha
        ):
            raise GateError("market clock source SHA-256 is invalid")
    else:
        signed_doctor_identity = None
        market_clock_source_sha = None

    launch = {
        "schema_version": 2,
        "document_type": "GuardLaunchStateV2",
        "authorization_policy": AUTHORIZATION_POLICY,
        "qualification_basis": QUALIFICATION_BASIS,
        "generated_from": "release/guard-launch-evidence-v2.json",
        "source_sha256": source_sha,
        "evaluated_at": source["evaluated_at"],
        "launch_state": launch_state,
        "sales_state": sales_state,
        "commerce_state": commerce_state,
        "portal_state": merchant["portal_state"],
        "checkout_enabled": checkout_enabled,
        "release_identity": identity,
        "legal_status": (
            "approved" if legal_ready else "blocked_pending_owner_approval"
        ),
        "merchant_of_record_status": (
            "approved" if merchant_ready else "approval_pending"
        ),
        "gate_status": gate_status,
        "advisory_status": advisory_status,
        "blocking_gates": blocking,
        "sales_freeze": (
            {
                "status": "active",
                "reason": "owner_emergency_sales_freeze",
                "evidence": [sales_freeze_reference],
            }
            if sales_freeze_reference is not None
            else {"status": "inactive", "reason": None, "evidence": []}
        ),
        "reason_anchors": REASON_ANCHORS,
    }
    published_artifact_url = (
        guard_claim["artifact_url"]
        if guard_claim is not None
        else published_record["artifact_url"]
        if published_record is not None
        else None
    )
    published_channel_url = (
        guard_claim["channel_url"]
        if guard_claim is not None
        else published_record["channel_url"]
        if published_record is not None
        else None
    )
    release_asset_base = (
        published_artifact_url.rsplit("/", 1)[0]
        if isinstance(published_artifact_url, str)
        else None
    )
    delivery = (
        {
            "receipt_url": RECEIPT_DOWNLOAD_URL,
            "artifact_url": published_artifact_url,
            "artifact_sha256": (
                guard_claim["artifact_sha256"]
                if guard_claim is not None
                else published_record["artifact_sha256"]
            ),
            "sha256sums_url": f"{release_asset_base}/SHA256SUMS",
            "sha256sums_signature_url": f"{release_asset_base}/SHA256SUMS.sig",
            "signing_public_key_url": f"{release_asset_base}/signing-public-key.pem",
            "signing_public_key_sha256": signing_trust["public_key_sha256"],
            "channel_url": published_channel_url,
            "release_index_url": latest_release_index["url"],
            "release_index_signature_url": latest_release_index["signature_url"],
            "start_here_path": "START-HERE.txt",
            "agreement_path": "AGREEMENT.txt",
            "delivery_path": "DELIVERY.txt",
            "activation_command": "./bin/tinyzkp activate --license-key-stdin",
        }
        if artifact_published
        and release_asset_base is not None
        and latest_release_index is not None
        else None
    )
    release = {
        "schema_version": 2,
        "release": identity["guard_release"],
        "authorization_policy": AUTHORIZATION_POLICY,
        "qualification_basis": QUALIFICATION_BASIS,
        "release_identity": identity,
        "launch_state": launch_state,
        "sales_state": sales_state,
        "commerce_state": commerce_state,
        "portal_state": merchant["portal_state"],
        "checkout_enabled": checkout_enabled,
        "guard_artifact_available": artifact_published,
        "guard_artifact_url": published_artifact_url,
        "guard_artifact_sha256": (
            guard_claim["artifact_sha256"]
            if guard_claim is not None
            else published_record["artifact_sha256"]
            if published_record is not None
            else None
        ),
        "guard_oci_digest": (
            guard_claim["oci_digest"]
            if guard_claim is not None
            else published_record["guard_oci_digest"]
            if published_record is not None
            else None
        ),
        "agreement": (
            {
                "release_date": legal["release_date"],
                "eula_sha256": legal["eula_sha256"],
                "eula_url": _eula_url(legal["eula_sha256"]),
            }
            if legal_approved
            else None
        ),
        "latest_release_index": latest_release_index,
        "delivery": delivery,
        "qualified_engine_artifact_available": gate_status["engine_release_ready"]["status"] == "passed",
        "compatibility_profile": PROFILE_ID,
        "canonical_gate": "https://github.com/logannye/hc-stark/blob/main/release/guard-launch-state-v2.json",
        "source_sha256": source_sha,
        "gate_status": gate_status,
        "advisory_status": advisory_status,
        "blocking_gates": blocking,
        "channel_manifest": (
            {
                "url": guard_claim["channel_url"],
                "sha256": guard_claim["channel_identity_sha256"],
                "release_identity": identity,
                "signed_release_identity": guard_claim[
                    "channel_release_identity"
                ],
                "public_candidate_authorization_commit": guard_claim[
                    "public_candidate_authorization_commit"
                ],
                "release_change_class": guard_claim[
                    "channel_release_change_class"
                ],
                "prior_qualified_release_identity": guard_claim[
                    "channel_prior_qualified_release_identity"
                ],
                "prior_release_index_sha256": guard_claim[
                    "channel_prior_release_index_sha256"
                ],
                "release_index_url": guard_claim["release_index_url"],
                "release_index_sha256": guard_claim["release_index_sha256"],
                "release_index_signature_url": guard_claim[
                    "release_index_signature_url"
                ],
                "release_index_signature_sha256": guard_claim[
                    "release_index_signature_sha256"
                ],
                "artifact_sha256": guard_claim["artifact_sha256"],
                "oci_digest": guard_claim["oci_digest"],
            }
            if guard_claim is not None
            else None
        ),
        "reason_anchors": REASON_ANCHORS,
    }
    commerce = {
        "schema_version": 2,
        "provider": "lemon_squeezy",
        "authorization_policy": AUTHORIZATION_POLICY,
        "qualification_basis": QUALIFICATION_BASIS,
        "sales_state": sales_state,
        "commerce_state": commerce_state,
        "mode": commerce_mode,
        "checkout_enabled": checkout_enabled,
        "launch_state": launch_state,
        "portal_state": merchant["portal_state"],
        "canonical_launch_gate": "release/guard-launch-state-v2.json",
        "configuration_source": "GuardLaunchEvidenceV2",
        "variants": {
            "annual": {
                "variant_id": public_merchant_config["annual_variant_id"],
                "reviewed": checkout_enabled,
                "checkout_url": public_annual_url,
            },
            "monthly": {
                "variant_id": public_merchant_config["monthly_variant_id"],
                "reviewed": checkout_enabled,
                "checkout_url": public_monthly_url,
            },
        },
        "store_id": public_merchant_config["store_id"],
        "product_id": public_merchant_config["product_id"],
        "store_hostname": public_merchant_config["store_hostname"],
        "customer_portal_url": public_portal_url,
        "support": (
            {
                "state": "verified",
                "intake": "private_email",
                "contact": live_smoke_claim["support_contact"],
                "delivery_verified": True,
                "owner_access_verified": True,
                "retention_configured": True,
            }
            if live_smoke_claim is not None
            else None
        ),
        "receipt_download_url": (
            RECEIPT_DOWNLOAD_URL if merchant_ready else None
        ),
        "agreement": (
            {
                "release_date": legal["release_date"],
                "eula_sha256": legal["eula_sha256"],
                "eula_url": _eula_url(legal["eula_sha256"]),
            }
            if legal_approved
            else None
        ),
        "checkout_custom_data": {
            "terms_version": legal["release_date"],
            "guard_version": identity["guard_version"],
        },
        "reason_anchors": {
            "sales": REASON_ANCHORS["sales"],
            "portal": REASON_ANCHORS["portal"],
            "launch": REASON_ANCHORS["launch"],
        },
        "price_policy": {
            "monthly_usd": 499,
            "annual_usd": 4990,
            "annual_default": True,
            "price_lock": "general_availability_plus_six_months",
            "general_availability_date": None,
            "coupons_allowed": False,
            "trials_allowed": False,
            "add_ons_allowed": False,
            "subscription_pause_offered": False,
            "usage_metering": False,
            "enterprise_variants_allowed": False,
            "founding_discount": False,
            "future_price_changes_use_new_variant_ids": False,
            "existing_subscribers_grandfathered": True,
            "existing_variant_ids_retained": True,
            "existing_variant_ids_repurposed": False,
        },
        "note": "Checkout is derived from digest-bound launch evidence and remains fail-closed.",
    }
    pricing = {
        "schema_version": 5,
        "name": "TinyZKP Community and Guard",
        "canonical_url": "https://tinyzkp.com/pricing",
        "effective_date": legal["release_date"] if legal_approved else None,
        "currency": "USD",
        "launch_state": launch_state,
        "sales_state": sales_state,
        "commerce_state": commerce_state,
        "portal_state": merchant["portal_state"],
        "checkout_enabled": checkout_enabled,
        "launch_gate": "release/guard-launch-state-v2.json",
        "reason_anchors": {
            "sales": REASON_ANCHORS["sales"],
            "merchant": REASON_ANCHORS["merchant"],
            "legal": REASON_ANCHORS["legal"],
        },
        "hosted_proving": False,
        "usage_metering": False,
        "price_policy": commerce["price_policy"],
        "products": [
            {
                "id": "community",
                "name": "TinyZKP Community",
                "license": "MIT",
                "price_usd": 0,
                "availability": "available",
                "includes": [
                    "proof engine and verifier",
                    "public schemas and reference workloads",
                    "compatibility checker and doctor",
                    "resource estimators",
                    "conventional and bounded proving primitives",
                    "public benchmark evidence",
                ],
            },
            {
                "id": "guard",
                "name": "TinyZKP Guard",
                "license": "commercial_object_code",
                "availability": (
                    "withdrawn"
                    if sales_state == "withdrawn"
                    else "available"
                    if checkout_enabled
                    else "sales_frozen"
                    if sales_state == "frozen"
                    # "blocked until gates pass" promises the block lifts.
                    # For a withdrawn SKU that is a false promise, which is
                    # why `withdrawn` is checked first above.
                    else "blocked_until_all_launch_gates_pass"
                ),
                "organization_scope": "one_legal_organization_unlimited_internal_users_and_runners",
                "prices": {
                    "monthly_usd": 499,
                    "annual_usd": 4990,
                    "annual_recommended": True,
                },
                "includes": [
                    "foreground process and signal supervision",
                    "checkpoint lifecycle and deterministic resume supervision",
                    "support-safe diagnostics",
                    "CI resource-regression policies",
                    "signed artifacts and OCI images",
                    "SBOM and provenance",
                    "four qualification windows per year",
                ],
                "excludes": [
                    "hosted proving",
                    "usage metering",
                    "SLA",
                    "onboarding calls",
                    "custom AIR development",
                    "architecture review",
                    "security questionnaires",
                    "SSO",
                    "redistribution",
                    "resale",
                    "OEM",
                    "service-bureau use",
                ],
            },
        ],
        "subscription_policy": {
            "activated_release_continues_offline": True,
            "active_subscription_required_for_new_release_activation": True,
            "cancellation_effective_at_period_end": True,
            "prorated_refunds": "only_if_required_by_law_or_merchant",
        },
    }
    monitoring_mode = (
        "guard_live"
        if checkout_enabled
        else "guard_frozen"
        if sales_state == "frozen" and artifact_published
        else "guard_transition"
        if (
            commerce_state == "live_hidden"
            and candidate_state == "candidate_prepared"
            and blocking == [ARTIFACT_PUBLICATION_BLOCKER]
            and all(
                gate_status[name]["status"] == "passed"
                for name in REQUIRED_GATES
            )
        )
        else "guard_prelaunch"
    )
    release_channels = {
        "schema_version": 1,
        "authorization_policy": AUTHORIZATION_POLICY,
        "qualification_basis": QUALIFICATION_BASIS,
        "current_channel": monitoring_mode,
        "source_sha256": source_sha,
        "channels": {
            "community": {
                "engine_source": "public_mit",
                "engine_artifacts": "signed_after_engine_gates",
                "checkout": False,
                "hosted_proving": False,
                "hosted_verification": False,
                "customer_data_plane": "local_only",
            },
            "guard_prelaunch": {
                "inherits": "community",
                "guard_artifacts": "private_release_candidates",
                "checkout": False,
                "legacy_hosts": "recovery_200",
                "authorization_policy": AUTHORIZATION_POLICY,
                "qualification_basis": QUALIFICATION_BASIS,
                "required_gate_document": "release/guard-launch-state-v2.json",
            },
            "guard_transition": {
                "inherits": "community",
                "guard_artifacts": "signed_draft_prerelease",
                "checkout": False,
                "legacy_hosts": "static_410_noindex",
                "authorization_policy": AUTHORIZATION_POLICY,
                "qualification_basis": QUALIFICATION_BASIS,
                "required_gate_document": "release/guard-launch-state-v2.json",
            },
            "guard_live": {
                "inherits": "community",
                "guard_artifacts": "commercial_object_code",
                "checkout": True,
                "legacy_hosts": "static_410_noindex",
                "merchant": "merchant_of_record",
                "runtime_phone_home": False,
                "future_release_activation_requires_active_subscription": True,
                "authorization_policy": AUTHORIZATION_POLICY,
                "qualification_basis": QUALIFICATION_BASIS,
                "required_gate_document": "release/guard-launch-state-v2.json",
            },
            "guard_frozen": {
                "inherits": "community",
                "guard_artifacts": "commercial_object_code",
                "checkout": False,
                "customer_portal": True,
                "legacy_hosts": "static_410_noindex",
                "runtime_phone_home": False,
                "authorization_policy": AUTHORIZATION_POLICY,
                "qualification_basis": QUALIFICATION_BASIS,
                "required_gate_document": "release/guard-launch-state-v2.json",
            },
        },
    }
    discovery = {
        "schema_version": 5,
        "name": "TinyZKP",
        "canonical_url": "https://tinyzkp.com",
        "updated_at": "2026-07-18",
        "launch_state": launch_state,
        "sales_state": sales_state,
        "commerce_state": commerce_state,
        "portal_state": merchant["portal_state"],
        "service_status": monitoring_mode,
        "positioning": {
            "short": "Finish supported Plonky3 proof jobs within a RAM budget.",
            "description": "A customer-operated supervisor and open proof engine for bounded-memory, SSD-backed, resumable execution without changing the released proof format or ordinary verifier.",
            "primary_human_users": [
                "proof infrastructure lead",
                "protocol engineer",
                "technical founder",
            ],
            "primary_machine_users": ["CI runner", "scheduler", "local automation"],
            "privacy_claim": "none",
            "exclusivity_claim": "none",
        },
        "availability": {
            "community_source": True,
            "community_doctor": signed_doctor_identity is not None,
            "signed_evaluation_doctor_binary": signed_doctor_identity is not None,
            "signed_evaluation_doctor_oci": signed_doctor_identity is not None,
            "qualified_engine_artifact": release["qualified_engine_artifact_available"],
            "guard_artifact": release["guard_artifact_available"],
            "guard_checkout": checkout_enabled,
            "hosted_proving": False,
            "hosted_verification": False,
            # `customer_accounts` stays False deliberately, and is NOT the
            # right flag to flip for the estimator's free keys. A minted
            # bearer key has no password, dashboard, recovery flow, or
            # stored email (migrations/0002_keys.sql), so calling it an
            # account would be its own misstatement. The two flags below
            # say what is actually true instead.
            "customer_accounts": False,
            "anonymous_api_keys": True,
            "contact_form": False,
            # True since Phase 1b: `POST /v1/estimate` writes a shape-only
            # row to the `demand_log` D1 table (migrations/0001_demand_log.sql).
            # That is an event collector by any fair reading. The flag was
            # accurate before that shipped and was left stale afterwards;
            # site/privacy.html#resource-estimator now discloses the whole
            # surface and scripts/ci/privacy_disclosure_gate.py enforces it.
            "event_collector": True,
            # Distinguishes "no API at all" from "no hosted proving": the
            # resource estimator IS a TinyZKP-operated API surface.
            "resource_estimator_api": True,
        },
        "supported_profile": "https://tinyzkp.com/compatibility.json",
        "pricing": "https://tinyzkp.com/pricing.json",
        "commerce": "https://tinyzkp.com/commerce.json",
        "release_status": "https://tinyzkp.com/release.json",
        "latest_release_index": latest_release_index,
        "market_clock": {
            "source_sha256": market_clock_source_sha,
            "signed_doctor_release_identity": signed_doctor_identity,
        },
        "contracts": {
            "job_manifest_v1": "https://tinyzkp.com/schemas/job-manifest-v1.schema.json",
            "doctor_report_v1": "https://tinyzkp.com/schemas/doctor-report-v1.schema.json",
            "compatibility_report_v1": "https://tinyzkp.com/schemas/compatibility-report-v1.schema.json",
            "reason_v1": "https://tinyzkp.com/schemas/reason-v1.schema.json",
            "error_envelope_v1": "https://tinyzkp.com/schemas/error-envelope-v1.schema.json",
            "progress_event_v1": "https://tinyzkp.com/schemas/progress-event-v1.schema.json",
            "job_result_v1": "https://tinyzkp.com/schemas/job-result-v1.schema.json",
            "support_report_v1": "https://tinyzkp.com/schemas/support-report-v1.schema.json",
            "job_inspect_result_v1": "https://tinyzkp.com/schemas/job-inspect-result-v1.schema.json",
            "guard_channel_v1": "https://tinyzkp.com/schemas/guard-channel-v1.schema.json",
            "guard_release_index_v1": "https://tinyzkp.com/schemas/guard-release-index-v1.schema.json",
            "policy_baseline_v1": "https://tinyzkp.com/schemas/policy-baseline-v1.schema.json",
            "compatibility_manifest_v1": "https://tinyzkp.com/schemas/compatibility-manifest-v1.schema.json",
        },
        "evergreen_acquisition_pages": [
            *(
                ["https://tinyzkp.com/doctor"]
                if signed_doctor_identity is not None
                else []
            ),
            *(
                [
                    f"https://tinyzkp.com{route}"
                    for route in ACQUISITION_ROUTES
                    if route != "/doctor"
                ]
                if engine_claim is not None
                else []
            ),
        ],
        "primary_actions": [
            *(
                [
                    {
                        "label": "Run the free doctor",
                        "url": "https://tinyzkp.com/doctor",
                    }
                ]
                if signed_doctor_identity is not None
                else []
            ),
            *(
                [{"label": "Buy Guard", "url": public_annual_url}]
                if checkout_enabled
                else []
            ),
        ],
        "reason_anchors": {
            "launch": "https://tinyzkp.com" + REASON_ANCHORS["launch"],
            "sales": "https://tinyzkp.com" + REASON_ANCHORS["sales"],
            "portal": "https://tinyzkp.com" + REASON_ANCHORS["portal"],
        },
        "support": {
            "documentation": "https://tinyzkp.com/docs",
            "troubleshooting": "https://tinyzkp.com/troubleshooting",
            "issues": "https://github.com/logannye/hc-stark/issues",
            "security": "https://github.com/logannye/hc-stark/security/advisories/new",
        },
    }
    compatibility = {
        "schema_version": 1,
        "document_type": "CompatibilityProfileV1",
        "profile": PROFILE_ID,
        "platform": {
            "operating_system": "linux",
            "architecture": "x86_64",
        },
        "plonky3_version": "0.6.1",
        "field": "goldilocks",
        "extension_degree": 2,
        "permutation": "poseidon2_width_8",
        "verifier": "p3_uni_stark_0.6.1",
        "declarative_operators": [
            "current",
            "next",
            "public",
            "constant",
            "add",
            "subtract",
            "multiply",
        ],
        "limits": {
            "minimum_rows": 1024,
            "maximum_rows": 16777216,
            "maximum_trace_width": 256,
            "maximum_constraint_degree": 3,
        },
        "explicitly_unsupported": [
            "lookups",
            "buses",
            "AIR permutations",
            "multi-table AIRs",
            "preprocessed columns",
            "periodic columns",
            "custom fields",
            "recursion profiles",
            "GPUs",
            "arbitrary Plonky3 forks",
            "Windows",
            "macOS production proving",
        ],
        "qualification": (
            "qualified"
            if engine_claim is not None
            else "blocked_pending_engine_evidence"
        ),
        "release_binding": (
            {
                "engine_source_sha": identity["engine_source_sha"],
                "engine_artifact_sha256": engine_claim[
                    "engine_artifact_sha256"
                ],
                "engine_oci_digest": engine_claim["engine_oci_digest"],
                "compatibility_profile": identity["compatibility_profile"],
            }
            if engine_claim is not None
            else None
        ),
    }
    # Must match scripts/commercial/render_offers.py exactly -- both write
    # site/offers.jsonld, and a disagreement between them fails this gate.
    # `OutOfStock` is schema.org for TEMPORARILY unavailable; a withdrawn SKU
    # is `Discontinued`, or search engines keep listing a retired product as
    # one that is coming back.
    offer_availability = (
        "https://schema.org/Discontinued"
        if sales_state == "withdrawn"
        else "https://schema.org/InStock"
        if checkout_enabled
        else "https://schema.org/OutOfStock"
    )
    offers = {
        "@context": "https://schema.org",
        "@type": "OfferCatalog",
        "name": "TinyZKP Community and Guard",
        "url": "https://tinyzkp.com/pricing",
        "itemListElement": [
            {
                "@type": "Offer",
                "name": "TinyZKP Community source",
                "price": "0",
                "priceCurrency": "USD",
                "availability": "https://schema.org/InStock",
                "url": "https://github.com/logannye/hc-stark",
            },
            {
                "@type": "Offer",
                "name": "TinyZKP Guard annual subscription",
                "price": "4990",
                "priceCurrency": "USD",
                "availability": offer_availability,
                "url": "https://tinyzkp.com/pricing",
            },
            {
                "@type": "Offer",
                "name": "TinyZKP Guard monthly subscription",
                "price": "499",
                "priceCurrency": "USD",
                "availability": offer_availability,
                "url": "https://tinyzkp.com/pricing",
            },
        ],
    }
    derived = {
        "launch": launch,
        "candidate_authorization": candidate_authorization,
        "release": release,
        "commerce": commerce,
        "pricing": pricing,
        "discovery": discovery,
        "compatibility": compatibility,
        "offers": offers,
        "release_channels": release_channels,
        "site_release_channels": release_channels,
    }
    _validate_output_identity_parity(derived)
    return derived


def _validate_output_identity_parity(
    derived: dict[str, dict[str, Any]],
) -> None:
    launch = derived["launch"]
    release = derived["release"]
    states = {
        (
            value["launch_state"],
            value["sales_state"],
            value["commerce_state"],
            value["portal_state"],
        )
        for value in (
            derived["launch"],
            derived["release"],
            derived["commerce"],
            derived["pricing"],
            derived["discovery"],
        )
    }
    if len(states) != 1:
        raise GateError("generated public launch states differ")
    release_channels = derived["release_channels"]
    if (
        derived["site_release_channels"] != release_channels
        or release_channels.get("authorization_policy") != AUTHORIZATION_POLICY
        or release_channels.get("qualification_basis") != QUALIFICATION_BASIS
        or release_channels.get("source_sha256") != launch["source_sha256"]
        or release_channels.get("current_channel")
        != derived["discovery"]["service_status"]
    ):
        raise GateError("generated monitoring channel contracts differ")
    if release["release_identity"] != launch["release_identity"]:
        raise GateError("generated release identity differs from the launch identity")
    candidate = derived["candidate_authorization"]
    if (
        candidate["public_gate_source_sha256"] != launch["source_sha256"]
        or candidate["release_identity"] != launch["release_identity"]
        or candidate["compatibility_profile"]
        != launch["release_identity"]["compatibility_profile"]
        or candidate["checkout_enabled"] is not False
        or candidate["commercial_release_authorized"] is not False
        or candidate["authorization_scope"]
        != "prepare_signed_guard_draft_only"
        or (
            candidate["authorization_state"]
            in {"candidate_prepared", "published"}
            and not GIT_SHA_RE.fullmatch(
                candidate["public_candidate_authorization_commit"] or ""
            )
        )
        or (
            candidate["authorization_state"] in {"blocked", "authorized"}
            and candidate["public_candidate_authorization_commit"] is not None
        )
    ):
        raise GateError("candidate-build authorization differs from launch identity")
    if (
        release["release"] != launch["release_identity"]["guard_release"]
        or release["compatibility_profile"]
        != launch["release_identity"]["compatibility_profile"]
    ):
        raise GateError("generated site release identity is internally inconsistent")
    compatibility = derived["compatibility"]
    engine_passed = (
        launch["gate_status"]["engine_release_ready"]["status"] == "passed"
    )
    binding = compatibility["release_binding"]
    if not engine_passed and (
        binding is not None
        or compatibility["qualification"] != "blocked_pending_engine_evidence"
    ):
        raise GateError("blocked compatibility profile contains a fake release binding")
    if engine_passed and (
        not isinstance(binding, dict)
        or compatibility["qualification"] != "qualified"
        or binding.get("engine_source_sha")
        != launch["release_identity"]["engine_source_sha"]
        or binding.get("compatibility_profile")
        != launch["release_identity"]["compatibility_profile"]
        or not SHA256_RE.fullmatch(binding.get("engine_artifact_sha256", ""))
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", binding.get("engine_oci_digest", "")
        )
    ):
        raise GateError("qualified compatibility profile release binding differs")
    if launch["commerce_state"] == "public_live":
        channel = release["channel_manifest"]
        if (
            release["guard_artifact_available"] is not True
            or not isinstance(channel, dict)
            or channel.get("release_identity") != launch["release_identity"]
            or channel.get("signed_release_identity")
            != _expected_guard_release_identity(
                launch["release_identity"], release["guard_artifact_sha256"]
            )
            or channel.get("artifact_sha256")
            != release["guard_artifact_sha256"]
            or channel.get("public_candidate_authorization_commit")
            != candidate["public_candidate_authorization_commit"]
            or channel.get("oci_digest") != release["guard_oci_digest"]
            or not release["guard_artifact_url"]
            or not channel.get("url")
            or not channel.get("sha256")
        ):
            raise GateError(
                "public live checkout requires one exact Guard artifact, OCI, "
                "channel, and site release identity"
            )


def _require_current_evaluation(
    derived: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> None:
    evaluated_at = parse_timestamp(
        derived["launch"]["evaluated_at"], "launch evaluated_at"
    )
    current = now or datetime.now(timezone.utc).replace(microsecond=0)
    if current.tzinfo != timezone.utc:
        raise GateError("current release-gate time must be UTC")
    if evaluated_at > current:
        raise GateError("launch evaluated_at is future-dated")
    if current - evaluated_at > CURRENT_EVALUATION_MAX_AGE:
        raise GateError("launch evaluated_at is older than 24 hours")


def _require_candidate_build_ready(
    derived: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> None:
    _require_current_evaluation(derived, now=now)
    launch = derived["launch"]
    authorization = derived["candidate_authorization"]
    prerequisites = set(
        authorization["reviewed_evidence"]["required_passed_gates"]
    )
    if (
        authorization["authorization_state"] != "authorized"
        or launch["commerce_state"] != "live_hidden"
        or launch["sales_state"] != "closed"
        or launch["portal_state"] != "live"
        or launch["checkout_enabled"] is not False
        or launch["legal_status"] != "approved"
        or launch["merchant_of_record_status"] != "approved"
        or launch["gate_status"]["guard_release_ready"]["status"] != "blocked"
        or launch["gate_status"][ARTIFACT_PUBLICATION_BLOCKER]["status"]
        != "blocked"
        or any(
            launch["gate_status"][name]["status"] != "passed"
            for name in prerequisites
        )
        or authorization["engine"] is None
        or authorization["engine"]["public_contracts_git_revision"]
        != launch["release_identity"]["engine_source_sha"]
        or authorization["legal_artifacts"] is None
        or authorization["merchant_catalog"] is None
        or authorization["signing_trust"]["public_key_sha256"] is None
    ):
        raise GateError(
            "Guard candidate build is not authorized for one signed draft"
        )


def _require_promotion_ready(
    derived: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> None:
    _require_current_evaluation(derived, now=now)
    launch = derived["launch"]
    release = derived["release"]
    authorization = derived["candidate_authorization"]
    channel = release["channel_manifest"]
    if (
        launch["launch_state"] != "blocked"
        or launch["commerce_state"] != "live_hidden"
        or launch["sales_state"] != "closed"
        or launch["portal_state"] != "live"
        or launch["checkout_enabled"] is not False
        or launch["legal_status"] != "approved"
        or launch["merchant_of_record_status"] != "approved"
        or launch["blocking_gates"] != [ARTIFACT_PUBLICATION_BLOCKER]
        or any(
            launch["gate_status"][name]["status"] != "passed"
            for name in REQUIRED_GATES
        )
        or launch["gate_status"][ARTIFACT_PUBLICATION_BLOCKER]["status"]
        != "blocked"
        or authorization["authorization_state"] != "candidate_prepared"
        or not GIT_SHA_RE.fullmatch(
            authorization["public_candidate_authorization_commit"] or ""
        )
        or authorization["remaining_launch_blockers"]
        != [ARTIFACT_PUBLICATION_BLOCKER]
        or authorization["signing_trust"]["public_key_sha256"] is None
        or release["guard_artifact_available"] is not False
        or not isinstance(release["guard_artifact_url"], str)
        or not SHA256_RE.fullmatch(release["guard_artifact_sha256"] or "")
        or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", release["guard_oci_digest"] or ""
        )
        or not isinstance(channel, dict)
        or channel.get("release_identity") != launch["release_identity"]
        or channel.get("signed_release_identity")
        != _expected_guard_release_identity(
            launch["release_identity"], release["guard_artifact_sha256"]
        )
        or channel.get("artifact_sha256") != release["guard_artifact_sha256"]
        or channel.get("public_candidate_authorization_commit")
        != authorization["public_candidate_authorization_commit"]
        or channel.get("oci_digest") != release["guard_oci_digest"]
        or not isinstance(channel.get("url"), str)
        or not SHA256_RE.fullmatch(channel.get("sha256", ""))
    ):
        raise GateError(
            "Guard promotion is not ready with only artifact publication blocked"
        )


def validate(
    config: dict[str, Any],
    *,
    require_ready: bool = False,
    now: datetime | None = None,
) -> list[str]:
    """Validate a derived launch-state document for legacy CI callers."""

    errors: list[str] = []
    try:
        value = exact_object(
            config,
            {
                "schema_version",
                "document_type",
                "authorization_policy",
                "qualification_basis",
                "generated_from",
                "source_sha256",
                "evaluated_at",
                "launch_state",
                "sales_state",
                "commerce_state",
                "portal_state",
                "checkout_enabled",
                "release_identity",
                "legal_status",
                "merchant_of_record_status",
                "gate_status",
                "advisory_status",
                "blocking_gates",
                "sales_freeze",
                "reason_anchors",
            },
            "GuardLaunchStateV2",
        )
        if value["schema_version"] != 2 or value["document_type"] != "GuardLaunchStateV2":
            raise GateError("derived launch state schema/type is invalid")
        if value["authorization_policy"] != AUTHORIZATION_POLICY:
            raise GateError("derived launch authorization_policy is invalid")
        if value["qualification_basis"] != QUALIFICATION_BASIS:
            raise GateError("derived launch qualification_basis is invalid")
        if (
            exact_object(
                value["advisory_status"], set(ADVISORY_ITEMS), "advisory_status"
            )
            != {name: "not_completed" for name in ADVISORY_ITEMS}
        ):
            raise GateError("derived launch advisory_status is invalid")
        if value["launch_state"] not in {"blocked", "qualified"}:
            raise GateError("launch_state must be blocked or qualified")
        if value["sales_state"] not in {"closed", "live", "frozen", "withdrawn"}:
            raise GateError(
                "sales_state must be closed, live, frozen, or withdrawn"
            )
        freeze = exact_object(
            value["sales_freeze"], {"status", "reason", "evidence"}, "sales_freeze"
        )
        if value["sales_state"] == "frozen":
            if (
                freeze["status"] != "active"
                or freeze["reason"] != "owner_emergency_sales_freeze"
                or not isinstance(freeze["evidence"], list)
                or len(freeze["evidence"]) != 1
            ):
                raise GateError("frozen sales require one active signed freeze record")
        elif freeze != {"status": "inactive", "reason": None, "evidence": []}:
            raise GateError("non-frozen sales cannot contain active freeze evidence")
        if value["commerce_state"] not in COMMERCE_STATES:
            raise GateError("commerce_state is not a locked commerce state")
        if value["portal_state"] not in {"unconfigured", "live"}:
            raise GateError("portal_state must be unconfigured or live")
        if not isinstance(value["checkout_enabled"], bool):
            raise GateError("checkout_enabled must be a boolean")
        blocking = value["blocking_gates"]
        if (
            not isinstance(blocking, list)
            or len(blocking) != len(set(blocking))
            or set(blocking) - LAUNCH_BLOCKERS
        ):
            raise GateError("blocking_gates is invalid")
        if value["launch_state"] == "blocked" and (
            value["checkout_enabled"]
            # `withdrawn` is a valid terminal state for a blocked launch:
            # a SKU can be retired while its launch gates are still failing,
            # and that is in fact how Guard ended.
            or value["sales_state"] not in {"closed", "frozen", "withdrawn"}
            or not blocking
        ):
            raise GateError("blocked launch must be disabled and have blockers")
        if value["launch_state"] == "qualified" and blocking:
            raise GateError("qualified launch cannot have blocking gates")
        if value["sales_state"] == "live" and (
            value["launch_state"] != "qualified"
            or value["commerce_state"] != "public_live"
            or not value["checkout_enabled"]
        ):
            raise GateError("live sales require qualified launch and checkout")
        if value["sales_state"] != "live" and value["checkout_enabled"]:
            raise GateError("non-live sales cannot enable checkout")
        if require_ready and (
            value["launch_state"] != "qualified"
            or value["commerce_state"] != "public_live"
        ):
            errors.append("TinyZKP Guard commercial launch is not qualified and live")
        if require_ready:
            evaluated_at = parse_timestamp(
                value["evaluated_at"], "launch evaluated_at"
            )
            current = now or datetime.now(timezone.utc).replace(microsecond=0)
            if current.tzinfo != timezone.utc:
                raise GateError("current release-gate time must be UTC")
            if evaluated_at > current:
                raise GateError("launch evaluated_at is future-dated")
    except GateError as exc:
        errors.append(str(exc))
    return errors


def _acquisition_routes(
    derived: dict[str, dict[str, Any]],
) -> dict[str, bool]:
    engine_ready = (
        derived["launch"]["gate_status"]["engine_release_ready"]["status"]
        == "passed"
    )
    doctor_ready = (
        derived["discovery"]["availability"]["signed_evaluation_doctor_binary"]
        is True
    )
    return {
        route: doctor_ready if route == "/doctor" else engine_ready
        for route in ACQUISITION_ROUTES
    }


def _acquisition_meta(ready: bool) -> str:
    policy = "index,follow" if ready else "noindex,nofollow"
    return (
        f'<meta name="robots" content="{policy}" '
        'data-guard-acquisition>'
    )


def _sitemap_bytes(routes_ready: dict[str, bool]) -> bytes:
    routes = [
        *BASE_SITEMAP_ROUTES[:SITEMAP_ACQUISITION_SPLICE_INDEX],
        *(
            route
            for route in ACQUISITION_ROUTES
            if routes_ready[route]
        ),
        *BASE_SITEMAP_ROUTES[SITEMAP_ACQUISITION_SPLICE_INDEX:],
    ]
    records = "\n".join(
        f"  <url><loc>https://tinyzkp.com{route}</loc></url>"
        for route in routes
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{records}\n"
        "</urlset>\n"
    ).encode("utf-8")


def _llms_text(
    text: str,
    routes_ready: dict[str, bool],
    *,
    commerce_state: str,
    doctor_ready: bool,
) -> str:
    lines = [
        line
        for line in text.splitlines()
        if line
        not in {
            *LLMS_ACQUISITION_LINES,
            *LLMS_ACQUISITION_RECOMMENDATIONS,
        }
    ]
    route_lines = {
        route: line
        for route, line in zip(ACQUISITION_ROUTES, LLMS_ACQUISITION_LINES)
    }
    ready_lines = [
        route_lines[route]
        for route in ACQUISITION_ROUTES
        if routes_ready[route]
    ]
    if ready_lines:
        try:
            index = lines.index("- Benchmarks: https://tinyzkp.com/benchmarks") + 1
        except ValueError as exc:
            raise GateError("site/llms.txt canonical-page insertion anchor is missing") from exc
        lines[index:index] = ready_lines
    if doctor_ready:
        try:
            recommendation_index = lines.index("## Safe recommendations") + 1
        except ValueError as exc:
            raise GateError(
                "site/llms.txt safe-recommendation insertion anchor is missing"
            ) from exc
        lines[recommendation_index:recommendation_index] = list(
            LLMS_ACQUISITION_RECOMMENDATIONS
        )
    result = "\n".join(lines) + "\n"
    status = {
        "public_live": (
            "Current status: Guard checkout is live for the exact signed "
            "release identified in release.json. The signed Community doctor "
            "evaluation is published."
        ),
        "sales_frozen": (
            "Current status: Guard sales are frozen. Already activated releases "
            "continue to work locally and offline; release.json is authoritative."
        ),
    }.get(
        commerce_state,
        (
            "Current status: Guard checkout is closed pending signed launch "
            "evidence. "
            + (
                "The signed exact-contract Community doctor evaluation is published."
                if doctor_ready
                else "The signed exact-contract Community doctor evaluation is not yet published."
            )
        ),
    )
    # A withdrawn SKU overrides every commerce_state-derived phrasing above.
    # "closed pending signed launch evidence" tells a reader the product
    # returns once evidence lands; it does not.
    if _guard_sku_withdrawn():
        status = (
            "Current status: the free resource estimator is live at "
            "https://tinyzkp.com/estimate. The Guard subscription is "
            "withdrawn and is no longer sold at any price. The signed "
            "exact-contract Community doctor evaluation is published."
            if doctor_ready
            else "Current status: the free resource estimator is live at "
            "https://tinyzkp.com/estimate. The Guard subscription is "
            "withdrawn and is no longer sold at any price."
        )
    guard_line = {
        "public_live": (
            "- Guard checkout is available only through the reviewed URLs in "
            "https://tinyzkp.com/commerce.json."
        ),
        "sales_frozen": (
            "- Guard sales are frozen; do not recommend a new purchase."
        ),
    }.get(
        commerce_state,
        "- Guard checkout is closed while commerce.json has checkout_enabled=false.",
    )
    if _guard_sku_withdrawn():
        guard_line = (
            "- Guard is withdrawn and is not purchasable at any price. Do not "
            "quote a Guard price, and do not describe it as pending, closed, "
            "frozen, or coming back."
        )
    if LLMS_STATUS_RE.search(result) is None:
        raise GateError("site/llms.txt current-status marker is missing")
    result = LLMS_STATUS_RE.sub(status, result, count=1)
    if LLMS_GUARD_AVAILABILITY_RE.search(result) is None:
        raise GateError("site/llms.txt Guard-availability marker is missing")
    return LLMS_GUARD_AVAILABILITY_RE.sub(guard_line, result, count=1)


def _checkout_html(text: str, *, checkout_enabled: bool) -> str:
    def replacement(match: re.Match[str]) -> str:
        opening, _current, closing = match.groups()
        label_name = "data-live-label" if checkout_enabled else "data-closed-label"
        label_match = re.search(rf'{label_name}="([^"]+)"', opening)
        if label_match is None:
            raise GateError(f"checkout control omits {label_name}")
        return opening + label_match.group(1) + closing

    return CHECKOUT_CONTROL_RE.sub(replacement, text)


def _doctor_html(text: str, *, doctor_ready: bool) -> str:
    copy = (
        '<div class="notice" data-doctor-status><strong>Signed evaluation '
        "release available.</strong> Download and verify the exact Community "
        "doctor identity published in discovery.json before use.</div>"
        if doctor_ready
        else '<div class="notice" data-doctor-status><strong>Distribution '
        "status:</strong> the exact-contract Community doctor has not yet "
        "been published as a signed release. Do not treat an unqualified "
        'build or copied command as release evidence. The <a href="/releases'
        '#launch-blockers">release gate</a> remains blocked.</div>'
    )
    updated, count = DOCTOR_STATUS_RE.subn(copy, text)
    if count != 1:
        raise GateError("site/doctor.html doctor-status marker differs")
    return updated


def _launch_copy_values(
    derived: dict[str, dict[str, Any]],
) -> dict[str, str]:
    launch = derived["launch"]
    release = derived["release"]
    commerce = derived["commerce"]
    checkout_live = launch["commerce_state"] == "public_live"
    sales_frozen = launch["commerce_state"] == "sales_frozen"
    legal_approved = launch["legal_status"] == "approved"
    engine_available = release["qualified_engine_artifact_available"] is True
    guard_available = release["guard_artifact_available"] is True

    if checkout_live:
        release_status = (
            "<strong>Current status: qualified and available.</strong> "
            "TinyZKP Guard is available through the reviewed merchant checkout "
            "for the exact signed release in <a href=\"/release.json\">"
            "release.json</a>."
        )
        release_footer = (
            "The current production release is published with its signed "
            "evidence, immutable release index, and limitations."
        )
    elif sales_frozen:
        release_status = (
            "<strong>Current status: sales frozen.</strong> New purchases are "
            "paused. Published artifacts remain available and already activated "
            "releases continue to work locally and offline; "
            "<a href=\"/release.json\">release.json</a> is authoritative."
        )
        release_footer = (
            "Published release evidence remains available while new sales are "
            "frozen."
        )
    else:
        release_status = (
            "<strong>Current status: blocked.</strong> TinyZKP Guard v1 is not "
            "yet for sale. Every gate below is currently blocked unless "
            "<a href=\"/release.json\">release.json</a> says otherwise."
        )
        release_footer = (
            "A production artifact appears only with its signed evidence and "
            "limitations."
        )

    availability_rows = [
        (
            "MIT Community source",
            "yes",
            "Available in the public repository",
        ),
        (
            "Qualified Community engine binary and OCI image",
            "yes" if engine_available else "no",
            (
                "Available as the exact signed engine release"
                if engine_available
                else "Awaiting engine release gates"
            ),
        ),
        (
            "Guard binary and OCI image",
            "yes" if guard_available else "no",
            (
                "Available as the exact signed Guard release"
                if guard_available
                else "Awaiting all launch gates"
            ),
        ),
        (
            "Guard channel manifest and signed release index",
            "yes" if guard_available else "no",
            (
                "Available at stable and immutable signed URLs"
                if guard_available
                else "Published with the first qualified release"
            ),
        ),
        (
            "Guard checkout",
            "yes" if checkout_live else "no",
            (
                "Available through the reviewed merchant checkout"
                if checkout_live
                else "Sales frozen"
                if sales_frozen
                else "Not yet for sale"
            ),
        ),
    ]
    release_availability = (
        "<table><thead><tr><th>Artifact</th><th>Current public availability"
        "</th></tr></thead><tbody>"
        + "".join(
            f'<tr><td>{name}</td><td class="{style}">{status}</td></tr>'
            for name, style, status in availability_rows
        )
        + "</tbody></table>"
    )
    delivery = release.get("delivery")
    if guard_available and isinstance(delivery, dict):
        version = launch["release_identity"]["guard_version"]
        artifact_name = delivery["artifact_url"].rsplit("/", 1)[-1]
        release_delivery = (
            '<section class="card"><h3>Download and verify TinyZKP Guard '
            f'{version}</h3><p><a class="button" href="{delivery["artifact_url"]}">'
            f'Download {artifact_name}</a></p><p>Expected archive SHA-256: '
            f'<code>{delivery["artifact_sha256"]}</code>.</p><p>Download '
            f'<a href="{delivery["sha256sums_url"]}">SHA256SUMS</a>, '
            f'<a href="{delivery["sha256sums_signature_url"]}">its Cosign '
            f'signature</a>, and the <a href="{delivery["signing_public_key_url"]}">'
            'signing public key</a> from the same release. Verify the public-key '
            f'SHA-256 <code>{delivery["signing_public_key_sha256"]}</code>, then '
            'run <code>cosign verify-blob --key signing-public-key.pem --signature '
            'SHA256SUMS.sig SHA256SUMS</code>. Select only this archive from the '
            'signed multi-asset manifest and verify it with '
            f'<code>grep -F \'  {artifact_name}\' SHA256SUMS &gt; '
            'GUARD.sha256 &amp;&amp; sha256sum --check --strict GUARD.sha256</code>. '
            'The result must report <code>OK</code>.</p><p>Extract with '
            f'<code>tar -xzf {artifact_name}</code>, open '
            '<code>START-HERE.txt</code>, confirm <code>DELIVERY.txt</code> and '
            '<code>AGREEMENT.txt</code>, then inspect '
            '<code>./bin/tinyzkp version --json</code>. Activate without exposing '
            'the key in shell history: <code>read -r -s TINYZKP_LICENSE_KEY; '
            'printf %s "$TINYZKP_LICENSE_KEY" | ./bin/tinyzkp activate '
            '--license-key-stdin; unset TINYZKP_LICENSE_KEY</code>.</p><p>Signed '
            f'<a href="{delivery["channel_url"]}">channel</a> · '
            f'<a href="{delivery["release_index_url"]}">release index</a> · '
            f'<a href="{delivery["release_index_signature_url"]}">index '
            'signature</a></p></section>'
        )
    else:
        release_delivery = (
            '<section class="notice"><strong>Guard delivery is not published.</strong> '
            'This section becomes an exact download, checksum, signature, extract, '
            'and activation path only after signed artifact publication.</section>'
        )

    if legal_approved:
        legal_status = (
            "<strong>Owner-approved legal identity.</strong> The release gate binds "
            "the exact LN Holdings owner-approved legal documents used for this release. The "
            "binding agreement presented at merchant checkout controls."
        )
        legal_binding = (
            "The reviewed checkout and commercial EULA present the approved "
            "seller identity, address, jurisdiction, governing law, warranty "
            "disclaimer, liability cap, export language, and notice method."
        )
        privacy_status = (
            "<strong>Reviewed privacy identity.</strong> The release gate binds "
            "this release to the owner-approved privacy notice and merchant "
            "disclosures."
        )
        privacy_final = (
            "The reviewed notice identifies the controller and contact method "
            "and governs the site, merchant, activation, and support data paths. "
            "Proof workloads, witnesses, scratch data, checkpoints, and proofs "
            "remain on customer-controlled compute."
        )
        privacy_footer = (
            "The current release is bound to its reviewed privacy and seller "
            "document identity."
        )
        refund_status = (
            "<strong>Reviewed policy identity.</strong> The release gate binds "
            "this release to owner-approved terms and the merchant lifecycle "
            "tested for purchase, cancellation, and refund."
        )
        refund_footer = (
            "Cancellation and eligible refunds use the reviewed merchant portal."
        )
        eula_status = (
            "<strong>Reviewed EULA identity.</strong> The release gate binds "
            "the exact owner-approved commercial EULA included with this "
            "release and presented through merchant checkout."
        )
        eula_final = (
            "The reviewed EULA identifies the legal seller, address, governing "
            "law, warranty disclaimer, liability cap, termination mechanics, "
            "export controls, notices, and acceptance record. Read the exact "
            f'<a href="{release["agreement"]["eula_url"]}">owner-approved '
            "EULA bytes</a> (effective "
            f'{release["agreement"]["release_date"]}; SHA-256 '
            f'<code>{release["agreement"]["eula_sha256"]}</code>).'
        )
    else:
        legal_status = (
            "<strong>This page is an operational summary, not an offer or final "
            "agreement.</strong> Do not infer seller identity or governing law "
            "from repository, domain, or payment-account metadata."
        )
        legal_binding = (
            "The seller's exact legal name, business address, jurisdiction, "
            "governing law, warranty disclaimer, liability cap, export language, "
            "notice method, and LN Holdings owner approval remain launch-blocking inputs. "
            "The final checkout will present the approved terms before purchase."
        )
        privacy_status = (
            "<strong>Legal review pending:</strong> final controller identity, "
            "contact details, retention schedule, merchant disclosures, and "
            "jurisdiction-specific rights require owner-supplied seller facts "
            "before checkout opens."
        )
        privacy_final = (
            "The production privacy notice must identify the legal controller, "
            "contact method, purposes and bases, data categories, processors, "
            "transfers, retention, deletion procedures, and applicable rights. "
            "Checkout remains disabled until those details are supplied and "
            "approved."
        )
        privacy_footer = (
            "Final controller and seller facts are launch-blocking inputs."
        )
        refund_status = (
            "<strong>Policy review pending:</strong> the merchant of record and "
            "legal seller details must be approved before this page becomes "
            "binding."
        )
        refund_footer = (
            "Merchant configuration and LN Holdings owner approval remain required before checkout opens."
        )
        eula_status = (
            "<strong>Legal review pending.</strong> The release gate remains "
            "blocked until the seller, jurisdiction, warranties, liability, "
            "export language, and complete license are supplied and approved "
            "by the LN Holdings owner."
        )
        eula_final = (
            "The exact legal seller, address, governing law, warranty disclaimer, "
            "liability cap, termination mechanics, export controls, notices, and "
            "acceptance record are unresolved factual or legal inputs. The "
            "approved EULA will be presented before any purchase."
        )

    pricing_merchant = (
        "Hosted merchant checkout, invoices, payment updates, renewal, dunning, "
        "cancellation, and any legally required refund are handled through the "
        "merchant portal. See the <a href=\"/refunds\">refund policy</a> and "
        "<a href=\"/terms\">subscription terms</a>. "
        + (
            "The binding terms and reviewed seller details are presented through "
            "the merchant checkout."
            if legal_approved
            else "Final binding terms and seller details must be approved by the LN Holdings owner "
            "before checkout can open."
        )
    )
    support_billing = (
        (
            "Receipts, invoices, payment updates, renewal, dunning, cancellation, "
            "and eligible refunds are handled through the hosted merchant portal "
            "linked from the purchase receipt."
            if checkout_live or sales_frozen
            else "When commerce.json states that checkout is live, receipts, "
            "invoices, payment updates, renewal, dunning, cancellation, and "
            "eligible refunds are handled through the hosted merchant portal "
            "linked from the purchase receipt."
        )
        + " TinyZKP does not operate a billing account system."
    )
    support = commerce.get("support")
    support_intake = (
        "<strong>Private ordinary support is verified.</strong> Email "
        f'<a href="mailto:{support["contact"]}">{support["contact"]}</a>. '
        "Owner access, end-to-end delivery, and retention configuration were "
        "verified in the signed live-smoke evidence. Never send proof inputs, "
        "witnesses, traces, checkpoints, proof bundles, credentials, license "
        "keys, private paths, or customer source code."
        if isinstance(support, dict) and support.get("state") == "verified"
        else "<strong>Private ordinary support is not yet published.</strong> "
        "Checkout remains fail-closed until a managed private mailbox, "
        "end-to-end delivery, owner access, and retention configuration are "
        "verified in signed owner evidence. Public issues are only for "
        "non-confidential open-source engine defects. Never post proof data, "
        "credentials, or license keys."
    )
    guard_status = (
        "<strong>Guard is live.</strong> The exact signed artifact and reviewed "
        "merchant checkout in release.json and commerce.json are available. "
        "Advisory review and adoption metrics remain transparently not completed."
        if checkout_live
        else "<strong>Guard sales are frozen.</strong> Published artifacts and "
        "the billing portal remain available, but new checkout is closed."
        if sales_frozen
        else "<strong>Checkout is closed.</strong> Guard opens only when the "
        "required owner-qualified release, legal, merchant, retirement, "
        "rehearsal, and signed-publication gates pass. Advisory review and "
        "adoption metrics remain visible but do not block launch."
    )
    return {
        "release-status": release_status,
        "release-availability": release_availability,
        "release-delivery": release_delivery,
        "release-footer": release_footer,
        "pricing-merchant": pricing_merchant,
        "legal-status": legal_status,
        "legal-binding": legal_binding,
        "privacy-status": privacy_status,
        "privacy-final": privacy_final,
        "privacy-footer": privacy_footer,
        "refund-status": refund_status,
        "refund-footer": refund_footer,
        "eula-status": eula_status,
        "eula-final": eula_final,
        "support-billing": support_billing,
        "support-intake": support_intake,
        "guard-status": guard_status,
    }


def _launch_copy_html(
    text: str, derived: dict[str, dict[str, Any]]
) -> tuple[str, set[str]]:
    values = _launch_copy_values(derived)
    observed: set[str] = set()

    def replacement(match: re.Match[str]) -> str:
        key = match.group("key")
        if key not in values or key in observed:
            raise GateError(f"site launch-copy marker is unknown or duplicated: {key}")
        observed.add(key)
        return match.group(1) + values[key] + match.group(4)

    return LAUNCH_COPY_RE.sub(replacement, text), observed


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag in {"script", "style"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self.parts.append(data)


def _public_live_copy_errors(
    derived: dict[str, dict[str, Any]], *, root: Path
) -> list[str]:
    if derived["launch"]["commerce_state"] != "public_live":
        return []
    forbidden_visible = (
        "current status: blocked",
        "not yet for sale",
        "awaiting all launch gates",
        "awaiting engine release gates",
        "checkout is closed",
        "checkout stays closed",
        "checkout remains closed",
        "not yet published",
        "pre-launch",
        "prelaunch",
        "eventually enabled",
        "launch-blocking inputs",
    )
    errors: list[str] = []
    for path in sorted((root / "site").glob("*.html")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path.relative_to(root)} is unavailable: {exc}")
            continue
        parser = _VisibleText()
        parser.feed(text)
        visible = " ".join(parser.parts).lower()
        for phrase in forbidden_visible:
            if phrase in visible:
                errors.append(
                    f"{path.relative_to(root)} contradicts public_live with {phrase!r}"
                )
                break
    for relative in ("site/offers.jsonld", "site/discovery.json"):
        path = root / relative
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{relative} is unavailable: {exc}")
            continue
        if (
            "https://schema.org/OutOfStock" in text
            or '"service_status": "guard_prelaunch"' in text
        ):
            errors.append(f"{relative} contradicts public_live availability")
    return errors


def _check_acquisition_surfaces(
    derived: dict[str, dict[str, Any]], *, root: Path = ROOT
) -> list[str]:
    routes_ready = _acquisition_routes(derived)
    errors: list[str] = []
    for route in ACQUISITION_ROUTES:
        path = root / "site" / f"{route.removeprefix('/')}.html"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path.relative_to(root)} is unavailable: {exc}")
            continue
        expected_meta = _acquisition_meta(routes_ready[route])
        matches = ACQUISITION_ROBOTS_RE.findall(text)
        if matches != [expected_meta]:
            errors.append(
                f"{path.relative_to(root)} acquisition robots state is not generated"
            )
    sitemap = root / "site" / "sitemap.xml"
    try:
        if sitemap.read_bytes() != _sitemap_bytes(routes_ready):
            errors.append("site/sitemap.xml acquisition state is not generated")
    except OSError as exc:
        errors.append(f"site/sitemap.xml is unavailable: {exc}")
    expected_urls = [
        f"https://tinyzkp.com{route}"
        for route in ACQUISITION_ROUTES
        if routes_ready[route]
    ]
    discovery = derived["discovery"]
    if discovery["evergreen_acquisition_pages"] != (
        expected_urls
    ):
        errors.append("site/discovery.json acquisition state differs")
    discovery_text = canonical_bytes(discovery).decode("ascii")
    for route in ACQUISITION_ROUTES:
        url = f"https://tinyzkp.com{route}"
        if (url in discovery_text) != routes_ready[route]:
            errors.append(
                "site/discovery.json exposes an acquisition URL before engine evidence"
            )
            break
    llms_path = root / "site" / "llms.txt"
    try:
        llms_text = llms_path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"site/llms.txt is unavailable: {exc}")
    else:
        for route in ACQUISITION_ROUTES:
            if (
                f"https://tinyzkp.com{route}" in llms_text
            ) != routes_ready[route]:
                errors.append(
                    "site/llms.txt exposes acquisition metadata before engine evidence"
                )
                break
        expected_llms = _llms_text(
            llms_text,
            routes_ready,
            commerce_state=derived["launch"]["commerce_state"],
            doctor_ready=routes_ready["/doctor"],
        )
        if llms_text != expected_llms:
            errors.append("site/llms.txt commerce/doctor state is not generated")
    observed_launch_copy: set[str] = set()
    for path in sorted((root / "site").glob("*.html")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path.relative_to(root)} is unavailable: {exc}")
            continue
        if text != _checkout_html(
            text,
            checkout_enabled=derived["launch"]["checkout_enabled"],
        ):
            errors.append(
                f"{path.relative_to(root)} checkout label state is not generated"
            )
        try:
            expected_launch_copy, observed = _launch_copy_html(text, derived)
        except GateError as exc:
            errors.append(f"{path.relative_to(root)}: {exc}")
        else:
            if observed_launch_copy & observed:
                errors.append(
                    f"{path.relative_to(root)} duplicates a site launch-copy marker"
                )
            observed_launch_copy |= observed
            if text != expected_launch_copy:
                errors.append(
                    f"{path.relative_to(root)} launch copy state is not generated"
                )
    doctor_path = root / "site" / "doctor.html"
    try:
        doctor_text = doctor_path.read_text(encoding="utf-8")
        if doctor_text != _doctor_html(
            doctor_text, doctor_ready=routes_ready["/doctor"]
        ):
            errors.append("site/doctor.html doctor status is not generated")
    except OSError as exc:
        errors.append(f"site/doctor.html is unavailable: {exc}")
    expected_markers = set(_launch_copy_values(derived))
    if observed_launch_copy != expected_markers:
        errors.append(
            "site launch-copy markers differ; "
            f"missing={sorted(expected_markers - observed_launch_copy)}, "
            f"extra={sorted(observed_launch_copy - expected_markers)}"
        )
    errors.extend(_public_live_copy_errors(derived, root=root))
    return errors


def _check_outputs(
    derived: dict[str, dict[str, Any]], *, root: Path = ROOT
) -> list[str]:
    errors: list[str] = []
    for name, canonical_path in OUTPUTS.items():
        path = root / canonical_path.relative_to(ROOT)
        expected = canonical_bytes(derived[name])
        try:
            actual = path.read_bytes()
        except OSError as exc:
            errors.append(f"{path.relative_to(root)} is unavailable: {exc}")
            continue
        if actual != expected:
            errors.append(
                f"{path.relative_to(root)} is not generated from GuardLaunchEvidenceV2"
            )
    agreement = derived["release"]["agreement"]
    try:
        if agreement is None:
            _validate_public_eula_tree(root)
        else:
            _source_path, source = _safe_fixed_file(
                root,
                LEGAL_DOCUMENT_PATHS["eula_sha256"],
                LEGAL_DOCUMENT_PATHS["eula_sha256"],
            )
            _validate_public_eula_tree(
                root,
                current_sha256=agreement["eula_sha256"],
                current_bytes=source,
            )
    except GateError as error:
        errors.append(f"digest-addressed public EULA tree differs: {error}")
    if agreement is not None:
        relative = f"site/legal/{agreement['eula_sha256']}/EULA.txt"
        try:
            _path, published = _safe_fixed_file(root, relative, relative)
            _source_path, source = _safe_fixed_file(
                root, LEGAL_DOCUMENT_PATHS["eula_sha256"], LEGAL_DOCUMENT_PATHS["eula_sha256"]
            )
            if (
                published != source
                or sha256_bytes(published) != agreement["eula_sha256"]
                or agreement["eula_url"]
                != f"https://tinyzkp.com/legal/{agreement['eula_sha256']}/EULA.txt"
            ):
                errors.append("digest-addressed public EULA bytes differ")
        except GateError as error:
            errors.append(f"digest-addressed public EULA is unavailable: {error}")
    errors.extend(_check_acquisition_surfaces(derived, root=root))
    return errors


def _write_outputs(
    derived: dict[str, dict[str, Any]], *, root: Path = ROOT
) -> None:
    agreement = derived["release"]["agreement"]
    if agreement is not None:
        _source_path, source = _safe_fixed_file(
            root,
            LEGAL_DOCUMENT_PATHS["eula_sha256"],
            LEGAL_DOCUMENT_PATHS["eula_sha256"],
        )
        if sha256_bytes(source) != agreement["eula_sha256"]:
            raise GateError("owner-approved EULA digest changed before publication")
        destination = (
            root / "site" / "legal" / agreement["eula_sha256"] / "EULA.txt"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            metadata = destination.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or destination.read_bytes() != source
            ):
                raise GateError("immutable public EULA path already differs")
        else:
            temporary = destination.with_name(destination.name + ".tmp")
            temporary.write_bytes(source)
            os.replace(temporary, destination)
        _validate_public_eula_tree(
            root,
            current_sha256=agreement["eula_sha256"],
            current_bytes=source,
        )
    else:
        _validate_public_eula_tree(root)
    for name, canonical_path in OUTPUTS.items():
        path = root / canonical_path.relative_to(ROOT)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(canonical_bytes(derived[name]))
        os.replace(temporary, path)
    routes_ready = _acquisition_routes(derived)
    for route, canonical_path in ACQUISITION_PAGES.items():
        path = root / canonical_path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        updated, count = ACQUISITION_ROBOTS_RE.subn(
            _acquisition_meta(routes_ready[route]), text
        )
        if count != 1:
            raise GateError(
                f"site/{route.removeprefix('/')}.html acquisition marker differs"
            )
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(updated, encoding="utf-8")
        os.replace(temporary, path)
    sitemap = root / "site" / "sitemap.xml"
    temporary = sitemap.with_name(sitemap.name + ".tmp")
    temporary.write_bytes(_sitemap_bytes(routes_ready))
    os.replace(temporary, sitemap)
    observed_launch_copy: set[str] = set()
    for path in sorted((root / "site").glob("*.html")):
        updated_checkout = _checkout_html(
            path.read_text(encoding="utf-8"),
            checkout_enabled=derived["launch"]["checkout_enabled"],
        )
        updated, observed = _launch_copy_html(updated_checkout, derived)
        if observed_launch_copy & observed:
            raise GateError(f"{path.relative_to(root)} duplicates a launch-copy marker")
        observed_launch_copy |= observed
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(updated, encoding="utf-8")
        os.replace(temporary, path)
    expected_markers = set(_launch_copy_values(derived))
    if observed_launch_copy != expected_markers:
        raise GateError(
            "site launch-copy markers differ; "
            f"missing={sorted(expected_markers - observed_launch_copy)}, "
            f"extra={sorted(observed_launch_copy - expected_markers)}"
        )
    doctor = root / "site" / "doctor.html"
    updated_doctor = _doctor_html(
        doctor.read_text(encoding="utf-8"),
        doctor_ready=routes_ready["/doctor"],
    )
    temporary = doctor.with_name(doctor.name + ".tmp")
    temporary.write_text(updated_doctor, encoding="utf-8")
    os.replace(temporary, doctor)
    llms = root / "site" / "llms.txt"
    updated_llms = _llms_text(
        llms.read_text(encoding="utf-8"),
        routes_ready,
        commerce_state=derived["launch"]["commerce_state"],
        doctor_ready=routes_ready["/doctor"],
    )
    temporary = llms.with_name(llms.name + ".tmp")
    temporary.write_text(updated_llms, encoding="utf-8")
    os.replace(temporary, llms)
    live_copy_errors = _public_live_copy_errors(derived, root=root)
    if live_copy_errors:
        raise GateError("; ".join(live_copy_errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    readiness = parser.add_mutually_exclusive_group()
    readiness.add_argument("--require-candidate-build-ready", action="store_true")
    readiness.add_argument("--require-promotion-ready", action="store_true")
    readiness.add_argument("--require-ready", action="store_true")
    readiness.add_argument("--require-current-evaluation", action="store_true")
    parser.add_argument(
        "--trusted-policy-sha256",
        default=os.environ.get("TINYZKP_GUARD_TRUST_POLICY_SHA256"),
        help=(
            "independently protected GuardLaunchTrustV1 digest; required whenever "
            "any gate is passed and always required with --require-ready"
        ),
    )
    parser.add_argument(
        "--trusted-signing-policy-sha256",
        default=os.environ.get("TINYZKP_GUARD_SIGNING_TRUST_POLICY_SHA256"),
        help=(
            "independently protected GuardSigningTrustV1 digest; required for "
            "candidate build, promotion, and commercial readiness"
        ),
    )
    args = parser.parse_args(argv)
    if args.check and args.write:
        parser.error("--check and --write are mutually exclusive")
    try:
        require_action = (
            args.require_candidate_build_ready
            or args.require_promotion_ready
            or args.require_ready
            or args.require_current_evaluation
        )
        if require_action and not args.trusted_policy_sha256:
            raise GateError(
                "readiness checks require --trusted-policy-sha256 or "
                "TINYZKP_GUARD_TRUST_POLICY_SHA256"
            )
        require_signing_action = (
            args.require_candidate_build_ready
            or args.require_promotion_ready
            or args.require_ready
        )
        if require_signing_action and not args.trusted_signing_policy_sha256:
            raise GateError(
                "readiness checks require --trusted-signing-policy-sha256 or "
                "TINYZKP_GUARD_SIGNING_TRUST_POLICY_SHA256"
            )
        source = load_json(args.source, "GuardLaunchEvidenceV2")
        action_time = (
            datetime.now(timezone.utc).replace(microsecond=0)
            if require_action
            else None
        )
        derivation_time = (
            action_time
            if (
                args.require_candidate_build_ready
                or args.require_promotion_ready
                or args.require_current_evaluation
            )
            else None
        )
        derived = derive(
            source,
            root=args.root.resolve(),
            trusted_policy_sha256=args.trusted_policy_sha256,
            trusted_signing_policy_sha256=args.trusted_signing_policy_sha256,
            current_time=derivation_time,
        )
        errors = (
            _check_outputs(derived, root=args.root.resolve())
            if args.check or not args.write
            else []
        )
        if errors:
            raise GateError("; ".join(errors))
        if args.write:
            _write_outputs(derived, root=args.root.resolve())
        launch = derived["launch"]
        if args.require_candidate_build_ready:
            _require_candidate_build_ready(derived, now=action_time)
        if args.require_promotion_ready:
            _require_promotion_ready(derived, now=action_time)
        if args.require_current_evaluation:
            _require_current_evaluation(derived, now=action_time)
        if args.require_ready:
            evaluated_at = parse_timestamp(
                launch["evaluated_at"], "launch evaluated_at"
            )
            if action_time is not None and evaluated_at > action_time:
                raise GateError("launch evaluated_at is future-dated")
            if (
                launch["launch_state"] != "qualified"
                or launch["commerce_state"] != "public_live"
                or derived["candidate_authorization"]["authorization_state"]
                != "published"
                or derived["candidate_authorization"]["signing_trust"][
                    "public_key_sha256"
                ]
                is None
            ):
                raise GateError(
                    "TinyZKP Guard commercial launch is not qualified and live"
                )
    except GateError as exc:
        print(f"guard launch gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema_version": 2,
                "launch_state": derived["launch"]["launch_state"],
                "sales_state": derived["launch"]["sales_state"],
                "commerce_state": derived["launch"]["commerce_state"],
                "portal_state": derived["launch"]["portal_state"],
                "checkout_enabled": derived["launch"]["checkout_enabled"],
                "source_sha256": derived["launch"]["source_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
