#!/usr/bin/env python3
"""Contract tests for the static, fail-closed TinyZKP Guard site."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
LAUNCH_GATE = ROOT / "release" / "guard-launch-state-v2.json"
MARKET_CLOCK = ROOT / "release" / "guard-market-clock-v1.json"
GUARD_SKU_WITHDRAWAL = ROOT / "release" / "guard-sku-withdrawal-v1.json"


def _guard_sku_withdrawn() -> bool:
    """True when the Guard SKU is recorded as withdrawn.

    Mirrors ``guard_launch_gate._guard_sku_withdrawn`` deliberately rather than
    importing it: this module is a CONTRACT test on the shipped site, and it
    must keep working if the gate is refactored. Absent or malformed record
    means NOT withdrawn, so a parse failure can never silently relax the
    stricter "is this described as pending?" assertions below.
    """
    try:
        data = json.loads(GUARD_SKU_WITHDRAWAL.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data.get("withdrawn") is True

PUBLIC_PAGES = {
    "index.html",
    "guard.html",
    "compatibility.html",
    "benchmarks.html",
    "doctor.html",
    "estimate.html",
    "troubleshooting.html",
    "plonky3-out-of-memory.html",
    "resumable-plonky3-prover.html",
    "ssd-backed-plonky3-proving.html",
    "pricing.html",
    "docs.html",
    "security.html",
    "releases.html",
    "support.html",
    "terms.html",
    "privacy.html",
    "refunds.html",
    "eula.html",
}


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class CheckoutParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.checkout_controls: list[dict[str, str | None]] = []
        self.portal_controls: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if "data-checkout" in attributes:
            self.checkout_controls.append(attributes)
        if "data-portal" in attributes:
            self.portal_controls.append(attributes)


class PrimaryButtonParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.buttons: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if tag == "a" and "button" in classes and "secondary" not in classes:
            self._current = {"attrs": attributes, "text": ""}

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["text"] = str(self._current["text"]) + data

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current is not None:
            self._current["text"] = str(self._current["text"]).strip()
            self.buttons.append(self._current)
            self._current = None


def test_public_page_set_is_exact() -> None:
    assert {path.name for path in SITE.glob("*.html")} == PUBLIC_PAGES


def test_checkout_is_consistently_fail_closed() -> None:
    gate = load_json(LAUNCH_GATE)
    commerce = load_json(SITE / "commerce.json")
    pricing = load_json(SITE / "pricing.json")
    release = load_json(SITE / "release.json")

    assert gate["checkout_enabled"] is False
    assert commerce["checkout_enabled"] is False
    assert pricing["checkout_enabled"] is False
    assert release["checkout_enabled"] is False
    for item in (gate, commerce, release):
        assert item["authorization_policy"] == "owner_only_ga_v1"
        assert item["qualification_basis"] == "owner_attested"
    assert {
        (
            item["launch_state"],
            item["sales_state"],
            item["commerce_state"],
            item["portal_state"],
        )
        for item in (gate, commerce, pricing, release)
        # `withdrawn`, not `closed`: the Guard SKU is retired, not merely
        # not-selling-right-now. `closed` renders as schema.org/OutOfStock,
        # which tells machine readers the product is coming back. See
        # release/guard-sku-withdrawal-v1.json.
    } == {("blocked", "withdrawn", "unconfigured", "unconfigured")}
    assert set(release["blocking_gates"]) == set(gate["blocking_gates"])
    assert release["gate_status"] == gate["gate_status"]
    for variant in commerce["variants"].values():
        assert variant == {
            "variant_id": None,
            "reviewed": False,
            "checkout_url": None,
        }
    assert commerce["checkout_custom_data"] == {
        "terms_version": None,
        "guard_version": None,
    }
    assert set(gate["advisory_status"].values()) == {"not_completed"}
    assert release["advisory_status"] == gate["advisory_status"]


def test_homepage_describes_the_blocked_launch_state_unambiguously() -> None:
    homepage = (SITE / "index.html").read_text(encoding="utf-8")
    if _guard_sku_withdrawn():
        # "Closed pending evidence" says the gates could still open, which is
        # true of a blocked launch and false of a withdrawal. Once the SKU is
        # withdrawn the homepage must say so and must NOT carry the pending
        # phrasing, or the panel contradicts the page's own body copy.
        assert "Withdrawn, not for sale" in homepage
        assert "Closed pending evidence" not in homepage
    else:
        assert "Closed pending evidence" in homepage
    assert "Evidence gates open" not in homepage


def test_checkout_urls_cannot_be_in_page_markup() -> None:
    controls = []
    portals = []
    for page in sorted(PUBLIC_PAGES):
        parser = CheckoutParser()
        parser.feed((SITE / page).read_text(encoding="utf-8"))
        controls.extend((page, attributes) for attributes in parser.checkout_controls)
        portals.extend((page, attributes) for attributes in parser.portal_controls)

    assert controls, "site must expose visibly closed Guard purchase controls"
    # The allowed label set is DERIVED from the withdrawal record rather than
    # pinned, so that revoking the withdrawal moves the site back to "not yet"
    # copy and re-withdrawing moves it forward again, without either state
    # needing a hand edit here. A withdrawn SKU described as pending is the
    # specific defect this asserts against: "not yet" promises a launch that is
    # not coming, and site/llms.txt forbids exactly that phrasing.
    sku_withdrawn = _guard_sku_withdrawn()
    allowed = (
        {"Guard withdrawn", "Monthly withdrawn"}
        if sku_withdrawn
        else {"Not yet for sale", "Monthly not yet for sale"}
    )
    for page, attributes in controls:
        assert attributes.get("href") is None, f"{page} hardcodes a checkout href"
        label = attributes.get("data-closed-label")
        assert label in allowed, f"{page}: {label!r} not one of {sorted(allowed)}"
        if sku_withdrawn:
            lowered = (label or "").lower()
            pending = [
                phrase
                for phrase in ("not yet", "coming", "soon", "pending", "launch")
                if phrase in lowered
            ]
            assert not pending, (
                f"{page} describes the withdrawn Guard SKU as pending "
                f"({label!r} contains {pending}); a withdrawal is not a delay"
            )
    assert len(portals) == 1
    portal_page, portal = portals[0]
    assert portal_page == "support.html"
    assert portal.get("href") is None
    assert portal.get("data-closed-label") == "Billing portal unavailable"
    assert portal.get("data-live-label") == "Manage billing"


def test_primary_buttons_are_only_doctor_or_guard_actions() -> None:
    observed = []
    for page in sorted(PUBLIC_PAGES):
        parser = PrimaryButtonParser()
        parser.feed((SITE / page).read_text(encoding="utf-8"))
        observed.extend((page, button) for button in parser.buttons)

    assert observed
    for page, button in observed:
        attrs = button["attrs"]
        if attrs.get("data-checkout") == "annual":
            assert attrs.get("data-live-label") == "Buy Guard", page
            continue
        assert button["text"] == "Run the free doctor", page
        assert attrs.get("href") in {"/doctor", "#run"}, page


def test_pricing_has_only_community_and_guard() -> None:
    pricing = load_json(SITE / "pricing.json")
    assert [product["id"] for product in pricing["products"]] == ["community", "guard"]
    assert pricing["products"][0]["price_usd"] == 0
    assert pricing["products"][1]["prices"] == {
        "monthly_usd": 499,
        "annual_usd": 4990,
        "annual_recommended": True,
    }
    assert pricing["hosted_proving"] is False
    assert pricing["usage_metering"] is False
    assert pricing["price_policy"] == {
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
    }
    pricing_copy = (SITE / "pricing.html").read_text(encoding="utf-8")
    assert "retains the reviewed merchant variant IDs" in pricing_copy
    assert "preserves each existing subscription's original price" in pricing_copy


def test_machine_assets_are_json_and_public_contracts_have_ids() -> None:
    for name in (
        "pricing.json",
        "discovery.json",
        "commerce.json",
        "compatibility.json",
        "release.json",
        "offers.jsonld",
    ):
        load_json(SITE / name)

    for name in (
        "job-manifest-v1.schema.json",
        "doctor-report-v1.schema.json",
        "compatibility-report-v1.schema.json",
        "reason-v1.schema.json",
        "error-envelope-v1.schema.json",
        "progress-event-v1.schema.json",
        "job-result-v1.schema.json",
        "support-report-v1.schema.json",
        "job-inspect-result-v1.schema.json",
        "guard-channel-v1.schema.json",
        "guard-release-index-v1.schema.json",
        "policy-baseline-v1.schema.json",
        "compatibility-manifest-v1.schema.json",
    ):
        schema = load_json(SITE / "schemas" / name)
        assert schema["$id"] == f"https://tinyzkp.com/schemas/{name}"


def test_compatibility_profile_id_is_canonical_across_contracts() -> None:
    profile_id = "tinyzkp-p3-goldilocks-v1"
    compatibility = load_json(SITE / "compatibility.json")
    assert compatibility["profile"] == profile_id
    assert compatibility["qualification"] == "blocked_pending_engine_evidence"
    assert compatibility["release_binding"] is None
    assert load_json(SITE / "release.json")["compatibility_profile"] == profile_id
    assert load_json(SITE / "schemas" / "compatibility-report-v1.schema.json")["$defs"]["CompatibilityManifestV1"]["properties"]["profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "compatibility-manifest-v1.schema.json")["properties"]["profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "job-manifest-v1.schema.json")["properties"]["compatibility_profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "job-result-v1.schema.json")["$defs"]["ReleaseIdentityV1"]["properties"]["compatibility_profile"]["const"] == profile_id
    assert load_json(SITE / "schemas" / "guard-channel-v1.schema.json")["properties"]["compatibility_profile"]["const"] == profile_id


def test_discovery_exposes_exact_thirteen_published_contract_urls() -> None:
    contracts = load_json(SITE / "discovery.json")["contracts"]
    assert set(contracts) == {
        "job_manifest_v1",
        "doctor_report_v1",
        "compatibility_report_v1",
        "reason_v1",
        "error_envelope_v1",
        "progress_event_v1",
        "job_result_v1",
        "support_report_v1",
        "job_inspect_result_v1",
        "guard_channel_v1",
        "guard_release_index_v1",
        "policy_baseline_v1",
        "compatibility_manifest_v1",
    }
    assert len(set(contracts.values())) == 13
    assert all(
        value.startswith("https://tinyzkp.com/schemas/")
        and value.endswith("-v1.schema.json")
        for value in contracts.values()
    )


def test_signed_evaluation_doctor_matches_market_evidence() -> None:
    discovery = load_json(SITE / "discovery.json")
    market_clock = load_json(MARKET_CLOCK)
    doctor_ready = market_clock["doctor_evaluation_release"]["status"] == "passed"
    assert discovery["availability"]["community_source"] is True
    assert discovery["availability"]["community_doctor"] is doctor_ready
    assert discovery["availability"]["signed_evaluation_doctor_binary"] is doctor_ready
    assert discovery["availability"]["signed_evaluation_doctor_oci"] is doctor_ready
    assert discovery["primary_actions"] == (
        [{"label": "Run the free doctor", "url": "https://tinyzkp.com/doctor"}]
        if doctor_ready
        else []
    )


def test_acquisition_page_indexing_matches_signed_doctor_evidence() -> None:
    routes = (
        "/doctor",
        "/plonky3-out-of-memory",
        "/resumable-plonky3-prover",
        "/ssd-backed-plonky3-proving",
    )
    discovery = load_json(SITE / "discovery.json")
    market_clock = load_json(MARKET_CLOCK)
    doctor_ready = market_clock["doctor_evaluation_release"]["status"] == "passed"
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
    # The three content pages no longer wait on `engine_release_ready`, which
    # gates a release of the WITHDRAWN Guard SKU and had been holding the whole
    # organic-acquisition surface out of the index. `/doctor` still requires
    # its own signed release. See `guard_launch_gate._acquisition_routes`.
    assert discovery["evergreen_acquisition_pages"] == (
        [f"https://tinyzkp.com{route}" for route in routes]
        if doctor_ready
        else []
    )
    for route in routes:
        page = SITE / f"{route.removeprefix('/')}.html"
        text = page.read_text(encoding="utf-8")
        route_ready = doctor_ready
        robots = "index,follow" if route_ready else "noindex,nofollow"
        assert (
            f'<meta name="robots" content="{robots}" data-guard-acquisition>'
        ) in text
        if route_ready:
            assert f"https://tinyzkp.com{route}" in sitemap
            assert f"https://tinyzkp.com{route}" in json.dumps(discovery)
        else:
            assert f"https://tinyzkp.com{route}" not in sitemap
            assert f"https://tinyzkp.com{route}" not in json.dumps(discovery)


def test_activation_disclosure_matches_the_guard_transport() -> None:
    privacy = (SITE / "privacy.html").read_text(encoding="utf-8")
    security = (SITE / "security.html").read_text(encoding="utf-8")
    llms = (SITE / "llms.txt").read_text(encoding="utf-8")
    for document in (privacy, security, llms):
        assert "license key" in document
        assert "Guard version" in document
        assert "User-Agent" in document
        assert "ordinary request metadata" in document
    assert "supported request does not send the release identity" not in privacy
    assert "supported request keeps release identity local" not in security
    assert "proofs, and release identity stay on customer compute" not in llms


def test_withdrawal_copy_discloses_the_offline_activation_limit() -> None:
    for name in ("guard.html", "docs.html", "releases.html", "llms.txt"):
        document = (SITE / name).read_text(encoding="utf-8").lower()
        assert "withdraw" in document
        assert "supersed" in document
        assert "already-downloaded" in document or "downloaded earlier" in document
        assert "release-specific denylist" in document
        assert "may still activate" in document
        assert "cannot learn" in document
        assert "resume-only" in document


def test_docs_publish_every_locked_guard_cli_entrypoint() -> None:
    docs = (SITE / "docs.html").read_text(encoding="utf-8")
    for command in (
        "tinyzkp activate --license-key-stdin",
        "tinyzkp compatibility check --job job.json",
        "tinyzkp doctor --job job.json",
        "tinyzkp run --job job.json",
        "tinyzkp resume --job-dir ./job",
        "tinyzkp verify --bundle proof.json",
        "tinyzkp policy check --report run.json --baseline baseline.json",
        "tinyzkp license status --json",
        "tinyzkp version --json",
    ):
        assert command in docs


def test_current_readme_and_issue_template_do_not_reintroduce_hosted_beta_copy() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "guard-launch-gates-v1.json" not in readme
    assert "external design-partner integration" not in readme
    assert "doctor, prove, resume, policy" not in readme
    assert "hosted API/MCP/billing launch audit is retired" in readme
    assert "tinyzkp-engine doctor --job job.json" in readme
    assert "doctor --job /path/to/job.json" not in readme

    issue = (
        ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml"
    ).read_text(encoding="utf-8")
    assert "Do not attach witnesses, traces, proofs, checkpoints, scratch files" in issue
    assert "Include only a manually inspected SupportReportV1" in issue
    assert "Never attach DoctorReportV1" in issue
    diagnostics = issue.split("id: diagnostics", 1)[1].split(
        "id: confirmation", 1
    )[0]
    assert "required: true" not in diagnostics


def test_blocked_homepage_labels_the_profile_as_a_target_not_production() -> None:
    homepage = (SITE / "index.html").read_text(encoding="utf-8")
    assert "Target v1 profile" in homepage
    assert "Production profile" not in homepage


def test_dynamic_and_legacy_business_surfaces_are_absent() -> None:
    assert not (SITE / "functions").exists() or not any((SITE / "functions").rglob("*.js"))
    for name in ("analytics.js", "openapi.json", "contact.html", "requests.html", "status.html", "engine.html", "plonky3.html"):
        assert not (SITE / name).exists()

    published = "\n".join(path.read_text(encoding="utf-8") for path in SITE.glob("*.html")).lower()
    for stale in ("tinyzkp certified", "fleet / oem", "$25k", "$40k", "$60k", "$125k", "proof credits"):
        assert stale not in published


def test_site_never_promises_a_quarterly_release() -> None:
    published = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in SITE.glob("*")
        if path.suffix in {".html", ".json", ".txt"}
    )
    for prohibited in (
        "quarterly qualified release",
        "qualified releases are planned quarterly",
        "quarterly release channel",
        "quarterly releases",
    ):
        assert prohibited not in published
    assert "four qualification windows per year" in published
    assert "a window may publish no new binary" in published


def test_no_checkout_host_or_contact_backend_is_hardcoded() -> None:
    pages = "\n".join(path.read_text(encoding="utf-8") for path in SITE.glob("*.html"))
    assert "lemonsqueezy.com/buy/" not in pages
    assert "/api/contact" not in pages
    assert "/api/events" not in pages


def test_every_frozen_reason_code_has_an_exact_troubleshooting_anchor() -> None:
    reason_codes = {
        "unsupported_platform",
        "unsupported_profile",
        "unsupported_air_feature",
        "manifest_contract_invalid",
        "unsafe_path",
        "input_limit_exceeded",
        "ram_budget_insufficient",
        "scratch_budget_insufficient",
        "scratch_space_insufficient",
        "job_state_exists",
        "interrupted_resumable",
        "checkpoint_missing",
        "checkpoint_corrupt",
        "checkpoint_release_mismatch",
        "job_not_resumable",
        "verification_rejected",
        "release_not_activated",
        "license_inactive",
        "license_provider_unavailable",
        "engine_artifact_mismatch",
        "engine_protocol_invalid",
        "release_identity_mismatch",
        "internal_error",
    }
    page = (SITE / "troubleshooting.html").read_text(encoding="utf-8")
    parser = CheckoutParser()
    parser.feed(page)

    class AnchorParser(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.ids: set[str] = set()

        def handle_starttag(self, tag, attrs):
            value = dict(attrs).get("id")
            if value:
                self.ids.add(value)

    anchors = AnchorParser()
    anchors.feed(page)
    assert reason_codes <= anchors.ids
    assert page.count('id="') >= len(reason_codes)


def test_generated_reason_anchors_resolve_to_public_pages() -> None:
    gate = load_json(LAUNCH_GATE)
    assert gate["reason_anchors"]["launch"] == "/releases#launch-blockers"
    assert gate["reason_anchors"]["sales"] == "/pricing#sales-status"
    assert gate["reason_anchors"]["portal"] == "/support#merchant-portal"
    for name, record in gate["gate_status"].items():
        assert record["reason_anchor"] == gate["reason_anchors"][name]
