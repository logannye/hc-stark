import copy

import pytest

import render_offers as offers


def test_current_offer_source_is_valid():
    source = offers.load_source()
    assert offers.validate(source) == []
    assert offers.validate_pricing_html(
        source, offers.PRICING_HTML.read_text(encoding="utf-8")
    ) == []


def test_rejects_enabled_checkout_and_price_drift():
    source = copy.deepcopy(offers.load_source())
    source["checkout_enabled"] = True
    source["products"][0]["price_usd"] = 1
    failures = offers.validate(source)
    assert "enabled checkout requires sales_state 'live'" in failures
    assert "live checkout requires launch_state qualified" in failures
    assert "live checkout requires commerce_state public_live" in failures
    assert "community price_usd must be 0" in failures


def test_rendered_catalog_contains_only_current_products():
    rendered = offers.render_sales_matrix(offers.load_source())
    assert "TinyZKP Community source" in rendered
    assert "$4,990/year" in rendered
    assert "$499/month" in rendered
    assert "$25,000" not in rendered
    assert "Fleet / OEM" not in rendered


def test_live_checkout_requires_guard_availability_and_portal():
    source = copy.deepcopy(offers.load_source())
    source["checkout_enabled"] = True
    source["sales_state"] = "live"
    source["launch_state"] = "qualified"
    source["commerce_state"] = "public_live"
    source["portal_state"] = "live"
    source["products"][1]["availability"] = "available"
    assert offers.validate(source) == []


def test_sales_frozen_uses_canonical_state_and_availability():
    source = copy.deepcopy(offers.load_source())
    source["sales_state"] = "frozen"
    source["commerce_state"] = "sales_frozen"
    source["portal_state"] = "live"
    source["products"][1]["availability"] = "sales_frozen"
    assert offers.validate(source) == []
    frozen_matrix = offers.render_sales_matrix(source)
    assert frozen_matrix.count("| Sales frozen |") == 2
    assert "Closed pending launch evidence" not in frozen_matrix


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (
            lambda products: products.append(copy.deepcopy(products[1])),
            "duplicate product id: guard",
        ),
        (lambda products: products.__setitem__(1, "guard"), "products[1] must be an object"),
        (
            lambda products: products[1].pop("id"),
            "products[1].id must be a non-empty string",
        ),
    ],
)
def test_rejects_duplicate_and_malformed_products(mutation, expected):
    source = copy.deepcopy(offers.load_source())
    mutation(source["products"])
    assert expected in offers.validate(source)


def test_rejects_reviewed_scope_and_boundary_drift():
    source = copy.deepcopy(offers.load_source())
    source["products"][1]["organization_scope"] = "one_runner_only"
    source["products"][1]["includes"] = []
    source["products"][1]["excludes"] = []
    failures = offers.validate(source)
    assert "guard organization_scope must match the reviewed scope" in failures
    assert "guard includes must match the reviewed product scope" in failures
    assert "guard excludes must match the reviewed product boundary" in failures


def test_visible_pricing_dom_rejects_price_and_scope_drift():
    source = offers.load_source()
    html = offers.PRICING_HTML.read_text(encoding="utf-8")
    html = html.replace(
        '<p class="price">$4,990', '<p class="price">$9,999', 1
    ).replace(
        "One legal organization; unlimited internal users and runners",
        "One runner",
        1,
    ).replace(
        "SBOM and provenance",
        "Packaging metadata",
        1,
    )
    failures = offers.validate_pricing_html(source, html)
    assert "pricing.html Guard card is missing '$4,990 / year'" in failures
    assert (
        "pricing.html Guard card is missing "
        "'One legal organization; unlimited internal users and runners'"
    ) in failures
    assert (
        "pricing.html Guard card is missing reviewed inclusion 'SBOM and provenance'"
    ) in failures


def test_visible_pricing_dom_rejects_exclusion_drift():
    source = offers.load_source()
    html = offers.PRICING_HTML.read_text(encoding="utf-8").replace(
        "Security questionnaires", "General security material", 1
    )
    assert "pricing.html is missing reviewed exclusion 'security questionnaires'" in (
        offers.validate_pricing_html(source, html)
    )


def test_pricing_dom_cannot_hide_required_copy_in_script_or_style():
    source = offers.load_source()
    html = offers.PRICING_HTML.read_text(encoding="utf-8").replace(
        "Security questionnaires", "General security material", 1
    )
    html = html.replace(
        "</body>",
        "<script>Security questionnaires</script>"
        "<style>.decoy::after { content: 'Security questionnaires'; }</style>"
        "</body>",
    )

    assert "pricing.html is missing reviewed exclusion 'security questionnaires'" in (
        offers.validate_pricing_html(source, html)
    )


def test_visible_pricing_dom_rejects_duplicate_product_card_identity():
    source = offers.load_source()
    html = offers.PRICING_HTML.read_text(encoding="utf-8").replace(
        'data-offer-product="guard"', 'data-offer-product="community"', 1
    )
    assert offers.validate_pricing_html(source, html) == [
        "pricing.html must contain exactly one identified Community and Guard card"
    ]


def test_structured_community_offer_is_explicitly_available_source():
    community = offers.render_jsonld(offers.load_source())
    assert '"name": "TinyZKP Community source"' in community
    assert f'"url": "{offers.COMMUNITY_SOURCE_URL}"' in community
    assert '"url": "https://tinyzkp.com/doctor"' not in community


def test_rejects_price_variant_identity_drift():
    source = copy.deepcopy(offers.load_source())
    source["price_policy"]["future_price_changes_use_new_variant_ids"] = True
    source["price_policy"]["existing_variant_ids_repurposed"] = True
    failures = offers.validate(source)
    assert "price_policy.future_price_changes_use_new_variant_ids must be False" in failures
    assert "price_policy.existing_variant_ids_repurposed must be False" in failures
