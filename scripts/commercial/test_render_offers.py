import copy

import render_offers as offers


def test_current_offer_source_is_valid():
    assert offers.validate(offers.load_source()) == []


def test_rejects_enabled_checkout_and_price_drift():
    source = copy.deepcopy(offers.load_source())
    source["checkout_enabled"] = True
    source["offers"][0]["price"] = 1
    failures = offers.validate(source)
    assert "checkout_enabled must be False" in failures
    assert "founding_evaluation price must be 25000" in failures


def test_rendered_cards_include_all_public_offers():
    rendered = offers.render_cards(offers.load_source())
    assert rendered.count('<article class="card">') == 4
    assert "$25,000" in rendered
    assert "$125,000+" in rendered
    assert "$15,000" not in rendered
