import copy

import render_offers as offers


def test_current_offer_source_is_valid():
    assert offers.validate(offers.load_source()) == []
    assert offers.validate_repository_parity(offers.load_source()) == []


def test_rejects_enabled_checkout_and_price_drift():
    source = copy.deepcopy(offers.load_source())
    source["checkout_enabled"] = True
    source["offers"][0]["price"] = 0
    failures = offers.validate(source)
    assert "checkout_enabled must be False" in failures
    assert "founding_evaluation price must be a positive integer" in failures


def test_rendered_cards_include_all_public_offers():
    rendered = offers.render_cards(offers.load_source())
    assert rendered.count('<article class="card">') == 4
    assert "$15,000" in rendered
    assert "$125,000+" in rendered
    assert "$25,000" not in rendered


def test_founding_terms_and_milestones_are_data_driven():
    source = copy.deepcopy(offers.load_source())
    founding = source["offers"][0]
    assert founding["customer_cap"] == 3
    assert founding["duration"] == "2_weeks"
    assert founding["engineering_day_cap"] == 8
    assert founding["billing_milestones"] == {
        "deposit_percent": 50,
        "delivery_percent": 50,
    }

    founding["customer_cap"] = 0
    founding["billing_milestones"]["delivery_percent"] = 40
    failures = offers.validate(source)
    assert "Founding Evaluation customer cap must be positive" in failures
    assert (
        "founding_evaluation billing milestones must be positive and total 100"
        in failures
    )


def test_repository_parity_detects_source_change_without_copy_updates():
    source = copy.deepcopy(offers.load_source())
    source["offers"][0]["price"] += 1000
    failures = offers.validate_repository_parity(source)
    assert any("README.md" in failure for failure in failures)
    assert any("site/discovery.json" in failure for failure in failures)
