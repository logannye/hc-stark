import pytest

import beta_credits


def test_eligible_job_honors_margin_floor_and_rounds_up_to_cent():
    quote = beta_credits.quote_job(120, 1_000)
    assert quote.retail_floor_millicredits == 400
    assert quote.competitive_cap_millicredits == 700
    assert quote.price_millicredits == 500
    assert quote.self_serve_eligible


def test_unprofitable_job_is_not_self_serve_eligible():
    quote = beta_credits.quote_job(300, 1_000)
    assert quote.retail_floor_millicredits == 1_000
    assert quote.competitive_cap_millicredits == 700
    assert quote.price_millicredits is None


def test_reservation_consumes_expiring_subscription_before_topup_and_settles():
    original = beta_credits.Balance(1_000, 1_000)
    after_reserve, reservation = beta_credits.reserve(original, 1_250)
    assert after_reserve == beta_credits.Balance(0, 750)
    assert reservation == beta_credits.Reservation(1_000, 250)

    after_settle, consumed = beta_credits.settle(after_reserve, reservation, 800)
    assert consumed == beta_credits.Reservation(800, 0)
    assert after_settle == beta_credits.Balance(200, 1_000)


def test_platform_failure_releases_full_reservation():
    original = beta_credits.Balance(400, 900)
    after_reserve, reservation = beta_credits.reserve(original, 1_000)
    assert beta_credits.release(after_reserve, reservation) == original


def test_no_overage_when_measured_price_exceeds_reservation():
    balance, reservation = beta_credits.reserve(beta_credits.Balance(2_000, 0), 1_250)
    with pytest.raises(beta_credits.CreditError, match="exceeds reservation"):
        beta_credits.settle(balance, reservation, 1_251)


def test_reservation_is_125_percent_and_rounded_up():
    assert beta_credits.reservation_amount(1_001) == 1_260
