#!/usr/bin/env python3
"""Exact public-beta pricing, reservation, and settlement rules.

Amounts are integer millicredits: 1,000 millicredits = one USD credit. The
database persists every mutation as an immutable event; this module contains
the deterministic policy used by the API and replay/reconciliation jobs.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING


MILLIS_PER_CREDIT = 1_000
MILLIS_PER_CENT = 10
RESERVATION_NUMERATOR = 125
RESERVATION_DENOMINATOR = 100


class CreditError(ValueError):
    pass


@dataclass(frozen=True)
class PriceQuote:
    measured_cost_millicredits: int
    conventional_baseline_millicredits: int
    retail_floor_millicredits: int
    competitive_cap_millicredits: int
    price_millicredits: int | None

    @property
    def self_serve_eligible(self) -> bool:
        return self.price_millicredits is not None


def _ceil_decimal(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _round_up_cent(millicredits: int) -> int:
    if millicredits < 0:
        raise CreditError("amount cannot be negative")
    return ((millicredits + MILLIS_PER_CENT - 1) // MILLIS_PER_CENT) * MILLIS_PER_CENT


def quote_job(
    measured_cost_millicredits: int,
    conventional_baseline_millicredits: int,
) -> PriceQuote:
    if measured_cost_millicredits <= 0 or conventional_baseline_millicredits <= 0:
        raise CreditError("costs must be positive")
    retail_floor = _ceil_decimal(Decimal(measured_cost_millicredits) / Decimal("0.30"))
    competitive_cap = _ceil_decimal(
        Decimal(conventional_baseline_millicredits) * Decimal("0.70")
    )
    price = None
    if retail_floor <= competitive_cap:
        price = _round_up_cent(
            max(
                retail_floor,
                _ceil_decimal(
                    Decimal(conventional_baseline_millicredits) * Decimal("0.50")
                ),
            )
        )
    return PriceQuote(
        measured_cost_millicredits=measured_cost_millicredits,
        conventional_baseline_millicredits=conventional_baseline_millicredits,
        retail_floor_millicredits=retail_floor,
        competitive_cap_millicredits=competitive_cap,
        price_millicredits=price,
    )


def reservation_amount(estimated_price_millicredits: int) -> int:
    if estimated_price_millicredits <= 0:
        raise CreditError("estimated price must be positive")
    return _round_up_cent(
        (estimated_price_millicredits * RESERVATION_NUMERATOR + RESERVATION_DENOMINATOR - 1)
        // RESERVATION_DENOMINATOR
    )


@dataclass(frozen=True)
class Balance:
    subscription_millicredits: int
    purchased_millicredits: int

    def __post_init__(self) -> None:
        if self.subscription_millicredits < 0 or self.purchased_millicredits < 0:
            raise CreditError("balances cannot be negative")

    @property
    def available_millicredits(self) -> int:
        return self.subscription_millicredits + self.purchased_millicredits


@dataclass(frozen=True)
class Reservation:
    subscription_millicredits: int
    purchased_millicredits: int

    @property
    def total_millicredits(self) -> int:
        return self.subscription_millicredits + self.purchased_millicredits


def reserve(balance: Balance, amount_millicredits: int) -> tuple[Balance, Reservation]:
    if amount_millicredits <= 0:
        raise CreditError("reservation must be positive")
    if balance.available_millicredits < amount_millicredits:
        raise CreditError("insufficient credit balance")
    subscription = min(balance.subscription_millicredits, amount_millicredits)
    purchased = amount_millicredits - subscription
    return (
        Balance(
            balance.subscription_millicredits - subscription,
            balance.purchased_millicredits - purchased,
        ),
        Reservation(subscription, purchased),
    )


def release(balance: Balance, reservation: Reservation) -> Balance:
    return Balance(
        balance.subscription_millicredits + reservation.subscription_millicredits,
        balance.purchased_millicredits + reservation.purchased_millicredits,
    )


def settle(
    balance: Balance,
    reservation: Reservation,
    verified_price_millicredits: int,
) -> tuple[Balance, Reservation]:
    """Charge only an officially verified proof and return the unused reserve.

    The returned Reservation identifies the consumed source buckets for the
    immutable settlement event. A price above the 125% reserve is a platform
    estimation failure and must be refunded instead of creating an overage.
    """
    if verified_price_millicredits <= 0:
        raise CreditError("verified price must be positive")
    if verified_price_millicredits > reservation.total_millicredits:
        raise CreditError("verified price exceeds reservation")
    consumed_subscription = min(
        reservation.subscription_millicredits, verified_price_millicredits
    )
    consumed_purchased = verified_price_millicredits - consumed_subscription
    refund = Reservation(
        reservation.subscription_millicredits - consumed_subscription,
        reservation.purchased_millicredits - consumed_purchased,
    )
    return release(balance, refund), Reservation(consumed_subscription, consumed_purchased)
