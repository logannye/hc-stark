import pytest

import build_dark_canary_authorization as builder


def test_dark_canary_authorization_is_narrow_and_sha_bound():
    result = builder.build("a" * 40)
    assert result["status"] == "dark_canary"
    assert result["purpose"] == "stripe_live_canary"
    assert result["public_activation"] is False
    assert result["release_sha"] == "a" * 40


@pytest.mark.parametrize("release_sha", ["a" * 39, "A" * 40, "main"])
def test_dark_canary_authorization_rejects_mutable_or_noncanonical_sha(release_sha):
    with pytest.raises(ValueError, match="full lowercase Git commit"):
        builder.build(release_sha)
