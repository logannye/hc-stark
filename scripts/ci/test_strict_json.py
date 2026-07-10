import pytest

import strict_json


@pytest.mark.parametrize(
    "payload",
    [
        '{"x":1,"x":2}',
        '{"x":NaN}',
        '{"x":Infinity}',
        '{"x":1e0}',
        '{"x":-0}',
        '{"x":1.00}',
    ],
)
def test_rejects_ambiguous_or_noncanonical_numbers(payload):
    with pytest.raises(ValueError):
        strict_json.loads(payload)


def test_preserves_contractual_integral_float_spelling():
    assert strict_json.loads('{"cpu_seconds":1.0}') == {"cpu_seconds": 1.0}
