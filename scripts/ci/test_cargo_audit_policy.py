import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("cargo_audit_policy.py")
SPEC = importlib.util.spec_from_file_location("cargo_audit_policy_test", MODULE_PATH)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def report() -> dict:
    return {
        "vulnerabilities": {"count": 0, "list": []},
        "warnings": {
            "yanked": [
                {
                    "kind": "yanked",
                    "package": {
                        "name": name,
                        "version": version,
                        "source": source,
                        "checksum": checksum,
                    },
                }
                for name, version, source, checksum in sorted(POLICY.ALLOWED_YANKED)
            ]
        },
    }


def test_accepts_only_the_exact_yanked_compatibility_bytes():
    assert POLICY.validate_report(report()) == sorted(POLICY.ALLOWED_YANKED)


def test_allows_the_compatibility_exceptions_to_disappear():
    value = report()
    value["warnings"] = {}
    assert POLICY.validate_report(value) == []


def test_rejects_vulnerabilities_and_other_warning_categories():
    value = report()
    value["vulnerabilities"]["count"] = 1
    with pytest.raises(ValueError, match="vulnerability"):
        POLICY.validate_report(value)

    value = report()
    value["warnings"]["unmaintained"] = [{"package": {}}]
    with pytest.raises(ValueError, match="not allowed"):
        POLICY.validate_report(value)


@pytest.mark.parametrize("field", ["name", "version", "source", "checksum"])
def test_rejects_any_yanked_identity_skew(field: str):
    value = report()
    value["warnings"]["yanked"][0]["package"][field] += "-changed"
    with pytest.raises(ValueError, match="outside the exact"):
        POLICY.validate_report(value)


def test_rejects_malformed_or_duplicate_records():
    with pytest.raises(ValueError, match="warning summary"):
        POLICY.validate_report({"vulnerabilities": {"count": 0}})

    value = report()
    value["warnings"]["yanked"].append(value["warnings"]["yanked"][0])
    with pytest.raises(ValueError, match="repeated"):
        POLICY.validate_report(value)
