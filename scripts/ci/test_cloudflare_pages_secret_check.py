import pathlib
from types import SimpleNamespace

import cloudflare_pages_secret_check as check


def test_parse_secret_names_returns_names_only():
    output = """
      - INTERNAL_SECRET: Value Encrypted
      - STRIPE_SECRET_KEY: Value Encrypted
      noise that must be ignored
    """
    assert check.parse_secret_names(output) == {"INTERNAL_SECRET", "STRIPE_SECRET_KEY"}


def test_static_inventory_requires_no_secrets_and_rejects_legacy_secrets():
    checks = check.validate_secret_names(set())
    assert all(item.status == "PASS" for item in checks)

    checks = check.validate_secret_names(
        {"STRIPE_SECRET_KEY", "STRIPE_PRICE_ID_PRO", "TINYZKP_DEMO_API_KEY"}
    )
    failure = next(item for item in checks if item.name == "legacy billing/demo secrets")
    assert failure.status == "FAIL"
    assert "STRIPE_PRICE_ID_PRO" in failure.detail


def test_retired_internal_secret_fails_minimal_inventory():
    checks = check.validate_secret_names({"INTERNAL_SECRET"})
    unexpected = next(
        item for item in checks if item.name == "unexpected static-site secrets"
    )
    assert unexpected.status == "FAIL"
    assert "INTERNAL_SECRET" in unexpected.detail


def test_arbitrary_unconsumed_secret_fails_minimal_inventory():
    checks = check.validate_secret_names({"INTERNAL_SECRET", "UNUSED_RECOVERY_SECRET"})
    unexpected = next(
        item for item in checks if item.name == "unexpected static-site secrets"
    )
    assert unexpected.status == "FAIL"
    assert "UNUSED_RECOVERY_SECRET" in unexpected.detail


def test_wrangler_is_invoked_through_explicit_node_with_sanitized_environment(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        captured["stdin"] = kwargs["stdin"]
        return SimpleNamespace(
            returncode=0,
            stdout="  - INTERNAL_SECRET: Value Encrypted\n",
        )

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    monkeypatch.setenv("NODE_OPTIONS", "--require=/attacker.js")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")

    names, _output = check.read_wrangler_secret_names(
        "tinyzkp",
        timeout=30,
        node_executable=pathlib.Path("/usr/bin/node"),
        wrangler_entrypoint=pathlib.Path(
            "/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js"
        ),
    )

    assert names == {"INTERNAL_SECRET"}
    assert captured["command"] == (
        "/usr/bin/node",
        "/var/lib/tinyzkp-runtime/cloudflare-toolchain/node_modules/wrangler/bin/wrangler.js",
        "pages",
        "secret",
        "list",
        "--project-name",
        "tinyzkp",
    )
    assert captured["environment"]["CLOUDFLARE_API_TOKEN"] == "test-token"
    assert "NODE_OPTIONS" not in captured["environment"]
    assert captured["environment"]["HOME"] == "/nonexistent"


def test_wrangler_rejects_path_resolution():
    try:
        check.read_wrangler_secret_names(
            "tinyzkp",
            timeout=30,
            node_executable=pathlib.Path("node"),
            wrangler_entrypoint=pathlib.Path("wrangler"),
        )
    except RuntimeError as error:
        assert "absolute paths" in str(error)
    else:
        raise AssertionError("PATH-resolved Node/Wrangler must fail closed")
