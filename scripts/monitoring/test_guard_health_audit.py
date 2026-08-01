from email.message import Message
import hashlib
import io
import json
from pathlib import Path

import pytest

import guard_health_audit as audit


ARTIFACT_BODY = b"guard artifact"
CHANNEL_BODY = b"guard channel"
INDEX_BODY = b"guard index"
SIGNATURE_BODY = b"guard index signature"
GUARD_OCI_BODY = b'{"schemaVersion":2,"name":"guard"}'
ENGINE_OCI_BODY = b'{"schemaVersion":2,"name":"engine"}'


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]):
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value

    def read(self, limit: int) -> bytes:
        return self._body.read(limit)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def contracts(mode: str) -> dict[str, dict]:
    owner = {
        "schema_version": 2,
        "authorization_policy": "owner_only_ga_v1",
        "qualification_basis": "owner_attested",
    }
    source_sha256 = "a" * 64
    discovery = {"service_status": mode}
    if mode == "guard_live":
        terms = "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-21"
        guard = "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0"
        commerce = {
            **owner,
            "checkout_enabled": True,
            "launch_state": "qualified",
            "sales_state": "live",
            "commerce_state": "public_live",
            "portal_state": "live",
            "price_policy": {
                "monthly_usd": 499,
                "annual_usd": 4990,
                "annual_default": True,
            },
            "checkout_custom_data": {
                "terms_version": "2026-07-21",
                "guard_version": "0.1.0",
            },
            "customer_portal_url": "https://lnholdings.lemonsqueezy.com/billing",
            "support": {
                "state": "verified",
                "intake": "private_email",
                "contact": "support@tinyzkp.com",
                "delivery_verified": True,
                "owner_access_verified": True,
                "retention_configured": True,
            },
            "store_hostname": "lnholdings.lemonsqueezy.com",
            "variants": {
                "monthly": {
                    "reviewed": True,
                    "variant_id": "101",
                    "checkout_url": f"https://lnholdings.lemonsqueezy.com/checkout/buy/monthly01?{terms}&{guard}",
                },
                "annual": {
                    "reviewed": True,
                    "variant_id": "102",
                    "checkout_url": f"https://lnholdings.lemonsqueezy.com/checkout/buy/annual001?{terms}&{guard}",
                },
            },
        }
        release = {
            **owner,
            "source_sha256": source_sha256,
            "launch_state": "qualified",
            "sales_state": "live",
            "checkout_enabled": True,
            "guard_artifact_available": True,
            "guard_artifact_url": "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/tinyzkp-guard.tar.gz",
            "guard_artifact_sha256": sha(ARTIFACT_BODY),
            "guard_oci_digest": "sha256:" + sha(GUARD_OCI_BODY),
            "channel_manifest": {
                "url": "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/guard-channel-v1.json",
                "sha256": sha(CHANNEL_BODY),
            },
            "latest_release_index": {
                "url": "https://tinyzkp.com/guard-release-index-v1.json",
                "signature_url": "https://tinyzkp.com/guard-release-index-v1.json.sig",
                "sha256": sha(INDEX_BODY),
                "signature_sha256": sha(SIGNATURE_BODY),
            },
            "release_identity": {"guard_version": "0.1.0"},
            "blocking_gates": [],
        }
    elif mode == "guard_frozen":
        commerce = {
            **owner,
            "checkout_enabled": False,
            "sales_state": "frozen",
            "commerce_state": "sales_frozen",
            "portal_state": "live",
            "store_hostname": "lnholdings.lemonsqueezy.com",
            "customer_portal_url": "https://lnholdings.lemonsqueezy.com/billing",
            "support": {
                "state": "verified",
                "intake": "private_email",
                "contact": "support@tinyzkp.com",
                "delivery_verified": True,
                "owner_access_verified": True,
                "retention_configured": True,
            },
            "variants": {
                "monthly": {
                    "reviewed": False,
                    "variant_id": "101",
                    "checkout_url": None,
                },
                "annual": {
                    "reviewed": False,
                    "variant_id": "102",
                    "checkout_url": None,
                },
            },
        }
        release = {
            **owner,
            "source_sha256": source_sha256,
            "launch_state": "qualified",
            "sales_state": "frozen",
            "checkout_enabled": False,
            "guard_artifact_available": True,
            "guard_artifact_url": "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/tinyzkp-guard.tar.gz",
            "guard_artifact_sha256": sha(ARTIFACT_BODY),
            "guard_oci_digest": "sha256:" + sha(GUARD_OCI_BODY),
            "channel_manifest": {
                "url": "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0/guard-channel-v1.json",
                "sha256": sha(CHANNEL_BODY),
            },
            "latest_release_index": {
                "url": "https://tinyzkp.com/guard-release-index-v1.json",
                "signature_url": "https://tinyzkp.com/guard-release-index-v1.json.sig",
                "sha256": sha(INDEX_BODY),
                "signature_sha256": sha(SIGNATURE_BODY),
            },
            "release_identity": {"guard_version": "0.1.0"},
            "blocking_gates": [],
        }
    elif mode == "guard_transition":
        commerce = {
            **owner,
            "checkout_enabled": False,
            "commerce_state": "live_hidden",
        }
        release = {
            **owner,
            "source_sha256": source_sha256,
            "blocking_gates": ["guard_artifact_published"],
        }
    elif mode == "guard_withdrawn":
        discovery.update(
            {
                "sales_state": "withdrawn",
                "availability": {
                    "guard_checkout": False,
                    "guard_artifact": False,
                    "hosted_proving": False,
                    "hosted_verification": False,
                },
            }
        )
        commerce = {
            **owner,
            "checkout_enabled": False,
            "launch_state": "blocked",
            "sales_state": "withdrawn",
            "commerce_state": "unconfigured",
            "portal_state": "unconfigured",
            "customer_portal_url": None,
            "store_hostname": None,
            "support": None,
            "variants": {
                "monthly": {
                    "reviewed": False,
                    "variant_id": None,
                    "checkout_url": None,
                },
                "annual": {
                    "reviewed": False,
                    "variant_id": None,
                    "checkout_url": None,
                },
            },
        }
        release = {
            **owner,
            "source_sha256": source_sha256,
            "launch_state": "blocked",
            "sales_state": "withdrawn",
            "checkout_enabled": False,
            "guard_artifact_available": False,
            "blocking_gates": ["guard_artifact_published"],
        }
    else:
        commerce = {**owner, "checkout_enabled": False}
        release = {
            **owner,
            "source_sha256": source_sha256,
            "blocking_gates": ["engine_release_ready"],
        }
    return {
        "release-channels-v1.json": {
            **owner,
            "schema_version": 1,
            "current_channel": mode,
            "source_sha256": source_sha256,
            "channels": {mode: owner},
        },
        "discovery.json": discovery,
        "commerce.json": commerce,
        "release.json": release,
        "compatibility.json": {
            "release_binding": {
                "engine_oci_digest": "sha256:" + sha(ENGINE_OCI_BODY)
            }
        },
    }


def opener_for(mode: str, *, noindex: bool = True, values: dict | None = None):
    values = values or contracts(mode)

    def opener(request, timeout):
        url = request.full_url
        name = url.rsplit("/", 1)[-1]
        if name in values:
            return Response(200, json.dumps(values[name]).encode(), {})
        if "github.com/logannye/hc-stark/releases" in url:
            body = ARTIFACT_BODY if url.endswith(".tar.gz") else CHANNEL_BODY
            return Response(200, body, {})
        if url == "https://tinyzkp.com/guard-release-index-v1.json":
            return Response(200, INDEX_BODY, {})
        if url == "https://tinyzkp.com/guard-release-index-v1.json.sig":
            return Response(200, SIGNATURE_BODY, {})
        if url.startswith("https://ghcr.io/token?"):
            return Response(200, b'{"token":"anonymous"}', {})
        if url.startswith("https://ghcr.io/v2/"):
            if request.headers.get("Authorization") == "Bearer anonymous":
                body = GUARD_OCI_BODY if "tinyzkp-guard" in url else ENGINE_OCI_BODY
                return Response(200, body, {})
            repository = "logannye/tinyzkp-guard" if "tinyzkp-guard" in url else "logannye/tinyzkp-engine"
            return Response(
                401,
                b"",
                {
                    "WWW-Authenticate": (
                        'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                        f'scope="repository:{repository}:pull"'
                    )
                },
            )
        if "lemonsqueezy.com" in url:
            body = b"$4,990" if "annual" in url else b"$499" if "monthly" in url else b"billing"
            return Response(200, body, {})
        if mode == "guard_prelaunch":
            return Response(200, b"ok", {})
        headers = {"X-Robots-Tag": "noindex, nofollow"} if noindex else {}
        return Response(410, b"gone", headers)

    return opener


@pytest.mark.parametrize(
    ("mode", "checks"),
    (
        ("guard_prelaunch", 7),
        ("guard_withdrawn", 10),
        ("guard_transition", 10),
        ("guard_live", 20),
        ("guard_frozen", 18),
    ),
)
def test_exact_guard_monitoring_modes_pass(mode: str, checks: int):
    assert audit.audit(mode, opener=opener_for(mode)) == checks


def test_transition_requires_noindex_on_every_retired_host():
    with pytest.raises(audit.AuditError, match="410/noindex"):
        audit.audit("guard_transition", opener=opener_for("guard_transition", noindex=False))


def test_withdrawn_mode_rejects_checkout_or_hosted_service_revival():
    values = contracts("guard_withdrawn")
    values["commerce.json"]["variants"]["monthly"]["checkout_url"] = (
        "https://store.example/checkout"
    )
    with pytest.raises(audit.AuditError, match="withdrawn Guard surfaces"):
        audit.audit(
            "guard_withdrawn",
            opener=opener_for("guard_withdrawn", values=values),
        )


def test_retired_host_redirect_cannot_mask_the_origin() -> None:
    normal = opener_for("guard_transition")

    def redirect(request, timeout):
        if "retirement-canary" in request.full_url:
            return Response(302, b"", {"Location": "https://tinyzkp.com/gone"})
        return normal(request, timeout)

    with pytest.raises(audit.AuditError, match="410/noindex"):
        audit.audit("guard_transition", opener=redirect)


def test_concrete_mode_must_match_the_canonical_channel() -> None:
    with pytest.raises(audit.AuditError, match="differs from canonical"):
        audit.audit("guard_live", opener=opener_for("guard_transition"))
    assert audit.audit("canonical", opener=opener_for("guard_prelaunch")) == 7


def test_live_checkout_links_must_be_distinct_and_generic():
    values = contracts("guard_live")
    commerce = values["commerce.json"]
    commerce["variants"]["annual"]["checkout_url"] = commerce["variants"]["monthly"]["checkout_url"]
    with pytest.raises(audit.AuditError, match="checkout variants"):
        audit.audit("guard_live", opener=opener_for("guard_live", values=values))


@pytest.mark.parametrize("mode", ["guard_live", "guard_frozen"])
@pytest.mark.parametrize("suffix", ["?", "#", "/", "?signed=customer"])
def test_billing_portal_is_exact_generic_unsigned_url(mode: str, suffix: str):
    values = contracts(mode)
    values["commerce.json"]["customer_portal_url"] += suffix
    with pytest.raises(audit.AuditError, match="portal|checkout variants"):
        audit.audit(mode, opener=opener_for(mode, values=values))


def test_live_checkout_pages_must_render_reviewed_prices():
    values = contracts("guard_live")
    normal = opener_for("guard_live", values=values)

    def wrong_price(request, timeout):
        if "monthly" in request.full_url:
            return Response(200, b"$1", {})
        return normal(request, timeout)

    with pytest.raises(audit.AuditError, match="reviewed price"):
        audit.audit("guard_live", opener=wrong_price)


def test_successor_guard_version_is_bound_dynamically() -> None:
    values = contracts("guard_live")
    values["release.json"]["release_identity"]["guard_version"] = "0.1.1"
    values["commerce.json"]["checkout_custom_data"]["guard_version"] = "0.1.1"
    for variant in values["commerce.json"]["variants"].values():
        variant["checkout_url"] = variant["checkout_url"].replace("0.1.0", "0.1.1")
    values["release.json"]["guard_artifact_url"] = values["release.json"][
        "guard_artifact_url"
    ].replace("0.1.0", "0.1.1")
    values["release.json"]["channel_manifest"]["url"] = values["release.json"][
        "channel_manifest"
    ]["url"].replace("0.1.0", "0.1.1")
    assert audit.audit("guard_live", opener=opener_for("guard_live", values=values)) == 20


def test_shell_wrapper_accepts_only_exact_guard_modes():
    wrapper = Path(__file__).with_name("api_health_audit.sh").read_text()
    assert "canonical|guard_prelaunch|guard_withdrawn|guard_transition|guard_live|guard_frozen" in wrapper
    assert "containment|production" not in wrapper
