from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import pytest

import static_site_canary as canary


class Response:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]):
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value

    def read(self, limit: int):
        return self._body.read(limit)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_canary_retry_allows_bounded_pages_propagation():
    calls = []
    sleeps = []

    def check():
        calls.append(len(calls) + 1)
        if len(calls) < 3:
            raise canary.CanaryError("edge has not propagated")

    canary.retry_canary(
        check,
        attempts=3,
        delay_seconds=2,
        sleeper=sleeps.append,
    )

    assert calls == [1, 2, 3]
    assert sleeps == [2, 2]


def test_default_canary_window_allows_slow_pages_edge_propagation():
    assert (
        canary.CANARY_ATTEMPTS - 1
    ) * canary.CANARY_RETRY_DELAY_SECONDS >= 60
    assert (
        canary.CANARY_ATTEMPTS - 1
    ) * canary.CANARY_RETRY_DELAY_SECONDS < 180


def test_canary_retry_remains_fail_closed_after_the_bound():
    calls = []
    sleeps = []

    def check():
        calls.append(len(calls) + 1)
        raise canary.CanaryError("persistent mismatch")

    with pytest.raises(canary.CanaryError, match="persistent mismatch"):
        canary.retry_canary(
            check,
            attempts=3,
            delay_seconds=2,
            sleeper=sleeps.append,
        )

    assert calls == [1, 2, 3]
    assert sleeps == [2, 2]


def test_base_url_is_restricted_to_tinyzkp_pages():
    assert canary.safe_base_url("https://candidate.tinyzkp.pages.dev") == (
        "https://candidate.tinyzkp.pages.dev/"
    )
    with pytest.raises(canary.CanaryError):
        canary.safe_base_url("https://example.com")
    with pytest.raises(canary.CanaryError):
        canary.safe_base_url("https://tinyzkp.com/path")


def test_contract_canary_compares_exact_reviewed_bytes(tmp_path: Path):
    for name in canary.CONTRACTS:
        value = {
            "authorization_policy": "owner_only_ga_v1",
            "qualification_basis": "owner_attested",
            "launch_state": "blocked",
            "sales_state": "closed",
            "commerce_state": "unconfigured",
            "portal_state": "unconfigured",
            "checkout_enabled": False,
            "source_sha256": "a" * 64,
            "availability": {"guard_checkout": False},
            "variants": {
                "annual": {"reviewed": False, "checkout_url": None},
                "monthly": {"reviewed": False, "checkout_url": None},
            },
        }
        if name == "discovery.json":
            value["service_status"] = "guard_prelaunch"
        elif name == "release-channels-v1.json":
            value = {
                "authorization_policy": "owner_only_ga_v1",
                "qualification_basis": "owner_attested",
                "current_channel": "guard_prelaunch",
                "source_sha256": "a" * 64,
            }
        (tmp_path / name).write_text(
            json.dumps(value),
            encoding="utf-8",
        )

    def opener(request, timeout):
        name = request.full_url.rsplit("/", 1)[-1]
        return Response(
            200,
            (tmp_path / name).read_bytes(),
            {"Content-Type": "application/json"},
        )

    canary.check_contracts(
        "https://candidate.tinyzkp.pages.dev/", tmp_path, opener=opener
    )

    (tmp_path / "release.json").write_text("{}", encoding="utf-8")
    with pytest.raises(canary.CanaryError, match="disagree"):
        canary.check_contracts(
            "https://candidate.tinyzkp.pages.dev/", tmp_path, opener=opener
        )


def test_contract_canary_validates_exact_public_live_checkout_and_portal(
    tmp_path: Path,
):
    host = "lnholdings.lemonsqueezy.com"
    custom = {"terms_version": "2026-07-18", "guard_version": "0.1.0"}

    def checkout(token: str) -> str:
        return (
            f"https://{host}/checkout/buy/{token}?"
            "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
            "checkout%5Bcustom%5D%5Bguard_version%5D=0.1.0"
        )

    base = {
        "authorization_policy": "owner_only_ga_v1",
        "qualification_basis": "owner_attested",
        "launch_state": "qualified",
        "sales_state": "live",
        "commerce_state": "public_live",
        "portal_state": "live",
        "checkout_enabled": True,
        "source_sha256": "a" * 64,
        "availability": {"guard_checkout": True},
    }
    values = {
        "release.json": {
            **base,
            "guard_artifact_available": True,
            "blocking_gates": [],
            "release_identity": {"guard_version": "0.1.0"},
        },
        "commerce.json": {
            **base,
            "provider": "lemon_squeezy",
            "mode": "live",
            "checkout_custom_data": custom,
            "customer_portal_url": f"https://{host}/billing",
            "store_hostname": host,
            "support": {
                "state": "verified",
                "intake": "private_email",
                "contact": "support@tinyzkp.com",
                "delivery_verified": True,
                "owner_access_verified": True,
                "retention_configured": True,
            },
            "variants": {
                "annual": {
                    "variant_id": "301",
                    "reviewed": True,
                    "checkout_url": checkout("annual-live"),
                },
                "monthly": {
                    "variant_id": "302",
                    "reviewed": True,
                    "checkout_url": checkout("monthly-live"),
                },
            },
        },
        "pricing.json": base,
        "discovery.json": {**base, "service_status": "guard_live"},
        "release-channels-v1.json": {
            "authorization_policy": "owner_only_ga_v1",
            "qualification_basis": "owner_attested",
            "current_channel": "guard_live",
            "source_sha256": "a" * 64,
        },
        "compatibility.json": {
            "release_binding": {"engine_oci_digest": "sha256:" + "b" * 64}
        },
    }
    for name, value in values.items():
        (tmp_path / name).write_text(json.dumps(value), encoding="utf-8")

    def opener(request, timeout):
        name = request.full_url.rsplit("/", 1)[-1]
        return Response(
            200,
            (tmp_path / name).read_bytes(),
            {"Content-Type": "application/json"},
        )

    canary.check_contracts(
        "https://candidate.tinyzkp.pages.dev/", tmp_path, opener=opener
    )

    for invalid_suffix in ("?signed=customer", "?", "#", "/"):
        values["commerce.json"]["customer_portal_url"] = (
            f"https://{host}/billing{invalid_suffix}"
        )
        (tmp_path / "commerce.json").write_text(
            json.dumps(values["commerce.json"]), encoding="utf-8"
        )
        with pytest.raises(canary.CanaryError, match="portal"):
            canary.check_contracts(
                "https://candidate.tinyzkp.pages.dev/", tmp_path, opener=opener
            )


def live_fulfillment_fixture() -> tuple[dict, dict]:
    base = (
        "https://github.com/logannye/hc-stark/releases/download/guard-v0.1.0"
    )
    channel = {
        "url": f"{base}/guard-channel-v1.json",
        "sha256": "2" * 64,
    }
    latest = {
        "url": "https://tinyzkp.com/guard-release-index-v1.json",
        "sha256": "3" * 64,
        "signature_url": "https://tinyzkp.com/guard-release-index-v1.json.sig",
        "signature_sha256": "4" * 64,
        "immutable_revision_url": (
            f"https://tinyzkp.com/release-index-revisions/{'3' * 64}/"
            "guard-release-index-v1.json"
        ),
        "immutable_revision_signature_url": (
            f"https://tinyzkp.com/release-index-revisions/{'3' * 64}/"
            "guard-release-index-v1.json.sig"
        ),
    }
    artifact = f"{base}/tinyzkp-guard-0.1.0-linux-x86_64.tar.gz"
    release = {
        "guard_artifact_url": artifact,
        "guard_artifact_sha256": "1" * 64,
        "guard_oci_digest": "sha256:" + "5" * 64,
        "channel_manifest": channel,
        "latest_release_index": latest,
        "delivery": {
            "receipt_url": "https://tinyzkp.com/releases",
            "artifact_url": artifact,
            "artifact_sha256": "1" * 64,
            "sha256sums_url": f"{base}/SHA256SUMS",
            "sha256sums_signature_url": f"{base}/SHA256SUMS.sig",
            "signing_public_key_url": f"{base}/signing-public-key.pem",
            "signing_public_key_sha256": "6" * 64,
            "channel_url": channel["url"],
            "release_index_url": latest["url"],
            "release_index_signature_url": latest["signature_url"],
            "start_here_path": "START-HERE.txt",
            "agreement_path": "AGREEMENT.txt",
            "delivery_path": "DELIVERY.txt",
            "activation_command": "./bin/tinyzkp activate --license-key-stdin",
        },
    }
    compatibility = {
        "release_binding": {"engine_oci_digest": "sha256:" + "7" * 64}
    }
    return release, compatibility


def test_live_fulfillment_binds_exact_buyer_delivery_contract(monkeypatch):
    release, compatibility = live_fulfillment_fixture()
    downloads = []
    oci = []
    monkeypatch.setattr(
        canary,
        "anonymous_download_sha256",
        lambda url, expected, **kwargs: downloads.append((url, expected)),
    )
    monkeypatch.setattr(
        canary,
        "anonymous_oci_manifest",
        lambda repository, digest, **kwargs: oci.append((repository, digest)),
    )
    canary.check_live_fulfillment(release, compatibility)
    assert len(downloads) == 7
    assert downloads[-1] == (
        release["delivery"]["signing_public_key_url"],
        release["delivery"]["signing_public_key_sha256"],
    )
    assert oci == [
        ("logannye/tinyzkp-guard", release["guard_oci_digest"]),
        (
            "logannye/tinyzkp-engine",
            compatibility["release_binding"]["engine_oci_digest"],
        ),
    ]
    release["delivery"]["receipt_url"] = "https://example.com/download"
    with pytest.raises(canary.CanaryError, match="buyer delivery"):
        canary.check_live_fulfillment(release, compatibility)


def test_guard_frozen_mode_preserves_portal_and_exact_fulfillment(monkeypatch):
    release, compatibility = live_fulfillment_fixture()
    release.update(
        {
            "launch_state": "qualified",
            "sales_state": "frozen",
            "guard_artifact_available": True,
            "blocking_gates": [],
        }
    )
    commerce = {
        "checkout_enabled": False,
        "commerce_state": "sales_frozen",
        "sales_state": "frozen",
        "portal_state": "live",
        "customer_portal_url": "https://lnholdings.lemonsqueezy.com/billing",
        "store_hostname": "lnholdings.lemonsqueezy.com",
        "support": {
            "state": "verified",
            "intake": "private_email",
            "contact": "support@tinyzkp.com",
            "delivery_verified": True,
            "owner_access_verified": True,
            "retention_configured": True,
        },
    }
    parsed = {
        "release.json": release,
        "commerce.json": commerce,
        "discovery.json": {"service_status": "guard_frozen"},
        "compatibility.json": compatibility,
    }
    calls = []
    monkeypatch.setattr(canary, "check_contracts", lambda *args, **kwargs: parsed)
    monkeypatch.setattr(
        canary, "check_retired_hosts", lambda **kwargs: calls.append("retired")
    )
    monkeypatch.setattr(
        canary,
        "check_live_fulfillment",
        lambda *args, **kwargs: calls.append("fulfillment"),
    )
    canary.check_monitoring_mode(
        "https://tinyzkp.com/", "guard_frozen", site=Path("unused")
    )
    assert calls == ["retired", "fulfillment"]
    commerce["customer_portal_url"] += "?"
    with pytest.raises(canary.CanaryError, match="generic and unsigned"):
        canary.check_monitoring_mode(
            "https://tinyzkp.com/", "guard_frozen", site=Path("unused")
        )


def test_routes_require_static_security_noindex_and_410():
    def opener(request, timeout):
        retired = request.full_url.endswith(
            tuple(path for path in canary.RETIRED_ROUTES)
        )
        return Response(
            410 if retired else 200,
            b"ok",
            {
                "X-Content-Type-Options": "nosniff",
                "X-Robots-Tag": "noindex, nofollow",
            },
        )

    canary.check_routes("https://candidate.tinyzkp.pages.dev/", opener=opener)


def test_routes_fail_when_retired_surface_is_live():
    def opener(request, timeout):
        return Response(
            200,
            b"live",
            {
                "X-Content-Type-Options": "nosniff",
                "X-Robots-Tag": "noindex, nofollow",
            },
        )

    with pytest.raises(canary.CanaryError, match="not 410"):
        canary.check_routes("https://candidate.tinyzkp.pages.dev/", opener=opener)


def test_every_retired_hostname_returns_origin_free_410_for_get_and_post():
    observed = []

    def opener(request, timeout):
        observed.append((request.method, request.full_url))
        return Response(
            410,
            b"gone",
            {"X-Robots-Tag": "noindex, nofollow"},
        )

    canary.check_retired_hosts(opener=opener)
    assert observed == [
        (method, f"https://{hostname}/retirement-canary")
        for hostname in canary.RETIRED_HOSTS
        for method in ("GET", "POST")
    ]


def test_retired_hostname_redirect_or_live_origin_fails():
    def opener(request, timeout):
        return Response(
            308,
            b"",
            {
                "Location": "https://tinyzkp.com/",
                "X-Robots-Tag": "noindex, nofollow",
            },
        )

    with pytest.raises(canary.CanaryError, match="not 410"):
        canary.check_retired_hosts(opener=opener)


def test_anonymous_release_download_requires_exact_bytes_and_boundary() -> None:
    body = b"signed release bytes"
    expected = hashlib.sha256(body).hexdigest()

    def opener(request, timeout):
        assert "authorization" not in {key.lower() for key in request.headers}
        return Response(200, body, {})

    url = (
        "https://github.com/logannye/hc-stark/releases/download/"
        "guard-v0.1.0/guard-channel-v1.json"
    )
    assert canary.anonymous_download_sha256(
        url, expected, label="Guard channel", opener=opener
    ) == expected
    with pytest.raises(canary.CanaryError, match="bytes or destination differ"):
        canary.anonymous_download_sha256(
            url, "0" * 64, label="Guard channel", opener=opener
        )
    with pytest.raises(canary.CanaryError, match="outside"):
        canary.anonymous_download_sha256(
            "https://example.com/channel", expected, label="Guard channel", opener=opener
        )


def test_anonymous_oci_manifest_challenge_and_digest_are_exact() -> None:
    manifest = b'{"schemaVersion":2}'
    expected = "sha256:" + hashlib.sha256(manifest).hexdigest()
    calls = []

    def opener(request, timeout):
        calls.append(request)
        if request.full_url.startswith("https://ghcr.io/token?"):
            return Response(200, b'{"token":"anonymous-pull"}', {})
        if request.headers.get("Authorization") == "Bearer anonymous-pull":
            return Response(200, manifest, {"Content-Type": "application/json"})
        return Response(
            401,
            b"",
            {
                "WWW-Authenticate": (
                    'Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                    'scope="repository:logannye/tinyzkp-guard:pull"'
                )
            },
        )

    canary.anonymous_oci_manifest(
        "logannye/tinyzkp-guard", expected, opener=opener
    )
    assert len(calls) == 3
    with pytest.raises(canary.CanaryError, match="manifest differs"):
        canary.anonymous_oci_manifest(
            "logannye/tinyzkp-guard", "sha256:" + "0" * 64, opener=opener
        )
