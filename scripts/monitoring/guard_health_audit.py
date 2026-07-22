#!/usr/bin/env python3
"""Audit the exact owner-only Guard production posture without buying anything."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse


LEGACY_HOSTS = ("api.tinyzkp.com", "mcp.tinyzkp.com", "webhook.tinyzkp.com")
PRELAUNCH_URLS = (
    "https://api.tinyzkp.com/healthz",
    "https://mcp.tinyzkp.com/version",
    "https://webhook.tinyzkp.com/health",
)
SITE = "https://tinyzkp.com"
AUTHORIZATION_POLICY = "owner_only_ga_v1"
QUALIFICATION_BASIS = "owner_attested"
MAX_BODY = 4 * 1024 * 1024
CHECKOUT_PATH = re.compile(r"^/checkout/buy/[A-Za-z0-9_-]{8,128}/?$")
STORE_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class AuditError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect()).open


def request(
    url: str,
    *,
    method: str = "GET",
    opener: Callable[..., Any] = urllib.request.urlopen,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, str], bytes, str]:
    req = urllib.request.Request(
        url,
        data=b"{}" if method == "POST" else None,
        method=method,
        headers={
            "Accept": "application/json,*/*;q=0.1",
            "Content-Type": "application/json",
            "User-Agent": "TinyZKP-Guard-Health-Audit/1",
        },
    )
    try:
        selected_opener = (
            NO_REDIRECT_OPENER
            if not follow_redirects and opener is urllib.request.urlopen
            else opener
        )
        with selected_opener(req, timeout=20) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(MAX_BODY + 1)
            final_url = response.geturl() if hasattr(response, "geturl") else url
    except urllib.error.HTTPError as error:
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
        body = error.read(MAX_BODY + 1)
        final_url = error.geturl()
    except (OSError, urllib.error.URLError) as error:
        raise AuditError(f"request failed: {url}") from error
    if len(body) > MAX_BODY:
        raise AuditError(f"oversized response: {url}")
    return status, headers, body, final_url


def owner_contract(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("authorization_policy") == AUTHORIZATION_POLICY
        and value.get("qualification_basis") == QUALIFICATION_BASIS
    )


def json_contract(
    path: str, *, opener: Callable[..., Any]
) -> dict[str, Any]:
    status, _headers, raw, _final_url = request(f"{SITE}/{path}", opener=opener)
    if status != 200:
        raise AuditError(f"/{path} returned HTTP {status}")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AuditError(f"/{path} is not JSON") from error
    if not isinstance(value, dict):
        raise AuditError(f"/{path} is not an object")
    return value


def canonical_mode(*, opener: Callable[..., Any]) -> tuple[str, dict[str, Any]]:
    channels = json_contract("release-channels-v1.json", opener=opener)
    mode = channels.get("current_channel")
    selected = channels.get("channels", {}).get(mode)
    if (
        channels.get("schema_version") != 1
        or not owner_contract(channels)
        or re.fullmatch(r"[0-9a-f]{64}", str(channels.get("source_sha256")))
        is None
        or mode not in {
            "guard_prelaunch",
            "guard_transition",
            "guard_live",
            "guard_frozen",
        }
        or not owner_contract(selected)
    ):
        raise AuditError("canonical release channel contract is invalid")
    return mode, channels


def store_url(raw: Any, *, checkout: bool) -> tuple[str, Any] | None:
    if (
        not isinstance(raw, str)
        or any(ord(char) <= 0x20 for char in raw)
        or "#" in raw
    ):
        return None
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
        or not host.endswith(".lemonsqueezy.com")
    ):
        return None
    slug = host.removesuffix(".lemonsqueezy.com")
    if slug in {"api", "app", "www"} or STORE_SLUG.fullmatch(slug) is None:
        return None
    if checkout and CHECKOUT_PATH.fullmatch(parsed.path) is None:
        return None
    if not checkout and (
        parsed.path != "/billing" or "?" in raw or "#" in raw or parsed.query
    ):
        return None
    return host, parsed


def validate_live_commerce(commerce: dict[str, Any], guard_version: str) -> None:
    variants = commerce.get("variants")
    custom = commerce.get("checkout_custom_data")
    if (
        not owner_contract(commerce)
        or commerce.get("checkout_enabled") is not True
        or commerce.get("launch_state") != "qualified"
        or commerce.get("sales_state") != "live"
        or commerce.get("commerce_state") != "public_live"
        or commerce.get("portal_state") != "live"
        or commerce.get("price_policy", {}).get("monthly_usd") != 499
        or commerce.get("price_policy", {}).get("annual_usd") != 4990
        or commerce.get("price_policy", {}).get("annual_default") is not True
        or not isinstance(variants, dict)
        or set(variants) != {"monthly", "annual"}
        or not isinstance(custom, dict)
        or set(custom) != {"terms_version", "guard_version"}
        or custom.get("guard_version") != guard_version
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(custom.get("terms_version")))
        is None
        or not verified_private_support(commerce.get("support"))
    ):
        raise AuditError("live commerce state differs from owner-qualified GA")
    urls: list[tuple[str, Any]] = []
    for cadence in ("monthly", "annual"):
        variant = variants[cadence]
        parsed = store_url(variant.get("checkout_url"), checkout=True)
        if (
            variant.get("reviewed") is not True
            or re.fullmatch(r"[1-9][0-9]*", str(variant.get("variant_id"))) is None
            or parsed is None
        ):
            raise AuditError(f"{cadence} checkout is not reviewed and hosted")
        query = parse_qsl(parsed[1].query, keep_blank_values=True, strict_parsing=True)
        if dict(query) != {
            "checkout[custom][terms_version]": custom["terms_version"],
            "checkout[custom][guard_version]": custom["guard_version"],
        } or len(query) != 2:
            raise AuditError(f"{cadence} checkout custom data differs")
        urls.append(parsed)
    portal = store_url(commerce.get("customer_portal_url"), checkout=False)
    if (
        variants["monthly"]["variant_id"] == variants["annual"]["variant_id"]
        or variants["monthly"]["checkout_url"] == variants["annual"]["checkout_url"]
        or portal is None
        or len({urls[0][0], urls[1][0], portal[0]}) != 1
        or portal[0] != commerce.get("store_hostname")
    ):
        raise AuditError("checkout variants or generic billing portal differ")


def verified_private_support(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {
            "state",
            "intake",
            "contact",
            "delivery_verified",
            "owner_access_verified",
            "retention_configured",
        }
        and value.get("state") == "verified"
        and value.get("intake") == "private_email"
        and re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]{0,62})@tinyzkp\.com",
            str(value.get("contact")),
        )
        is not None
        and value.get("delivery_verified") is True
        and value.get("owner_access_verified") is True
        and value.get("retention_configured") is True
    )


def probe_live_merchant(
    commerce: dict[str, Any], *, opener: Callable[..., Any]
) -> int:
    targets = (
        (
            "monthly checkout",
            commerce["variants"]["monthly"]["checkout_url"],
            ("499", "$499"),
        ),
        (
            "annual checkout",
            commerce["variants"]["annual"]["checkout_url"],
            ("4,990", "4990"),
        ),
        ("billing portal", commerce["customer_portal_url"], ()),
    )
    store_host = urlparse(commerce["customer_portal_url"]).hostname
    for label, url, markers in targets:
        status, headers, body, final_url = request(
            url, opener=opener, follow_redirects=False
        )
        location = headers.get("location")
        destination = urlparse(location or final_url)
        source = urlparse(url)
        is_checkout = bool(markers)
        checkout_destination = (
            is_checkout
            and status == 200
            and destination.hostname == store_host
            and destination.path == source.path
        )
        portal_destination = (
            not is_checkout
            and (
                (
                    status == 200
                    and destination.hostname == store_host
                    and destination.path == "/billing"
                )
                or (
                    status in {301, 302, 303, 307, 308}
                    and location is not None
                    and destination.hostname == "app.lemonsqueezy.com"
                    and re.fullmatch(r"/(?:login|billing|my-orders)(?:/.*)?", destination.path)
                    is not None
                    and not destination.query
                )
            )
        )
        if (
            destination.scheme != "https"
            or destination.username is not None
            or destination.password is not None
            or destination.fragment
            or not (checkout_destination or portal_destination)
        ):
            raise AuditError(f"{label} is not reachable on an approved merchant host")
        text = body.decode("utf-8", errors="replace")
        if markers and not any(marker in text for marker in markers):
            raise AuditError(f"{label} does not render the reviewed price")
    return len(targets)


def probe_frozen_portal(
    commerce: dict[str, Any], *, opener: Callable[..., Any]
) -> int:
    portal = commerce.get("customer_portal_url")
    parsed = urlparse(portal) if isinstance(portal, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/billing"
        or "?" in portal
        or "#" in portal
        or not (parsed.hostname or "").endswith(".lemonsqueezy.com")
        or parsed.hostname != commerce.get("store_hostname")
    ):
        raise AuditError("frozen billing portal identity differs")
    status, headers, _body, final_url = request(
        portal, opener=opener, follow_redirects=False
    )
    location = headers.get("location")
    destination = urlparse(location or final_url)
    approved = (
        status == 200
        and destination.hostname == parsed.hostname
        and destination.path == "/billing"
    ) or (
        status in {301, 302, 303, 307, 308}
        and location is not None
        and destination.hostname == "app.lemonsqueezy.com"
        and re.fullmatch(r"/(?:login|billing|my-orders)(?:/.*)?", destination.path)
        is not None
        and not destination.query
    )
    if (
        destination.scheme != "https"
        or destination.username is not None
        or destination.password is not None
        or destination.fragment
        or not approved
    ):
        raise AuditError("frozen billing portal is not reachable")
    return 1


def anonymous_sha256(
    url: Any,
    expected: Any,
    *,
    label: str,
    opener: Callable[..., Any],
) -> None:
    if not isinstance(url, str) or re.fullmatch(r"[0-9a-f]{64}", str(expected)) is None:
        raise AuditError(f"{label} identity is missing")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    allowed_initial = (
        host == "github.com"
        and re.fullmatch(
            r"/logannye/hc-stark/releases/download/guard-v[^/]+/[^/]+",
            parsed.path,
        )
        is not None
    ) or (
        host in {"tinyzkp.com", "www.tinyzkp.com"}
        and re.fullmatch(r"/guard-release-index-v1\.json(?:\.sig)?", parsed.path)
        is not None
    )
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not allowed_initial
    ):
        raise AuditError(f"{label} URL is outside the public release boundary")
    request_value = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/octet-stream", "User-Agent": "TinyZKP-Guard-Health-Audit/1"},
    )
    try:
        with opener(request_value, timeout=45) as response:
            final_url = response.geturl() if hasattr(response, "geturl") else url
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1024 * 1024 * 1024:
                    raise AuditError(f"{label} is oversized")
                digest.update(chunk)
            status = response.status
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise AuditError(f"anonymous {label} download failed") from error
    final = urlparse(final_url)
    allowed_final = (
        {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
        if host == "github.com"
        else {"tinyzkp.com", "www.tinyzkp.com"}
    )
    if (
        status != 200
        or final.scheme != "https"
        or final.username
        or final.password
        or final.hostname not in allowed_final
        or final.fragment
        or digest.hexdigest() != expected
    ):
        raise AuditError(f"anonymous {label} bytes or destination differ")


def anonymous_oci(
    repository: str,
    expected: Any,
    *,
    opener: Callable[..., Any],
) -> None:
    if (
        repository not in {"logannye/tinyzkp-engine", "logannye/tinyzkp-guard"}
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(expected)) is None
    ):
        raise AuditError("anonymous OCI identity is invalid")
    url = f"https://ghcr.io/v2/{repository}/manifests/{expected}"

    def fetch(raw_url: str, headers: dict[str, str]):
        req = urllib.request.Request(raw_url, method="GET", headers=headers)
        try:
            with opener(req, timeout=30) as response:
                return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(MAX_BODY + 1)
        except urllib.error.HTTPError as error:
            return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read(MAX_BODY + 1)

    status, headers, body = fetch(url, {"Accept": "application/vnd.oci.image.manifest.v1+json", "User-Agent": "TinyZKP-Guard-Health-Audit/1"})
    if status == 401:
        match = re.fullmatch(
            r'Bearer realm="(https://ghcr\.io/token)",service="ghcr\.io",scope="([^"]+)"',
            headers.get("www-authenticate", ""),
        )
        scope = f"repository:{repository}:pull"
        if match is None or match.group(2) != scope:
            raise AuditError("anonymous OCI challenge differs")
        token_url = match.group(1) + "?" + urlencode({"service": "ghcr.io", "scope": scope})
        token_status, _headers, raw = fetch(token_url, {"Accept": "application/json", "User-Agent": "TinyZKP-Guard-Health-Audit/1"})
        try:
            token = json.loads(raw).get("token")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AuditError("anonymous OCI token differs") from error
        if token_status != 200 or not isinstance(token, str) or not token:
            raise AuditError("anonymous OCI token is unavailable")
        status, _headers, body = fetch(
            url,
            {
                "Accept": "application/vnd.oci.image.manifest.v1+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "TinyZKP-Guard-Health-Audit/1",
            },
        )
    if status != 200 or "sha256:" + hashlib.sha256(body).hexdigest() != expected:
        raise AuditError(f"anonymous OCI manifest differs: {repository}")


def probe_live_fulfillment(
    release: dict[str, Any],
    compatibility: dict[str, Any],
    *,
    opener: Callable[..., Any],
) -> int:
    channel = release.get("channel_manifest")
    latest = release.get("latest_release_index")
    if not isinstance(channel, dict) or not isinstance(latest, dict):
        raise AuditError("live signed channel/index identity is missing")
    for url, digest, label in (
        (release.get("guard_artifact_url"), release.get("guard_artifact_sha256"), "Guard artifact"),
        (channel.get("url"), channel.get("sha256"), "Guard channel"),
        (latest.get("url"), latest.get("sha256"), "Guard release index"),
        (latest.get("signature_url"), latest.get("signature_sha256"), "Guard release index signature"),
    ):
        anonymous_sha256(url, digest, label=label, opener=opener)
    anonymous_oci("logannye/tinyzkp-guard", release.get("guard_oci_digest"), opener=opener)
    anonymous_oci(
        "logannye/tinyzkp-engine",
        compatibility.get("release_binding", {}).get("engine_oci_digest"),
        opener=opener,
    )
    return 6


def audit(mode: str, *, opener: Callable[..., Any] = urllib.request.urlopen) -> int:
    selected_mode, release_channels = canonical_mode(opener=opener)
    checks = 1
    if mode != "canonical" and mode != selected_mode:
        raise AuditError(
            f"configured audit mode {mode} differs from canonical {selected_mode}"
        )
    mode = selected_mode
    if mode == "guard_prelaunch":
        for url in PRELAUNCH_URLS:
            status, _headers, _body, _final_url = request(url, opener=opener)
            checks += 1
            if status != 200:
                raise AuditError(f"prelaunch legacy endpoint returned HTTP {status}: {url}")
    else:
        for host in LEGACY_HOSTS:
            for method in ("GET", "POST"):
                status, headers, _body, _final_url = request(
                    f"https://{host}/retirement-canary",
                    method=method,
                    opener=opener,
                    follow_redirects=False,
                )
                checks += 1
                if (
                    status != 410
                    or "noindex" not in headers.get("x-robots-tag", "").lower()
                    or "location" in headers
                ):
                    raise AuditError(f"retired host is not 410/noindex: {host} {method}")

    discovery = json_contract("discovery.json", opener=opener)
    commerce = json_contract("commerce.json", opener=opener)
    release = json_contract("release.json", opener=opener)
    checks += 3
    if discovery.get("service_status") != mode:
        raise AuditError("published discovery monitoring mode differs")
    if release_channels.get("source_sha256") != release.get("source_sha256"):
        raise AuditError("published release channel source identity differs")
    if not owner_contract(commerce) or not owner_contract(release):
        raise AuditError("published contracts are not owner-qualified")
    if mode == "guard_prelaunch":
        if commerce.get("checkout_enabled") is not False:
            raise AuditError("prelaunch checkout is open")
    elif mode == "guard_transition":
        if (
            commerce.get("checkout_enabled") is not False
            or commerce.get("commerce_state") != "live_hidden"
            or release.get("blocking_gates") != ["guard_artifact_published"]
        ):
            raise AuditError("transition state is not promotion-ready and closed")
    elif mode == "guard_live":
        guard_version = release.get("release_identity", {}).get("guard_version")
        if not isinstance(guard_version, str) or re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", guard_version
        ) is None:
            raise AuditError("live Guard release version is invalid")
        validate_live_commerce(commerce, guard_version)
        if (
            release.get("launch_state") != "qualified"
            or release.get("sales_state") != "live"
            or release.get("checkout_enabled") is not True
            or release.get("guard_artifact_available") is not True
            or release.get("blocking_gates") != []
        ):
            raise AuditError(f"live release state differs from Guard {guard_version} GA")
        checks += probe_live_merchant(commerce, opener=opener)
        compatibility = json_contract("compatibility.json", opener=opener)
        checks += 1
        checks += probe_live_fulfillment(
            release, compatibility, opener=opener
        )
    elif mode == "guard_frozen":
        variants = commerce.get("variants")
        if (
            commerce.get("checkout_enabled") is not False
            or commerce.get("commerce_state") != "sales_frozen"
            or commerce.get("sales_state") != "frozen"
            or commerce.get("portal_state") != "live"
            or not verified_private_support(commerce.get("support"))
            or not isinstance(variants, dict)
            or set(variants) != {"monthly", "annual"}
            or variants["monthly"].get("checkout_url") is not None
            or variants["annual"].get("checkout_url") is not None
            or variants["monthly"].get("reviewed") is not False
            or variants["annual"].get("reviewed") is not False
            or release.get("launch_state") != "qualified"
            or release.get("sales_state") != "frozen"
            or release.get("guard_artifact_available") is not True
            or release.get("blocking_gates") != []
        ):
            raise AuditError("frozen release does not preserve portal and artifacts")
        checks += probe_frozen_portal(commerce, opener=opener)
        compatibility = json_contract("compatibility.json", opener=opener)
        checks += 1
        checks += probe_live_fulfillment(
            release, compatibility, opener=opener
        )
    else:
        raise AuditError(f"unsupported monitoring mode: {mode}")
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        required=True,
        choices=(
            "canonical",
            "guard_prelaunch",
            "guard_transition",
            "guard_live",
            "guard_frozen",
        ),
    )
    args = parser.parse_args(argv)
    try:
        checks = audit(args.mode)
    except AuditError as error:
        print(f"TinyZKP {args.mode} audit: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS TinyZKP {args.mode} audit ({checks} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
