#!/usr/bin/env python3
"""Verify one exact TinyZKP Pages deployment using static surfaces only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
MAX_BODY = 4 * 1024 * 1024
CONTRACTS = (
    "release.json",
    "commerce.json",
    "pricing.json",
    "discovery.json",
    "release-channels-v1.json",
    "compatibility.json",
)
PUBLIC_ROUTES = (
    "/",
    "/guard",
    "/compatibility",
    "/benchmarks",
    "/doctor",
    "/pricing",
    "/docs",
    "/troubleshooting",
    "/security",
    "/releases",
    "/support",
    "/plonky3-out-of-memory",
    "/resumable-plonky3-prover",
    "/ssd-backed-plonky3-proving",
)
RETIRED_ROUTES = (
    "/api/release",
    "/api/create-checkout",
    "/mcp",
    "/receipts",
    "/signup",
)
RETIRED_HOSTS = (
    "api.tinyzkp.com",
    "mcp.tinyzkp.com",
    "webhook.tinyzkp.com",
)
AUTHORIZATION_POLICY = "owner_only_ga_v1"
QUALIFICATION_BASIS = "owner_attested"
MAX_ARTIFACT_BODY = 1024 * 1024 * 1024
OCI_ACCEPT = (
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json"
)


class CanaryError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect()).open


def merchant_store_url(value: object, *, label: str) -> tuple[str, object]:
    if not isinstance(value, str) or "#" in value:
        raise CanaryError(f"{label} is not a URL")
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or parsed.fragment
        or host == "lemonsqueezy.com"
        or host in {"api.lemonsqueezy.com", "app.lemonsqueezy.com", "www.lemonsqueezy.com"}
        or not host.endswith(".lemonsqueezy.com")
    ):
        raise CanaryError(f"{label} is outside the reviewed Lemon Squeezy store")
    return host, parsed


def live_checkout_url(
    value: object,
    *,
    label: str,
    custom_data: dict,
) -> str:
    host, parsed = merchant_store_url(value, label=label)
    if not re.fullmatch(r"/checkout/buy/[A-Za-z0-9_-]{8,128}/?", parsed.path):
        raise CanaryError(f"{label} is not a hosted /checkout/buy/... link")
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise CanaryError(f"{label} custom data is malformed") from error
    expected = {
        "checkout[custom][terms_version]": custom_data.get("terms_version"),
        "checkout[custom][guard_version]": custom_data.get("guard_version"),
    }
    if len(query) != 2 or dict(query) != expected:
        raise CanaryError(f"{label} custom data differs from the reviewed release")
    return host


def verified_private_support(value: object) -> bool:
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


def safe_base_url(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not (
            host == "tinyzkp.com"
            or host == "www.tinyzkp.com"
            or host == "tinyzkp.pages.dev"
            or host.endswith(".tinyzkp.pages.dev")
        )
    ):
        raise CanaryError("base URL is outside the TinyZKP Pages boundary")
    return value.rstrip("/") + "/"


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    opener=urllib.request.urlopen,
    follow_redirects: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    url = urljoin(base_url, path.lstrip("/"))
    body = b"{}" if method == "POST" else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
            "Content-Type": "application/json",
            "User-Agent": "TinyZKP-Static-Pages-Canary/1",
        },
    )
    try:
        selected_opener = (
            NO_REDIRECT_OPENER
            if not follow_redirects and opener is urllib.request.urlopen
            else opener
        )
        with selected_opener(req, timeout=20) as response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_BODY + 1)
        status = error.code
        headers = {key.lower(): value for key, value in error.headers.items()}
    except (OSError, urllib.error.URLError) as error:
        raise CanaryError(f"request failed for {path}") from error
    if len(raw) > MAX_BODY:
        raise CanaryError(f"response is oversized for {path}")
    return status, headers, raw


def anonymous_download_sha256(
    url: object,
    expected_sha256: object,
    *,
    label: str,
    opener=urllib.request.urlopen,
) -> str:
    if not isinstance(url, str) or not isinstance(expected_sha256, str):
        raise CanaryError(f"{label} identity is missing")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    github_path = re.fullmatch(
        r"/logannye/hc-stark/releases/download/guard-v[^/]+/[^/]+", parsed.path
    )
    tinyzkp_path = re.fullmatch(
        r"/(?:release-index-revisions/[0-9a-f]{64}/)?guard-release-index-v1\.json(?:\.sig)?",
        parsed.path,
    )
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        or not (
            (host == "github.com" and github_path is not None)
            or (host in {"tinyzkp.com", "www.tinyzkp.com"} and tinyzkp_path is not None)
        )
    ):
        raise CanaryError(f"{label} URL or digest is outside the public release boundary")
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "TinyZKP-Static-Pages-Canary/1",
        },
    )
    try:
        with opener(req, timeout=45) as response:
            status = response.status
            final_url = response.geturl() if hasattr(response, "geturl") else url
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BODY:
                    raise CanaryError(f"{label} exceeds the bounded download size")
                digest.update(chunk)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as error:
        raise CanaryError(f"anonymous {label} download failed") from error
    final = urlparse(final_url)
    allowed_final_hosts = (
        {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
        if host == "github.com"
        else {"tinyzkp.com", "www.tinyzkp.com"}
    )
    if (
        status != 200
        or final.scheme != "https"
        or final.username
        or final.password
        or (final.hostname or "").lower() not in allowed_final_hosts
        or final.fragment
        or digest.hexdigest() != expected_sha256
    ):
        raise CanaryError(f"anonymous {label} bytes or destination differ")
    return digest.hexdigest()


def anonymous_oci_manifest(
    repository: str,
    expected_digest: object,
    *,
    opener=urllib.request.urlopen,
) -> None:
    if (
        repository not in {"logannye/tinyzkp-engine", "logannye/tinyzkp-guard"}
        or not isinstance(expected_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest) is None
    ):
        raise CanaryError("anonymous OCI identity is invalid")
    manifest_url = f"https://ghcr.io/v2/{repository}/manifests/{expected_digest}"

    def open_request(url: str, headers: dict[str, str]):
        request_value = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with opener(request_value, timeout=30) as response:
                return (
                    response.status,
                    {key.lower(): value for key, value in response.headers.items()},
                    response.read(MAX_BODY + 1),
                )
        except urllib.error.HTTPError as error:
            return (
                error.code,
                {key.lower(): value for key, value in error.headers.items()},
                error.read(MAX_BODY + 1),
            )

    status, headers, body = open_request(
        manifest_url,
        {"Accept": OCI_ACCEPT, "User-Agent": "TinyZKP-Static-Pages-Canary/1"},
    )
    if status == 401:
        challenge = headers.get("www-authenticate", "")
        match = re.fullmatch(
            r'Bearer realm="(https://ghcr\.io/token)",service="([^"]+)",scope="([^"]+)"',
            challenge,
        )
        expected_scope = f"repository:{repository}:pull"
        if match is None or match.group(2) != "ghcr.io" or match.group(3) != expected_scope:
            raise CanaryError("anonymous OCI challenge differs")
        token_url = match.group(1) + "?" + urlencode(
            {"service": match.group(2), "scope": match.group(3)}
        )
        token_status, _token_headers, token_raw = open_request(
            token_url,
            {"Accept": "application/json", "User-Agent": "TinyZKP-Static-Pages-Canary/1"},
        )
        try:
            token = json.loads(token_raw).get("token")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CanaryError("anonymous OCI token response differs") from error
        if token_status != 200 or not isinstance(token, str) or not token:
            raise CanaryError("anonymous OCI token is unavailable")
        status, _headers, body = open_request(
            manifest_url,
            {
                "Accept": OCI_ACCEPT,
                "Authorization": f"Bearer {token}",
                "User-Agent": "TinyZKP-Static-Pages-Canary/1",
            },
        )
    if (
        status != 200
        or len(body) > MAX_BODY
        or "sha256:" + hashlib.sha256(body).hexdigest() != expected_digest
    ):
        raise CanaryError(f"anonymous OCI manifest differs: {repository}")


def check_live_fulfillment(
    release: dict,
    compatibility: dict,
    *,
    opener=urllib.request.urlopen,
) -> None:
    channel = release.get("channel_manifest")
    latest = release.get("latest_release_index")
    delivery = release.get("delivery")
    if (
        not isinstance(channel, dict)
        or not isinstance(latest, dict)
        or not isinstance(delivery, dict)
    ):
        raise CanaryError("live signed channel/index identity is missing")
    expected_delivery_keys = {
        "receipt_url",
        "artifact_url",
        "artifact_sha256",
        "sha256sums_url",
        "sha256sums_signature_url",
        "signing_public_key_url",
        "signing_public_key_sha256",
        "channel_url",
        "release_index_url",
        "release_index_signature_url",
        "start_here_path",
        "agreement_path",
        "delivery_path",
        "activation_command",
    }
    artifact_url = release.get("guard_artifact_url")
    if not isinstance(artifact_url, str) or "/" not in artifact_url:
        raise CanaryError("live Guard artifact URL is missing")
    release_asset_base = artifact_url.rsplit("/", 1)[0]
    expected_delivery = {
        "receipt_url": "https://tinyzkp.com/releases",
        "artifact_url": artifact_url,
        "artifact_sha256": release.get("guard_artifact_sha256"),
        "sha256sums_url": f"{release_asset_base}/SHA256SUMS",
        "sha256sums_signature_url": f"{release_asset_base}/SHA256SUMS.sig",
        "signing_public_key_url": f"{release_asset_base}/signing-public-key.pem",
        "signing_public_key_sha256": delivery.get("signing_public_key_sha256"),
        "channel_url": channel.get("url"),
        "release_index_url": latest.get("url"),
        "release_index_signature_url": latest.get("signature_url"),
        "start_here_path": "START-HERE.txt",
        "agreement_path": "AGREEMENT.txt",
        "delivery_path": "DELIVERY.txt",
        "activation_command": "./bin/tinyzkp activate --license-key-stdin",
    }
    if (
        set(delivery) != expected_delivery_keys
        or delivery != expected_delivery
        or re.fullmatch(
            r"[0-9a-f]{64}", str(delivery.get("signing_public_key_sha256"))
        )
        is None
    ):
        raise CanaryError("live buyer delivery contract differs")
    downloads = (
        (release.get("guard_artifact_url"), release.get("guard_artifact_sha256"), "Guard artifact"),
        (channel.get("url"), channel.get("sha256"), "Guard channel"),
        (latest.get("url"), latest.get("sha256"), "stable Guard release index"),
        (latest.get("signature_url"), latest.get("signature_sha256"), "stable Guard release index signature"),
        (latest.get("immutable_revision_url"), latest.get("sha256"), "immutable Guard release index"),
        (latest.get("immutable_revision_signature_url"), latest.get("signature_sha256"), "immutable Guard release index signature"),
    )
    for url, expected, label in downloads:
        anonymous_download_sha256(url, expected, label=label, opener=opener)
    anonymous_download_sha256(
        delivery["signing_public_key_url"],
        delivery["signing_public_key_sha256"],
        label="Guard signing public key",
        opener=opener,
    )
    guard_digest = release.get("guard_oci_digest")
    engine_digest = compatibility.get("release_binding", {}).get("engine_oci_digest")
    anonymous_oci_manifest("logannye/tinyzkp-guard", guard_digest, opener=opener)
    anonymous_oci_manifest("logannye/tinyzkp-engine", engine_digest, opener=opener)


def check_contracts(
    base_url: str, site: Path = SITE, *, opener=urllib.request.urlopen
) -> dict[str, dict]:
    parsed: dict[str, dict] = {}
    for name in CONTRACTS:
        status, headers, raw = request(base_url, "/" + name, opener=opener)
        if status != 200:
            raise CanaryError(f"/{name} returned HTTP {status}")
        expected = (site / name).read_bytes()
        if raw != expected:
            raise CanaryError(f"/{name} differs from the reviewed static source")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise CanaryError(f"/{name} is not JSON") from error
        if not isinstance(value, dict):
            raise CanaryError(f"/{name} must be a JSON object")
        parsed[name] = value
        if "application/json" not in headers.get("content-type", ""):
            raise CanaryError(f"/{name} has the wrong content type")

    release = parsed["release.json"]
    commerce = parsed["commerce.json"]
    pricing = parsed["pricing.json"]
    discovery = parsed["discovery.json"]
    release_channels = parsed["release-channels-v1.json"]
    if (
        release_channels.get("authorization_policy") != AUTHORIZATION_POLICY
        or release_channels.get("qualification_basis") != QUALIFICATION_BASIS
        or release_channels.get("current_channel")
        != discovery.get("service_status")
        or release_channels.get("source_sha256") != release.get("source_sha256")
    ):
        raise CanaryError("release channel and published monitoring state disagree")
    states = {
        (
            item.get("launch_state"),
            item.get("sales_state"),
            item.get("commerce_state"),
            item.get("portal_state"),
        )
        for item in (release, commerce, pricing, discovery)
    }
    if len(states) != 1:
        raise CanaryError("generated public state contracts disagree")
    for label, value in (("release", release), ("commerce", commerce)):
        if (
            value.get("authorization_policy") != AUTHORIZATION_POLICY
            or value.get("qualification_basis") != QUALIFICATION_BASIS
        ):
            raise CanaryError(f"{label} does not declare owner-only qualification")
    enabled = [
        release.get("checkout_enabled"),
        commerce.get("checkout_enabled"),
        pricing.get("checkout_enabled"),
        discovery.get("availability", {}).get("guard_checkout"),
    ]
    if len(set(enabled)) != 1:
        raise CanaryError("generated checkout states disagree")
    if enabled[0] is not True:
        for variant in commerce.get("variants", {}).values():
            if variant.get("checkout_url") is not None or variant.get("reviewed") is not False:
                raise CanaryError("closed commerce exposes a checkout URL")
        return parsed

    if states != {("qualified", "live", "public_live", "live")}:
        raise CanaryError("enabled checkout is not in the exact public-live state")
    if (
        release.get("guard_artifact_available") is not True
        or release.get("blocking_gates") != []
        or commerce.get("provider") != "lemon_squeezy"
        or commerce.get("mode") != "live"
    ):
        raise CanaryError("public-live artifact or commerce state is incomplete")
    custom_data = commerce.get("checkout_custom_data")
    if (
        not isinstance(custom_data, dict)
        or set(custom_data) != {"terms_version", "guard_version"}
        or not isinstance(custom_data.get("terms_version"), str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", custom_data["terms_version"])
        or custom_data.get("guard_version")
        != release.get("release_identity", {}).get("guard_version")
    ):
        raise CanaryError("public-live checkout custom data is not release-bound")
    variants = commerce.get("variants")
    if not isinstance(variants, dict) or set(variants) != {"annual", "monthly"}:
        raise CanaryError("public-live commerce variants differ")
    annual = variants["annual"]
    monthly = variants["monthly"]
    if (
        not all(isinstance(item, dict) for item in (annual, monthly))
        or annual.get("reviewed") is not True
        or monthly.get("reviewed") is not True
        or annual.get("variant_id") == monthly.get("variant_id")
        or annual.get("checkout_url") == monthly.get("checkout_url")
    ):
        raise CanaryError("public-live variants are not distinct and reviewed")
    annual_host = live_checkout_url(
        annual.get("checkout_url"), label="annual checkout", custom_data=custom_data
    )
    monthly_host = live_checkout_url(
        monthly.get("checkout_url"), label="monthly checkout", custom_data=custom_data
    )
    portal_host, portal = merchant_store_url(
        commerce.get("customer_portal_url"), label="customer portal"
    )
    if (
        annual_host != monthly_host
        or annual_host != portal_host
        or annual_host != commerce.get("store_hostname")
        or portal.path != "/billing"
        or "?" in commerce.get("customer_portal_url", "")
        or "#" in commerce.get("customer_portal_url", "")
        or portal.query
        or portal.fragment
        or not verified_private_support(commerce.get("support"))
    ):
        raise CanaryError("public-live portal and checkout store identity differ")
    return parsed


def check_monitoring_mode(
    base_url: str,
    mode: str,
    *,
    site: Path = SITE,
    opener=urllib.request.urlopen,
) -> None:
    parsed = check_contracts(base_url, site=site, opener=opener)
    release = parsed["release.json"]
    commerce = parsed["commerce.json"]
    discovery = parsed["discovery.json"]
    if discovery.get("service_status") != mode:
        raise CanaryError(f"discovery service_status does not equal {mode}")
    if mode == "guard_prelaunch":
        if commerce.get("checkout_enabled") is not False:
            raise CanaryError("guard_prelaunch checkout is not closed")
        return
    if mode == "guard_transition":
        if (
            commerce.get("checkout_enabled") is not False
            or commerce.get("commerce_state") != "live_hidden"
            or release.get("launch_state") != "blocked"
            or release.get("sales_state") != "closed"
            or release.get("blocking_gates") != ["guard_artifact_published"]
            or release.get("gate_status", {})
            .get("hosted_infrastructure_decommissioned", {})
            .get("status")
            != "passed"
        ):
            raise CanaryError("guard_transition contract is not promotion-ready")
        check_retired_hosts(opener=opener)
        return
    if mode == "guard_live":
        if (
            commerce.get("checkout_enabled") is not True
            or release.get("launch_state") != "qualified"
            or release.get("sales_state") != "live"
            or release.get("blocking_gates") != []
        ):
            raise CanaryError("guard_live contract is not public-live")
        check_retired_hosts(opener=opener)
        check_live_fulfillment(
            release, parsed["compatibility.json"], opener=opener
        )
        return
    if mode == "guard_frozen":
        if (
            commerce.get("checkout_enabled") is not False
            or commerce.get("commerce_state") != "sales_frozen"
            or commerce.get("sales_state") != "frozen"
            or commerce.get("portal_state") != "live"
            or release.get("launch_state") != "qualified"
            or release.get("sales_state") != "frozen"
            or release.get("guard_artifact_available") is not True
            or release.get("blocking_gates") != []
            or not isinstance(commerce.get("customer_portal_url"), str)
            or not verified_private_support(commerce.get("support"))
        ):
            raise CanaryError("guard_frozen contract does not preserve fulfillment")
        _portal_host, portal = merchant_store_url(
            commerce["customer_portal_url"], label="frozen customer portal"
        )
        if (
            _portal_host != commerce.get("store_hostname")
            or portal.path != "/billing"
            or "?" in commerce["customer_portal_url"]
            or "#" in commerce["customer_portal_url"]
            or portal.query
            or portal.fragment
        ):
            raise CanaryError("guard_frozen portal is not generic and unsigned")
        check_retired_hosts(opener=opener)
        check_live_fulfillment(
            release, parsed["compatibility.json"], opener=opener
        )
        return
    raise CanaryError(f"unknown Guard monitoring mode: {mode}")


def check_routes(base_url: str, *, opener=urllib.request.urlopen) -> None:
    preview = urlparse(base_url).hostname.endswith(".pages.dev")
    for path in PUBLIC_ROUTES:
        status, headers, _raw = request(base_url, path, opener=opener)
        if status != 200:
            raise CanaryError(f"{path} returned HTTP {status}")
        if headers.get("x-content-type-options") != "nosniff":
            raise CanaryError(f"{path} omits static security headers")
        if preview and headers.get("x-robots-tag") != "noindex, nofollow":
            raise CanaryError(f"{path} preview is indexable")
    for path in RETIRED_ROUTES:
        for method in ("GET", "POST"):
            status, headers, _raw = request(
                base_url,
                path,
                method=method,
                opener=opener,
                follow_redirects=False,
            )
            if status != 410:
                raise CanaryError(f"{method} {path} returned HTTP {status}, not 410")
            if headers.get("x-robots-tag") != "noindex, nofollow":
                raise CanaryError(f"{path} retirement response is indexable")


def check_retired_hosts(*, opener=urllib.request.urlopen) -> None:
    for hostname in RETIRED_HOSTS:
        for method in ("GET", "POST"):
            status, headers, _raw = request(
                f"https://{hostname}/",
                "/retirement-canary",
                method=method,
                opener=opener,
                follow_redirects=False,
            )
            if status != 410:
                raise CanaryError(
                    f"{method} https://{hostname}/ returned HTTP {status}, not 410"
                )
            if headers.get("x-robots-tag") != "noindex, nofollow":
                raise CanaryError(f"{hostname} retirement response is indexable")
            if "location" in headers:
                raise CanaryError(f"{hostname} redirects instead of returning 410")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument(
        "--mode",
        choices=(
            "contracts",
            "routes",
            "retired-hosts",
            "guard_prelaunch",
            "guard_transition",
            "guard_live",
            "guard_frozen",
        ),
        required=True,
    )
    args = parser.parse_args(argv)
    try:
        if args.mode == "retired-hosts":
            if args.base_url is not None:
                raise CanaryError("--base-url is not used for retired-hosts mode")
            check_retired_hosts()
        elif args.base_url is None:
            raise CanaryError("--base-url is required for site canary modes")
        else:
            base = safe_base_url(args.base_url)
            if args.mode == "contracts":
                check_contracts(base)
            elif args.mode == "routes":
                check_routes(base)
            else:
                check_monitoring_mode(base, args.mode)
    except CanaryError as error:
        print(f"static Pages canary: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS static Pages {args.mode} canary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
