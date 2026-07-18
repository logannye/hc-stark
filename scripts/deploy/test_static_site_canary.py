from email.message import Message
import io
import json
from pathlib import Path
import urllib.error

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
        (tmp_path / name).write_text(
            json.dumps(
                {
                    "launch_state": "blocked",
                    "sales_state": "closed",
                    "commerce_state": "unconfigured",
                    "portal_state": "unconfigured",
                    "checkout_enabled": False,
                    "availability": {"guard_checkout": False},
                    "variants": {
                        "annual": {"reviewed": False, "checkout_url": None},
                        "monthly": {"reviewed": False, "checkout_url": None},
                    },
                }
            ),
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
