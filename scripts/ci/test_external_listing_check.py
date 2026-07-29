"""Tests for the external listing check.

The historical manifests are used as fixtures on purpose: a gate justified by
a past incident should be shown catching that incident, not a synthetic
approximation of it.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

import pytest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import external_listing_check as gate  # noqa: E402


# Verbatim excerpts of the manifests as they were published while
# mcp.tinyzkp.com returned 410.
HISTORICAL_SERVER_JSON = """{
  "websiteUrl": "https://tinyzkp.com/status",
  "remotes": [{"type": "streamable-http", "url": "https://mcp.tinyzkp.com/mcp"}],
  "_meta": {"io.modelcontextprotocol.registry/publisher-provided": {
    "capabilitiesUrl": "https://tinyzkp.com/status",
    "contactUrl": "https://tinyzkp.com/requests"}}
}"""

HISTORICAL_SMITHERY_YAML = """
startCommand:
  type: http
  url: https://mcp.tinyzkp.com
homepage: https://tinyzkp.com
description: Get a free key at https://tinyzkp.com/signup
"""


@pytest.fixture
def routes() -> dict[str, Any]:
    return gate.worker_routes(gate.WORKER.read_text(encoding="utf-8"))


@pytest.fixture
def assets() -> set[str]:
    return gate.served_assets()


def test_repository_state_passes(routes, assets) -> None:
    surfaces = {
        name: (gate.ROOT / name).read_text(encoding="utf-8")
        for name in gate.PUBLISHED_SURFACES
        if (gate.ROOT / name).is_file()
    }
    assert gate.check(surfaces, routes, assets) == []


def test_the_worker_route_table_actually_parsed(routes) -> None:
    """Every assertion here is vacuous if the regexes matched nothing."""
    assert "mcp.tinyzkp.com" in routes["retired_hosts"]
    assert "api.tinyzkp.com" in routes["retired_hosts"]
    assert "/estimate" in routes["public_routes"]
    assert "/status" in routes["redirects"]
    assert "/signup" in routes["gone_prefixes"]


def test_it_catches_the_historical_server_json(routes, assets) -> None:
    failures = gate.check({"server.json": HISTORICAL_SERVER_JSON}, routes, assets)

    assert any("mcp.tinyzkp.com/mcp" in f and "retired host" in f for f in failures), failures
    assert any("/requests" in f and "gone prefix" in f for f in failures), failures


def test_it_catches_the_historical_smithery_yaml(routes, assets) -> None:
    failures = gate.check({"smithery.yaml": HISTORICAL_SMITHERY_YAML}, routes, assets)

    assert any("mcp.tinyzkp.com" in f and "retired host" in f for f in failures), failures
    assert any("/signup" in f and "gone prefix" in f for f in failures), failures


def test_a_delisted_manifest_is_not_a_failure(routes, assets) -> None:
    """Deleting a listing is a valid outcome, not a missing-file error."""
    assert gate.check({}, routes, assets) == []


def test_live_routes_and_assets_are_accepted(routes, assets) -> None:
    text = (
        "https://tinyzkp.com/estimate https://tinyzkp.com/docs "
        "https://tinyzkp.com/privacy-disclosure-v1.json "
        "https://tinyzkp.com/v1/estimate https://tinyzkp.com/status"
    )
    assert gate.check({"site/llms.txt": text}, routes, assets) == []


def test_prose_punctuation_is_not_mistaken_for_a_path(routes, assets) -> None:
    """These URLs appear mid-sentence; a swallowed full stop is a phantom."""
    text = "The estimator lives at https://tinyzkp.com/estimate. Try it."
    assert gate.check({"site/llms.txt": text}, routes, assets) == []


def test_an_unserved_path_is_rejected(routes, assets) -> None:
    failures = gate.check(
        {"site/llms.txt": "https://tinyzkp.com/a-page-that-does-not-exist"},
        routes,
        assets,
    )
    assert any("not a served route" in f for f in failures), failures


def test_the_delisted_manifests_are_gone_from_the_repository() -> None:
    """Retraction, not repair: see docs/runbooks/external_listing_retraction.md."""
    for name in ("server.json", "smithery.yaml", "glama.json"):
        assert not (gate.ROOT / name).exists(), (
            f"{name} advertises a retired MCP endpoint and a deleted crate; "
            "it was deliberately removed rather than corrected"
        )
