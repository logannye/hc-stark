import release_identity_check as check


def test_fetch_headers_identify_release_monitor():
    assert check.MONITOR_HEADERS["Accept"] == "application/json"
    assert check.MONITOR_HEADERS["User-Agent"].startswith("TinyZKP-Release-Check/")


def test_validate_payload_requires_service_sha_and_version():
    surface = check.ReleaseSurface("site", "https://tinyzkp.com/api/release", "site")

    assert check.validate_payload(
        surface,
        {
            "service": "site",
            "package_version": "0.1.0",
            "release_sha": "abc123",
        },
        "abc123",
    ) == []

    failures = check.validate_payload(
        surface,
        {
            "service": "api",
            "package_version": "",
            "release_sha": "old",
        },
        "abc123",
    )
    assert "site service must be 'site'; got 'api'" in failures
    assert "site release_sha must be 'abc123'; got 'old'" in failures
    assert "site package_version is missing" in failures


def test_release_surfaces_include_site_api_and_mcp_version_endpoints():
    surfaces = check.release_surfaces(
        "https://tinyzkp.com/",
        "https://api.tinyzkp.com/",
        "https://mcp.tinyzkp.com/",
    )

    assert [surface.url for surface in surfaces] == [
        "https://tinyzkp.com/api/release",
        "https://api.tinyzkp.com/version",
        "https://mcp.tinyzkp.com/version",
    ]
    assert [surface.expected_service for surface in surfaces] == ["site", "api", "mcp"]
