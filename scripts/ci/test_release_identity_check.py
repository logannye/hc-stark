import json
import stat

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


def test_live_surfaces_must_share_package_version(monkeypatch):
    payloads = {
        "https://site/version": {"service": "site", "package_version": "0.1.0", "release_sha": "abc"},
        "https://api/version": {"service": "api", "package_version": "0.2.0", "release_sha": "abc"},
    }
    monkeypatch.setattr(check, "fetch_json", lambda url, _timeout: payloads[url])
    failures = check.check_surfaces(
        [
            check.ReleaseSurface("site", "https://site/version", "site"),
            check.ReleaseSurface("api", "https://api/version", "api"),
        ],
        "abc",
        1,
    )
    assert "release package versions disagree: api=0.2.0, site=0.1.0" in failures


def test_site_release_identity_binds_critical_static_asset_digest(monkeypatch):
    payload = {
        "service": "site",
        "package_version": "0.1.0",
        "release_sha": "abc",
        "asset_manifest_complete": True,
        "asset_manifest_sha256": "a" * 64,
    }
    monkeypatch.setattr(check, "fetch_json", lambda _url, _timeout: payload)
    surface = check.ReleaseSurface("site", "https://site/api/release", "site")
    assert check.check_surfaces([surface], "abc", 1, "a" * 64) == []
    failures = check.check_surfaces([surface], "abc", 1, "b" * 64)
    assert any("site asset manifest digest" in failure for failure in failures)


def test_local_cli_and_benchmark_artifacts_bind_to_same_release(tmp_path):
    cli = tmp_path / "cli.json"
    cli.write_text('{"service":"cli","package_version":"0.1.0","release_sha":"abc123"}')
    assert check.validate_artifact(cli, "abc123", "cli") == []

    report = tmp_path / "report.json"
    report.write_text(
        '{"release_sha":"abc123","dependency_profile":"tinyzkp-p3-goldilocks-v1",'
        '"verification_succeeded":true}'
    )
    assert check.validate_artifact(report, "abc123", "benchmark") == []
    report.write_text(
        '{"release_sha":"old","dependency_profile":"tinyzkp-p3-goldilocks-v1",'
        '"verification_succeeded":true}'
    )
    assert "benchmark release_sha must be 'abc123'; got 'old'" in check.validate_artifact(
        report, "abc123", "benchmark"
    )


def test_main_writes_owner_only_typed_identity_report(monkeypatch, tmp_path):
    live = {
        name: {
            "url": f"https://{name}.example/version",
            "service": name,
            "package_version": "0.1.0",
            "release_sha": "abc123",
        }
        for name in ("site", "api", "mcp")
    }
    monkeypatch.setattr(check, "collect_surfaces", lambda *_args: ([], live.copy()))
    cli = tmp_path / "cli.json"
    cli.write_text(
        '{"service":"cli","package_version":"0.1.0","release_sha":"abc123"}',
        encoding="utf-8",
    )
    output = tmp_path / "evidence" / "identity.json"

    assert check.main(
        [
            "--expected-sha",
            "abc123",
            "--cli-release-file",
            str(cli),
            "--output",
            str(output),
        ]
    ) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == 1
    assert report["release_sha"] == "abc123"
    assert set(report["surfaces"]) == {"api", "mcp", "site", "cli"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_typed_report_rejects_cli_package_version_skew(monkeypatch, tmp_path):
    live = {
        name: {
            "url": f"https://{name}.example/version",
            "service": name,
            "package_version": "0.1.0",
            "release_sha": "abc123",
        }
        for name in ("site", "api", "mcp")
    }
    monkeypatch.setattr(check, "collect_surfaces", lambda *_args: ([], live.copy()))
    cli = tmp_path / "cli.json"
    cli.write_text(
        '{"service":"cli","package_version":"0.2.0","release_sha":"abc123"}',
        encoding="utf-8",
    )

    assert check.main(
        [
            "--expected-sha",
            "abc123",
            "--cli-release-file",
            str(cli),
            "--output",
            str(tmp_path / "identity.json"),
        ]
    ) == 1
