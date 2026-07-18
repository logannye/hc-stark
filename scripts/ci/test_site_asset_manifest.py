import site_asset_manifest as manifest


def test_manifest_is_complete_deterministic_and_covers_guard_surfaces():
    first = manifest.build(manifest.ROOT / "site")
    second = manifest.build(manifest.ROOT / "site")
    assert first == second
    assert first["complete"] is True
    assert len(first["sha256"]) == 64
    paths = {asset["path"] for asset in first["assets"]}
    assert {
        "/guard.html",
        "/compatibility.html",
        "/pricing.html",
        "/releases.html",
        "/support.html",
        "/commerce.json",
        "/.well-known/security.txt",
    } <= paths
