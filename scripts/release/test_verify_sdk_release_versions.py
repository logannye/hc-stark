import json
from pathlib import Path

import verify_sdk_release_versions as versions


def write_packages(root: Path, python: str, rust: str, typescript: str) -> None:
    (root / "clients/python").mkdir(parents=True, exist_ok=True)
    (root / "clients/rust").mkdir(parents=True, exist_ok=True)
    (root / "clients/typescript").mkdir(parents=True, exist_ok=True)
    (root / "clients/python/pyproject.toml").write_text(
        f'[project]\nversion = "{python}"\n', encoding="utf-8"
    )
    (root / "clients/rust/Cargo.toml").write_text(
        f'[package]\nversion = "{rust}"\n', encoding="utf-8"
    )
    (root / "clients/typescript/package.json").write_text(
        json.dumps({"version": typescript}), encoding="utf-8"
    )


def test_release_and_dev_versions_match_cross_language(tmp_path):
    write_packages(tmp_path, "1.2.3", "1.2.3", "1.2.3")
    assert versions.failures("v1.2.3", root=tmp_path) == []
    write_packages(tmp_path, "1.2.3.dev4", "1.2.3-dev.4", "1.2.3-dev.4")
    assert versions.failures("v1.2.3-dev.4", root=tmp_path) == []


def test_mismatch_and_unsupported_tag_fail_closed(tmp_path):
    write_packages(tmp_path, "1.2.3", "1.2.4", "1.2.3")
    assert "Rust package version" in versions.failures("v1.2.3", root=tmp_path)[0]
    assert versions.failures("1.2.3", root=tmp_path)
    assert versions.failures("v1.2.3-preview.1", root=tmp_path)
