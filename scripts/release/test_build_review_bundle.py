import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import zipfile

import pytest


MODULE_PATH = Path(__file__).with_name("build_review_bundle.py")
SPEC = importlib.util.spec_from_file_location("build_review_bundle", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def commit_all(root: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            message,
        ],
        cwd=root,
        check=True,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def review_repository(tmp_path: Path, monkeypatch) -> str:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    required = (
        "release/backend-v1-gates.json",
        "scripts/ci/source_tree_identity.py",
        "scripts/ci/test_source_tree_identity.py",
    )
    for relative in required:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"committed {relative}\n", encoding="utf-8")
    engine = tmp_path / "src" / "engine.rs"
    engine.parent.mkdir()
    engine.write_text("pub const SOURCE: &str = \"committed\";\n", encoding="utf-8")
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "REQUIRED_FILES", required)
    monkeypatch.setattr(MODULE, "SOURCE_GLOBS", ("src/*.rs",))
    return commit_all(tmp_path, "review source")


def spdx(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentNamespace": "https://tinyzkp.com/spdx/test",
                "creationInfo": {"created": "2026-07-10T00:00:00Z"},
                "packages": [{"SPDXID": "SPDXRef-Package-test", "name": "test"}],
            }
        )
    )
    return path


def complete_optional(tmp_path: Path, sbom_path: Path, replacements=None):
    replacements = replacements or {}
    result = {}
    for category, roles in MODULE.REQUIRED_EVIDENCE_ROLES.items():
        values = []
        for role in sorted(roles):
            path = replacements.get((category, role))
            if path is None:
                path = sbom_path if category == "sbom" else tmp_path / f"{category}-{role}.json"
                if category != "sbom":
                    path.write_text("{}\n", encoding="utf-8")
            values.append((role, path))
        result[category] = values
    return result


def test_review_bundle_is_commit_bound_and_byte_deterministic(tmp_path, monkeypatch):
    release_sha = review_repository(tmp_path, monkeypatch)
    (tmp_path / "src" / "engine.rs").write_text(
        "pub const SOURCE: &str = \"dirty-worktree\";\n", encoding="utf-8"
    )
    sbom = spdx(tmp_path / "preliminary.spdx.json")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    optional = complete_optional(tmp_path, sbom)
    one = MODULE.build_bundle(output=first, release_sha=release_sha, optional=optional)
    two = MODULE.build_bundle(output=second, release_sha=release_sha, optional=optional)
    assert first.read_bytes() == second.read_bytes()
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.stat().st_mode) == 0o600
    assert one["bundle_sha256"] == two["bundle_sha256"]
    assert one["schema_version"] == 2
    assert one["release_sha"] == release_sha
    assert one["source_tree_sha256"] == MODULE.source_tree_identity.source_tree_sha256(
        tmp_path, release_sha
    )
    assert any(
        f"HC_RELEASE_SHA={release_sha} python3 scripts/release/run_fuzz_smoke.py"
        in command
        for command in one["reproduction_commands"]
    )
    assert any(
        f"HC_RELEASE_SHA={release_sha} scripts/release/run_crash_matrix_disk_full.sh"
        in command
        for command in one["reproduction_commands"]
    )
    assert sum("--require-fixed-host" in command for command in one["reproduction_commands"]) == 4
    assert sum(
        "fixed_host_preflight.py" in command
        for command in one["reproduction_commands"]
    ) == 1
    with zipfile.ZipFile(first) as archive:
        assert "review-manifest.json" in archive.namelist()
        assert "scripts/ci/source_tree_identity.py" in archive.namelist()
        assert "scripts/ci/test_source_tree_identity.py" in archive.namelist()
        assert archive.read("src/engine.rs") == (
            b'pub const SOURCE: &str = "committed";\n'
        )
        manifest = json.loads(archive.read("review-manifest.json"))
        for item in manifest["files"]:
            archived = archive.read(item["path"])
            assert item["archive_bytes"] == len(archived)
            assert item["archive_sha256"] == MODULE.hashlib.sha256(
                archived
            ).hexdigest()
    engine = next(item for item in manifest["files"] if item["path"] == "src/engine.rs")
    assert engine["origin"] == "git"
    assert engine["source_sha256"] == engine["archive_sha256"]
    assert engine["source_bytes"] == engine["archive_bytes"]
    assert engine["normalized"] is False
    assert engine["git_mode"] == "100644"
    verified, _ = MODULE.verify_bundle(first, root=tmp_path, release_sha=release_sha)
    assert verified["source_tree_sha256"] == one["source_tree_sha256"]

    empty = tmp_path / "empty.zip"
    empty_manifest = dict(manifest)
    empty_manifest["files"] = []
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("review-manifest.json", json.dumps(empty_manifest))
    with pytest.raises(ValueError, match="inventory is empty"):
        MODULE.verify_bundle(empty, root=tmp_path, release_sha=release_sha)


def test_review_source_inventory_includes_identity_implementation_and_tests():
    assert "scripts/ci/source_tree_identity.py" in MODULE.REQUIRED_FILES
    assert "scripts/ci/test_source_tree_identity.py" in MODULE.REQUIRED_FILES
    assert "scripts/release/run_crash_matrix_disk_full.sh" in MODULE.REQUIRED_FILES


def test_review_bundle_requires_a_real_non_symlink_spdx_inventory(tmp_path):
    try:
        MODULE.build_bundle(output=tmp_path / "missing.zip", release_sha="abc123", optional={})
    except ValueError as error:
        assert "categories are incomplete" in str(error)
    else:
        raise AssertionError("review bundle accepted a missing SBOM")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}")
    try:
        MODULE.build_bundle(
            output=tmp_path / "malformed.zip",
            release_sha="abc123",
            optional=complete_optional(tmp_path, malformed),
        )
    except ValueError as error:
        assert "SPDX" in str(error)
    else:
        raise AssertionError("review bundle accepted malformed SPDX")

    valid = tmp_path / "valid.json"
    valid.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentNamespace": "https://tinyzkp.com/spdx/test",
                "creationInfo": {"created": "2026-07-10T00:00:00Z"},
                "packages": [{"SPDXID": "SPDXRef-Package-test", "name": "test"}],
            }
        )
    )
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(valid)
    try:
        MODULE.build_bundle(
            output=tmp_path / "symlink.zip",
            release_sha="abc123",
            optional=complete_optional(tmp_path, symlink),
        )
    except ValueError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("review bundle accepted a symlinked SBOM")


def test_optional_paths_preserve_source_and_normalized_archive_digests(
    tmp_path, monkeypatch
):
    release_sha = review_repository(tmp_path, monkeypatch)
    sbom = spdx(tmp_path / "preliminary.spdx.json")
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "repo_path": str(MODULE.ROOT / "raw-reports" / "result.json"),
                "home_path": str(Path.home() / "private" / "result.log"),
            }
        )
    )
    log = tmp_path / "fuzz.log"
    log.write_text(
        f"repository={MODULE.ROOT}/target\nhome={Path.home()}/.cargo\n",
        encoding="utf-8",
    )
    output = tmp_path / "review.zip"
    MODULE.build_bundle(
        output=output,
        release_sha=release_sha,
        optional=complete_optional(
            tmp_path,
            sbom,
            {
                ("raw-reports", "one_million_fibonacci_candidate_report"): report,
                ("fuzz", "fuzz_smoke"): log,
            },
        ),
    )
    with zipfile.ZipFile(output) as archive:
        payload = archive.read(
            "evidence/raw-reports/one_million_fibonacci_candidate_report.json"
        )
        log_payload = archive.read("evidence/fuzz/fuzz_smoke.log")
        manifest = json.loads(archive.read("review-manifest.json"))
    assert str(Path.home()).encode() not in payload
    assert b"$REPO/raw-reports/result.json" in payload
    assert b"$HOME/private/result.log" in payload
    assert str(Path.home()).encode() not in log_payload
    assert b"repository=$REPO/target" in log_payload
    assert b"home=$HOME/.cargo" in log_payload
    report_entry = next(
        item
        for item in manifest["files"]
        if item["evidence_role"] == "one_million_fibonacci_candidate_report"
    )
    assert report_entry["origin"] == "artifact"
    assert report_entry["normalized"] is True
    assert report_entry["source_bytes"] == len(report.read_bytes())
    assert report_entry["source_sha256"] == MODULE.hashlib.sha256(
        report.read_bytes()
    ).hexdigest()
    assert report_entry["archive_bytes"] == len(payload)
    assert report_entry["archive_sha256"] == MODULE.hashlib.sha256(payload).hexdigest()
    assert report_entry["source_sha256"] != report_entry["archive_sha256"]


def test_review_bundle_rejects_mutable_release_revision(tmp_path, monkeypatch):
    review_repository(tmp_path, monkeypatch)
    sbom = spdx(tmp_path / "preliminary.spdx.json")
    with pytest.raises(ValueError, match="exact canonical Git commit"):
        MODULE.build_bundle(
            output=tmp_path / "review.zip",
            release_sha="HEAD",
            optional=complete_optional(tmp_path, sbom),
        )
