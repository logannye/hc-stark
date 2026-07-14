import base64
import hashlib
import io
import json
import pathlib
import tarfile
from types import SimpleNamespace

import pytest

import cloudflare_toolchain_check as check
import materialize_cloudflare_toolchain as materialize


def _write_fixture(tmp_path: pathlib.Path):
    root = tmp_path / "repo"
    package_dir = root / "toolchains" / "cloudflare"
    release_dir = root / "release"
    package_dir.mkdir(parents=True)
    release_dir.mkdir()
    package = {
        "name": "tinyzkp-cloudflare-production-toolchain",
        "version": "1.0.0",
        "private": True,
        "description": "fixture",
        "engines": {"node": "24.18.0"},
        "devDependencies": {"wrangler": "4.85.0"},
    }
    lock = {
        "name": package["name"],
        "version": package["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": package["name"],
                "version": package["version"],
                "devDependencies": package["devDependencies"],
                "engines": package["engines"],
            },
            "node_modules/wrangler": {
                "version": "4.85.0",
                "resolved": "https://registry.npmjs.org/wrangler/-/wrangler-4.85.0.tgz",
                "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode("ascii"),
                "dev": True,
            },
        },
    }
    package_raw = (json.dumps(package, indent=2) + "\n").encode()
    lock_raw = (json.dumps(lock, indent=2) + "\n").encode()
    (package_dir / "package.json").write_bytes(package_raw)
    lock_path = package_dir / "package-lock.json"
    lock_path.write_bytes(lock_raw)

    runtime = tmp_path / "runtime"
    node = runtime / "node-v24.18.0-linux-x64" / "bin" / "node"
    install_root = runtime / "cloudflare-toolchain" / "node_modules"
    wrangler = install_root / "wrangler" / "bin" / "wrangler.js"
    wrangler.mkdir(parents=True)
    wrangler_file = wrangler
    # The final path component was created as a directory above; replace it with a file.
    wrangler_file.rmdir()
    wrangler_file.write_text("fixture wrangler\n", encoding="utf-8")
    installed_package = install_root / "wrangler" / "package.json"
    installed_package.write_text(
        json.dumps(
            {
                "version": "4.85.0",
                "bin": {"wrangler": "./bin/wrangler.js"},
            }
        ),
        encoding="utf-8",
    )
    node.parent.mkdir(parents=True)
    node.write_bytes(b"fixture-node")
    node.chmod(0o555)
    profile = {
        "schema_version": 1,
        "profile_id": "tinyzkp-cloudflare-production-v1",
        "release_status": "backend_recovery",
        "platform": {"os": "linux", "architecture": "x86_64"},
        "node": {
            "version": "v24.18.0",
            "production_path": str(node),
            "archive_url": "https://nodejs.org/dist/v24.18.0/node-v24.18.0-linux-x64.tar.xz",
            "archive_sha256": "a" * 64,
            "binary_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
            "bundled_npm_version": "11.16.0",
        },
        "wrangler": {
            "package": "wrangler",
            "version": "4.85.0",
            "production_install_root": str(install_root),
            "entrypoint": "wrangler/bin/wrangler.js",
        },
        "package_manifest_path": "toolchains/cloudflare/package.json",
        "package_lock_path": "toolchains/cloudflare/package-lock.json",
        "package_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
        "install_script_metadata_allowlist": [],
    }
    profile_path = release_dir / "cloudflare-production-toolchain-v1.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return root, profile_path, lock_path, node, install_root, wrangler_file


def _freeze(root: pathlib.Path):
    directories = []
    for current, directory_names, file_names in __import__("os").walk(root):
        current_path = pathlib.Path(current)
        directories.append(current_path)
        for name in file_names:
            (current_path / name).chmod(0o444)
    for directory in reversed(directories):
        directory.chmod(0o555)


def _thaw(root: pathlib.Path):
    if not root.exists():
        return
    for current, directory_names, file_names in __import__("os").walk(root):
        current_path = pathlib.Path(current)
        current_path.chmod(0o755)
        for name in file_names:
            (current_path / name).chmod(0o644)


def _seal_fixture_runtime(
    root: pathlib.Path,
    profile_path: pathlib.Path,
    node: pathlib.Path,
    install_root: pathlib.Path,
) -> pathlib.Path:
    _freeze(install_root)
    static_identity = check.validate_static(root=root, profile_path=profile_path)
    profile, _raw, _package, _lock = check.load_profile(
        root=root, profile_path=profile_path
    )
    installation_identity = check._installation_identity(install_root)
    document = check.materialization_document(
        static_identity=static_identity,
        node_sha256=hashlib.sha256(node.read_bytes()).hexdigest(),
        wrangler_version=profile["wrangler"]["version"],
        installation_identity=installation_identity,
    )
    evidence = install_root.parent / check.MATERIALIZATION_FILENAME
    evidence.write_bytes(check.canonical_materialization_bytes(document))
    evidence.chmod(0o444)
    install_root.parent.chmod(0o555)
    return evidence


def _thaw_fixture_runtime(install_root: pathlib.Path) -> None:
    install_root.parent.chmod(0o755)
    evidence = install_root.parent / check.MATERIALIZATION_FILENAME
    if evidence.exists():
        evidence.chmod(0o644)
    _thaw(install_root)


def _rewrite_lock(lock_path: pathlib.Path, profile_path: pathlib.Path, lock: dict):
    raw = (json.dumps(lock, indent=2) + "\n").encode()
    lock_path.write_bytes(raw)
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile["package_lock_sha256"] = hashlib.sha256(raw).hexdigest()
    profile_path.write_text(json.dumps(profile), encoding="utf-8")


def test_static_profile_binds_exact_package_lock(tmp_path):
    root, profile, lock, _node, _install, _entrypoint = _write_fixture(tmp_path)
    identity = check.validate_static(root=root, profile_path=profile)
    assert identity["node_version"] == "v24.18.0"
    assert identity["wrangler_version"] == "4.85.0"

    lock.write_bytes(lock.read_bytes() + b"\n")
    with pytest.raises(check.ToolchainError, match="SHA-256 differs"):
        check.validate_static(root=root, profile_path=profile)


def test_profile_rejects_duplicate_json_keys(tmp_path):
    root, profile, _lock, _node, _install, _entrypoint = _write_fixture(tmp_path)
    raw = profile.read_text(encoding="utf-8")
    profile.write_text(raw[:-1] + ',"profile_id":"duplicate"}', encoding="utf-8")
    with pytest.raises(check.ToolchainError, match="duplicates"):
        check.validate_static(root=root, profile_path=profile)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda record: record.update(resolved="file:///tmp/wrangler.tgz"),
            "canonical HTTPS",
        ),
        (
            lambda record: record.update(integrity="sha512-not-base64"),
            "integrity digest",
        ),
        (lambda record: record.update(hasInstallScript=True), "allowlist"),
    ],
)
def test_static_profile_semantically_rejects_unsafe_lock_entries(
    tmp_path, mutation, message
):
    root, profile, lock_path, _node, _install, _entrypoint = _write_fixture(tmp_path)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    mutation(lock["packages"]["node_modules/wrangler"])
    _rewrite_lock(lock_path, profile, lock)
    with pytest.raises(check.ToolchainError, match=message):
        check.validate_static(root=root, profile_path=profile)


def test_runtime_hashes_complete_read_only_install(tmp_path, monkeypatch):
    root, profile, _lock, node, install, entrypoint = _write_fixture(tmp_path)
    evidence = _seal_fixture_runtime(root, profile, node, install)
    monkeypatch.setattr(check, "_runtime_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(check, "_exact_version", lambda *_args, **_kwargs: None)
    try:
        identity = check.validate_runtime(
            node, entrypoint, root=root, profile_path=profile
        )
        assert identity["node_sha256"] == hashlib.sha256(b"fixture-node").hexdigest()
        assert identity["wrangler_file_count"] == 2
        assert len(identity["wrangler_tree_sha256"]) == 64
        assert identity["materialization_sha256"] == hashlib.sha256(
            evidence.read_bytes()
        ).hexdigest()
    finally:
        _thaw_fixture_runtime(install)


def test_runtime_rejects_mutation_symlink_and_wrong_node_bytes(tmp_path, monkeypatch):
    root, profile, _lock, node, install, entrypoint = _write_fixture(tmp_path)
    monkeypatch.setattr(check, "_runtime_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(check, "_exact_version", lambda *_args, **_kwargs: None)

    with pytest.raises(check.ToolchainError, match="read-only"):
        check.validate_runtime(node, entrypoint, root=root, profile_path=profile)

    _seal_fixture_runtime(root, profile, node, install)
    try:
        node.chmod(0o755)
        node.write_bytes(b"changed-node")
        node.chmod(0o555)
        with pytest.raises(check.ToolchainError, match="reviewed release artifact"):
            check.validate_runtime(node, entrypoint, root=root, profile_path=profile)
    finally:
        _thaw_fixture_runtime(install)


def test_runtime_rejects_symlink_inside_install(tmp_path, monkeypatch):
    root, profile, _lock, node, install, entrypoint = _write_fixture(tmp_path)
    (install / "alias.js").symlink_to(entrypoint)
    _freeze(install)
    monkeypatch.setattr(check, "_runtime_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(check, "_exact_version", lambda *_args, **_kwargs: None)
    try:
        with pytest.raises(check.ToolchainError, match="non-symlink regular file"):
            check.validate_runtime(node, entrypoint, root=root, profile_path=profile)
    finally:
        _thaw(install)


def test_runtime_requires_materialization_evidence(tmp_path, monkeypatch):
    root, profile, _lock, node, install, entrypoint = _write_fixture(tmp_path)
    _freeze(install)
    install.parent.chmod(0o555)
    monkeypatch.setattr(check, "_runtime_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(check, "_exact_version", lambda *_args, **_kwargs: None)
    try:
        with pytest.raises(check.ToolchainError, match="evidence is unavailable"):
            check.validate_runtime(node, entrypoint, root=root, profile_path=profile)
    finally:
        _thaw_fixture_runtime(install)


def test_runtime_rejects_mutated_or_noncanonical_materialization(
    tmp_path, monkeypatch
):
    root, profile, _lock, node, install, entrypoint = _write_fixture(tmp_path)
    evidence = _seal_fixture_runtime(root, profile, node, install)
    monkeypatch.setattr(check, "_runtime_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(check, "_exact_version", lambda *_args, **_kwargs: None)
    try:
        install.parent.chmod(0o755)
        evidence.chmod(0o644)
        document = json.loads(evidence.read_text(encoding="utf-8"))
        document["wrangler_total_bytes"] += 1
        evidence.write_bytes(check.canonical_materialization_bytes(document))
        evidence.chmod(0o444)
        install.parent.chmod(0o555)
        with pytest.raises(check.ToolchainError, match="differs from installed bytes"):
            check.validate_runtime(node, entrypoint, root=root, profile_path=profile)

        install.parent.chmod(0o755)
        evidence.chmod(0o644)
        document["wrangler_total_bytes"] -= 1
        evidence.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        evidence.chmod(0o444)
        install.parent.chmod(0o555)
        with pytest.raises(check.ToolchainError, match="not canonical JSON"):
            check.validate_runtime(node, entrypoint, root=root, profile_path=profile)
    finally:
        _thaw_fixture_runtime(install)


def test_materializer_rejects_uncontrolled_source_and_parent(tmp_path):
    source = tmp_path / "profile.json"
    source.write_text("{}", encoding="utf-8")
    source.chmod(0o666)
    with pytest.raises(check.ToolchainError, match="root-owned"):
        check.validate_root_materialization_source(source, label="fixture source")


def test_materializer_writes_canonical_read_only_evidence(tmp_path):
    destination = tmp_path / check.MATERIALIZATION_FILENAME
    static_identity = {
        "profile_id": check.PROFILE_ID,
        "profile_sha256": "1" * 64,
        "package_lock_sha256": "2" * 64,
    }
    installation_identity = {
        "wrangler_tree_sha256": "3" * 64,
        "wrangler_file_count": 7,
        "wrangler_total_bytes": 11,
    }
    materialize._write_materialization_evidence(
        destination,
        static_identity=static_identity,
        node_sha256="4" * 64,
        wrangler_version="4.85.0",
        installation_identity=installation_identity,
    )
    expected = check.materialization_document(
        static_identity=static_identity,
        node_sha256="4" * 64,
        wrangler_version="4.85.0",
        installation_identity=installation_identity,
    )
    assert destination.read_bytes() == check.canonical_materialization_bytes(expected)
    assert destination.stat().st_mode & 0o777 == 0o444


def test_version_probe_uses_sanitized_environment_and_exact_stdout(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="v24.18.0\n", stderr="")

    monkeypatch.setenv("NODE_OPTIONS", "--require=/attacker.js")
    monkeypatch.setattr(check.subprocess, "run", fake_run)
    check._exact_version(
        ("/reviewed/node", "--version"), label="Node", expected="v24.18.0"
    )
    assert captured["command"] == ("/reviewed/node", "--version")
    assert "NODE_OPTIONS" not in captured["environment"]
    assert captured["environment"]["HOME"] == "/nonexistent"

    with pytest.raises(check.ToolchainError, match="differs"):
        check._exact_version(
            ("/reviewed/node", "--version"), label="Node", expected="v24.18.1"
        )


def test_materializer_always_uses_pinned_npm_ci_without_scripts():
    node_root = pathlib.Path("/var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64")
    command = materialize.npm_ci_command(node_root)
    assert command[:2] == (
        str(node_root / "bin" / "node"),
        str(node_root / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"),
    )
    assert command[2:] == (
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )

    environment = materialize._subprocess_environment(pathlib.Path("/private/home"))
    assert environment["NPM_CONFIG_IGNORE_SCRIPTS"] == "true"
    assert environment["NPM_CONFIG_USERCONFIG"] == (
        "/private/home/.npmrc-user-disabled"
    )
    assert environment["NPM_CONFIG_GLOBALCONFIG"] == (
        "/private/home/.npmrc-global-disabled"
    )
    assert environment["NPM_CONFIG_USERCONFIG"] != environment["NPM_CONFIG_GLOBALCONFIG"]
    assert environment["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"
    assert "NODE_OPTIONS" not in environment


def test_materializer_rejects_archive_path_traversal(tmp_path):
    archive = tmp_path / "node.tar.xz"
    with tarfile.open(archive, mode="w:xz") as output:
        safe = tarfile.TarInfo("node-v24.18.0-linux-x64/bin/node")
        safe.size = 4
        output.addfile(safe, io.BytesIO(b"node"))
        npm_package = tarfile.TarInfo(
            "node-v24.18.0-linux-x64/lib/node_modules/npm/package.json"
        )
        npm_package.size = 2
        output.addfile(npm_package, io.BytesIO(b"{}"))
    materialize._validate_archive_layout(
        archive, expected_root="node-v24.18.0-linux-x64"
    )
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    materialize._extract_build_inputs(
        archive, extracted, expected_root="node-v24.18.0-linux-x64"
    )
    assert (extracted / "node-v24.18.0-linux-x64/bin/node").read_bytes() == b"node"

    unsafe = tmp_path / "unsafe.tar.xz"
    with tarfile.open(unsafe, mode="w:xz") as output:
        escaped = tarfile.TarInfo("../outside")
        escaped.size = 1
        output.addfile(escaped, io.BytesIO(b"x"))
    with pytest.raises(materialize.MaterializationError, match="unsafe path"):
        materialize._validate_archive_layout(
            unsafe, expected_root="node-v24.18.0-linux-x64"
        )


def test_materializer_seals_one_verified_archive_inode_before_tar_reads(tmp_path):
    reviewed = b"reviewed archive bytes"
    source = tmp_path / "caller-controlled.tar.xz"
    source.write_bytes(reviewed)
    sealed = tmp_path / "private" / "node.verified.tar.xz"
    sealed.parent.mkdir(mode=0o700)

    assert materialize._seal_verified_archive(
        source,
        sealed,
        expected_sha256=hashlib.sha256(reviewed).hexdigest(),
        max_bytes=1024,
    ) == sealed
    assert sealed.read_bytes() == reviewed
    assert sealed.stat().st_mode & 0o777 == 0o400

    # Later path replacement cannot affect the private inode consumed by both
    # archive validation and extraction.
    source.unlink()
    source.write_bytes(b"replacement npm code")
    assert sealed.read_bytes() == reviewed

    rejected = tmp_path / "private" / "rejected.tar.xz"
    with pytest.raises(materialize.MaterializationError, match="SHA-256"):
        materialize._seal_verified_archive(
            source,
            rejected,
            expected_sha256="0" * 64,
            max_bytes=1024,
        )
    assert not rejected.exists()

    source_code = pathlib.Path(materialize.__file__).read_text(encoding="utf-8")
    seal_position = source_code.index("sealed_archive = _seal_verified_archive(")
    validate_position = source_code.index("_validate_archive_layout(\n            sealed_archive")
    extract_position = source_code.index("_extract_build_inputs(\n            sealed_archive")
    assert seal_position < validate_position < extract_position


def test_materializer_rolls_back_only_same_created_directory(tmp_path):
    created = tmp_path / "created"
    created.mkdir()
    (created / "artifact").write_text("bytes", encoding="utf-8")
    _freeze(created)
    identity = materialize._directory_identity(created)
    materialize._rollback_created_directory(created, identity)
    assert not created.exists()

    replacement = tmp_path / "replacement"
    replacement.mkdir()
    stale_identity = (replacement.stat().st_dev, replacement.stat().st_ino + 1)
    with pytest.raises(materialize.MaterializationError, match="refusing to roll back"):
        materialize._rollback_created_directory(replacement, stale_identity)
