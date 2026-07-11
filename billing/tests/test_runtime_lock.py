import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))

import runtime_lock  # noqa: E402


def _wheel(
    name: str,
    version: str,
    *,
    tag: str = "py3-none-any",
    requires: tuple[str, ...] = (),
    extra_members: dict[str, bytes] | None = None,
) -> bytes:
    import io

    output = io.BytesIO()
    dist = name.replace("-", "_")
    prefix = f"{dist}-{version}.dist-info"
    metadata = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    metadata.extend(f"Requires-Dist: {requirement}" for requirement in requires)
    members = {
        f"{dist}/__init__.py": b"",
        f"{prefix}/METADATA": ("\n".join(metadata) + "\n").encode(),
        f"{prefix}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: TinyZKP test\n"
            f"Root-Is-Purelib: true\nTag: {tag}\n"
        ).encode(),
        f"{prefix}/RECORD": f"{prefix}/RECORD,,\n".encode(),
    }
    members.update(extra_members or {})
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, value in sorted(members.items()):
            archive.writestr(path, value)
    return output.getvalue()


def _write_bundle(
    tmp_path: Path,
    *,
    roots: tuple[str, ...] = ("demo==1.0",),
    runtime_wheels: tuple[tuple[str, str, bytes], ...] | None = None,
) -> dict[str, Path]:
    runtime_wheels = runtime_wheels or (("demo", "1.0", _wheel("demo", "1.0")),)
    requirements = tmp_path / "requirements.txt"
    lock = tmp_path / "requirements.lock"
    bootstrap_lock = tmp_path / "requirements-bootstrap.lock"
    profile = tmp_path / "runtime-profile.json"
    manifest = tmp_path / "wheelhouse-manifest.json"
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir(mode=0o700)

    requirements.write_text("\n".join(roots) + "\n", encoding="utf-8")
    artifacts = []
    lock_lines = []
    for name, version, raw in runtime_wheels:
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        (wheelhouse / filename).write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        lock_lines.append(f"{name}=={version} --hash=sha256:{digest}")
        artifacts.append(
            {
                "filename": filename,
                "name": runtime_lock.normalize_name(name),
                "role": "runtime",
                "sha256": digest,
                "size": len(raw),
                "version": version,
            }
        )
    lock.write_text("\n".join(lock_lines) + "\n", encoding="utf-8")

    bootstrap_raw = _wheel("pip", "25.3")
    bootstrap_filename = "pip-25.3-py3-none-any.whl"
    bootstrap_digest = hashlib.sha256(bootstrap_raw).hexdigest()
    (wheelhouse / bootstrap_filename).write_bytes(bootstrap_raw)
    bootstrap_lock.write_text(
        f"pip==25.3 --hash=sha256:{bootstrap_digest}\n", encoding="utf-8"
    )
    artifacts.insert(
        0,
        {
            "filename": bootstrap_filename,
            "name": "pip",
            "role": "bootstrap",
            "sha256": bootstrap_digest,
            "size": len(bootstrap_raw),
            "version": "25.3",
        },
    )

    profile_payload = {
        "accepted_wheel_tags": [
            "py3-none-any",
            "cp311-cp311-manylinux2014_x86_64",
            "cp311-cp311-manylinux_2_17_x86_64",
            "cp311-cp311-manylinux_2_28_x86_64",
        ],
        "bootstrap_lock_sha256": hashlib.sha256(bootstrap_lock.read_bytes()).hexdigest(),
        "download_target": {
            "abi": "cp311",
            "implementation": "cp",
            "platform": "manylinux2014_x86_64",
            "python_version": "3.11",
        },
        "kernel": "linux",
        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "machine": "x86_64",
        "operating_system": {"id": "debian", "version_id": "12"},
        "profile_id": "tinyzkp-billing-debian12-x86_64-cpython311-v1",
        "python": {
            "abi": "cp311",
            "executable": "/usr/bin/python3",
            "implementation": "cpython",
            "major": 3,
            "minor": 11,
        },
        "requirements_sha256": hashlib.sha256(requirements.read_bytes()).hexdigest(),
        "schema_version": 1,
    }
    profile.write_text(
        json.dumps(profile_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_payload = {
        "artifacts": artifacts,
        "bootstrap_lock_sha256": profile_payload["bootstrap_lock_sha256"],
        "lock_sha256": profile_payload["lock_sha256"],
        "profile_id": profile_payload["profile_id"],
        "profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
        "requirements_sha256": profile_payload["requirements_sha256"],
        "schema_version": 1,
    }
    manifest.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "bootstrap_lock": bootstrap_lock,
        "lock": lock,
        "manifest": manifest,
        "profile": profile,
        "requirements": requirements,
        "wheelhouse": wheelhouse,
    }


def _verify_bundle(bundle: dict[str, Path]):
    return runtime_lock.verify_wheelhouse(
        bundle["wheelhouse"],
        profile_path=bundle["profile"],
        requirements_path=bundle["requirements"],
        lock_path=bundle["lock"],
        bootstrap_lock_path=bundle["bootstrap_lock"],
        manifest_path=bundle["manifest"],
    )


def test_committed_metadata_is_hash_bound_and_complete():
    profile, artifacts, runtime = runtime_lock.verify_metadata()

    assert profile["profile_id"] == "tinyzkp-billing-debian12-x86_64-cpython311-v1"
    assert len(artifacts) == 23
    assert len(runtime) == 22
    assert {item.name for item in artifacts if item.role == "bootstrap"} == {"pip"}
    assert {"flask", "gunicorn", "psycopg", "pytest", "stripe"} <= set(runtime)


def test_host_profile_accepts_only_debian12_x86_64_cpython311():
    profile, _raw = runtime_lock.load_profile(runtime_lock.DEFAULT_PROFILE)
    valid = runtime_lock.HostFacts(
        kernel="linux",
        machine="x86_64",
        os_id="debian",
        os_version_id="12",
        implementation="cpython",
        major=3,
        minor=11,
        soabi="cpython-311-x86_64-linux-gnu",
        executable="/usr/bin/python3",
    )
    runtime_lock.verify_host_facts(profile, valid)

    for changed in (
        {"os_id": "ubuntu"},
        {"machine": "aarch64"},
        {"minor": 12},
        {"executable": "/usr/local/bin/python3"},
        {"soabi": "cpython-312-x86_64-linux-gnu"},
    ):
        values = {**valid.__dict__, **changed}
        with pytest.raises(runtime_lock.RuntimeLockError, match="host|SOABI"):
            runtime_lock.verify_host_facts(profile, runtime_lock.HostFacts(**values))


def test_os_release_loader_rejects_symlinks(tmp_path):
    actual = tmp_path / "os-release.actual"
    actual.write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")
    link = tmp_path / "os-release"
    link.symlink_to(actual)

    assert runtime_lock._parse_os_release(actual) == ("debian", "12")
    with pytest.raises(runtime_lock.RuntimeLockError, match="non-symlink"):
        runtime_lock._parse_os_release(link)


def test_wheelhouse_verifies_exact_hashes_metadata_tags_and_closure(tmp_path):
    bundle = _write_bundle(tmp_path)
    artifacts, bootstrap = _verify_bundle(bundle)

    assert len(artifacts) == 2
    assert bootstrap.name == "pip-25.3-py3-none-any.whl"


def test_active_dependency_and_extra_closure_is_exact(tmp_path):
    demo = _wheel(
        "demo",
        "1.0",
        requires=(
            'helper>=2; implementation_name != "pypy" and extra == "binary"',
            'windows-only; sys_platform == "win32"',
        ),
    )
    helper = _wheel("helper", "2.0")
    bundle = _write_bundle(
        tmp_path,
        roots=("demo[binary]==1.0",),
        runtime_wheels=(("demo", "1.0", demo), ("helper", "2.0", helper)),
    )

    _verify_bundle(bundle)


def test_lock_rejects_unreachable_distribution(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        runtime_wheels=(
            ("demo", "1.0", _wheel("demo", "1.0")),
            ("orphan", "1.0", _wheel("orphan", "1.0")),
        ),
    )

    with pytest.raises(runtime_lock.RuntimeLockError, match="outside the active"):
        _verify_bundle(bundle)


def test_lock_rejects_missing_active_dependency(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        runtime_wheels=(
            ("demo", "1.0", _wheel("demo", "1.0", requires=("missing>=1",))),
        ),
    )

    with pytest.raises(runtime_lock.RuntimeLockError, match="absent from lock"):
        _verify_bundle(bundle)


@pytest.mark.parametrize("mutation", ["corrupt", "extra", "symlink"])
def test_wheelhouse_rejects_file_set_and_identity_mutations(tmp_path, mutation):
    bundle = _write_bundle(tmp_path)
    demo = bundle["wheelhouse"] / "demo-1.0-py3-none-any.whl"
    if mutation == "corrupt":
        demo.write_bytes(demo.read_bytes() + b"corrupt")
    elif mutation == "extra":
        (bundle["wheelhouse"] / "extra.whl").write_bytes(b"extra")
    else:
        target = tmp_path / "outside.whl"
        target.write_bytes(demo.read_bytes())
        demo.unlink()
        demo.symlink_to(target)

    with pytest.raises(runtime_lock.RuntimeLockError):
        _verify_bundle(bundle)


@pytest.mark.parametrize(
    ("tag", "extra_members", "message"),
    [
        ("cp312-cp312-manylinux2014_x86_64", {}, "unauthorized compatibility"),
        ("py3-none-any", {"startup.pth": b"import attacker\n"}, "path configuration"),
        ("py3-none-any", {"../escape": b"bad"}, "unsafe member"),
    ],
)
def test_wheelhouse_rejects_unsafe_wheel_structure(tmp_path, tag, extra_members, message):
    raw = _wheel("demo", "1.0", tag=tag, extra_members=extra_members)
    bundle = _write_bundle(tmp_path, runtime_wheels=(("demo", "1.0", raw),))

    with pytest.raises(runtime_lock.RuntimeLockError, match=message):
        _verify_bundle(bundle)


def test_lock_and_manifest_tampering_fails_before_wheel_use(tmp_path):
    bundle = _write_bundle(tmp_path)
    bundle["requirements"].write_text("demo==1.1\n", encoding="utf-8")

    with pytest.raises(runtime_lock.RuntimeLockError, match="does not bind"):
        runtime_lock.verify_metadata(
            profile_path=bundle["profile"],
            requirements_path=bundle["requirements"],
            lock_path=bundle["lock"],
            bootstrap_lock_path=bundle["bootstrap_lock"],
            manifest_path=bundle["manifest"],
        )


def test_venv_relocation_rewrites_all_production_entry_points(tmp_path):
    staging = tmp_path / ".billing-venv.staging"
    destination = tmp_path / "billing-venv"
    bin_directory = staging / "bin"
    bin_directory.mkdir(parents=True)
    destination.mkdir()
    for name in ("flask", "gunicorn", "py.test", "pytest"):
        path = bin_directory / name
        path.write_text(f"#!{staging}/bin/python\nprint('ok')\n", encoding="utf-8")
        path.chmod(0o755)
    (staging / "pyvenv.cfg").write_text(
        f"command = /usr/bin/python3 -m venv {staging}\n", encoding="utf-8"
    )

    assert runtime_lock.relocate_venv(staging, destination) == 4
    for name in ("flask", "gunicorn", "py.test", "pytest"):
        assert (bin_directory / name).read_text().startswith(
            f"#!{destination}/bin/python\n"
        )
    assert str(staging) not in (staging / "pyvenv.cfg").read_text()


def test_venv_relocation_rejects_residual_activation_path(tmp_path):
    staging = tmp_path / ".billing-venv.staging"
    destination = tmp_path / "billing-venv"
    bin_directory = staging / "bin"
    bin_directory.mkdir(parents=True)
    for name in ("flask", "gunicorn", "py.test", "pytest"):
        (bin_directory / name).write_text(
            f"#!{staging}/bin/python\n", encoding="utf-8"
        )
    (bin_directory / "activate").write_text(f"VIRTUAL_ENV={staging}\n", encoding="utf-8")
    (staging / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")

    with pytest.raises(runtime_lock.RuntimeLockError, match="staging path remains"):
        runtime_lock.relocate_venv(staging, destination)


def test_unconfigured_host_provenance_is_an_enforced_blocker(monkeypatch):
    valid = runtime_lock.HostFacts(
        kernel="linux",
        machine="x86_64",
        os_id="debian",
        os_version_id="12",
        implementation="cpython",
        major=3,
        minor=11,
        soabi="cpython-311-x86_64-linux-gnu",
        executable="/usr/bin/python3",
    )
    monkeypatch.setattr(runtime_lock, "collect_host_facts", lambda: valid)

    with pytest.raises(runtime_lock.RuntimeLockError, match="provenance is unconfigured"):
        runtime_lock.verify_host_runtime_provenance(
            runtime_lock.DEFAULT_HOST_PROVENANCE
        )


def _host_entry(path: str, *, category: str = "stdlib") -> dict[str, object]:
    return {
        "category": category,
        "gid": 0,
        "mode": 0o444,
        "nlink": 1,
        "parent_chain_sha256": "a" * 64,
        "path": path,
        "sha256": "b" * 64,
        "size": 7,
        "uid": 0,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"uid": 1000}, "ownership"),
        ({"gid": 1000}, "ownership"),
        ({"nlink": 2}, "link count"),
        ({"mode": 0o664}, "mode"),
        ({"path": "/usr/lib/../tmp/runtime"}, "path"),
        ({"parent_chain_sha256": "short"}, "parent-chain"),
    ],
)
def test_host_provenance_entries_bind_secure_file_and_parent_identity(
    mutation, message
):
    entry = {**_host_entry("/usr/lib/python3.11/runtime.py"), **mutation}

    with pytest.raises(runtime_lock.RuntimeLockError, match=message):
        runtime_lock._parse_provenance_entries([entry])


def test_runtime_metadata_rejects_non_root_links_and_writable_parents():
    secure_file = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o555,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
    )
    runtime_lock._validate_runtime_file_metadata(Path("/runtime"), secure_file)

    for changed, message in (
        ({"st_uid": 1000}, "root-owned"),
        ({"st_gid": 1000}, "root-owned"),
        ({"st_nlink": 2}, "exactly one link"),
        ({"st_mode": stat.S_IFREG | 0o575}, "writable"),
    ):
        metadata = SimpleNamespace(**{**secure_file.__dict__, **changed})
        with pytest.raises(runtime_lock.RuntimeLockError, match=message):
            runtime_lock._validate_runtime_file_metadata(Path("/runtime"), metadata)

    unsafe_parent = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o775,
        st_uid=0,
        st_gid=0,
    )
    with pytest.raises(runtime_lock.RuntimeLockError, match="writable"):
        runtime_lock._validate_runtime_directory_metadata(Path("/var/lib"), unsafe_parent)


def test_runtime_inventory_identity_is_order_independent_and_profile_bound():
    first = _host_entry("/usr/bin/python3.11", category="interpreter")
    second = _host_entry("/usr/lib/python3.11/runtime.py")
    first_identity = runtime_lock.runtime_inventory_identity(
        [first, second],
        profile_id="tinyzkp-billing-debian12-x86_64-cpython311-v1",
        profile_sha256="c" * 64,
        scope="base_host_runtime",
    )
    second_identity = runtime_lock.runtime_inventory_identity(
        [second, first],
        profile_id="tinyzkp-billing-debian12-x86_64-cpython311-v1",
        profile_sha256="c" * 64,
        scope="base_host_runtime",
    )

    assert first_identity == second_identity
    assert first_identity.file_count == 2
    assert first_identity.byte_count == 14
    assert len(first_identity.identity_sha256) == 64
    changed_profile = runtime_lock.runtime_inventory_identity(
        [first, second],
        profile_id="tinyzkp-billing-debian12-x86_64-cpython311-v2",
        profile_sha256="c" * 64,
        scope="base_host_runtime",
    )
    assert changed_profile.identity_sha256 != first_identity.identity_sha256


def test_reviewed_host_provenance_requires_schema2_inventory_identity(
    tmp_path, monkeypatch
):
    profile, profile_raw = runtime_lock.load_profile(runtime_lock.DEFAULT_PROFILE)
    valid = runtime_lock.HostFacts(
        kernel="linux",
        machine="x86_64",
        os_id="debian",
        os_version_id="12",
        implementation="cpython",
        major=3,
        minor=11,
        soabi="cpython-311-x86_64-linux-gnu",
        executable="/usr/bin/python3",
    )
    base = Path("/usr/bin/python3.11")
    entry = _host_entry(str(base), category="interpreter")
    identity = runtime_lock.runtime_inventory_identity(
        [entry],
        profile_id=str(profile["profile_id"]),
        profile_sha256=hashlib.sha256(profile_raw).hexdigest(),
        scope="base_host_runtime",
    )
    provenance = tmp_path / "reviewed.json"
    payload = {
        "captured_at": "2026-07-10T00:00:00Z",
        "files": [entry],
        "inventory_sha256": identity.identity_sha256,
        "profile_id": profile["profile_id"],
        "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
        "reviewed_at": "2026-07-10T01:00:00Z",
        "reviewer": "independent-reviewer",
        "schema_version": 2,
        "status": "reviewed",
    }
    provenance.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(runtime_lock, "collect_host_facts", lambda: valid)
    monkeypatch.setattr(
        runtime_lock,
        "_base_runtime_paths",
        lambda: ({base}, {base: "interpreter"}),
    )
    monkeypatch.setattr(runtime_lock, "_runtime_entry", lambda path, category: entry)
    monkeypatch.setattr(
        runtime_lock, "collect_host_runtime_inventory", lambda: [entry]
    )

    assert (
        runtime_lock.verify_host_runtime_provenance(provenance).identity_sha256
        == identity.identity_sha256
    )

    payload["inventory_sha256"] = "0" * 64
    provenance.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(runtime_lock.RuntimeLockError, match="inventory identity"):
        runtime_lock.verify_host_runtime_provenance(provenance)


def test_production_inventory_includes_venv_node_and_their_elf_closure(monkeypatch):
    base = Path("/usr/bin/python3.11")
    venv_python = Path("/var/lib/tinyzkp-runtime/billing-venv/bin/python")
    venv_extension = Path(
        "/var/lib/tinyzkp-runtime/billing-venv/lib/python3.11/site-packages/demo.so"
    )
    node = runtime_lock.DEFAULT_NODE_BINARY
    shared = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        runtime_lock,
        "_base_runtime_paths",
        lambda: ({base}, {base: "interpreter"}),
    )
    monkeypatch.setattr(
        runtime_lock,
        "_secure_runtime_tree_paths",
        lambda root, category: (
            {venv_python, venv_extension},
            {venv_python: category, venv_extension: category},
        ),
    )

    def fake_dependencies(inputs):
        observed["ldd_inputs"] = set(inputs)
        return {shared}

    monkeypatch.setattr(runtime_lock, "_ldd_dependencies", fake_dependencies)

    def fake_entry(path, category):
        digest = (
            runtime_lock.DEFAULT_NODE_SHA256
            if path == node
            else hashlib.sha256(str(path).encode()).hexdigest()
        )
        return {
            **_host_entry(str(path), category=category),
            "sha256": digest,
        }

    monkeypatch.setattr(runtime_lock, "_runtime_entry", fake_entry)

    entries = runtime_lock.collect_production_runtime_inventory(
        runtime_lock.DEFAULT_VENV_ROOT, node
    )

    assert observed["ldd_inputs"] == {base, venv_python, venv_extension, node}
    by_path = {entry["path"]: entry for entry in entries}
    assert by_path[str(venv_extension)]["category"] == "venv_runtime"
    assert by_path[str(node)]["category"] == "node_binary"
    assert by_path[str(shared)]["category"] == "shared_library"

    with pytest.raises(runtime_lock.RuntimeLockError, match="Node binary differs"):
        runtime_lock.collect_production_runtime_inventory(
            runtime_lock.DEFAULT_VENV_ROOT,
            node,
            expected_node_sha256="0" * 64,
        )


def test_installer_is_offline_profile_bound_staged_and_rollback_safe():
    installer = (ROOT / "deploy/hetzner/install_billing_runtime.sh").read_text(
        encoding="utf-8"
    )

    assert "--os-release /usr/lib/os-release" in installer
    assert "verify-host-provenance" in installer
    assert installer.index("verify-host-provenance") < installer.index("bootstrap-path")
    assert "--production-permissions" in installer
    assert '-I -S -m venv --copies --without-pip "$STAGING"' in installer
    assert 'PYTHONPATH="$BOOTSTRAP_WHEEL"' in installer
    assert '"$STAGING/bin/python" -S -m pip install' in installer
    assert "--no-index --require-hashes --only-binary=:all:" in installer
    assert "--no-compile" in installer
    assert 'python3 -m venv --copies --without-pip "$VENV"' not in installer
    assert 'HAD_PREVIOUS=1\n    /bin/mv -- "$VENV" "$ROLLBACK"' in installer
    assert 'ACTIVATED=1\n/bin/mv -- "$STAGING" "$VENV"' in installer
    assert "cleanup_runtime_install" in installer
    assert 'cd "$RUNTIME_ROOT"' in installer
    assert 'for trusted_directory in / /opt "$REPO" "$REPO/billing"' in installer
    assert '"$(/usr/bin/stat -c \'%u\' "$trusted_directory")" != 0' in installer
    assert '"$(/usr/bin/stat -c \'%u\' "$required")" != 0' in installer
    assert '"$(/usr/bin/stat -c \'%h\' "$required")" != 1' in installer
    assert '"$REQUIREMENTS" \\\n    "$LOCK"' in installer
    assert 'exec 9<"$RUNTIME_ROOT"' in installer
    assert "/usr/bin/flock -n 9" in installer
    assert installer.index('for trusted_directory in / /opt') < installer.index(
        '/usr/bin/python3 -I -S "$RUNTIME_LOCK_TOOL" verify-host'
    )
    assert installer.index('/usr/bin/flock -n 9') < installer.index(
        'for transient in "$STAGING" "$ROLLBACK"'
    )
    assert installer.index('TRANSACTION_STARTED=1') < installer.index(
        '/bin/mkdir --mode=0700 "$STAGING"'
    )
    assert installer.index('/bin/mkdir --mode=0700 "$STAGING"') < installer.index(
        '-m venv --copies --without-pip "$STAGING"'
    )
    assert installer.index('"$STAGING/bin/python" -S -m pip install') < installer.index(
        '/bin/mv -- "$VENV" "$ROLLBACK"'
    )
    for activation in ("activate", "activate.csh", "activate.fish", "Activate.ps1"):
        assert f'"$STAGING/bin/{activation}"' in installer


def test_runtime_lock_uses_nofollow_fd_reads_and_in_memory_wheel_inspection():
    source = (ROOT / "billing/runtime_lock.py").read_text(encoding="utf-8")

    assert "os.O_NOFOLLOW" in source
    assert "opened.st_ino != metadata.st_ino" in source
    assert "zipfile.ZipFile(io.BytesIO(raw))" in source
    assert "wheel contains executable path configuration" in source
