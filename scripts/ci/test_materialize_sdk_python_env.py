from pathlib import Path
import os
import sys

import pytest

import materialize_sdk_python_env as materializer


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="sealed memfds are Linux-only")
def test_spawned_python_can_open_inherited_sealed_wheel_link(tmp_path):
    release_dir = materializer.ROOT / "scripts/release"
    sys.path.insert(0, str(release_dir))
    try:
        import evidence_runtime
    finally:
        sys.path.remove(str(release_dir))
    descriptor, _ = evidence_runtime.sealed_memfd_from_bytes("wheel", b"sealed-wheel")
    link = tmp_path / "example.whl"
    link.symlink_to(f"/proc/self/fd/{descriptor}")
    try:
        observed = materializer._capture(
            [sys.executable, "-I", "-c", "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())", str(link)],
            cwd=tmp_path,
            environment={"PATH": "/usr/bin:/bin"},
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)
    assert observed == b"sealed-wheel"


def test_work_directory_must_be_empty_runner_owned_and_not_symlinked(tmp_path):
    work = tmp_path / "work"
    assert materializer._private_empty_directory(work) == work
    (work / "state").write_text("not empty", encoding="utf-8")
    with pytest.raises(ValueError, match="empty and runner-owned"):
        materializer._private_empty_directory(work)

    link = tmp_path / "link"
    link.symlink_to(work, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe ancestry"):
        materializer._private_empty_directory(link)


def test_materializer_has_no_index_or_arbitrary_requirement_interface():
    source = Path(materializer.__file__).read_text(encoding="utf-8")
    assert '"--no-index"' in source
    assert '"--require-hashes"' in source
    assert '"--only-binary=:all:"' in source
    assert "PIP_CONFIG_FILE" in source
    assert "PIP_INDEX_URL" not in source
    assert "add_argument(\"--requirements\"" not in source
    assert "add_argument(\"--index" not in source


def test_sdk_gate_scripts_do_not_resolve_unanchored_coreutils():
    root = materializer.ROOT
    gate = (root / "scripts/ci/sdk_contract_gate.sh").read_text(encoding="utf-8")
    wasm = (root / "crates/hc-wasm/build.sh").read_text(encoding="utf-8")
    for forbidden in (
        "$(dirname",
        "mktemp",
        "mkdir ",
        "rm -rf",
        "cmp ",
        "diff ",
        "cp -R",
        "cat >",
        "install -m",
    ):
        assert forbidden not in gate
        assert forbidden not in wasm
    assert '"$TINYZKP_BASH" crates/hc-wasm/build.sh' in gate
