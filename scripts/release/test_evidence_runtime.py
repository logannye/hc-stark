import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

import pytest


MODULE_PATH = Path(__file__).with_name("evidence_runtime.py")
SPEC = importlib.util.spec_from_file_location("evidence_runtime_test", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def commit_repository(root: Path) -> str:
    (root / "Cargo.lock").write_text("lock\n", encoding="utf-8")
    (root / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.95.0"\n', encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        cwd=root,
        check=True,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def release_trust_contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "cosign": {},
        "external_signers": [],
        "gate_tools": {},
        "git": {},
        "stripe_cli": {},
        "toolchains": {},
    }


def test_release_trust_accepts_exact_v1_contract(monkeypatch, tmp_path):
    value = release_trust_contract()
    monkeypatch.setattr(MODULE, "committed_json", lambda *_arguments: value)

    assert MODULE.release_trust(tmp_path, "a" * 40) is value


def test_release_trust_rejects_unknown_or_missing_sections(monkeypatch, tmp_path):
    value = release_trust_contract()
    value["unexpected"] = {}
    monkeypatch.setattr(MODULE, "committed_json", lambda *_arguments: value)
    with pytest.raises(ValueError, match="malformed"):
        MODULE.release_trust(tmp_path, "a" * 40)

    value = release_trust_contract()
    del value["stripe_cli"]
    monkeypatch.setattr(MODULE, "committed_json", lambda *_arguments: value)
    with pytest.raises(ValueError, match="malformed"):
        MODULE.release_trust(tmp_path, "a" * 40)


def test_owner_ga_tool_policy_is_version_bound_without_runner_byte_hashes(
    monkeypatch, tmp_path
):
    value = json.loads(
        (MODULE_PATH.parents[2] / "release" / "release-trust-v1.json").read_text()
    )
    monkeypatch.setattr(MODULE, "release_trust", lambda *_arguments: value)

    policy = MODULE.owner_ga_tool_policy(tmp_path, "a" * 40)
    assert policy["gate_tools"]["policy"] == "owner_only_ga_v1"
    assert policy["toolchains"]["fuzz"]["cargo_fuzz_version"] == "cargo-fuzz 0.13.2"
    encoded = json.dumps(
        {"gate_tools": value["gate_tools"], "toolchains": value["toolchains"]},
        sort_keys=True,
    )
    for retired in ("cargo_sha256", "rustc_sha256", "cargo_fuzz_executables"):
        assert retired not in encoded

def test_private_reset_rejects_symlinked_parent_without_deletion(tmp_path):
    victim = tmp_path / "victim"
    target = victim / "child"
    target.mkdir(parents=True)
    marker = target / "marker"
    marker.write_text("safe", encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(victim, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        MODULE.reset_private_directory(tmp_path, alias, alias / "child")
    assert marker.read_text(encoding="utf-8") == "safe"


def test_private_output_rejects_hardlinks(tmp_path):
    evidence = MODULE.ensure_private_directory(tmp_path, tmp_path / "evidence")
    source = evidence / "source"
    source.write_bytes(b"safe")
    linked = evidence / "linked"
    os.link(source, linked)
    with pytest.raises(ValueError, match="unsafe"):
        MODULE.open_private_output(tmp_path, linked)
    assert source.read_bytes() == b"safe"


def test_private_output_readback_rejects_path_replacement(tmp_path):
    evidence = MODULE.ensure_private_directory(tmp_path, tmp_path / "evidence")
    output = evidence / "run.log"
    descriptor = MODULE.open_private_output(tmp_path, output)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(b"actual")
        identity = MODULE.private_file_identity(handle.fileno())
    output.unlink()
    output.write_bytes(b"replacement")
    with pytest.raises(ValueError, match="identity changed"):
        MODULE.read_private_output(tmp_path, output, identity)


def test_release_identity_requires_clean_exact_head_and_allows_only_evidence(
    tmp_path,
):
    release_sha = commit_repository(tmp_path)
    evidence = tmp_path / "raw-reports"
    evidence.mkdir()
    (evidence / "prior.json").write_text("{}\n", encoding="utf-8")
    identity = MODULE.release_source_identity(
        tmp_path,
        release_sha,
        evidence_root=evidence,
        require_explicit_sha=True,
    )
    assert identity["release_sha"] == release_sha
    assert identity["dependency_lock_sha256"] == hashlib.sha256(b"lock\n").hexdigest()
    assert len(str(identity["source_tree_sha256"])) == 64

    (tmp_path / "Cargo.lock").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ValueError, match="tracked changes"):
        MODULE.release_source_identity(
            tmp_path,
            release_sha,
            evidence_root=evidence,
            require_explicit_sha=True,
        )


def test_release_identity_rejects_untracked_source_and_mutable_revision(tmp_path):
    release_sha = commit_repository(tmp_path)
    evidence = tmp_path / "raw-reports"
    evidence.mkdir()
    (tmp_path / "untracked.rs").write_text("source", encoding="utf-8")
    with pytest.raises(ValueError, match="untracked source"):
        MODULE.release_source_identity(
            tmp_path,
            release_sha,
            evidence_root=evidence,
            require_explicit_sha=True,
        )
    (tmp_path / "untracked.rs").unlink()
    with pytest.raises(ValueError, match="exact canonical Git commit"):
        MODULE.release_source_identity(
            tmp_path,
            "HEAD",
            evidence_root=evidence,
            require_explicit_sha=True,
        )


def test_environment_is_minimal_fixed_and_drops_build_overrides():
    environment = MODULE.sanitized_environment(
        {
            "HOME": "/home/test",
            "PATH": "/bin",
            "RUSTFLAGS": "-C target-cpu=native",
            "RUSTC_WRAPPER": "/tmp/fake",
            "SECRET": "do-not-copy",
        }
    )
    assert environment["HOME"] == "/home/test"
    assert environment["PATH"] == "/bin"
    assert environment["CARGO_NET_OFFLINE"] == "true"
    assert "RUSTFLAGS" not in environment
    assert "RUSTC_WRAPPER" not in environment
    assert "SECRET" not in environment
    policy = MODULE.environment_policy()
    assert MODULE.canonical_json_sha256(policy) == MODULE.canonical_json_sha256(
        json.loads(json.dumps(policy))
    )


def test_runtime_executable_resolves_command_name_from_path(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    tools.mkdir()
    cosign = tools / "cosign"
    cosign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cosign.chmod(0o700)
    monkeypatch.setenv("PATH", str(tools))

    assert MODULE.resolve_runtime_executable(tmp_path, "cosign") == cosign.absolute()


def test_runtime_executable_roots_explicit_relative_path(tmp_path):
    assert MODULE.resolve_runtime_executable(tmp_path, "tools/cosign") == (
        tmp_path / "tools" / "cosign"
    ).absolute()


def test_runtime_executable_rejects_missing_command_name(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(ValueError, match="runtime executable is unavailable"):
        MODULE.resolve_runtime_executable(tmp_path, "cosign")


def test_subprocess_timeout_fails_closed_and_kills_process_group(tmp_path):
    with tempfile.TemporaryFile("w+b") as log:
        status, timed_out = MODULE.run_logged(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            environment=MODULE.sanitized_environment(os.environ),
            log=log,
            timeout_seconds=1,
        )
    assert timed_out is True
    assert status == 124


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pre-exec boundary is Linux-only")
def test_preexec_boundary_has_child_side_hard_deadline(tmp_path, monkeypatch):
    def stuck(_parent_inode):
        __import__("time").sleep(30)

    monkeypatch.setattr(MODULE, "_enter_verified_no_network_namespace", stuck)
    monkeypatch.setattr(MODULE, "CHILD_BOUNDARY_STARTUP_TIMEOUT_SECONDS", 1)
    writable = tmp_path / "writable"
    writable.mkdir()
    started = __import__("time").monotonic()
    with tempfile.TemporaryFile("w+b") as log:
        with pytest.raises((ValueError, subprocess.SubprocessError)):
            MODULE.run_logged(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                environment=MODULE.sanitized_environment(os.environ),
                log=log,
                timeout_seconds=10,
                write_boundary_paths=(writable,),
                require_network_namespace=True,
                network_boundary_result={},
            )
    assert __import__("time").monotonic() - started < 5


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Landlock is Linux-only")
def test_landlock_blocks_transient_modify_and_restore_probe(tmp_path):
    try:
        assert MODULE.landlock_abi_version() >= 3
    except ValueError as error:
        pytest.skip(str(error))
    source = tmp_path / "source"
    source.mkdir()
    committed = source / "script.py"
    committed.write_bytes(b"original\n")
    committed.chmod(0o400)
    writable = tmp_path / "writable"
    writable.mkdir()
    command = [
        "/bin/sh",
        "-c",
        (
            'set -e; chmod 600 "$0"; printf evil > "$0"; '
            'printf "original\\n" > "$0"; chmod 400 "$0"'
        ),
        str(committed),
    ]
    with tempfile.TemporaryFile("w+b") as log:
        status, timed_out = MODULE.run_logged(
            command,
            cwd=tmp_path,
            environment=MODULE.sanitized_environment(os.environ),
            log=log,
            timeout_seconds=10,
            write_boundary_paths=(writable,),
        )
    assert timed_out is False
    assert status != 0
    assert committed.read_bytes() == b"original\n"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Landlock is Linux-only")
def test_landlock_allows_only_the_exact_dev_null_sink(tmp_path):
    try:
        assert MODULE.landlock_abi_version() >= 3
    except ValueError as error:
        pytest.skip(str(error))
    writable = tmp_path / "writable"
    writable.mkdir()
    with tempfile.TemporaryFile("w+b") as log:
        status, timed_out = MODULE.run_logged(
            ["/bin/sh", "-c", "printf allowed >/dev/null"],
            cwd=tmp_path,
            environment=MODULE.sanitized_environment(os.environ),
            log=log,
            timeout_seconds=10,
            write_boundary_paths=(writable,),
        )
    assert timed_out is False
    assert status == 0

    with tempfile.TemporaryFile("w+b") as log:
        status, timed_out = MODULE.run_logged(
            ["/bin/sh", "-c", "printf denied >/dev/zero"],
            cwd=tmp_path,
            environment=MODULE.sanitized_environment(os.environ),
            log=log,
            timeout_seconds=10,
            write_boundary_paths=(writable,),
        )
    assert timed_out is False
    assert status != 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="descriptor launch is Linux-only")
def test_open_executable_descriptor_defeats_path_swap_and_restore(tmp_path):
    tool = tmp_path / "tool"
    shutil.copyfile("/bin/echo", tool)
    tool.chmod(0o700)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    descriptor, executable = MODULE.open_executable_descriptor(
        tool, expected_sha256=digest
    )
    original = tmp_path / "original"
    tool.rename(original)
    shutil.copyfile("/usr/bin/false", tool)
    tool.chmod(0o700)
    try:
        completed = subprocess.run(
            [executable, "anchored"],
            pass_fds=(descriptor,),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 0
    assert completed.stdout == "anchored\n"
