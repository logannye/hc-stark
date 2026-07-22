import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

import source_tree_identity as identity


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def commit_all(root, message):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            message,
        ],
        cwd=root,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return git(root, "rev-parse", "HEAD")


def repository(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    (tmp_path / "release" / "evidence").mkdir(parents=True)
    (tmp_path / "release" / "backend-v1-gates.json").write_text("{}\n")
    configured = os.environ.get("TINYZKP_ANCHORED_GIT", "").strip()
    executable = Path(
        configured or shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
    ).resolve()
    (tmp_path / "release" / "release-trust-v1.json").write_text(
        json.dumps(
            {
                "git": {
                    "platforms": {
                        identity._runtime_platform(): {
                            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                            "version": subprocess.check_output(
                                [str(executable), "--version"], text=True
                            ).strip(),
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    source = commit_all(tmp_path, "source")
    return source


def test_evidence_commit_does_not_create_a_release_sha_self_reference(tmp_path):
    source = repository(tmp_path)
    digest = identity.source_tree_sha256(tmp_path, source)
    (tmp_path / "release" / "evidence" / "backend-v1-evidence.json").write_text(
        '{"source_release_sha":"' + source + '"}\n'
    )
    (tmp_path / "release" / "backend-v1-gates.json").write_text(
        '{"status":"candidate"}\n'
    )
    release = commit_all(tmp_path, "candidate evidence")

    release_digest, paths = identity.verify_evidence_only_transition(
        tmp_path, source, release, digest
    )
    assert release_digest == digest
    assert paths == [
        "release/backend-v1-gates.json",
        "release/evidence/backend-v1-evidence.json",
    ]


def test_non_evidence_source_change_is_rejected(tmp_path):
    source = repository(tmp_path)
    digest = identity.source_tree_sha256(tmp_path, source)
    (tmp_path / "src" / "lib.rs").write_text("pub fn value() -> u8 { 2 }\n")
    release = commit_all(tmp_path, "code changed")
    with pytest.raises(ValueError, match="outside evidence paths"):
        identity.verify_evidence_only_transition(tmp_path, source, release, digest)


def test_release_identity_requires_the_exact_immutable_commit(tmp_path):
    source = repository(tmp_path)
    assert identity.require_canonical_commit(tmp_path, source) == source
    for mutable_or_abbreviated in ("HEAD", source[:12]):
        with pytest.raises(ValueError, match="exact canonical Git commit"):
            identity.require_canonical_commit(tmp_path, mutable_or_abbreviated)


def test_evidence_transition_rejects_mutable_or_abbreviated_revisions(tmp_path):
    source = repository(tmp_path)
    digest = identity.source_tree_sha256(tmp_path, source)
    for source_revision, release_revision in (
        ("HEAD", source),
        (source[:12], source),
        (source, "HEAD"),
        (source, source[:12]),
    ):
        with pytest.raises(ValueError, match="exact canonical Git commit"):
            identity.verify_evidence_only_transition(
                tmp_path,
                source_revision,
                release_revision,
                digest,
            )


def test_source_tree_identity_hashes_blob_bytes_not_git_object_ids(tmp_path):
    source = repository(tmp_path)
    manifest = identity.source_tree_manifest(tmp_path, source)
    entry = next(item for item in manifest if item["path"] == "src/lib.rs")
    payload = (tmp_path / "src" / "lib.rs").read_bytes()
    assert entry["content_sha256"] == hashlib.sha256(payload).hexdigest()
    assert entry["bytes"] == len(payload)
    assert "object" not in entry


def test_source_identity_ignores_path_git_and_rejects_anchor_skew(tmp_path, monkeypatch):
    source = repository(tmp_path)
    fake_dir = tmp_path / "fake-bin"
    fake_dir.mkdir()
    fake = fake_dir / "git"
    fake.write_text("#!/bin/sh\nprintf 'forged\\n'\n", encoding="utf-8")
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(fake_dir))
    assert identity.require_canonical_commit(tmp_path, source) == source

    trust = tmp_path / "release" / "release-trust-v1.json"
    platform_key = identity._runtime_platform()
    trust.write_text(
        '{"git":{"platforms":{"'
        + platform_key
        + '":{"sha256":"'
        + "0" * 64
        + '","version":"git version forged"}}}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="committed anchor"):
        identity.require_canonical_commit(tmp_path, source)


@pytest.mark.parametrize(
    ("root_owner_uid", "effective_uid", "inherited"),
    [
        (1001, 1001, "1001"),
        (1001, 0, ""),
        (1001, 0, "0"),
        (1001, 0, "01001"),
        (1001, 0, "+1001"),
        (1001, 0, "-1001"),
        (1001, 0, "1001x"),
        (1001, 0, "1002"),
        (1001, 0, "10000000000"),
    ],
)
def test_sudo_uid_is_rejected_unless_root_repo_owner_matches_exactly(
    root_owner_uid, effective_uid, inherited
):
    assert (
        identity._canonical_sudo_uid(
            root_owner_uid,
            effective_uid=effective_uid,
            inherited=inherited,
        )
        is None
    )


def test_sudo_uid_is_accepted_for_root_and_exact_repo_owner():
    assert (
        identity._canonical_sudo_uid(
            1001,
            effective_uid=0,
            inherited="1001",
        )
        == "1001"
    )


def test_git_environment_copies_only_the_validated_sudo_uid(monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "_trusted_sudo_uid", lambda root: "1001")
    monkeypatch.setenv("SUDO_GID", "untrusted")
    monkeypatch.setenv("SUDO_COMMAND", "untrusted")

    environment = identity._git_environment(tmp_path)

    assert environment["SUDO_UID"] == "1001"
    assert "SUDO_GID" not in environment
    assert "SUDO_COMMAND" not in environment
