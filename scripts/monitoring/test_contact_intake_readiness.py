import json

import pytest

import contact_intake_readiness as readiness
import deploy_readiness_check as private_files


def test_secret_file_must_be_owner_only(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("a" * 32)
    secret.chmod(0o644)
    with pytest.raises(RuntimeError, match="mode 0600"):
        readiness.load_secret(secret)
    secret.chmod(0o600)
    assert readiness.load_secret(secret) == "a" * 32


def test_secret_file_rejects_symlink_directory_and_wrong_owner(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_text("a" * 32, encoding="utf-8")
    secret.chmod(0o600)
    symlink = tmp_path / "secret-link"
    symlink.symlink_to(secret)

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        readiness.load_secret(symlink)
    with pytest.raises(RuntimeError, match="regular non-symlink"):
        readiness.load_secret(tmp_path)

    actual_owner = secret.stat().st_uid
    monkeypatch.setattr(private_files.os, "geteuid", lambda: actual_owner + 1)
    with pytest.raises(RuntimeError, match="current-owner|current operator"):
        readiness.load_secret(secret)


def test_secret_file_rejects_oversize_control_and_noncanonical_mode(tmp_path):
    secret = tmp_path / "secret"
    secret.write_bytes(b"a" * 4097)
    secret.chmod(0o600)
    with pytest.raises(RuntimeError, match="exceeds 4096 bytes"):
        readiness.load_secret(secret)

    secret.write_bytes(b"a" * 20 + b"\n" + b"b" * 20)
    with pytest.raises(RuntimeError, match="invalid value"):
        readiness.load_secret(secret)

    secret.write_bytes(b"a" * 20 + b"\x00" + b"b" * 20)
    with pytest.raises(RuntimeError, match="invalid value"):
        readiness.load_secret(secret)

    secret.write_bytes(b"a" * 20 + b"\xff" + b"b" * 20)
    with pytest.raises(RuntimeError, match="must be UTF-8"):
        readiness.load_secret(secret)

    secret.write_bytes(b"a" * 32)
    secret.chmod(0o400)
    with pytest.raises(RuntimeError, match="mode 0600"):
        readiness.load_secret(secret)


def test_run_submits_and_cleans_no_pii_probe(monkeypatch):
    calls = []

    def fake_post(url, payload, headers):
        calls.append((url, payload, headers))
        if url.endswith("/api/contact"):
            return 200, {"application_id": "eval_probe"}
        return 200, {"ok": True, "stored": True, "cleaned": True}

    monkeypatch.setattr(readiness, "post_json", fake_post)
    monkeypatch.setattr(readiness.secrets, "token_hex", lambda _: "0123456789abcdef")
    result = readiness.run("https://tinyzkp.com", "https://webhook.tinyzkp.com", "secret")

    assert result["stored"] is True and result["cleaned"] is True
    submitted = calls[0][1]
    assert submitted["email"] == ""
    assert submitted["qualification"]["contact_method"] == "github"
    assert "@" not in json.dumps(submitted)
    assert calls[1][2] == {"X-Internal-Secret": "secret"}
