import json
import stat

import pytest

import contact_intake_readiness as readiness


def test_secret_file_must_be_owner_only(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("a" * 32)
    secret.chmod(0o644)
    with pytest.raises(RuntimeError, match="owner-only"):
        readiness.load_secret(secret)
    secret.chmod(0o600)
    assert readiness.load_secret(secret) == "a" * 32


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
