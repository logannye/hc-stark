import production_secret_parity_check as parity


def _private(path, content):
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_secret_parity_accepts_exact_private_values(tmp_path):
    host = _private(tmp_path / "host.env", "INTERNAL_SECRET=" + "a" * 32 + "\n")
    pages = _private(tmp_path / "pages.env", "INTERNAL_SECRET=" + "a" * 32 + "\n")

    report = parity.check_parity(host, pages)

    assert report["internal_secret_values_match"] is True
    assert "a" * 32 not in str(report)


def test_secret_parity_mismatch_fails_without_disclosing_values(tmp_path, capsys):
    host_secret = "host-secret-0123456789-ABCDEFGHIJ"
    pages_secret = "pages-secret-0123456789-ABCDEFG"
    host = _private(tmp_path / "host.env", f"INTERNAL_SECRET={host_secret}\n")
    pages = _private(tmp_path / "pages.env", f"INTERNAL_SECRET={pages_secret}\n")

    assert parity.main(
        [
            "--host-env-file",
            str(host),
            "--pages-bindings-file",
            str(pages),
        ]
    ) == 1
    output = capsys.readouterr()
    assert "do not match" in output.err
    assert host_secret not in output.err
    assert pages_secret not in output.err
    assert output.out == ""


def test_secret_parity_rejects_insecure_pages_file(tmp_path, capsys):
    host = _private(tmp_path / "host.env", "INTERNAL_SECRET=" + "a" * 32 + "\n")
    pages = _private(tmp_path / "pages.env", "INTERNAL_SECRET=" + "a" * 32 + "\n")
    pages.chmod(0o644)

    assert parity.main(
        [
            "--host-env-file",
            str(host),
            "--pages-bindings-file",
            str(pages),
        ]
    ) == 1
    assert "mode 0600" in capsys.readouterr().err
