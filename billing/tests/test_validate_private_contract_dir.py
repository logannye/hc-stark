import os

import validate_private_contract_dir as validator


def test_private_contract_tree_accepts_only_owner_files(tmp_path):
    tmp_path.chmod(0o700)
    document = tmp_path / "contract.pdf"
    document.write_bytes(b"contract")
    document.chmod(0o600)
    assert validator.validate(tmp_path) == []

    document.chmod(0o644)
    assert validator.validate(tmp_path) == ["contract directory is not owner-only"]


def test_private_contract_tree_rejects_symlinks_and_special_files(tmp_path):
    tmp_path.chmod(0o700)
    target = tmp_path / "target"
    target.write_bytes(b"contract")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    assert "contract directory contains a symlink" in validator.validate(tmp_path)

    link.unlink()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, mode=0o600)
    assert "contract directory contains a special file" in validator.validate(tmp_path)
