import importlib.util
import os
from pathlib import Path

import pytest


PATH = Path(__file__).with_name("activate_public_beta.py")
SPEC = importlib.util.spec_from_file_location("activate_public_beta", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_smoke_command_must_be_operator_owned_and_nonwritable(tmp_path: Path):
    command = tmp_path / "smoke"
    command.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(command, 0o755)
    assert MODULE.require_executable(command) == command.resolve()
    os.chmod(command, 0o777)
    with pytest.raises(ValueError, match="non-writable"):
        MODULE.require_executable(command)


def test_private_activation_evidence_is_owner_only(tmp_path: Path):
    output = tmp_path / "private" / "activation.json"
    MODULE.write_private(output, {"status": "passed"})
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="already exists"):
        MODULE.write_private(output, {"status": "passed"})
