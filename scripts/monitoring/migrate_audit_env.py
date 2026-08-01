#!/usr/bin/env python3
"""Atomically migrate one local TinyZKP audit.env without dropping other keys."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import tempfile


MODE_KEY = "TINYZKP_AUDIT_MODE"
LEGACY_MODES = {"containment", "production"}
VALID_MODES = {
    "canonical",
    "guard_prelaunch",
    "guard_withdrawn",
    "guard_transition",
    "guard_live",
    "guard_frozen",
}


class MigrationError(ValueError):
    pass


def migrate(path: Path) -> bool:
    if path.is_symlink():
        raise MigrationError("audit environment file cannot be a symlink")
    try:
        raw = path.read_bytes() if path.exists() else b""
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise MigrationError(f"cannot read audit environment: {error}") from error
    matches = list(
        re.finditer(rf"(?m)^[ \t]*{MODE_KEY}=([^\r\n]*)[ \t]*$", text)
    )
    if len(matches) > 1:
        raise MigrationError("audit environment contains duplicate mode entries")
    changed = False
    if matches:
        match = matches[0]
        mode = match.group(1).strip()
        if mode in LEGACY_MODES:
            replacement = f"{MODE_KEY}=canonical"
            text = text[: match.start()] + replacement + text[match.end() :]
            changed = True
        elif mode not in VALID_MODES:
            raise MigrationError(f"unsupported audit mode: {mode}")
    else:
        if text and not text.endswith(("\n", "\r")):
            text += "\n"
        text += f"{MODE_KEY}=canonical\n"
        changed = True
    if not changed and path.exists():
        os.chmod(path, 0o600)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".audit.env.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(text.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        migrate(args.path)
    except MigrationError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
