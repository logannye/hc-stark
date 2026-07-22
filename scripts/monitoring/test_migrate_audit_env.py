import os
from pathlib import Path

import pytest

import migrate_audit_env as migration


@pytest.mark.parametrize("legacy", ["containment", "production"])
def test_legacy_mode_is_migrated_without_losing_unrelated_entries(
    tmp_path: Path, legacy: str
) -> None:
    path = tmp_path / "audit.env"
    path.write_text(
        f"# retained\nUNRELATED=value\nTINYZKP_AUDIT_MODE={legacy}\nTOKEN=keep-me\n",
        encoding="utf-8",
    )
    assert migration.migrate(path) is True
    assert path.read_text(encoding="utf-8") == (
        "# retained\nUNRELATED=value\nTINYZKP_AUDIT_MODE=canonical\nTOKEN=keep-me\n"
    )
    assert os.stat(path).st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "mode",
    ["canonical", "guard_prelaunch", "guard_transition", "guard_live", "guard_frozen"],
)
def test_existing_guard_mode_is_preserved(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "audit.env"
    original = f"A=1\nTINYZKP_AUDIT_MODE={mode}\nB=2\n"
    path.write_text(original, encoding="utf-8")
    assert migration.migrate(path) is False
    assert path.read_text(encoding="utf-8") == original


def test_missing_mode_is_appended_and_duplicate_or_unknown_modes_fail(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.env"
    path.write_text("A=1", encoding="utf-8")
    assert migration.migrate(path) is True
    assert path.read_text(encoding="utf-8") == "A=1\nTINYZKP_AUDIT_MODE=canonical\n"

    path.write_text(
        "TINYZKP_AUDIT_MODE=canonical\nTINYZKP_AUDIT_MODE=guard_live\n",
        encoding="utf-8",
    )
    with pytest.raises(migration.MigrationError, match="duplicate"):
        migration.migrate(path)

    path.write_text("TINYZKP_AUDIT_MODE=surprise\n", encoding="utf-8")
    with pytest.raises(migration.MigrationError, match="unsupported"):
        migration.migrate(path)


def test_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("TINYZKP_AUDIT_MODE=containment\n", encoding="utf-8")
    link = tmp_path / "audit.env"
    link.symlink_to(target)
    with pytest.raises(migration.MigrationError, match="symlink"):
        migration.migrate(link)
