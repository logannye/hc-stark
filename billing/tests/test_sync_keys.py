"""Tests for billing/sync_keys.py."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenant_store
import sync_keys


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "tenant_store.sqlite")
    conn = tenant_store.open_db(db_path)
    yield conn
    conn.close()


class TestRegenerate:
    def test_writes_active_tenants_only(self, db, tmp_path):
        keys_file = str(tmp_path / "api_keys.txt")
        # Seed with known plaintext keys.
        with open(keys_file, "w") as f:
            f.write("t_1:key_active_123:standard\n")
            f.write("t_2:key_suspended_456:standard\n")

        tenant_store.create_tenant(db, "t_1", "a@b.com", "key_active_123")
        tenant_store.create_tenant(db, "t_2", "c@d.com", "key_suspended_456")
        tenant_store.suspend_tenant(db, "t_2")

        count = sync_keys.regenerate(db, api_keys_file=keys_file)
        assert count == 1

        with open(keys_file) as f:
            content = f.read()
        assert "t_1" in content
        assert "t_2" not in content

    def test_three_field_format(self, db, tmp_path):
        keys_file = str(tmp_path / "api_keys.txt")
        with open(keys_file, "w") as f:
            f.write("t_1:the_api_key:standard\n")

        tenant_store.create_tenant(db, "t_1", "a@b.com", "the_api_key", plan="pro")

        sync_keys.regenerate(db, api_keys_file=keys_file)

        with open(keys_file) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        assert len(lines) == 1
        parts = lines[0].split(":")
        assert len(parts) == 3
        assert parts[0] == "t_1"
        assert parts[1] == "the_api_key"
        assert parts[2] == "pro"  # Plan from DB, not from file.

    def test_active_keys_override(self, db, tmp_path):
        keys_file = str(tmp_path / "api_keys.txt")
        # Empty file — no existing keys.
        with open(keys_file, "w") as f:
            pass

        tenant_store.create_tenant(db, "t_1", "a@b.com", "any_key")

        # Provide the plaintext key explicitly.
        count = sync_keys.regenerate(
            db, api_keys_file=keys_file,
            active_keys={"t_1": ("new_rotated_key", "standard")},
        )
        assert count == 1

        with open(keys_file) as f:
            content = f.read()
        assert "new_rotated_key" in content

    def test_atomic_write_creates_file(self, db, tmp_path):
        keys_file = str(tmp_path / "subdir" / "api_keys.txt")
        os.makedirs(os.path.dirname(keys_file))

        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        # Seed keys file so the key is recoverable.
        with open(keys_file, "w") as f:
            f.write("t_1:key1:standard\n")

        sync_keys.regenerate(db, api_keys_file=keys_file)
        assert os.path.exists(keys_file)

    def test_file_locking(self, db, tmp_path):
        """Verify lock file is created during write."""
        keys_file = str(tmp_path / "api_keys.txt")
        with open(keys_file, "w") as f:
            f.write("t_1:key1:standard\n")

        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        sync_keys.regenerate(db, api_keys_file=keys_file)

        # Lock file should exist (created by fcntl.flock).
        assert os.path.exists(keys_file + ".lock")

    def test_empty_db_writes_header_only(self, db, tmp_path):
        keys_file = str(tmp_path / "api_keys.txt")
        count = sync_keys.regenerate(db, api_keys_file=keys_file)
        assert count == 0
        with open(keys_file) as f:
            lines = [l for l in f if not l.startswith("#")]
        # Only the header comment, no data lines.
        assert len(lines) == 0
