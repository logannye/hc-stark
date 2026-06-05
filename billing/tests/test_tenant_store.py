"""Tests for billing/tenant_store.py."""

import json
import os
import sqlite3
import tempfile

import pytest

# Add billing/ to sys.path so we can import tenant_store directly.
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenant_store


@pytest.fixture
def db(tmp_path):
    """Create a fresh tenant_store database in a temp directory."""
    db_path = str(tmp_path / "tenant_store.sqlite")
    conn = tenant_store.open_db(db_path)
    yield conn
    conn.close()


class TestCreateTenant:
    def test_create_and_get(self, db):
        tenant_store.create_tenant(
            db,
            tenant_id="t_abc",
            email="user@example.com",
            api_key="tzk_testkey123",
            stripe_customer_id="cus_123",
            stripe_subscription_id="sub_456",
            stripe_subscription_item_id="si_789",
            plan="standard",
        )
        t = tenant_store.get_tenant(db, "t_abc")
        assert t is not None
        assert t["tenant_id"] == "t_abc"
        assert t["email"] == "user@example.com"
        assert t["status"] == "active"
        assert t["plan"] == "standard"
        assert t["stripe_customer_id"] == "cus_123"
        assert t["stripe_subscription_id"] == "sub_456"
        assert t["stripe_subscription_item_id"] == "si_789"
        # Key should be hashed, not stored in plaintext.
        assert t["api_key_hash"] != "tzk_testkey123"
        assert t["api_key_prefix"] == "tzk_test"

    def test_duplicate_tenant_id_raises(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        with pytest.raises(sqlite3.IntegrityError):
            tenant_store.create_tenant(db, "t_1", "c@d.com", "key2")

    def test_duplicate_subscription_id_raises(self, db):
        tenant_store.create_tenant(
            db, "t_1", "a@b.com", "key1",
            stripe_subscription_id="sub_same",
        )
        with pytest.raises(sqlite3.IntegrityError):
            tenant_store.create_tenant(
                db, "t_2", "c@d.com", "key2",
                stripe_subscription_id="sub_same",
            )

    def test_get_nonexistent_returns_none(self, db):
        assert tenant_store.get_tenant(db, "t_nonexistent") is None


class TestGetBySubscriptionId:
    def test_found(self, db):
        tenant_store.create_tenant(
            db, "t_1", "a@b.com", "key1",
            stripe_subscription_id="sub_100",
        )
        t = tenant_store.get_by_subscription_id(db, "sub_100")
        assert t is not None
        assert t["tenant_id"] == "t_1"

    def test_not_found(self, db):
        assert tenant_store.get_by_subscription_id(db, "sub_missing") is None


class TestStatusUpdates:
    def test_suspend(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.suspend_tenant(db, "t_1")
        t = tenant_store.get_tenant(db, "t_1")
        assert t["status"] == "suspended"

    def test_activate(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.suspend_tenant(db, "t_1")
        tenant_store.activate_tenant(db, "t_1")
        t = tenant_store.get_tenant(db, "t_1")
        assert t["status"] == "active"

    def test_set_status_updates_timestamp(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        t_before = tenant_store.get_tenant(db, "t_1")
        import time; time.sleep(0.01)
        tenant_store.suspend_tenant(db, "t_1")
        t_after = tenant_store.get_tenant(db, "t_1")
        assert t_after["updated_at_ms"] >= t_before["updated_at_ms"]


class TestSetPlan:
    def test_set_plan(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.set_plan(db, "t_1", "pro")
        t = tenant_store.get_tenant(db, "t_1")
        assert t["plan"] == "pro"


class TestUpdateApiKey:
    def test_rotate_key(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "old_key_1234567890")
        old_hash = tenant_store.get_tenant(db, "t_1")["api_key_hash"]
        tenant_store.update_api_key(db, "t_1", "new_key_abcdefghij")
        t = tenant_store.get_tenant(db, "t_1")
        assert t["api_key_hash"] != old_hash
        assert t["api_key_prefix"] == "new_key_"


class TestListTenants:
    def test_list_all(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.create_tenant(db, "t_2", "c@d.com", "key2")
        result = tenant_store.list_tenants(db)
        assert len(result) == 2

    def test_list_by_status(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.create_tenant(db, "t_2", "c@d.com", "key2")
        tenant_store.suspend_tenant(db, "t_2")
        active = tenant_store.list_tenants(db, status="active")
        suspended = tenant_store.list_tenants(db, status="suspended")
        assert len(active) == 1
        assert len(suspended) == 1
        assert active[0]["tenant_id"] == "t_1"
        assert suspended[0]["tenant_id"] == "t_2"


class TestDeleteTenant:
    def test_delete_existing(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        deleted = tenant_store.delete_tenant(db, "t_1")
        assert deleted == 1
        assert tenant_store.get_tenant(db, "t_1") is None

    def test_delete_missing_returns_zero(self, db):
        assert tenant_store.delete_tenant(db, "t_nonexistent") == 0

    def test_delete_cleans_up_magic_links(self, db):
        tenant_store.create_tenant(db, "t_1", "a@b.com", "key1")
        tenant_store.create_magic_link(db, "hash_a", "t_1")
        tenant_store.create_magic_link(db, "hash_b", "t_1")
        tenant_store.delete_tenant(db, "t_1")
        # Both magic links should be gone with the tenant.
        assert tenant_store.verify_magic_link(db, "hash_a") is None
        assert tenant_store.verify_magic_link(db, "hash_b") is None


class TestEventIdempotency:
    def test_event_not_processed_initially(self, db):
        assert not tenant_store.is_event_processed(db, "evt_123")

    def test_mark_and_check(self, db):
        tenant_store.mark_event_processed(db, "evt_123")
        assert tenant_store.is_event_processed(db, "evt_123")

    def test_mark_twice_is_safe(self, db):
        tenant_store.mark_event_processed(db, "evt_123")
        tenant_store.mark_event_processed(db, "evt_123")
        assert tenant_store.is_event_processed(db, "evt_123")


class TestPartialUniqueIndexFreeTenant:
    """G8 race-safety: at most one free-plan tenant per email (DB-layer guard)."""

    def test_two_free_tenants_same_email_raises(self, db):
        """Second free signup for the same email must raise IntegrityError."""
        tenant_store.create_tenant(db, "t_free_1", "dup@example.com", "key_free_1", plan="free")
        with pytest.raises(sqlite3.IntegrityError):
            tenant_store.create_tenant(db, "t_free_2", "dup@example.com", "key_free_2", plan="free")

    def test_free_and_paid_same_email_both_succeed(self, db):
        """A free tenant and a paid tenant for the same email must BOTH succeed.

        This covers the free→paid upgrade path: a new paid tenant is created
        for the same email without touching or replacing the free row.
        """
        tenant_store.create_tenant(db, "t_free_1", "shared@example.com", "key_free_1", plan="free")
        # developer is a paid plan — the partial index WHERE plan='free' must
        # not block this insert.
        tenant_store.create_tenant(db, "t_dev_1", "shared@example.com", "key_dev_1", plan="developer")

        free_row = tenant_store.get_tenant(db, "t_free_1")
        paid_row = tenant_store.get_tenant(db, "t_dev_1")
        assert free_row is not None
        assert paid_row is not None
        assert free_row["plan"] == "free"
        assert paid_row["plan"] == "developer"


class TestMigrateFromTenantMap:
    def test_migrate(self, db, tmp_path):
        tenant_map = {
            "t_old": {
                "email": "old@example.com",
                "subscription_item_id": "si_old",
            }
        }
        map_path = str(tmp_path / "tenant_map.json")
        with open(map_path, "w") as f:
            json.dump(tenant_map, f)

        keys_path = str(tmp_path / "api_keys.txt")
        with open(keys_path, "w") as f:
            f.write("t_old:old_api_key_12345678\n")

        count = tenant_store.migrate_from_tenant_map(db, map_path, keys_path)
        assert count == 1
        t = tenant_store.get_tenant(db, "t_old")
        assert t is not None
        assert t["email"] == "old@example.com"

    def test_migrate_skips_existing(self, db, tmp_path):
        tenant_store.create_tenant(db, "t_old", "existing@b.com", "key1")

        tenant_map = {"t_old": {"email": "new@b.com"}}
        map_path = str(tmp_path / "tenant_map.json")
        with open(map_path, "w") as f:
            json.dump(tenant_map, f)

        keys_path = str(tmp_path / "api_keys.txt")
        with open(keys_path, "w") as f:
            f.write("t_old:some_key_12345678\n")

        count = tenant_store.migrate_from_tenant_map(db, map_path, keys_path)
        assert count == 0
        # Original email preserved.
        t = tenant_store.get_tenant(db, "t_old")
        assert t["email"] == "existing@b.com"

    def test_migrate_missing_file_returns_zero(self, db):
        count = tenant_store.migrate_from_tenant_map(db, "/nonexistent/path.json", "/nonexistent/keys.txt")
        assert count == 0
