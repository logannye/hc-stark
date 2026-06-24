"""Tests for billing/tenant_pg_tools.py."""

import hashlib
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenant_pg_tools
import tenant_store


def _seed(path):
    conn = tenant_store.open_db(str(path))
    tenant_store.create_tenant(conn, "t_free", "free@example.com", "tzk_free", plan="free")
    tenant_store.create_tenant(
        conn,
        "t_dev",
        "dev@example.com",
        "tzk_dev",
        stripe_customer_id="cus_123",
        stripe_subscription_id="sub_123",
        stripe_subscription_item_id="si_123",
        plan="developer",
    )
    tenant_store.suspend_tenant(conn, "t_dev")
    tenant_store.mark_event_processed(conn, "evt_123")
    tenant_store.create_magic_link(conn, hashlib.sha256(b"magic").hexdigest(), "t_free")
    tenant_store.create_session(conn, hashlib.sha256(b"session").hexdigest(), "t_free")
    conn.close()


def test_sqlite_summary_counts_tenant_store_tables(tmp_path):
    db_path = tmp_path / "tenant_store.sqlite"
    _seed(db_path)

    summary = tenant_pg_tools.sqlite_summary(str(db_path))

    assert summary["tenants"]["count"] == 2
    assert summary["tenants"]["active_count"] == 1
    assert summary["tenants"]["suspended_count"] == 1
    assert summary["tenants"]["free_count"] == 1
    assert summary["tenants"]["paid_count"] == 1
    assert summary["processed_events"]["count"] == 1
    assert summary["magic_links"]["count"] == 1
    assert summary["magic_links"]["unused_count"] == 1
    assert summary["sessions"]["count"] == 1


def test_compare_summaries_reports_deltas():
    sqlite_data = {
        "tenants": {"count": 2, "active_count": 1},
    }
    pg_data = {
        "tenants": {"count": 1, "active_count": 1},
    }

    result = tenant_pg_tools.compare_summaries(sqlite_data, pg_data)

    assert result["ok"] is False
    assert result["tables"]["tenants"]["count"]["delta"] == -1
    assert result["tables"]["tenants"]["active_count"]["delta"] == 0


def test_backfill_script_is_idempotent_and_updates_mutable_tenant_fields(tmp_path):
    db_path = tmp_path / "tenant_store.sqlite"
    _seed(db_path)

    script, counts = tenant_pg_tools.build_backfill_script(str(db_path))

    assert counts["tenants"] == 2
    assert counts["processed_events"] == 1
    assert counts["magic_links"] == 1
    assert counts["sessions"] == 1
    assert "COPY tenants_import" in script
    assert "ON CONFLICT (tenant_id) DO UPDATE SET" in script
    assert "api_key_hash=EXCLUDED.api_key_hash" in script
    assert "status=EXCLUDED.status" in script
    assert "ON CONFLICT (event_id) DO NOTHING" in script
    assert "ON CONFLICT (token_hash) DO UPDATE SET" in script


def test_schema_contains_auth_indexes():
    assert "CREATE TABLE IF NOT EXISTS tenants" in tenant_pg_tools.SCHEMA_SQL
    assert "idx_tenants_active_key" in tenant_pg_tools.SCHEMA_SQL
    assert "idx_one_free_tenant_per_email" in tenant_pg_tools.SCHEMA_SQL
