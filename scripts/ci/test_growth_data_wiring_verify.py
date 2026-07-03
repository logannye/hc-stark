import os
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "billing"))
import tenant_store  # noqa: E402


def create_usage_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    with conn:
        conn.execute(
            """CREATE TABLE usage_log (
              tenant_id TEXT NOT NULL,
              job_id TEXT UNIQUE,
              trace_length INTEGER NOT NULL,
              workload_id TEXT,
              duration_ms INTEGER,
              completed_at_ms INTEGER NOT NULL,
              billed INTEGER DEFAULT 0
            )"""
        )
    conn.close()


def growth_env(tmp_path: Path, tenant_db: Path, usage_db: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "TINYZKP_REPO": str(ROOT),
            "TINYZKP_PYTHON": sys.executable,
            "TINYZKP_ENV_FILE": str(tmp_path / "missing.env"),
            "HC_TENANT_STORE_PATH": str(tenant_db),
            "HC_USAGE_DB_PATH": str(usage_db),
            "TINYZKP_GROWTH_SNAPSHOT_DIR": str(tmp_path / "growth_snapshots"),
            "TINYZKP_GROWTH_EXPERIMENT_LEDGER": str(tmp_path / "growth_experiment_ledger.json"),
        }
    )
    return env


def test_daily_growth_cron_fails_when_production_stores_are_missing(tmp_path):
    env = growth_env(tmp_path, tmp_path / "missing-tenant.sqlite", tmp_path / "missing-usage.sqlite")

    result = subprocess.run(
        ["bash", "scripts/monitoring/daily_growth_decision_cron.sh"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert "production growth data store missing or empty: tenant store" in result.stderr


def test_verify_growth_data_wiring_runs_cron_and_writes_snapshot(tmp_path):
    tenant_db = tmp_path / "tenant_store.sqlite"
    usage_db = tmp_path / "usage.sqlite"
    conn = tenant_store.open_db(str(tenant_db))
    conn.close()
    create_usage_db(usage_db)

    result = subprocess.run(
        ["bash", "scripts/monitoring/verify_growth_data_wiring.sh"],
        cwd=ROOT,
        env=growth_env(tmp_path, tenant_db, usage_db),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "growth_data_wiring=ok" in result.stdout
    assert (tmp_path / "growth_experiment_ledger.json").is_file()
    assert list((tmp_path / "growth_snapshots").glob("*.json"))
