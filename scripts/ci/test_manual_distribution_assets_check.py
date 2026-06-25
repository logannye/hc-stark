import importlib.util
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "manual_distribution_assets_check.py"
spec = importlib.util.spec_from_file_location("manual_distribution_assets_check", MODULE_PATH)
asset_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = asset_check
spec.loader.exec_module(asset_check)


def copy_assets(tmp_path):
    for rel_path in asset_check.ASSETS:
        dst = tmp_path / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dst)


def test_default_manual_distribution_assets_are_valid():
    checks = asset_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_bare_signup_url_is_rejected(tmp_path):
    copy_assets(tmp_path)
    path = tmp_path / "marketing/HN_LAUNCH.md"
    path.write_text(
        path.read_text(encoding="utf-8") + "\nBare signup: https://tinyzkp.com/signup\n",
        encoding="utf-8",
    )

    checks = asset_check.validate(tmp_path)

    assert any("untagged conversion URLs" in check.detail for check in checks)


def test_stale_mcp_tool_name_is_rejected(tmp_path):
    copy_assets(tmp_path)
    path = tmp_path / "marketing/INTEGRATION_CURSOR.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nOld tool: prove_status\n", encoding="utf-8")

    checks = asset_check.validate(tmp_path)

    assert any("forbidden stale markers" in check.detail for check in checks)
