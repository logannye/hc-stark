import importlib.util
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "cursor_plugin_check.py"
spec = importlib.util.spec_from_file_location("cursor_plugin_check", MODULE_PATH)
cursor_plugin_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = cursor_plugin_check
spec.loader.exec_module(cursor_plugin_check)


def copy_fixture(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "plugins" / "tinyzkp-cursor", tmp_path / "plugins" / "tinyzkp-cursor")
    marketing = tmp_path / "marketing"
    marketing.mkdir()
    shutil.copy2(ROOT / "marketing" / "mcp_distribution_targets.json", marketing / "mcp_distribution_targets.json")
    return tmp_path


def test_default_cursor_plugin_package_is_valid():
    checks = cursor_plugin_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_mcp_config_requires_hosted_tinyzkp_endpoint(tmp_path):
    root = copy_fixture(tmp_path)
    path = root / "plugins" / "tinyzkp-cursor" / ".mcp.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["mcpServers"]["tinyzkp"]["args"][-1] = "https://example.com/mcp"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    checks = cursor_plugin_check.validate_mcp_config(root)

    assert any("https://mcp.tinyzkp.com/mcp" in check.detail for check in checks)


def test_manifest_rejects_untracked_homepage(tmp_path):
    root = copy_fixture(tmp_path)
    path = root / "plugins" / "tinyzkp-cursor" / ".plugin" / "plugin.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["homepage"] = "https://tinyzkp.com/mcp"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    checks = cursor_plugin_check.validate_manifest(root, Path(".plugin/plugin.json"))

    assert any("cursor_directory attribution" in check.detail for check in checks)


def test_distribution_target_requires_cursor_directory_entry(tmp_path):
    root = copy_fixture(tmp_path)
    path = root / "marketing" / "mcp_distribution_targets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for target in data["targets"]:
        if target["id"] == "cursor_directory":
            target["submission_url"] = "https://forum.cursor.com"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    checks = cursor_plugin_check.validate_distribution_target(root)

    assert any("https://cursor.directory/plugins/new" in check.detail for check in checks)
