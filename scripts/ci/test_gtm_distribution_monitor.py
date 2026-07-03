import copy
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "monitoring" / "gtm_distribution_monitor.py"
spec = importlib.util.spec_from_file_location("gtm_distribution_monitor", MODULE_PATH)
monitor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = monitor
spec.loader.exec_module(monitor)


def load_default_config():
    return monitor.load_config(ROOT / "marketing" / "mcp_distribution_targets.json")


def test_default_distribution_targets_are_valid():
    checks = monitor.validate_config(load_default_config())

    assert checks == [
        monitor.Check("PASS", "static target catalog", "source-tagged directory targets are valid")
    ]


def test_signup_url_must_preserve_source_tag():
    config = copy.deepcopy(load_default_config())
    config["targets"][0]["signup_url"] = (
        "https://tinyzkp.com/signup?source=wrong&medium=mcp_directory&platform=smithery&intent=mcp_install"
    )

    checks = monitor.validate_config(config)

    assert any("source=smithery_mcp" in check.detail for check in checks)


def test_active_target_requires_listing_url():
    config = copy.deepcopy(load_default_config())
    config["targets"][0]["listing_url"] = ""

    checks = monitor.validate_config(config)

    assert any("active target smithery must define listing_url" in check.detail for check in checks)


def test_online_checks_skip_non_active_targets():
    config = {
        "canonical_assets": [],
        "targets": [
            {
                "id": "draft",
                "status": "target",
                "listing_url": "",
            }
        ],
    }

    checks = monitor.run_online_checks(config, timeout=0.01)

    assert checks == [monitor.Check("SKIP", "directory target draft", "status=target; no live listing required")]


def test_online_checks_skip_active_targets_with_disabled_monitoring():
    config = {
        "canonical_assets": [],
        "targets": [
            {
                "id": "published_but_blocks_bots",
                "status": "active",
                "listing_url": "https://example.com/tinyzkp",
                "online_monitoring": False,
                "monitoring_note": "directory blocks automated fetches; verify manually",
            }
        ],
    }

    checks = monitor.run_online_checks(config, timeout=0.01)

    assert checks == [
        monitor.Check(
            "SKIP",
            "directory target published_but_blocks_bots",
            "status=active; directory blocks automated fetches; verify manually",
        )
    ]


def test_offline_cli_uses_static_checks_only(tmp_path, capsys):
    target_file = tmp_path / "targets.json"
    target_file.write_text(json.dumps(load_default_config()), encoding="utf-8")

    assert monitor.main(["--offline", "--targets", str(target_file)]) == 0
    out = capsys.readouterr().out
    assert "PASS static target catalog" in out
    assert "GTM distribution monitor" in out
