import importlib.util
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "badge_embed_check.py"
spec = importlib.util.spec_from_file_location("badge_embed_check", MODULE_PATH)
badge_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = badge_check
spec.loader.exec_module(badge_check)


def copy_required_files(tmp_path):
    paths = [
        badge_check.CONTRACT,
        badge_check.SCHEMA,
        badge_check.BADGE_PAGE,
        badge_check.RECIPES_PAGE,
        badge_check.SVG,
        badge_check.DISCOVERY,
        badge_check.INTEGRATIONS,
        badge_check.LLMS,
        badge_check.ROBOTS,
    ]
    for rel_path in paths:
        dst = tmp_path / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dst)


def failed_details(checks):
    return "\n".join(check.detail for check in checks if check.status != "PASS")


def test_default_badge_embed_contract_is_valid():
    checks = badge_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_badge_snippet_must_preserve_source_tag(tmp_path):
    copy_required_files(tmp_path)
    page = tmp_path / badge_check.BADGE_PAGE
    page.write_text(
        page.read_text(encoding="utf-8").replace("source=verified_badge", "source=wrong_badge"),
        encoding="utf-8",
    )

    checks = badge_check.validate(tmp_path)

    assert "source=verified_badge" in failed_details(checks)


def test_contract_requires_transparent_data_boundary(tmp_path):
    copy_required_files(tmp_path)
    contract_path = tmp_path / badge_check.CONTRACT
    data = json.loads(contract_path.read_text(encoding="utf-8"))
    data["data_boundaries"] = ["The badge points to a page."]
    contract_path.write_text(json.dumps(data), encoding="utf-8")

    checks = badge_check.validate(tmp_path)

    assert "data_boundaries must mention 'transparent'" in failed_details(checks)
