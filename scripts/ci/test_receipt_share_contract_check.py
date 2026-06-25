import importlib.util
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "receipt_share_contract_check.py"
spec = importlib.util.spec_from_file_location("receipt_share_contract_check", MODULE_PATH)
receipt_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = receipt_check
spec.loader.exec_module(receipt_check)


def copy_required_files(tmp_path):
    paths = [
        receipt_check.CONTRACT,
        receipt_check.SCHEMA,
        receipt_check.TRY_PAGE,
        receipt_check.VERIFY_PAGE,
        receipt_check.DISCOVERY,
        receipt_check.LLMS,
        receipt_check.ROBOTS,
        receipt_check.INDEX,
        receipt_check.EVENTS,
    ]
    for rel_path in paths:
        dst = tmp_path / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dst)


def failed_details(checks):
    return "\n".join(check.detail for check in checks if check.status != "PASS")


def test_default_receipt_share_contract_is_valid():
    checks = receipt_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_contract_requires_receipt_share_source(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / receipt_check.CONTRACT
    data = json.loads(path.read_text(encoding="utf-8"))
    data["share_url_template"] = data["share_url_template"].replace("source=receipt_share", "source=untracked")
    data["attribution"]["required_source"] = "untracked"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    checks = receipt_check.validate(tmp_path)

    assert "source=receipt_share" in failed_details(checks)


def test_page_max_fragment_must_match_contract(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / receipt_check.VERIFY_PAGE
    path.write_text(
        path.read_text(encoding="utf-8").replace("MAX_SHARE_FRAGMENT_CHARS = 120000", "MAX_SHARE_FRAGMENT_CHARS = 42"),
        encoding="utf-8",
    )

    checks = receipt_check.validate(tmp_path)

    assert "MAX_SHARE_FRAGMENT_CHARS=120000" in failed_details(checks)


def test_public_discovery_link_is_required(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / receipt_check.LLMS
    path.write_text(
        path.read_text(encoding="utf-8").replace(".well-known/tinyzkp-receipt-share.json", "missing-receipt-share.json"),
        encoding="utf-8",
    )

    checks = receipt_check.validate(tmp_path)

    assert "does not link the receipt-share contract" in failed_details(checks)
