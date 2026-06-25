import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "openai_chatgpt_app_check.py"
spec = importlib.util.spec_from_file_location("openai_chatgpt_app_check", MODULE_PATH)
app_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = app_check
spec.loader.exec_module(app_check)


def copy_app_files(tmp_path):
    for rel in [
        Path("marketing/OPENAI_CHATGPT_APP_PROTOTYPE.md"),
        Path("marketing/openai_chatgpt_app_submission.json"),
        Path("site/apps/tinyzkp-receipt-widget.html"),
    ]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst)


def test_default_chatgpt_app_prototype_is_valid():
    checks = app_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_submission_requires_source_tagged_signup(tmp_path):
    copy_app_files(tmp_path)
    submission = tmp_path / "marketing/openai_chatgpt_app_submission.json"
    data = json.loads(submission.read_text(encoding="utf-8"))
    data["signup_url"] = "https://tinyzkp.com/signup"
    submission.write_text(json.dumps(data), encoding="utf-8")

    checks = app_check.validate(tmp_path)

    assert any("source-tagged signup_url" in check.detail for check in checks)


def test_widget_must_call_mcp_tools(tmp_path):
    copy_app_files(tmp_path)
    widget = tmp_path / "site/apps/tinyzkp-receipt-widget.html"
    widget.write_text(widget.read_text(encoding="utf-8").replace("tools/call", "tools/missing"), encoding="utf-8")

    checks = app_check.validate(tmp_path)

    assert any(check.name == "receipt widget" and "tools/call" in check.detail for check in checks)
