import importlib.util
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "seo_conversion_check.py"
spec = importlib.util.spec_from_file_location("seo_conversion_check", MODULE_PATH)
seo_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = seo_check
spec.loader.exec_module(seo_check)


def copy_required_files(tmp_path):
    paths = [seo_check.SITEMAP, seo_check.LLMS]
    paths.extend(surface.file for surface in seo_check.PRIORITY_SURFACES)
    for rel_path in paths:
        dst = tmp_path / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel_path, dst)


def failed_details(checks):
    return "\n".join(check.detail for check in checks if check.status != "PASS")


def test_default_priority_seo_pages_are_measurable():
    checks = seo_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_bare_cta_conversion_link_is_rejected(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / "site/receipts.html"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n<a class="cta" href="/try">Broken conversion CTA</a>\n',
        encoding="utf-8",
    )

    checks = seo_check.validate(tmp_path)

    assert "CTA conversion links must include source" in failed_details(checks)


def test_missing_source_specific_cta_is_rejected(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / "site/verifiable-agent-output.html"
    path.write_text(
        path.read_text(encoding="utf-8").replace("source=verifiable_agent_output", "source=wrong_source"),
        encoding="utf-8",
    )

    checks = seo_check.validate(tmp_path)

    assert "source=verifiable_agent_output" in failed_details(checks)


def test_sitemap_membership_is_required(tmp_path):
    copy_required_files(tmp_path)
    path = tmp_path / seo_check.SITEMAP
    path.write_text(
        path.read_text(encoding="utf-8").replace("https://tinyzkp.com/agent-audit-trails", "https://tinyzkp.com/removed-agent-audit-trails"),
        encoding="utf-8",
    )

    checks = seo_check.validate(tmp_path)

    assert "route missing from sitemap.xml" in failed_details(checks)
