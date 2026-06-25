import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "ci" / "package_distribution_check.py"
spec = importlib.util.spec_from_file_location("package_distribution_check", MODULE_PATH)
package_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = package_check
spec.loader.exec_module(package_check)


def test_default_package_distribution_surfaces_are_valid():
    checks = package_check.validate(ROOT)

    assert all(check.status == "PASS" for check in checks)


def test_surface_requires_source_tagged_signup(tmp_path):
    surface = package_check.Surface(
        "test surface",
        Path("README.md"),
        "pypi_tinyzkp",
        "package_registry",
        "pypi",
        "api_key",
    )
    text = "\n".join(
        [
            "Default receipts are transparent",
            "https://tinyzkp.com/signup?source=wrong&medium=package_registry&platform=pypi&intent=api_key",
            "https://tinyzkp.com/verify?source=pypi_tinyzkp&medium=package_registry&platform=pypi&intent=verify_receipt",
            "https://tinyzkp.com/limits?source=pypi_tinyzkp&medium=package_registry&platform=pypi&intent=limits",
            "https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=pypi_tinyzkp&medium=package_registry&platform=pypi&intent=agent_offer",
        ]
    )
    (tmp_path / "README.md").write_text(text, encoding="utf-8")

    checks = package_check.validate_surface(tmp_path, surface)

    assert any("missing signup URL" in check.detail for check in checks)


def test_metadata_requires_registry_attribution(tmp_path):
    metadata = tmp_path / "clients" / "rust" / "Cargo.toml"
    metadata.parent.mkdir(parents=True)
    metadata.write_text('readme = "README.md"\nhomepage = "https://tinyzkp.com"\n', encoding="utf-8")

    checks = package_check.validate_metadata(tmp_path)

    assert any(check.name == "clients/rust/Cargo.toml" and "source=crates_tinyzkp" in check.detail for check in checks)
