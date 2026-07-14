import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release" / "stage_public_beta_site.sh"


def test_stage_builds_exact_release_beta_surface(tmp_path: Path):
    containment_worker = (ROOT / "site" / "_worker.js").read_text()
    assert '"/dashboard"' not in containment_worker
    assert '"/dashboard.html"' not in containment_worker

    output = tmp_path / "site"
    release_sha = "a" * 40
    subprocess.run(["bash", str(SCRIPT), release_sha, str(output)], cwd=ROOT, check=True)
    discovery = json.loads((output / "discovery.json").read_text())
    pricing = json.loads((output / "pricing.json").read_text())
    assert discovery["service_status"] == "public_beta"
    assert discovery["release_sha"] == release_sha
    assert pricing["automatic_overages"] is False
    assert release_sha in (output / "status.html").read_text()
    assert "Backend recovery in progress" not in (output / "index.html").read_text()
    assert (output / "dashboard.html").is_file()
    assert 'name="robots" content="noindex,nofollow"' in (
        output / "dashboard.html"
    ).read_text()
    for page in ("index.html", "pricing.html", "status.html", "dashboard.html", "docs.html", "security.html", "privacy.html", "terms.html", "requests.html"):
        assert (output / page).read_text().count('name="description"') == 1
    worker = (output / "_worker.js").read_text()
    assert '"/dashboard"' in worker
    assert '"/dashboard.html"' in worker
    assert '"/dashboard.js"' in worker
    assert "Dedicated Cloudflare Pages policy" in worker
    assert "Content-Security-Policy" in worker
    assert 'path === "/signup"' in worker
    assert not (output / "contact.html").exists()
    assert "innerHTML" not in (output / "dashboard.js").read_text()
    openapi = json.loads((output / "openapi.json").read_text())
    assert openapi["openapi"] == "3.1.0"
    assert openapi["info"]["version"] == release_sha
    assert openapi["components"]["parameters"]["IdempotencyKey"]["required"] is True
    assert openapi["paths"]["/v1/air-packages"]["post"]["requestBody"]["required"] is True
    assert openapi["paths"]["/v1/verify"]["post"]["security"] == []
    assert "201" in openapi["paths"]["/v1/proof-jobs"]["post"]["responses"]
    assert "200" not in openapi["paths"]["/v1/proof-jobs"]["post"]["responses"]
    assert "automatic tax" in openapi["paths"]["/v1/billing/checkout-sessions"]["post"]["description"]
    combined = "\n".join(path.read_text() for path in output.glob("*.html")).lower()
    for forbidden in ("backend recovery", "contact sales", "custom engineering", "evaluation application"):
        assert forbidden not in combined
    checksums = (output / "SHA256SUMS").read_text().splitlines()
    assert checksums
    assert all("  ./" in line for line in checksums)
    assert all(str(output) not in line for line in checksums)

    relocated = tmp_path / "relocated-site"
    shutil.copytree(output, relocated)
    subprocess.run(
        ["shasum", "-a", "256", "-c", "SHA256SUMS"],
        cwd=relocated,
        check=True,
    )


def test_stage_refuses_existing_output_or_short_sha(tmp_path: Path):
    output = tmp_path / "existing"
    output.mkdir()
    failed = subprocess.run(["bash", str(SCRIPT), "a" * 40, str(output)], cwd=ROOT)
    assert failed.returncode != 0
    failed = subprocess.run(["bash", str(SCRIPT), "short", str(tmp_path / "new")], cwd=ROOT)
    assert failed.returncode != 0
