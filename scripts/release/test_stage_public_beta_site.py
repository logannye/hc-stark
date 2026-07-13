import json
from pathlib import Path
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
    worker = (output / "_worker.js").read_text()
    assert '"/dashboard"' in worker
    assert '"/dashboard.html"' in worker
    assert '"/dashboard.js"' in worker
    assert (output / "SHA256SUMS").stat().st_size > 0


def test_stage_refuses_existing_output_or_short_sha(tmp_path: Path):
    output = tmp_path / "existing"
    output.mkdir()
    failed = subprocess.run(["bash", str(SCRIPT), "a" * 40, str(output)], cwd=ROOT)
    assert failed.returncode != 0
    failed = subprocess.run(["bash", str(SCRIPT), "short", str(tmp_path / "new")], cwd=ROOT)
    assert failed.returncode != 0
