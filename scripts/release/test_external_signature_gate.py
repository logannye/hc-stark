import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

CI_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "ci"
if str(CI_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(CI_SCRIPT_DIR))
import backend_release_ready as gate  # noqa: E402


def test_unsigned_external_truth_claim_fails_closed(tmp_path: Path):
    claim = tmp_path / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    failures = gate.verify_external_signature(
        [(claim, {"role": "claim"})],
        root=tmp_path,
        release_sha="a" * 40,
        claim_role="claim",
        signature_role="signature",
        signer_id="reviewer",
        purpose="review:implementation",
    )
    assert failures == [
        "external signature roles are incomplete for review:implementation"
    ]


def test_non_allowlisted_signer_cannot_authenticate_claim(tmp_path: Path):
    git_path = shutil.which("git", path="/usr/bin:/bin:/usr/local/bin")
    assert git_path is not None
    git_path = str(Path(git_path).resolve())
    trust = tmp_path / "release" / "release-trust-v1.json"
    trust.parent.mkdir(parents=True)
    trust.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cosign": {},
                "external_signers": [],
                "gate_tools": {},
                "git": {
                    "platforms": {
                        gate.source_tree_identity._runtime_platform(): {
                            "sha256": hashlib.sha256(Path(git_path).read_bytes()).hexdigest(),
                            "version": subprocess.check_output(
                                [git_path, "--version"], text=True
                            ).strip(),
                        }
                    }
                },
                "toolchains": {},
            }
        ),
        encoding="utf-8",
    )
    claim = tmp_path / "claim.json"
    bundle = tmp_path / "bundle.json"
    claim.write_text("{}", encoding="utf-8")
    bundle.write_text("{}", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TinyZKP Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "trust",
        ],
        cwd=tmp_path,
        check=True,
    )
    release_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True
    ).strip()
    failures = gate.verify_external_signature(
        [
            (claim, {"role": "claim"}),
            (bundle, {"role": "signature"}),
        ],
        root=tmp_path,
        release_sha=release_sha,
        claim_role="claim",
        signature_role="signature",
        signer_id="not-allowlisted",
        purpose="partner_acceptance",
    )
    assert any("not explicitly allowlisted" in failure for failure in failures)
