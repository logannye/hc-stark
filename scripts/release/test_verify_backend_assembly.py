import json
from pathlib import Path
import subprocess

import test_build_backend_assembly_provenance as fixtures
import verify_backend_assembly as verifier
import pytest


def signed_fixture(root: Path, monkeypatch):
    report, evidence = fixtures.build(root, monkeypatch)
    provenance_root = (
        root
        / "release"
        / "evidence"
        / "backend-v1"
        / fixtures.RELEASE_SHA
        / "provenance"
    )
    fixtures.write_json(provenance_root / verifier.ASSEMBLY_NAME, report)
    claims = {
        "identity": verifier.CERTIFICATE_IDENTITY,
        "issuer": verifier.OIDC_ISSUER,
        "sha": fixtures.RELEASE_SHA,
        "ref": "refs/heads/main",
        "repository": "logannye/hc-stark",
        "trigger": "workflow_dispatch",
    }
    fixtures.write_json(provenance_root / verifier.BUNDLE_NAME, claims)
    config = json.loads((root / "release/backend-v1-gates.json").read_text())
    monkeypatch.setattr(
        verifier.candidate.prerelease,
        "candidate_content_failures",
        lambda value, *, root: [],
    )
    return config, report, evidence, provenance_root, claims


def claim_checking_runner(root, release_sha, executable, arguments):
    values = {
        arguments[index]: arguments[index + 1]
        for index in range(0, len(arguments) - 1)
        if arguments[index].startswith("--")
    }
    claims = json.loads(Path(values["--bundle"]).read_text())
    expected = {
        "identity": values["--certificate-identity"],
        "issuer": values["--certificate-oidc-issuer"],
        "sha": values["--certificate-github-workflow-sha"],
        "ref": values["--certificate-github-workflow-ref"],
        "repository": values["--certificate-github-workflow-repository"],
        "trigger": values["--certificate-github-workflow-trigger"],
    }
    return subprocess.CompletedProcess(
        [str(executable), *arguments],
        0 if claims == expected and release_sha == claims["sha"] else 1,
        stdout="verified" if claims == expected else "claim mismatch",
    )


def verify(root: Path, config):
    return verifier.verify(
        root=root,
        candidate_config=config,
        expected_release_sha=fixtures.RELEASE_SHA,
        cosign="/usr/bin/cosign-fixture",
        cosign_runner=claim_checking_runner,
    )


def test_signed_assembly_binds_candidate_artifacts_and_both_source_runs(
    tmp_path, monkeypatch
):
    config, report, _evidence, _root, _claims = signed_fixture(tmp_path, monkeypatch)
    assert verify(tmp_path, config) == report


def test_missing_or_tampered_signed_assembly_fails_closed(tmp_path, monkeypatch):
    config, _report, evidence, provenance_root, _claims = signed_fixture(
        tmp_path, monkeypatch
    )
    bundle = provenance_root / verifier.BUNDLE_NAME
    bundle.unlink()
    with pytest.raises(ValueError, match="missing or unsafe"):
        verify(tmp_path, config)

    fixtures.write_json(
        bundle,
        {
            "identity": verifier.CERTIFICATE_IDENTITY,
            "issuer": verifier.OIDC_ISSUER,
            "sha": fixtures.RELEASE_SHA,
            "ref": "refs/heads/main",
            "repository": "logannye/hc-stark",
            "trigger": "workflow_dispatch",
        },
    )
    first = next(iter(evidence["gates"].values()))["artifacts"][0]
    (tmp_path / first["path"]).write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        verify(tmp_path, config)


@pytest.mark.parametrize(
    ("claim", "wrong"),
    [
        ("identity", "https://github.com/other/workflow@refs/heads/main"),
        ("issuer", "https://issuer.invalid"),
        ("sha", "f" * 40),
        ("ref", "refs/heads/other"),
        ("repository", "other/hc-stark"),
        ("trigger", "push"),
    ],
)
def test_wrong_certificate_identity_or_github_claim_fails(
    tmp_path, monkeypatch, claim, wrong
):
    config, _report, _evidence, provenance_root, claims = signed_fixture(
        tmp_path, monkeypatch
    )
    claims[claim] = wrong
    fixtures.write_json(provenance_root / verifier.BUNDLE_NAME, claims)
    with pytest.raises(ValueError, match="Sigstore certificate or signature"):
        verify(tmp_path, config)


def test_wrong_assembly_source_identity_fails(tmp_path, monkeypatch):
    config, report, _evidence, provenance_root, _claims = signed_fixture(
        tmp_path, monkeypatch
    )
    report["release_sha"] = "f" * 40
    fixtures.write_json(provenance_root / verifier.ASSEMBLY_NAME, report)
    with pytest.raises(ValueError, match="provenance identity"):
        verify(tmp_path, config)
