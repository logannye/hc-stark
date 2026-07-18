from pathlib import Path

import backend_release_ready


ROOT = Path(__file__).resolve().parents[2]


def text(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_hosted_beta_and_sdk_workflows_are_not_active():
    for name in (
        "public-beta-candidate.yml",
        "public-beta-release.yml",
        "publish-sdks.yml",
        "sdks-ci.yml",
    ):
        assert not (ROOT / ".github" / "workflows" / name).exists()


def test_engine_release_has_no_hosted_or_sdk_executables():
    workflow = text(".github/workflows/release-backend.yml")
    dockerfile = text("Dockerfile")
    for forbidden in (
        "hc-server",
        "hc-mcp",
        "hc-beta",
        "clients/python",
        "clients/typescript",
        "clients/rust",
    ):
        assert forbidden not in workflow
        assert forbidden not in dockerfile
    assert "tinyzkp-engine-linux-x86_64" in workflow
    assert "tinyzkp-engine.oci.tar" in workflow
    assert "ENTRYPOINT [\"/usr/local/bin/tinyzkp-engine\"]" in dockerfile
    for retired in (
        "build_commercial_authorization.py",
        "backend-v1-commercial-authorization",
        "backend-v1-release-ready-report",
        "annual contract",
    ):
        assert retired not in workflow


def test_signed_release_inventory_is_exactly_engine_and_evidence():
    assert backend_release_ready.SIGNED_RELEASE_CHECKSUM_NAMES == {
        "backend-v1-gates.json",
        "engine-identity.json",
        "engine-release.json",
        "plonky3-compatibility-v1.json",
        "tinyzkp-engine.spdx.json",
        "tinyzkp-engine-linux-x86_64",
        "tinyzkp-engine.oci.tar",
    }


def test_air_gate_has_no_retired_sdk_dependency_path():
    runner = text("scripts/release/run_evidenced_command.py")
    assert "air_job_contracts" in runner
    for forbidden in ("replacement_sdk", "sdk_python", "sdk_npm", "--sdk-"):
        assert forbidden not in runner
