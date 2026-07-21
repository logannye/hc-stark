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


def test_pull_request_ci_does_not_import_protected_launch_trust() -> None:
    workflow = text(".github/workflows/ci.yml")
    for variable in (
        "GUARD_LAUNCH_TRUST_POLICY_SHA256",
        "GUARD_MARKET_TRUST_POLICY_SHA256",
        "GUARD_SIGNING_TRUST_POLICY_SHA256",
    ):
        assert variable not in workflow


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
    assert "cargo build --locked --release -p hc-cli --bin hc-cli" in workflow
    assert (
        "target/release/hc-cli release-artifacts/tinyzkp-engine-linux-x86_64"
        in workflow
    )
    assert (
        "COPY --from=builder /app/target/release/hc-cli "
        "/usr/local/bin/tinyzkp-engine"
        in dockerfile
    )
    assert "ENTRYPOINT [\"/usr/local/bin/tinyzkp-engine\"]" in dockerfile
    assert "COPY examples/partner-adapter ./examples/partner-adapter" in dockerfile
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


def test_engine_candidate_cannot_trigger_irreversible_crates_publication():
    candidate = text(".github/workflows/release-backend.yml")
    crates = text(".github/workflows/publish-backend-crates.yml")
    assert 'gh release create "$RELEASE_TAG"' in candidate
    assert "--draft" in candidate
    assert "cargo publish" not in candidate
    assert "release:" not in crates
    assert "cargo publish" not in crates
    assert "exit 1" in crates


def test_joint_promotion_is_protected_no_rebuild_exact_candidate_promotion():
    workflow = text(".github/workflows/promote-guard-release.yml")
    assert "contents: write" in workflow
    assert "environment: tinyzkp-release-promotion" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "guard_launch_gate.py" in workflow
    assert "--check" in workflow
    assert "--require-promotion-ready" in workflow
    assert "--require-ready" not in workflow
    assert "GUARD_LAUNCH_TRUST_POLICY_SHA256" in workflow
    assert "GUARD_SIGNING_TRUST_POLICY_SHA256" in workflow
    assert "isDraft" in workflow
    assert "verify_engine_candidate_inventory.py" in workflow
    assert "verify_guard_candidate.py" in workflow
    assert "cosign verify-blob" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "packages: write" in workflow
    assert "skopeo copy --preserve-digests" in workflow
    assert "oci-archive:" in workflow
    assert "remote_digest" in workflow
    assert "docker buildx imagetools inspect" in workflow
    assert "static_site_canary.py" in workflow
    assert 'publish_if_draft "$ENGINE_TAG"' in workflow
    assert 'publish_if_draft "$GUARD_TAG"' in workflow
    assert 'gh release edit "$tag" --draft=false --prerelease=false' in workflow
    assert "engine_state=" in workflow
    assert "guard_state=" in workflow
    assert "$'true\\tfalse'|$'false\\tfalse'" in workflow
    assert "$'true\\ttrue'|$'false\\tfalse'" in workflow
    assert workflow.count("--json isPrerelease --jq .isPrerelease") == 2
    assert workflow.count("--json isDraft --jq .isDraft") == 3
    assert "skopeo inspect --no-creds" in workflow
    assert "package_visibility" in workflow
    for forbidden in (
        "cargo build",
        "docker build ",
        "docker buildx build ",
        "cargo publish",
        "Promotion remains deliberately disabled",
    ):
        assert forbidden not in workflow


def test_guard_promotion_uses_the_canonical_keyed_signature_contract():
    workflow = text(".github/workflows/promote-guard-release.yml")
    guard_verification = workflow.split(
        "- name: Verify signed Guard package, channel, schemas, and OCI identity",
        1,
    )[1]
    for required in (
        "release/guard-signing-public-key.pem",
        "SHA256SUMS.sig",
        "guard-channel-v1.json.sig",
        "guard-release-index-v1.json.sig",
        "--signature SHA256SUMS.sig",
        "--signature guard-channel-v1.json.sig",
        "--signature guard-release-index-v1.json.sig",
        "guard-candidate-build-authorization-v1.json",
        "--build-authorization",
    ):
        assert required in workflow
    for forbidden in (
        "SHA256SUMS.sigstore.json",
        "release-guard.yml@refs/tags",
        'git rev-parse "$GUARD_TAG^{commit}")" = "$guard_sha"',
    ):
        assert forbidden not in guard_verification
    assert ".public_candidate_authorization_commit" in workflow
    assert (
        'git -C "$GITHUB_WORKSPACE" rev-parse "$GUARD_TAG^{commit}")" ='
        in workflow
    )
    assert "merge-base --is-ancestor" in workflow
    assert (
        '$public_candidate_authorization_commit:release/'
        "guard-candidate-build-authorization-v1.json"
        in workflow
    )
    assert (
        'git rev-parse "$GUARD_TAG^{commit}")" = "$GITHUB_SHA"'
        not in workflow
    )
    verifier = text("scripts/ci/verify_guard_candidate.py")
    assert '"candidate_authorization_sha256"' in verifier
    assert "BUILD_AUTHORIZATION_NAME" in verifier


def test_index_only_revision_import_is_protected_exact_byte_and_no_rebuild():
    workflow = text(
        ".github/workflows/import-guard-release-index-revision.yml"
    )
    assert "workflow_dispatch:" in workflow
    assert "environment: tinyzkp-release-index-promotion" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "GUARD_PRIVATE_HANDOFF_TOKEN" in workflow
    assert "logannye/tinyzkp-guard" in workflow
    assert "guard-release-index-revision-$PRIVATE_RUN_ID" in workflow
    assert "guard-release-index-revision-handoff-v1.json" in workflow
    assert "scripts/ci/guard_release_index.py" in workflow
    assert "cosign verify-blob" in workflow
    assert "release-index-revisions/$EXPECTED_REVISED_SHA256" in workflow
    assert "site/guard-release-index-v1.json" in workflow
    assert "guard_launch_gate.py" in workflow
    assert "gh pr create" in workflow
    for forbidden in (
        "cargo build",
        "docker build ",
        "docker buildx build ",
        "gh release upload",
        "gh release edit",
    ):
        assert forbidden not in workflow


def test_production_site_deploy_requires_current_evidence_for_active_states():
    workflow = text(".github/workflows/deploy-site.yml")
    for marker in (
        "--require-ready",
        "--require-promotion-ready",
        "--require-candidate-build-ready",
        "--require-current-evaluation",
    ):
        assert marker in workflow


def test_oci_promotion_copies_both_archives_and_verifies_remote_identity():
    workflow = text(".github/workflows/promote-guard-release.yml")
    assert "tinyzkp-engine.oci.tar" in workflow
    assert "tinyzkp-guard:$guard_version" in workflow
    assert workflow.count("skopeo copy --preserve-digests") == 1
    assert workflow.count("copy_exact_archive \\") == 2
    assert workflow.count("docker buildx imagetools inspect") == 1
    assert "refusing to overwrite immutable OCI tag" in workflow
    assert "refusing to publish after an indeterminate OCI tag lookup" in workflow
    assert "manifest unknown|name unknown" in workflow
    assert 'test "$observed_digest" != "$expected_digest"' in workflow
    assert "org.opencontainers.image.tinyzkp.release-identity" in workflow
    for forbidden in ("docker build ", "docker buildx build "):
        assert forbidden not in workflow


def test_evaluation_doctor_release_is_separate_signed_prerelease_only():
    workflow = text(".github/workflows/evaluation-doctor.yml")
    assert "workflow_dispatch:" in workflow
    assert "doctor-eval-v*" in workflow
    assert "environment: tinyzkp-evaluation-release" in workflow
    assert "cargo test --locked -p tinyzkp-contracts" in workflow
    assert "tinyzkp-engine-linux-x86_64 doctor --job job.json" in workflow
    assert "tinyzkp-public-schemas.tar.gz" in workflow
    assert "tinyzkp-synthetic-doctor-job.tar.gz" in workflow
    assert "tinyzkp-engine-evaluation.oci.tar" in workflow
    assert "cosign sign-blob" in workflow
    assert "actions/attest@" in workflow
    assert "--prerelease" in workflow
    assert "doctor-evaluation-provenance-v1.json" in workflow
    assert "Recover an earlier exact staged bundle" in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 2
    assert "production_qualified:false" in workflow
    assert "performance_qualified:false" in workflow
    for forbidden in (
        "cargo publish",
        "backend_prerelease_ready.py",
        "run_fixed_host_release_matrix.py",
        "public_live",
    ):
        assert forbidden not in workflow
