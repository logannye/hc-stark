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
        "engine-runtime-smoke.json",
        "plonky3-compatibility-v1.json",
        "tinyzkp-engine.spdx.json",
        "tinyzkp-engine-linux-x86_64",
        "tinyzkp-engine.oci.tar",
    }
    workflow = text(".github/workflows/release-backend.yml")
    assert "-printf '%f\\0'" in workflow
    assert "LC_ALL=C sort -z | xargs -0 sha256sum" in workflow


def test_engine_release_executes_confined_runtime_smoke_before_signing():
    workflow = text(".github/workflows/release-backend.yml")
    buildx = (
        "docker/setup-buildx-action@"
        "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c"
    )
    assert buildx in workflow
    assert workflow.index(buildx) < workflow.index("--output type=oci")
    assert "sudo apt-get install --yes --no-install-recommends skopeo" in workflow
    assert "scripts/release/smoke_engine_release_artifacts.py" in workflow
    assert "--runtime-smoke release-artifacts/engine-runtime-smoke.json" in workflow
    assert workflow.index("smoke_engine_release_artifacts.py") < workflow.index(
        "Create checksums"
    )


def test_engine_candidate_gate_installs_anchored_cosign_before_prerelease():
    workflow = text(".github/workflows/release-backend.yml")
    candidate = workflow.split("  signed-artifacts:", 1)[0]
    installer = (
        "sigstore/cosign-installer@"
        "f713795cb21599bc4e5c4b58cbad1da852d7eeb9"
    )
    assert installer in candidate
    assert "cosign-release: v2.4.3" in candidate
    assert candidate.index(installer) < candidate.index("backend_prerelease_ready.py")


def test_engine_release_is_owner_dispatched_from_exact_current_main_in_protected_jobs():
    workflow = text(".github/workflows/release-backend.yml")
    trigger = workflow.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger
    assert "push:" not in trigger
    assert "permissions: {}" in workflow
    assert workflow.count("github.actor == github.repository_owner") == 3
    assert workflow.count("github.triggering_actor == github.repository_owner") == 3
    assert workflow.count('test "$EXPECTED_OWNER" = logannye') == 3
    assert workflow.count("environment: tinyzkp-engine-signing") == 2
    assert workflow.count(
        "+refs/heads/main:refs/remotes/origin/main"
    ) == 3
    assert workflow.count('test "$(git rev-parse origin/main)" =') == 3
    assert "^backend-v(0|[1-9][0-9]*)" in workflow

    candidate, signed = workflow.split("  signed-artifacts:", 1)
    assert candidate.index("actions/checkout@") < candidate.index(
        "Bind the immutable tag to exact current protected main"
    )
    assert candidate.index("origin/main") < candidate.index(
        "backend_prerelease_ready.py"
    )
    signed, publication = signed.split("  publish-draft:", 1)
    assert signed.index("origin/main") < signed.index("dtolnay/rust-toolchain@")
    assert publication.index("origin/main") < publication.index(
        "Recover the protected staged candidate"
    )


def test_engine_finalizer_receives_every_exact_release_binding():
    workflow = text(".github/workflows/release-backend.yml")
    finalization = workflow.split(
        "- name: Verify signature and construct final release evidence", 1
    )[1].split("- name: Attest released files", 1)[0]
    for marker in (
        "finalize_signed_evidence.py",
        '--release-sha "$HC_RELEASE_SHA"',
        '--release-ref "$HC_RELEASE_REF"',
        "--sbom release-artifacts/tinyzkp-engine.spdx.json",
        "--checksums release-artifacts/SHA256SUMS",
        "--signature release-artifacts/SHA256SUMS.sigstore.json",
        "--identity-report release-artifacts/engine-identity.json",
        "--runtime-smoke release-artifacts/engine-runtime-smoke.json",
        "--output-evidence release-artifacts/backend-v1-final-evidence.json",
        "--output-config release-artifacts/backend-v1-final-gates.json",
    ):
        assert marker in finalization


def test_engine_signature_and_attestations_bind_exact_source_workflow_identity():
    release = text(".github/workflows/release-backend.yml")
    promotion = text(".github/workflows/promote-guard-release.yml")
    for workflow in (release, promotion):
        for marker in (
            "--certificate-github-workflow-sha",
            "--certificate-github-workflow-ref",
            "--certificate-github-workflow-repository",
            "--certificate-github-workflow-trigger workflow_dispatch",
            "--cert-identity",
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref",
            "--deny-self-hosted-runners",
        ):
            assert marker in workflow
    assert release.count("--certificate-github-workflow-sha") >= 1
    assert release.count("gh attestation verify") >= 2
    assert promotion.count("gh attestation verify") == 1
    assert '--certificate-github-workflow-sha "$engine_sha"' in promotion
    assert '--certificate-github-workflow-ref "$engine_ref"' in promotion
    assert '--source-digest "$engine_sha"' in promotion
    assert '--source-ref "$engine_ref"' in promotion
    assert 'jq -er .release_ref engine-release.json' in promotion
    assert "signed_release_sbom_and_checksums.metadata.release_ref" in promotion


def test_pull_request_ci_executes_actual_signed_candidate_gate():
    workflow = text(".github/workflows/ci.yml")
    assert '.status == "candidate"' in workflow
    assert "python3 scripts/ci/backend_prerelease_ready.py" in workflow
    assert "scripts/release/test_verify_backend_assembly.py" in workflow


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
    assert (
        'gh release download "$ENGINE_TAG" --dir '
        '"$GITHUB_WORKSPACE/release-artifacts"'
        in workflow
    )
    assert "working-directory: ${{ github.workspace }}/release-artifacts" in workflow
    assert (
        '"$GITHUB_WORKSPACE/release-artifacts/tinyzkp-engine.oci.tar"'
        in workflow
    )
    assert "$RUNNER_TEMP/engine-candidate" not in workflow
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
