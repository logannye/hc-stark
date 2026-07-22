from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "assemble-backend-evidence.yml"
RESOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "benches.yml"
RESOURCE_EVIDENCE_FILES = (
    "fibonacci-1m.json",
    "fibonacci-1m.bounded.manifest.json",
    "fibonacci-1m.baseline.json",
    "fibonacci-1m.baseline.conventional.manifest.json",
    "poseidon2-1m.json",
    "poseidon2-1m.bounded.manifest.json",
    "poseidon2-1m.baseline.json",
    "poseidon2-1m.baseline.conventional.manifest.json",
    "fibonacci-16m.json",
    "fibonacci-16m.bounded.manifest.json",
    "fixed-host-release-matrix-v1.json",
)


def workflow():
    return WORKFLOW.read_text(encoding="utf-8")


def resource_workflow():
    return RESOURCE_WORKFLOW.read_text(encoding="utf-8")


def test_resource_workflow_uploads_the_exact_closed_assembly_inventory():
    value = resource_workflow()
    checksum_start = value.index("      - name: Bind the exact qualification artifact inventory")
    checksum_end = value.index("      - name: Attest the exact-main qualification inventory")
    checksum_block = value[checksum_start:checksum_end]
    upload_start = value.index("      - name: Upload source- and CLI-bound qualification evidence")
    upload_block = value[upload_start:]

    assert "find ." not in checksum_block
    assert ".fixed-host-release-matrix.lock" not in value
    for name in RESOURCE_EVIDENCE_FILES:
        assert checksum_block.count(name) == 1
        assert upload_block.count(
            f"raw-reports/fixed-host-release-matrix/{name}"
        ) == 1
    assert checksum_block.count("qualification-SHA256SUMS") == 2
    assert upload_block.count(
        "raw-reports/fixed-host-release-matrix/qualification-SHA256SUMS"
    ) == 1


def test_assembly_is_owner_dispatched_from_exact_current_main_only():
    value = workflow()
    assert "workflow_dispatch:" in value
    assert "\n  push:" not in value
    assert "\n  schedule:" not in value
    assert "github.ref == 'refs/heads/main'" in value
    assert "github.actor == github.repository_owner" in value
    assert "github.triggering_actor == github.repository_owner" in value
    assert 'test "$GITHUB_SHA" = "$EXPECTED_MAIN_SHA"' in value
    assert 'test "$(git rev-parse origin/main)" = "$EXPECTED_MAIN_SHA"' in value


def test_source_runs_and_artifacts_are_verified_by_exact_identity():
    value = workflow()
    for marker in (
        "actions/runs/$run_id/attempts/$run_attempt",
        ".path == $path",
        ".head_sha == $sha",
        '.conclusion == "success"',
        ".actor.login == $owner",
        ".triggering_actor.login == $owner",
        ".workflow_run.id == $run",
        ".workflow_run.head_sha == $sha",
        ".created_at >= $started",
        "actions/artifacts/$artifact_id/zip",
        'archive_sha256="$(sha256sum "$archive"',
    ):
        assert marker in value


def test_source_checksum_manifests_are_closed_and_attestation_verified():
    value = workflow()
    assert "extract_backend_qualification_manifests.py" in value
    for marker in (
        "qualification-SHA256SUMS",
        "recovery-SHA256SUMS",
        '"github.com/$GITHUB_REPOSITORY/.github/workflows/benches.yml"',
        '"github.com/$GITHUB_REPOSITORY/.github/workflows/nightly-backend.yml"',
        '--source-digest "$EXPECTED_MAIN_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
    ):
        assert marker in value
    assert value.count("gh attestation verify") == 2


def test_candidate_is_semantically_validated_and_oidc_signed():
    value = workflow()
    assert "assemble_backend_candidate.py" in value
    assert "build_candidate_evidence.py build" in value
    assert value.count("backend_prerelease_ready.py") >= 2
    assert "build_backend_assembly_provenance.py" in value
    assert "id-token: write" in value
    assert "cosign sign-blob" in value
    assert "assemble-backend-evidence.yml@refs/heads/main" in value
    assert "verify_backend_assembly.py" in value
    for marker in (
        '--certificate-github-workflow-sha "$EXPECTED_MAIN_SHA"',
        "--certificate-github-workflow-ref 'refs/heads/main'",
        "--certificate-github-workflow-repository 'logannye/hc-stark'",
        "--certificate-github-workflow-trigger 'workflow_dispatch'",
    ):
        assert marker in value
    assert 'python-version: "3.12.13"' in value


def test_staged_bytes_are_reverified_immediately_before_commit():
    value = workflow()
    staged = value.index("git add \\")
    final_gate = value.index("backend_prerelease_ready.py", staged)
    clean_index = value.index("git diff --quiet", final_gate)
    commit = value.index('git commit -m "Record qualified backend evidence', clean_index)
    assert staged < final_gate < clean_index < commit


def test_evidence_pr_uses_only_builtin_token_and_never_merges_itself():
    value = workflow()
    assert "GH_TOKEN: ${{ github.token }}" in value
    assert "secrets." not in value
    assert "gh pr create" in value
    assert "gh pr merge" not in value
    assert 'branch="codex/evidence/backend-' in value
    assert "actions: read" in value
    assert "attestations: read" in value
    assert "actions: write" not in value
    assert "/approve" not in value
    assert "gh pr review" not in value
    assert 'if pr_url="$(gh pr create' in value
    assert 'compare_url="https://github.com/$GITHUB_REPOSITORY/compare/main...' in value
    assert "Open the evidence PR:" in value


def test_change_allowlist_is_evidence_only():
    value = workflow()
    assert "release/backend-v1-gates.json" in value
    assert "release/evidence/backend-v1-evidence.json" in value
    assert 'release/evidence/backend-v1/"$EXPECTED_MAIN_SHA"/*' in value
    assert "unexpected backend evidence change" in value
