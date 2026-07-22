import check_pinned_actions
import recovery_reconciliation_invariants as invariants


def test_reviewed_action_count_accepts_only_exact_sha_pinned_versioned_uses():
    revision = check_pinned_actions.ACTION_ALLOWLIST["actions/attest"]
    workflow = (
        "      - name: first\n"
        f"        uses: actions/attest@{revision} # v4\n"
        f"      - uses: actions/attest@{revision} # v4\n"
    )
    assert (
        invariants.reviewed_action_count(
            workflow, "actions/attest", revision, "v4"
        )
        == 2
    )


def test_reviewed_action_count_rejects_tags_wrong_sha_and_wrong_version_comment():
    revision = check_pinned_actions.ACTION_ALLOWLIST["actions/attest"]
    workflow = (
        "      - uses: actions/attest@v4\n"
        f"      - uses: actions/attest@{'0' * 40} # v4\n"
        f"      - uses: actions/attest@{revision} # v3\n"
        f"      - uses: actions/attest@{revision}\n"
    )
    assert (
        invariants.reviewed_action_count(
            workflow, "actions/attest", revision, "v4"
        )
        == 0
    )


def test_fixed_host_release_workflow_requires_single_matrix_controller():
    workflow = invariants.text(".github/workflows/benches.yml")
    assert invariants.fixed_host_workflow_failures(workflow) == []
    assert 'toolchain: "1.95.0"\n          components: rustfmt, clippy' in workflow

    weakened = workflow.replace(
        "scripts/benchmark/run_fixed_host_release_matrix.py",
        "scripts/benchmark/run_plonky3_cgroup.py",
    )
    failures = invariants.fixed_host_workflow_failures(weakened)
    assert any(
        "run_fixed_host_release_matrix.py" in failure for failure in failures
    )


def test_nightly_qualification_tests_use_exact_release_toolchain():
    workflow = invariants.text(".github/workflows/nightly-backend.yml")
    assert "cargo +1.95.0 fetch --locked" in workflow
    assert "--manifest-path fuzz/Cargo.toml" in workflow
    assert "--locked" in workflow
    assert workflow.count("run: cargo +1.95.0 test -p hc-plonky3") == 2
    assert "run: cargo test -p hc-plonky3" not in workflow


def test_required_ci_rejects_a_stale_standalone_fuzz_lock():
    workflow = invariants.text(".github/workflows/ci.yml")
    assert (
        "cargo +1.95.0 fetch --locked --manifest-path fuzz/Cargo.toml"
        in workflow
    )


def test_owner_qualification_workflows_materialize_reviewed_git():
    materializer = "python3 scripts/ci/materialize_anchored_git.py"
    resource = invariants.text(".github/workflows/benches.yml")
    recovery = invariants.text(".github/workflows/nightly-backend.yml")

    assert resource.count(materializer) == 1
    assert recovery.count(materializer) == 1
    assert (
        "sudo --preserve-env=HC_RELEASE_SHA,HC_RELEASE_REF,"
        "TINYZKP_ANCHORED_GIT"
    ) in resource
