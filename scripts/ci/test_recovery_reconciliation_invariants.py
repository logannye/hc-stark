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

    weakened = workflow.replace(
        "scripts/benchmark/run_fixed_host_release_matrix.py",
        "scripts/benchmark/run_plonky3_cgroup.py",
    )
    failures = invariants.fixed_host_workflow_failures(weakened)
    assert any(
        "run_fixed_host_release_matrix.py" in failure for failure in failures
    )
