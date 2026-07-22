from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/owner-launch-evidence.yml"
CONFIGURE_WORKFLOW = ROOT / ".github/workflows/configure-guard-launch.yml"
PUBLICATION_WORKFLOW = (
    ROOT / ".github/workflows/import-initial-guard-release-index.yml"
)
MONITORING_WORKFLOW = ROOT / ".github/workflows/deploy-uptime-probe.yml"


def test_owner_evidence_dispatch_and_rerun_are_both_owner_bound():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.triggering_actor == github.repository_owner" in workflow
    assert 'test "$DISPATCH_ACTOR" = "$EXPECTED_OWNER"' in workflow
    assert 'test "$TRIGGERING_ACTOR" = "$EXPECTED_OWNER"' in workflow
    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "\n  schedule:" not in workflow
    for flag in (
        "--certificate-github-workflow-sha",
        "--certificate-github-workflow-ref",
        "--certificate-github-workflow-repository",
        "--certificate-github-workflow-trigger",
    ):
        assert flag in workflow


def test_owner_evidence_pr_uses_fresh_codex_branch_and_never_self_merges():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert 'branch="codex/evidence/owner-${GATE}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"' in workflow
    assert "gh pr create" in workflow
    assert "compare/main...${branch}?expand=1" in workflow
    assert "No evidence needs to be rebuilt" in workflow
    assert "gh pr merge" not in workflow


def test_owner_workflows_install_pinned_pytest_before_running_tests():
    for path in (WORKFLOW, CONFIGURE_WORKFLOW, PUBLICATION_WORKFLOW):
        workflow = path.read_text(encoding="utf-8")
        assert "pytest==8.4.2" in workflow
        assert workflow.index("pytest==8.4.2") < workflow.index("python3 -m pytest")


def test_configuration_workflow_is_owner_main_only_and_never_merges():
    workflow = CONFIGURE_WORKFLOW.read_text(encoding="utf-8")
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.triggering_actor == github.repository_owner" in workflow
    assert "configure_guard_launch.py" in workflow
    assert 'branch="codex/guard-owner-${OPERATION}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"' in workflow
    assert "gh pr create" in workflow
    assert "compare/main...${branch}?expand=1" in workflow
    assert "No operation needs to be rerun" in workflow
    assert "gh pr merge" not in workflow
    assert '--workflow-source-sha "$EXPECTED_MAIN_SHA"' in workflow
    assert "--certificate-github-workflow-trigger workflow_dispatch" in workflow
    assert "id-token: write" in workflow
    assert "cosign sign-blob --yes --bundle \"$bundle\" \"$evidence\"" in workflow
    assert "--require-current-evaluation" not in workflow


def test_publication_workflow_verifies_run_hosts_and_opens_only_a_codex_pr():
    workflow = PUBLICATION_WORKFLOW.read_text(encoding="utf-8")
    assert "actions: read" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.triggering_actor == github.repository_owner" in workflow
    assert "release-assets.githubusercontent.com" in workflow
    assert "objects.githubusercontent.com" in workflow
    assert 'branch="codex/guard-publication-$PROMOTION_RUN_ID-$PROMOTION_RUN_ATTEMPT"' in workflow
    assert "gh pr create" in workflow
    assert "compare/main...${branch}?expand=1" in workflow
    assert "No publication evidence needs to be rebuilt" in workflow
    assert "gh pr merge" not in workflow
    assert '--workflow-source-sha "$EXPECTED_MAIN_SHA"' in workflow
    assert "--certificate-github-workflow-repository 'logannye/hc-stark'" in workflow


def test_monitoring_deploy_is_owner_main_commit_bound_and_uses_separate_token():
    workflow = MONITORING_WORKFLOW.read_text(encoding="utf-8")
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "github.actor == github.repository_owner" in workflow
    assert "github.triggering_actor == github.repository_owner" in workflow
    assert 'test "$GITHUB_SHA" = "$EXPECTED_MAIN_SHA"' in workflow
    assert "environment: tinyzkp-monitoring-production" in workflow
    assert "secrets.CLOUDFLARE_MONITORING_API_TOKEN" in workflow
    assert "secrets.CLOUDFLARE_API_TOKEN" not in workflow
    assert "vars.CLOUDFLARE_ACCOUNT_ID" in workflow
    assert "secrets.CLOUDFLARE_ACCOUNT_ID" not in workflow
    assert "vars.TINYZKP_UPTIME_PROBE_HOST" in workflow
    assert 'url.pathname !== "/"' in workflow
    assert "url.search || url.hash" in workflow
    assert "npm --prefix deploy/uptime-probe test" in workflow
    assert 'AUDIT_MODE = \\"canonical\\"' not in workflow
    assert 'AUDIT_MODE = "canonical"' in workflow
    assert ".ok == true and .mode == $mode" in workflow
