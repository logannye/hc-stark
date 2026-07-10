from pathlib import Path

import check_pinned_actions as checker


def trust(tmp_path: Path):
    path = tmp_path.parent.parent / "release" / "release-trust-v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"schema_version":1,"cosign":{"installer_action_sha":"'
        + checker.ACTION_ALLOWLIST["sigstore/cosign-installer"]
        + '","version":"v2.4.3"}}',
        encoding="utf-8",
    )


def test_rejects_tags_branches_and_abbreviated_commits(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    trust(workflows)
    workflow = workflows / "release.yml"
    workflow.write_text(
        "jobs:\n  x:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: owner/action@main\n"
        "      - uses: owner/action@0123456789ab\n",
        encoding="utf-8",
    )
    assert len(checker.failures(workflows)) == 3


def test_accepts_full_commits_and_local_actions(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    trust(workflows)
    workflow = workflows / "release.yaml"
    workflow.write_text(
        "jobs:\n  x:\n    steps:\n"
        "      - uses: actions/checkout@"
        + checker.ACTION_ALLOWLIST["actions/checkout"]
        + "\n"
        "      - uses: ./.github/actions/local\n",
        encoding="utf-8",
    )
    assert checker.failures(workflows) == []


def test_rejects_unknown_full_sha_and_cosign_version_skew(tmp_path: Path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    trust(workflows)
    (workflows / "release.yml").write_text(
        "jobs:\n  x:\n    steps:\n"
        "      - uses: actions/checkout@" + "a" * 40 + "\n"
        "      - uses: sigstore/cosign-installer@"
        + checker.ACTION_ALLOWLIST["sigstore/cosign-installer"]
        + "\n        with:\n          cosign-release: v9.9.9\n",
        encoding="utf-8",
    )
    failures = checker.failures(workflows)
    assert any("reviewed allowlist" in failure for failure in failures)
    assert any("cosign release" in failure for failure in failures)
