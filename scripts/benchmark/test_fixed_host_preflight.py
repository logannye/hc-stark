import json

import fixed_host_preflight as preflight


def test_fixed_host_preflight_emits_typed_success(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    cgroup = tmp_path / "cgroup"
    monkeypatch.setattr(preflight.HARNESS, "ensure_cgroup_v2", lambda path: None)
    monkeypatch.setattr(
        preflight.HARNESS,
        "collect_host_metadata",
        lambda path: {"logical_cpu_count": 8},
    )
    monkeypatch.setattr(preflight.HARNESS, "fixed_host_failures", lambda value: [])

    report = preflight.check(scratch, cgroup)
    assert report["schema_version"] == 1
    assert report["passed"] is True
    assert report["failures"] == []
    assert report["host"] == {"logical_cpu_count": 8}


def test_fixed_host_preflight_preserves_every_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(preflight.HARNESS, "ensure_cgroup_v2", lambda path: None)
    monkeypatch.setattr(preflight.HARNESS, "collect_host_metadata", lambda path: {})
    monkeypatch.setattr(
        preflight.HARNESS,
        "fixed_host_failures",
        lambda value: ["wrong CPU count", "scratch is undersized"],
    )
    report = preflight.check(tmp_path / "scratch", tmp_path / "cgroup")
    assert report["passed"] is False
    assert report["failures"] == ["wrong CPU count", "scratch is undersized"]


def test_fixed_host_preflight_persists_environment_failure(monkeypatch, tmp_path):
    output = tmp_path / "preflight.json"

    def fail_cgroup(_path):
        raise RuntimeError("cgroup v2 unavailable")

    monkeypatch.setattr(
        preflight.HARNESS,
        "ensure_cgroup_v2",
        fail_cgroup,
    )
    assert (
        preflight.main(
            [
                "--scratch-dir",
                str(tmp_path / "scratch"),
                "--cgroup-parent",
                str(tmp_path / "cgroup"),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["passed"] is False
    assert payload["host"] is None
    assert payload["failures"] == ["cgroup v2 unavailable"]
    assert output.stat().st_mode & 0o777 == 0o600
