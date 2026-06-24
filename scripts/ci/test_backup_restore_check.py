import pathlib

import backup_restore_check as check


def write(root: pathlib.Path, rel: str, text: str = "") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_check_file_reports_missing_file(tmp_path):
    assert check.check_file(tmp_path, "missing.txt", ("x",)) == ["missing missing.txt"]


def test_check_file_reports_missing_marker(tmp_path):
    write(tmp_path, "file.txt", "hello")
    assert check.check_file(tmp_path, "file.txt", ("marker",)) == ["file.txt missing marker: marker"]


def test_check_forbidden_reports_stale_marker(tmp_path):
    write(tmp_path, "restore.md", "curl /v1/ping")
    assert check.check_forbidden(tmp_path, "restore.md", ("/v1/ping",)) == [
        "restore.md contains stale marker: /v1/ping"
    ]


def test_check_passes_minimal_complete_tree(tmp_path):
    for rel, markers in check.REQUIRED_MARKERS.items():
        write(tmp_path, rel, "\n".join(markers))
    failures = check.check(tmp_path)
    assert failures == []
