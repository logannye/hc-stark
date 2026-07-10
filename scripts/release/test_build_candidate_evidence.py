import importlib.util
import json
from pathlib import Path
import stat
import sys


MODULE_PATH = Path(__file__).with_name("build_candidate_evidence.py")
SPEC = importlib.util.spec_from_file_location("build_candidate_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_template_contains_exact_unsigned_gate_set():
    value = module.template()
    assert set(value["gates"]) == module.prerelease.EXPECTED_GATES
    assert module.prerelease.SIGNED_GATE not in value["gates"]
    for name, gate in value["gates"].items():
        assert [artifact["role"] for artifact in gate["artifacts"]] == module.GATE_ROLES[name]
    assert len(value["gates"]["one_million_row_resource_gate"]["artifacts"]) == 10
    assert len(value["gates"]["independent_resource_reproduction"]["artifacts"]) == 17
    assert [
        artifact["role"]
        for artifact in value["gates"]["crash_resume_and_corruption_suite"]["artifacts"]
    ] == ["crash_matrix", "fuzz_smoke"]


def test_hashed_artifact_rejects_extra_fields_and_symlinks(tmp_path):
    artifact = tmp_path / "artifact.json"
    artifact.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(artifact)
    for raw in (
        {"role": "report", "path": "artifact.json", "sha256": "manual"},
        {"role": "report", "path": "linked.json"},
    ):
        try:
            module.hashed_artifact(tmp_path, raw)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe candidate artifact was accepted")


def test_invalid_candidate_never_emits_outputs(tmp_path):
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps({"schema_version": 1, "release_sha": "abc", "gates": {}}),
        encoding="utf-8",
    )
    try:
        module.construct_evidence(json.loads(source.read_text()), root=tmp_path)
    except ValueError as error:
        assert "candidate gates are missing" in str(error)
    else:
        raise AssertionError("incomplete candidate was accepted")


def test_atomic_output_is_owner_only(tmp_path):
    output = tmp_path / "candidate.json"
    module.write_json_atomic(output, {"status": "candidate"})
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
