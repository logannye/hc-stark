import copy
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "marketing" / "render_mcp_submissions.py"
spec = importlib.util.spec_from_file_location("render_mcp_submissions", MODULE_PATH)
renderer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = renderer
spec.loader.exec_module(renderer)


def load_config():
    return renderer.load_config(ROOT / "marketing" / "mcp_distribution_targets.json")


def test_render_target_preserves_source_tagged_cta_and_boundaries():
    config = load_config()
    target = config["targets"][0]

    rendered = renderer.render_target(config, target)

    assert target["signup_url"] in rendered
    assert "Do not put secrets" in rendered
    assert target["install_command"] in rendered
    assert "source=smithery_mcp" in rendered


def test_render_all_includes_every_target_and_index():
    config = load_config()

    outputs = renderer.render_all(config)

    assert Path("index.md") in outputs
    assert len(outputs) == len(config["targets"]) + 1
    assert Path("anthropic_connectors.md") in outputs


def test_check_outputs_detects_stale_generated_file(tmp_path):
    config = copy.deepcopy(load_config())
    config["targets"] = config["targets"][:1]
    outputs = renderer.render_all(config)

    renderer.write_outputs(outputs, tmp_path)
    assert renderer.check_outputs(outputs, tmp_path) == []

    (tmp_path / "smithery.md").write_text("stale\n", encoding="utf-8")
    failures = renderer.check_outputs(outputs, tmp_path)

    assert any("stale generated submission" in failure for failure in failures)


def test_check_outputs_detects_obsolete_generated_file(tmp_path):
    config = copy.deepcopy(load_config())
    config["targets"] = config["targets"][:1]
    outputs = renderer.render_all(config)

    renderer.write_outputs(outputs, tmp_path)
    (tmp_path / "removed_target.md").write_text("obsolete\n", encoding="utf-8")

    failures = renderer.check_outputs(outputs, tmp_path)

    assert any("obsolete generated submission" in failure for failure in failures)
