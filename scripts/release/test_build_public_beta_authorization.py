import hashlib
import json

import build_public_beta_authorization as builder


def test_authorization_is_bound_to_every_required_gate(tmp_path):
    required = ["one", "two"]
    (tmp_path / "release").mkdir()
    (tmp_path / "release" / "release-channels-v1.json").write_text(
        json.dumps({"channels": {"public_beta": {"required_gate_ids": required}}})
    )
    artifacts = {}
    for gate in required:
        path = tmp_path / f"{gate}.json"
        path.write_text("{}\n")
        artifacts[gate] = [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}]
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": "a" * 40,
        "gates": artifacts,
    }))
    result = builder.build(evidence, "a" * 40, root=tmp_path)
    assert result["status"] == "ready"
    assert result["verified_gate_ids"] == required

