import hashlib
import json

import build_public_beta_authorization as builder


def test_authorization_is_bound_to_every_required_gate(tmp_path):
    required = ["clean_merged_ci", "official_verifier_equivalence"]
    (tmp_path / "release").mkdir()
    (tmp_path / "release" / "release-channels-v1.json").write_text(
        json.dumps({"channels": {"public_beta": {"required_gate_ids": required}}})
    )
    values = {
        "clean_merged_ci": {
            "schema_version": "public-beta-clean-ci-v1",
            "status": "passed",
            "release_sha": "a" * 40,
            "branch": "main",
            "source_clean": True,
            "merged_source": True,
            "candidate_workflow_conclusion": "success",
            "candidate_workflow_run_id": 123,
            "required_checks": [
                {"name": f"check-{index}", "status": "success"}
                for index in range(4)
            ],
        },
        "official_verifier_equivalence": {
            "schema_version": "public-beta-verifier-equivalence-v1",
            "status": "passed",
            "release_sha": "a" * 40,
            "workloads": {
                workload: {
                    "official_verification": True,
                    "proof_sha256_by_mode": {
                        mode: str(index + 1) * 64
                        for mode in (
                            "memory",
                            "scratch",
                            "uninterrupted",
                            "resumed",
                        )
                    },
                }
                for index, workload in enumerate(
                    ("fibonacci", "poseidon2", "customer_cubic8")
                )
            },
        },
    }
    artifacts = {}
    for gate, value in values.items():
        path = tmp_path / f"{gate}.json"
        path.write_text(json.dumps(value) + "\n")
        path.chmod(0o600)
        artifacts[gate] = [
            {
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        ]
    evidence = tmp_path / "evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_channel": "public_beta",
                "release_sha": "a" * 40,
                "gates": artifacts,
            }
        )
    )
    evidence.chmod(0o600)
    result = builder.build(evidence, "a" * 40, root=tmp_path)
    assert result["status"] == "ready"
    assert result["verified_gate_ids"] == required
