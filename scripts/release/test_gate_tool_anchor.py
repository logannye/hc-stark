from copy import deepcopy

import pytest

import gate_tool_anchor as anchor


def candidate():
    tools = {
        name: {
            "path": f"/reviewed/{name}",
            "sha256": str(index) * 64,
            "version": f"{name} reviewed version",
        }
        for index, name in enumerate(sorted(anchor.expected_tool_names()), start=1)
    }
    platform = "linux-x86_64"
    return {
        "schema_version": 1,
        "release_sha": "a" * 40,
        "source_tree_sha256": "b" * 64,
        "dependency_lock_sha256": "c" * 64,
        "rust_toolchain_sha256": "d" * 64,
        "status": "unreviewed",
        "review_required": True,
        "platform": platform,
        "tools": tools,
        "trust_path": anchor.TRUST_PATH,
        "proposed_trust_entry": {
            platform: {name: value["sha256"] for name, value in tools.items()}
        },
    }


def test_expected_tools_are_derived_from_every_frozen_gate():
    assert anchor.expected_tool_names() == {
        "bash",
        "node",
        "python3",
        "wasm-pack",
    }


def test_candidate_is_unreviewed_closed_schema_and_exact_tool_set():
    value = candidate()
    assert anchor.validate_candidate(value) == value

    trusted = deepcopy(value)
    trusted["status"] = "reviewed"
    with pytest.raises(ValueError, match="cannot represent trusted state"):
        anchor.validate_candidate(trusted)

    missing = deepcopy(value)
    del missing["tools"]["node"]
    with pytest.raises(ValueError, match="exactly the evidence-gate tools"):
        anchor.validate_candidate(missing)

    extended = deepcopy(value)
    extended["passed"] = True
    with pytest.raises(ValueError, match="invalid schema"):
        anchor.validate_candidate(extended)


def test_proposed_mapping_must_exactly_match_observed_tool_digests():
    value = candidate()
    value["proposed_trust_entry"][value["platform"]]["bash"] = "f" * 64
    with pytest.raises(ValueError, match="differs from observed"):
        anchor.validate_candidate(value)


def test_missing_different_or_extra_committed_mapping_fails_closed():
    value = candidate()
    observed = value["proposed_trust_entry"][value["platform"]]
    with pytest.raises(ValueError, match="not anchored"):
        anchor.require_trusted_mapping(value, None)
    different = dict(observed)
    different["bash"] = "f" * 64
    with pytest.raises(ValueError, match="differ"):
        anchor.require_trusted_mapping(value, different)
    extra = {**observed, "unexpected": "e" * 64}
    with pytest.raises(ValueError, match="differ"):
        anchor.require_trusted_mapping(value, extra)
    anchor.require_trusted_mapping(value, observed)
