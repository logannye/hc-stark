from copy import deepcopy

import pytest

import fuzz_tool_anchor as anchor
import run_fuzz_smoke


DIGEST = "a" * 64


def candidate():
    return {
        "schema_version": 1,
        "release_sha": "1" * 40,
        "source_tree_sha256": "2" * 64,
        "dependency_lock_sha256": "3" * 64,
        "rust_toolchain_sha256": "4" * 64,
        "status": "unreviewed",
        "review_required": True,
        "toolchain": run_fuzz_smoke.FUZZ_TOOLCHAIN,
        "host": "x86_64-unknown-linux-gnu",
        "cargo_identity": {
            "path": "/reviewed/cargo",
            "sha256": "5" * 64,
            "version": "cargo 1.95.0\nhost: x86_64-unknown-linux-gnu",
        },
        "rustc_identity": {
            "path": "/reviewed/rustc",
            "sha256": "6" * 64,
            "version": "rustc 1.95.0",
        },
        "cargo_fuzz_identity": {
            "path": "/reviewed/cargo-fuzz",
            "sha256": DIGEST,
            "version": run_fuzz_smoke.CARGO_FUZZ_VERSION,
        },
        "trust_path": anchor.TRUST_PATH,
        "proposed_trust_entry": {"x86_64-unknown-linux-gnu": DIGEST},
    }


def test_candidate_is_explicitly_unreviewed_and_closed_schema():
    value = candidate()
    assert anchor.validate_candidate(value) == value

    promoted = deepcopy(value)
    promoted["status"] = "trusted"
    with pytest.raises(ValueError, match="cannot represent trusted state"):
        anchor.validate_candidate(promoted)

    extended = deepcopy(value)
    extended["passed"] = True
    with pytest.raises(ValueError, match="invalid schema"):
        anchor.validate_candidate(extended)


def test_candidate_digest_must_match_the_proposed_trust_entry():
    value = candidate()
    value["proposed_trust_entry"][value["host"]] = "b" * 64
    with pytest.raises(ValueError, match="does not match"):
        anchor.validate_candidate(value)


def test_missing_or_different_committed_anchor_fails_closed():
    value = candidate()
    with pytest.raises(ValueError, match="not anchored"):
        anchor.require_trusted_digest(value, None)
    with pytest.raises(ValueError, match="does not match"):
        anchor.require_trusted_digest(value, "b" * 64)
    anchor.require_trusted_digest(value, DIGEST)


def test_cargo_host_requires_one_canonical_host_line():
    assert (
        anchor.cargo_host("cargo 1.95.0\nhost: x86_64-unknown-linux-gnu")
        == "x86_64-unknown-linux-gnu"
    )
    with pytest.raises(ValueError, match="exactly one"):
        anchor.cargo_host("cargo 1.95.0")
    with pytest.raises(ValueError, match="exactly one"):
        anchor.cargo_host("host: first\nhost: second")


def test_nightly_captures_then_verifies_before_expensive_evidence():
    workflow = (anchor.ROOT / ".github/workflows/nightly-backend.yml").read_text(
        encoding="utf-8"
    )
    capture = workflow.index("fuzz_tool_anchor.py capture")
    verify = workflow.index("fuzz_tool_anchor.py verify")
    expensive = workflow.index("Randomized proof equality through 2^18")
    assert capture < verify < expensive
    for job in (
        "fuzz-tool-anchor:",
        "proof-equality:",
        "scratch-calibration:",
        "crash-matrix:",
        "fuzz-smoke:",
        "nightly-evidence-complete:",
    ):
        assert job in workflow
    assert "timeout-minutes: 720" not in workflow
    assert "cancel-in-progress: false" in workflow
