import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import guard_release_index as index  # noqa: E402


FIRST = "tinyzkp-guard/1.0.0+guard." + "a" * 40
SECOND = "tinyzkp-guard/1.1.0+guard." + "b" * 40
KEY_RAW = b"test-public-key\n"


def artifact(version: str) -> dict:
    name = f"tinyzkp-guard-{version}-x86_64-linux.tar.gz"
    base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{version}"
    )
    return {"name": name, "url": f"{base}/{name}", "sha256": "c" * 64}


def entry(
    version: str,
    identity: str,
    *,
    state: str,
    successor: str | None,
    advisory: str | None = None,
) -> dict:
    base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{version}"
    )
    return {
        "guard_version": version,
        "release_identity": identity,
        "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
        "release_date": "2026-07-18",
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_sha256": "d" * 64,
        "artifacts": [artifact(version)],
        "state": state,
        "successor_release_identity": successor,
        "advisory_url": advisory,
    }


def prior_index() -> dict:
    return {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": SECOND,
        "releases": [
            entry("1.0.0", FIRST, state="superseded", successor=SECOND),
            entry("1.1.0", SECOND, state="current", successor=None),
        ],
    }


def raw(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def handoff(prior: dict, revised: dict, *, target: str, replacement: str | None):
    return {
        "schema_version": 1,
        "document_type": "GuardReleaseIndexRevisionHandoffV1",
        "private_repository": "logannye/tinyzkp-guard",
        "private_run_id": "123456789",
        "private_source_sha": "e" * 40,
        "prior_index_sha256": hashlib.sha256(raw(prior)).hexdigest(),
        "revised_index_sha256": hashlib.sha256(raw(revised)).hexdigest(),
        "target_release_identity": target,
        "replacement_current_release_identity": replacement,
        "signer_public_key_sha256": hashlib.sha256(KEY_RAW).hexdigest(),
        "signature_format": "cosign-raw-signature-v1",
    }


def test_non_current_withdrawal_preserves_successor() -> None:
    prior = prior_index()
    revised = copy.deepcopy(prior)
    revised["releases"][0].update(
        {
            "state": "withdrawn",
            "advisory_url": "https://tinyzkp.com/security/advisories/guard-1-0",
        }
    )
    metadata = handoff(prior, revised, target=FIRST, replacement=None)
    index.validate_transition(prior, revised, metadata)


def test_current_withdrawal_rolls_back_only_to_named_replacement() -> None:
    prior = prior_index()
    revised = copy.deepcopy(prior)
    revised["current_release_identity"] = FIRST
    revised["releases"][0].update(
        {"state": "current", "successor_release_identity": None}
    )
    revised["releases"][1].update(
        {
            "state": "withdrawn",
            "successor_release_identity": FIRST,
            "advisory_url": (
                "https://github.com/logannye/hc-stark/security/advisories/GHSA-test"
            ),
        }
    )
    metadata = handoff(prior, revised, target=SECOND, replacement=FIRST)
    index.validate_transition(prior, revised, metadata)


def test_withdrawn_advisory_update_changes_only_url() -> None:
    prior = prior_index()
    prior["releases"][0].update(
        {
            "state": "withdrawn",
            "advisory_url": "https://tinyzkp.com/security/advisories/old",
        }
    )
    revised = copy.deepcopy(prior)
    revised["releases"][0]["advisory_url"] = (
        "https://tinyzkp.com/security/advisories/revised"
    )
    metadata = handoff(prior, revised, target=FIRST, replacement=None)
    index.validate_transition(prior, revised, metadata)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda revised: revised["releases"][1].__setitem__(
                "channel_sha256", "f" * 64
            ),
            "immutable history",
        ),
        (
            lambda revised: revised["releases"].reverse(),
            "full release-index order",
        ),
        (
            lambda revised: revised["releases"][0].__setitem__(
                "successor_release_identity", None
            ),
            "recommendation history",
        ),
    ],
)
def test_rejects_unrelated_or_history_changes(mutation, message: str) -> None:
    prior = prior_index()
    revised = copy.deepcopy(prior)
    revised["releases"][0].update(
        {
            "state": "withdrawn",
            "advisory_url": "https://tinyzkp.com/security/advisories/test",
        }
    )
    mutation(revised)
    metadata = handoff(prior, revised, target=FIRST, replacement=None)
    with pytest.raises(index.IndexError, match=message):
        index.validate_transition(prior, revised, metadata)


@pytest.mark.parametrize(
    "url",
    [
        "http://tinyzkp.com/security/advisories/test",
        "https://evil.example/advisory",
        "https://github.com/other/repo/advisory",
        "https://tinyzkp.com/security/advisories/test?secret=1",
        "https://user@tinyzkp.com/security/advisories/test",
        "https://tinyzkp.com:444/security/advisories/test",
        "https://tinyzkp.com/security/advisories/test#fragment",
        "https://tinyzkp.com/security/advisories/test\\evil",
    ],
)
def test_rejects_unsafe_advisory_urls(url: str) -> None:
    value = prior_index()
    value["releases"][0].update({"state": "withdrawn", "advisory_url": url})
    with pytest.raises(index.IndexError, match="advisory"):
        index.validate_index(value, "index")


def test_handoff_binds_exact_bytes_key_and_run() -> None:
    prior = prior_index()
    revised = copy.deepcopy(prior)
    revised["releases"][0].update(
        {
            "state": "withdrawn",
            "advisory_url": "https://tinyzkp.com/security/advisories/test",
        }
    )
    metadata = handoff(prior, revised, target=FIRST, replacement=None)
    assert (
        index.validate_handoff(
            metadata,
            prior_raw=raw(prior),
            revised_raw=raw(revised),
            public_key_sha256=hashlib.sha256(KEY_RAW).hexdigest(),
            expected_private_run_id="123456789",
        )
        == metadata
    )
    metadata["private_repository"] = "attacker/repo"
    with pytest.raises(index.IndexError, match="identity differs"):
        index.validate_handoff(
            metadata,
            prior_raw=raw(prior),
            revised_raw=raw(revised),
            public_key_sha256=hashlib.sha256(KEY_RAW).hexdigest(),
            expected_private_run_id="123456789",
        )
