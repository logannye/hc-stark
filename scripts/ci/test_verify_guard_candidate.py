import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

import verify_guard_candidate as verifier


IDENTITY = {
    "guard_version": "1.0.0",
    "guard_source_sha": "a" * 40,
    "engine_source_sha": "b" * 40,
    "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
}
ENGINE_ARTIFACT = "c" * 64
RELEASE_IDENTITY = verifier.expected_release_identity(IDENTITY, ENGINE_ARTIFACT)
PUBLIC_AUTHORIZATION_COMMIT = "f" * 40
CATALOG_POLICY = copy.deepcopy(verifier.MERCHANT_CATALOG_POLICY)
LEGAL = {
    "release_date": "2026-07-18",
    "eula_sha256": "8" * 64,
    "eula_url": f"https://tinyzkp.com/legal/{'8' * 64}/EULA.txt",
    "notices_sha256": "9" * 64,
}
MERCHANT_CATALOG = {
    "merchant": "lemon_squeezy",
    "mode": "live",
    "store_id": "102",
    "product_id": "202",
    "monthly_variant_id": "401",
    "annual_variant_id": "402",
    "monthly_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/monthly-live?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "annual_checkout_url": (
        "https://lnholdings.lemonsqueezy.com/checkout/buy/annual-live?"
        "checkout%5Bcustom%5D%5Bterms_version%5D=2026-07-18&"
        "checkout%5Bcustom%5D%5Bguard_version%5D=1.0.0"
    ),
    "customer_portal_url": "https://lnholdings.lemonsqueezy.com/billing",
    "store_hostname": "lnholdings.lemonsqueezy.com",
    "catalog_policy": CATALOG_POLICY,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def add_bytes(archive, name, raw):
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    member.mode = 0o644
    archive.addfile(member, io.BytesIO(raw))


def add_directory(archive, name):
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    archive.addfile(member)


def authorization_fixture(state: str, public_commit):
    return {
        "schema_version": 1,
        "document_type": "GuardCandidateBuildAuthorizationV1",
        "authorization_policy": "owner_only_ga_v1",
        "qualification_basis": "owner_attested",
        "authorization_state": state,
        "authorization_scope": "prepare_signed_guard_draft_only",
        "commercial_release_authorized": False,
        "checkout_enabled": False,
        "public_gate_source_sha256": "1" * 64,
        "release_change_class": "proof_critical",
        "prior_qualified_release": None,
        "public_candidate_authorization_commit": public_commit,
        "release_identity": {
            "guard_release": "tinyzkp-guard-v1",
            **IDENTITY,
        },
        "expected_public_candidate_tag": "guard-v1.0.0",
        "engine": {"identity": "engine"},
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "legal_artifacts": {"identity": "legal"},
        "merchant_catalog": {"identity": "catalog"},
        "signing_trust": {"identity": "signing"},
        "reviewed_evidence": {
            "launch_evidence_sha256": "1" * 64,
            "launch_trust_policy_sha256": "2" * 64,
            "required_passed_gates": [
                "engine_release_ready",
                "legal_terms_approved",
                "merchant_sandbox_lifecycle_passed",
                "release_rehearsal_within_budget",
            ],
            "advisory_status": {
                "external_design_partner_integration": "not_completed",
                "five_unaided_installs": "not_completed",
                "implementation_review_no_high_findings": "not_completed",
                "independent_resource_reproduction": "not_completed",
                "plonky3_specialist_review": "not_completed",
                "three_external_workloads": "not_completed",
                "two_standard_annual_customers": "not_completed",
            },
        },
        "remaining_launch_blockers": ["guard_artifact_published"],
    }


def oci_fixture(
    path: Path,
    *,
    release_identity: str = RELEASE_IDENTITY,
    extra_labels: dict[str, str] | None = None,
):
    labels = {
        "org.opencontainers.image.title": "TinyZKP Guard",
        "org.opencontainers.image.source": "https://github.com/logannye/hc-stark",
        "org.opencontainers.image.version": IDENTITY["guard_version"],
        "org.opencontainers.image.revision": IDENTITY["guard_source_sha"],
        "org.opencontainers.image.tinyzkp.release-identity": release_identity,
        "org.opencontainers.image.tinyzkp.engine-revision": IDENTITY[
            "engine_source_sha"
        ],
        "org.opencontainers.image.tinyzkp.engine-artifact-sha256": ENGINE_ARTIFACT,
        "org.opencontainers.image.tinyzkp.profile": IDENTITY[
            "compatibility_profile"
        ],
    }
    labels.update(extra_labels or {})
    config_raw = canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {"Labels": labels},
        }
    )
    config_digest = hashlib.sha256(config_raw).hexdigest()
    manifest_raw = canonical(
        {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": len(config_raw),
            },
            "layers": [],
        }
    )
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    index_raw = canonical(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{manifest_digest}",
                    "size": len(manifest_raw),
                }
            ],
        }
    )
    with tarfile.open(path, "w") as archive:
        add_bytes(archive, "index.json", index_raw)
        add_bytes(archive, f"blobs/sha256/{config_digest}", config_raw)
        add_bytes(archive, f"blobs/sha256/{manifest_digest}", manifest_raw)
    return {
        "guard_version": IDENTITY["guard_version"],
        "guard_source_sha": IDENTITY["guard_source_sha"],
        "engine_source_sha": IDENTITY["engine_source_sha"],
        "engine_artifact_sha256": ENGINE_ARTIFACT,
        "release_identity": RELEASE_IDENTITY,
        "oci_digest": f"sha256:{manifest_digest}",
    }


def test_exact_oci_archive_identity_is_accepted(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(archive)
    verifier.verify_oci(archive, channel, IDENTITY)


def test_oci_archive_with_different_embedded_release_is_rejected(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(archive, release_identity="tinyzkp-guard/wrong")
    with pytest.raises(verifier.CandidateError, match="OCI labels differ"):
        verifier.verify_oci(archive, channel, IDENTITY)


def test_oci_archive_cannot_embed_a_mutable_launch_state(tmp_path):
    archive = tmp_path / "guard.oci.tar"
    channel = oci_fixture(
        archive,
        extra_labels={
            "org.opencontainers.image.tinyzkp.qualification": "public_live"
        },
    )
    with pytest.raises(verifier.CandidateError, match="OCI labels differ"):
        verifier.verify_oci(archive, channel, IDENTITY)


def test_buyer_release_bundle_inventory_and_documents_are_exact(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    version_raw = b'{"release":{"guard_version":"1.0.0"}}\n'
    compatibility_raw = b'{"schema_version":1}\n'
    (candidate / "version.json").write_bytes(version_raw)
    (candidate / "compatibility-manifest-v1.json").write_bytes(compatibility_raw)
    schema_raw = b'{}\n'
    for name in verifier.GUARD_SCHEMA_NAMES:
        (candidate / name).write_bytes(schema_raw)

    documents = {
        "README.md": b"reviewed buyer readme\n",
        "SECURITY.md": b"reviewed buyer security guidance\n",
        "INSTALL.md": b"reviewed buyer installation guidance\n",
        "START-HERE.txt": b"reviewed buyer start sequence\n",
    }
    monkeypatch.setitem(
        verifier.GUARD_PACKAGE_STATIC_DOCUMENT_SHA256,
        IDENTITY["guard_version"],
        {name: hashlib.sha256(raw).hexdigest() for name, raw in documents.items()},
    )
    eula = b"exact owner-approved eula\nEffective Date: 2026-07-18\n"
    notices = b"exact notices\n"
    engine = b"exact engine binary\n"
    public_key_sha256 = "6" * 64
    artifact_name = "tinyzkp-guard-1.0.0-linux-x86_64.tar.gz"
    legal = {
        "release_date": "2026-07-18",
        "eula_sha256": hashlib.sha256(eula).hexdigest(),
        "notices_sha256": hashlib.sha256(notices).hexdigest(),
    }
    channel = {
        "guard_version": IDENTITY["guard_version"],
        "engine_artifact_sha256": hashlib.sha256(engine).hexdigest(),
    }
    authorization = {
        "legal_artifacts": legal,
        "signing_trust": {"public_key_sha256": public_key_sha256},
    }
    root = "tinyzkp-guard-1.0.0-linux-x86_64"
    agreement = (
        "schema_version=1\n"
        "release_date=2026-07-18\n"
        f"eula_sha256={legal['eula_sha256']}\n"
        f"eula_url=https://tinyzkp.com/legal/{legal['eula_sha256']}/EULA.txt\n"
        "bundled_eula=legal/EULA.txt\n"
    ).encode()
    delivery = (
        "schema_version=1\n"
        "guard_version=1.0.0\n"
        "release_tag=guard-v1.0.0\n"
        f"artifact_name={artifact_name}\n"
        "artifact_url=https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v1.0.0/{artifact_name}\n"
        "receipt_confirmation_url=https://tinyzkp.com/releases\n"
        f"signing_public_key_sha256={public_key_sha256}\n"
    ).encode()
    base_files = {
        **documents,
        "AGREEMENT.txt": agreement,
        "DELIVERY.txt": delivery,
        "bin/tinyzkp": b"exact guard binary\n",
        "bin/tinyzkp-engine": engine,
        "compatibility-manifest-v1.json": compatibility_raw,
        "legal/EULA.txt": eula,
        "legal/THIRD-PARTY-NOTICES.txt": notices,
        "version.json": version_raw,
        **{f"schemas/{name}": schema_raw for name in verifier.GUARD_SCHEMA_NAMES},
        **{
            f"examples/{name}": b'{}\n'
            for name in verifier.GUARD_EXAMPLE_NAMES
        },
    }
    archive_path = tmp_path / artifact_name

    def write_archive(*, mutations=None, extra=None):
        files = dict(base_files)
        files.update(mutations or {})
        if extra is not None:
            files[extra] = b"unexpected\n"
        with tarfile.open(archive_path, "w:gz") as archive:
            for directory in (root, f"{root}/bin", f"{root}/examples", f"{root}/legal", f"{root}/schemas"):
                add_directory(archive, directory)
            for name, raw in sorted(files.items()):
                add_bytes(archive, f"{root}/{name}", raw)

    def verify():
        verifier.verify_release_bundle(
            archive_path,
            candidate_dir=candidate,
            artifact_name=artifact_name,
            channel=channel,
            authorization=authorization,
        )

    write_archive()
    verify()
    write_archive(mutations={"AGREEMENT.txt": agreement + b"unexpected=true\n"})
    with pytest.raises(verifier.CandidateError, match="AGREEMENT"):
        verify()
    write_archive(mutations={"START-HERE.txt": b"stale source repository copy\n"})
    with pytest.raises(verifier.CandidateError, match="buyer document"):
        verify()
    write_archive(extra="SOURCE-README.md")
    with pytest.raises(verifier.CandidateError, match="file inventory"):
        verify()


def test_candidate_authorization_a_is_bound_to_promotion_evidence_b():
    build = authorization_fixture("authorized", None)
    promotion = authorization_fixture(
        "candidate_prepared", PUBLIC_AUTHORIZATION_COMMIT
    )
    verifier.verify_build_authorization(
        build, promotion, PUBLIC_AUTHORIZATION_COMMIT
    )


def test_candidate_authorization_a_cannot_differ_on_immutable_input():
    build = authorization_fixture("authorized", None)
    promotion = authorization_fixture(
        "candidate_prepared", PUBLIC_AUTHORIZATION_COMMIT
    )
    build["merchant_catalog"] = {"identity": "different"}
    with pytest.raises(verifier.CandidateError, match="immutable build inputs"):
        verifier.verify_build_authorization(
            build, promotion, PUBLIC_AUTHORIZATION_COMMIT
        )
    build = authorization_fixture("authorized", None)
    build["reviewed_evidence"]["advisory_status"].pop("five_unaided_installs")
    with pytest.raises(verifier.CandidateError, match="source/evidence digest differs"):
        verifier.verify_build_authorization(
            build, promotion, PUBLIC_AUTHORIZATION_COMMIT
        )


def test_candidate_authorization_requires_owner_policy_and_advisory_ledger():
    build = authorization_fixture("authorized", None)
    promotion = authorization_fixture(
        "candidate_prepared", PUBLIC_AUTHORIZATION_COMMIT
    )
    build["authorization_policy"] = "outside_review_v1"
    with pytest.raises(verifier.CandidateError, match="immutable build inputs"):
        verifier.verify_build_authorization(
            build, promotion, PUBLIC_AUTHORIZATION_COMMIT
        )


def test_cross_repo_authorization_catalog_contract_is_exact_and_fail_closed():
    assert verifier.validate_authorization_merchant_catalog(
        copy.deepcopy(MERCHANT_CATALOG),
        legal=LEGAL,
        identity=IDENTITY,
    ) == MERCHANT_CATALOG

    for mutation in (
        "extra",
        "signed_portal",
        "empty_portal_query",
        "empty_portal_fragment",
        "empty_checkout_fragment",
        "wrong_terms",
        "same_checkout",
    ):
        catalog = copy.deepcopy(MERCHANT_CATALOG)
        if mutation == "extra":
            catalog["api_key"] = "must-never-cross"
        elif mutation == "signed_portal":
            catalog["customer_portal_url"] += "?signed=customer"
        elif mutation == "empty_portal_query":
            catalog["customer_portal_url"] += "?"
        elif mutation == "empty_portal_fragment":
            catalog["customer_portal_url"] += "#"
        elif mutation == "empty_checkout_fragment":
            catalog["monthly_checkout_url"] += "#"
        elif mutation == "wrong_terms":
            catalog["monthly_checkout_url"] = catalog["monthly_checkout_url"].replace(
                "2026-07-18", "2026-07-19"
            )
        else:
            catalog["annual_checkout_url"] = catalog["monthly_checkout_url"]
        with pytest.raises(verifier.CandidateError):
            verifier.validate_authorization_merchant_catalog(
                catalog,
                legal=LEGAL,
                identity=IDENTITY,
            )

def index_entry(
    version: str,
    release_identity: str,
    *,
    state: str = "current",
    successor=None,
):
    base = (
        "https://github.com/logannye/hc-stark/releases/download/"
        f"guard-v{version}"
    )
    return {
        "guard_version": version,
        "release_identity": release_identity,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
        "channel_url": f"{base}/guard-channel-v1.json",
        "channel_sha256": "7" * 64,
        "artifacts": [
            {
                "name": "guard.tar.gz",
                "url": f"{base}/guard.tar.gz",
                "sha256": "8" * 64,
            }
        ],
        "state": state,
        "successor_release_identity": successor,
        "advisory_url": None,
    }


def test_first_ga_index_cannot_smuggle_prior_history():
    channel = {
        "guard_version": IDENTITY["guard_version"],
        "release_identity": RELEASE_IDENTITY,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
    }
    artifact_map = {"guard.tar.gz": {"sha256": "8" * 64}}
    current = index_entry(IDENTITY["guard_version"], RELEASE_IDENTITY)
    index = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": RELEASE_IDENTITY,
        "releases": [current],
    }
    verifier.verify_index(
        index,
        channel,
        "7" * 64,
        artifact_map,
        prior_index=None,
        prior_index_sha256=None,
        expected_prior_identity=None,
    )
    index["releases"].insert(
        0,
        index_entry(
            "0.9.0",
            "tinyzkp-guard/prior",
            state="superseded",
            successor=RELEASE_IDENTITY,
        ),
    )
    with pytest.raises(verifier.CandidateError, match="first Guard GA"):
        verifier.verify_index(
            index,
            channel,
            "7" * 64,
            artifact_map,
            prior_index=None,
            prior_index_sha256=None,
            expected_prior_identity=None,
        )


def test_successor_index_preserves_every_prior_entry():
    prior_identity = "tinyzkp-guard/prior"
    older_identity = "tinyzkp-guard/older"
    prior_entries = [
        index_entry(
            "0.8.0",
            older_identity,
            state="superseded",
            successor=prior_identity,
        ),
        index_entry("0.9.0", prior_identity),
    ]
    prior = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": prior_identity,
        "releases": prior_entries,
    }
    successor_entries = copy.deepcopy(prior_entries)
    successor_entries[-1]["state"] = "superseded"
    successor_entries[-1]["successor_release_identity"] = RELEASE_IDENTITY
    successor_entries.append(index_entry("1.0.0", RELEASE_IDENTITY))
    successor = {
        "schema_version": 1,
        "product": "tinyzkp-guard",
        "current_release_identity": RELEASE_IDENTITY,
        "releases": successor_entries,
    }
    channel = {
        "guard_version": "1.0.0",
        "release_identity": RELEASE_IDENTITY,
        "compatibility_profile": IDENTITY["compatibility_profile"],
        "release_date": "2026-07-18",
    }
    verifier.verify_index(
        successor,
        channel,
        "7" * 64,
        {"guard.tar.gz": {"sha256": "8" * 64}},
        prior_index=prior,
        prior_index_sha256="9" * 64,
        expected_prior_identity=prior_identity,
    )
    successor["releases"].pop(0)
    with pytest.raises(verifier.CandidateError, match="prior Guard release index"):
        verifier.verify_index(
            successor,
            channel,
            "7" * 64,
            {"guard.tar.gz": {"sha256": "8" * 64}},
            prior_index=prior,
            prior_index_sha256="9" * 64,
            expected_prior_identity=prior_identity,
        )
