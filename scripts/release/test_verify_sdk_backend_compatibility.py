from pathlib import Path

import verify_sdk_backend_compatibility as compatibility


SCHEMA = b'{"schema_version":1}\n'


def write_tree(root: Path, *, stream: str = "0.1.0", plonky3: str = "0.1.0") -> None:
    (root / "site/schemas").mkdir(parents=True)
    (root / "crates/hc-stream").mkdir(parents=True)
    (root / "crates/hc-plonky3").mkdir(parents=True)
    (root / "clients/rust").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\n[workspace.package]\nversion = "0.1.0"\n', encoding="utf-8"
    )
    for schema in compatibility.SCHEMAS:
        (root / "site/schemas" / schema).write_bytes(SCHEMA)
    (root / "crates/hc-stream/Cargo.toml").write_text(
        f'[package]\nname = "hc-stream"\nversion = "{stream}"\n', encoding="utf-8"
    )
    (root / "crates/hc-plonky3/Cargo.toml").write_text(
        f'[package]\nname = "hc-plonky3"\nversion = "{plonky3}"\n', encoding="utf-8"
    )
    (root / "clients/rust/Cargo.toml").write_text(
        "[package]\nname = \"tinyzkp\"\nversion = \"1.0.0\"\n"
        "[dependencies]\n"
        f'hc-stream = {{ version = "{stream}" }}\n'
        f'hc-plonky3 = {{ version = "{plonky3}" }}\n',
        encoding="utf-8",
    )


def test_matching_contracts_and_dependencies_pass(tmp_path):
    sdk = tmp_path / "sdk"
    backend = tmp_path / "backend"
    write_tree(sdk)
    write_tree(backend)
    assert compatibility.failures(backend, sdk_root=sdk) == []


def test_schema_and_dependency_skew_fail(tmp_path):
    sdk = tmp_path / "sdk"
    backend = tmp_path / "backend"
    write_tree(sdk)
    write_tree(backend, plonky3="0.1.1")
    (backend / "site/schemas/proof-bundle-v1.schema.json").write_bytes(b"different")
    failures = compatibility.failures(backend, sdk_root=sdk)
    assert any("proof-bundle-v1" in failure for failure in failures)
    assert any("hc-plonky3" in failure for failure in failures)
