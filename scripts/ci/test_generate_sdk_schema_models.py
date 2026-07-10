import generate_sdk_schema_models as generator


def test_models_are_deterministic_and_check_detects_drift(tmp_path):
    root = generator.Path(__file__).resolve().parents[2]
    definitions, roots, digest = generator.load_contracts(root / "site/schemas")
    python = generator.render_python(definitions, roots, digest)
    typescript = generator.render_typescript(definitions, roots, digest)
    assert "class WorkloadManifestV1Model(TypedDict)" in python
    assert "export interface ProofBundleV1" in typescript
    assert "export type UInt64 = number | bigint;" in typescript
    assert "public_values: Array<UInt64>;" in typescript

    python_path = tmp_path / "schema_models.py"
    typescript_path = tmp_path / "schema-models.ts"
    assert generator.write_or_check(python_path, python, False)
    assert generator.write_or_check(typescript_path, typescript, False)
    assert generator.write_or_check(python_path, python, True)
    python_path.write_text("drift\n", encoding="utf-8")
    assert not generator.write_or_check(python_path, python, True)
