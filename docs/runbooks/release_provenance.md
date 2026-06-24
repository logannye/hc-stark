# TinyZKP release provenance runbook

Status: active operator runbook for SDK, verifier, and MCP release artifacts.

TinyZKP release artifacts should be traceable back to a tagged GitHub Actions
run in `logannye/hc-stark`. The release workflow publishes packages and creates
GitHub artifact attestations for build outputs before upload.

## What is covered

| Artifact | Release job | Provenance mechanism |
|---|---|---|
| Python SDK (`tinyzkp`) | `publish-python` | GitHub artifact attestation for `clients/python/dist/*` before `twine upload` |
| TypeScript SDK (`tinyzkp`) | `publish-typescript` | `npm publish --provenance --access public` |
| Rust SDK (`tinyzkp`) | `publish-rust` | GitHub artifact attestation for `clients/rust/target/package/*.crate` before `cargo publish` |
| WASM verifier (`@tinyzkp/verify`) | `publish-wasm` | GitHub artifact attestation for `crates/hc-wasm/pkg/**` plus `npm publish --provenance --access public` |
| MCP binaries | `build-mcp-binaries` | SHA-256 checksum file plus GitHub artifact attestation using `subject-checksums` |

The workflow uses GitHub OIDC (`id-token: write`) and artifact-attestation
permissions (`attestations: write`) so downstream users can verify that the
artifact came from the tagged release workflow, not a local machine.

## Required registry setup

- npm: packages must allow provenance publishing from GitHub Actions. Keep
  `NPM_TOKEN` until the packages are fully moved to npm Trusted Publishing.
- PyPI: the current workflow still uses `PYPI_TOKEN` for upload. Configure a
  PyPI Trusted Publisher for `.github/workflows/publish-sdks.yml` before
  removing that secret.
- crates.io: `CRATES_IO_TOKEN` is still required; GitHub artifact attestation
  covers the packaged `.crate` file before publish.
- GitHub Releases: `GITHUB_TOKEN` with `contents: write` uploads MCP binaries
  and checksum files.

## Release checklist

1. Confirm `CHANGELOG.md` contains the release notes.
2. Confirm `docs/governance/release_policy.md` gates pass for the changed
   release surface.
3. Tag the release from the reviewed commit:

   ```sh
   git tag -s vX.Y.Z -m "TinyZKP vX.Y.Z"
   git push origin vX.Y.Z
   ```

   If a GPG signing key is not configured on the release machine, use an
   unsigned tag only after recording that exception in the release notes.

4. Watch `.github/workflows/publish-sdks.yml` until every package job either
   publishes or fails safely before upload.
5. Download MCP release assets and verify checksums:

   ```sh
   shasum -a 256 -c hc-mcp-linux-x86_64.sha256
   ```

6. Verify artifact attestations with GitHub CLI:

   ```sh
   gh attestation verify hc-mcp-linux-x86_64-stdio -R logannye/hc-stark
   gh attestation verify hc-mcp-linux-x86_64-http -R logannye/hc-stark
   gh attestation verify tinyzkp-*.crate -R logannye/hc-stark
   ```

7. Verify package registries show the new versions:

   ```sh
   npm view tinyzkp version
   npm view @tinyzkp/verify version
   python3 -m pip index versions tinyzkp
   cargo search tinyzkp --limit 1
   ```

8. Run the production reconciliation canary after deploying any matching
   API/MCP/site changes:

   ```sh
   ./scripts/ci/reconciliation_invariants.sh --live
   ```

## Failure handling

- If attestation fails before publish, stop the release and do not upload the
  artifact manually.
- If publish succeeds but attestation upload fails, keep the package live only
  if the package registry has its own provenance entry or the artifact is
  otherwise low-risk. Open a release incident and regenerate the affected
  artifact from the same commit if possible.
- If an MCP binary checksum does not verify, delete the GitHub release asset
  and rerun the release job from the tag.
- Never replace a package version in place. Publish a new patch version with a
  changelog entry and incident note.

## References

- GitHub artifact attestations:
  https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- npm provenance:
  https://docs.npmjs.com/generating-provenance-statements/
- PyPI Trusted Publishing:
  https://docs.pypi.org/trusted-publishers/using-a-publisher/
