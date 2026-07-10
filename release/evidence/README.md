# Backend v1 evidence

`backend-v1-evidence.json` is generated only for a concrete release candidate.
It is intentionally absent while the release is blocked. Every referenced
artifact must be repository-relative, non-symlinked, and bound by SHA-256.

Release evidence has two explicit stages. A candidate config has `status` set
to `candidate` and contains exactly the fourteen gates that can exist before
artifact signing; validate it with `backend_prerelease_ready.py`. The backend
release workflow then builds and signs the artifacts, verifies the Sigstore
bundle, and runs `finalize_signed_evidence.py`. That command is the only
supported way to add the signed-release gate and emit the final `ready` config.
The full `backend_release_ready.py` gate is rerun against those generated files
before a draft release can be created.

Signed finalization requires the checksum manifest to cover every production
CLI/API/MCP binary, the maintenance OCI archive, compatibility profile,
candidate gate file, embedded CLI identity, and a valid SPDX JSON SBOM. Cosign
verification pins both GitHub's OIDC issuer and the TinyZKP
`release-backend.yml@refs/tags/backend-v*` workflow certificate identity; a
valid signature from an unrelated keyless principal is rejected.

Do not hand-author digests. Run `build_candidate_evidence.py template` to create
an unhashed input skeleton, fill its required metadata/roles, then run
`build_candidate_evidence.py build`. The builder rejects manual digest/pass
fields, unknown or missing gates, duplicate roles, symlinks, unsafe paths, and
semantically invalid evidence before emitting an owner-only candidate manifest
and config.

For source, compatibility, verifier, deterministic-proof, and SDK gates, run
the exact template command through `run_evidenced_command.py`. The resulting
`test_report` binds the command, release SHA, compatibility profile, execution
profile, exit status, timestamps, duration, and SHA-256 of the separately
hashed `test_log`; typed metadata alone cannot claim a successful test run.

Release-identity evidence must use the `identity_report` role. Generate it with
`release_identity_check.py --expected-sha <sha> --cli-release-file <file>
--benchmark-report <report> --output <file>`. The checker reads the deployed
site, API, and MCP identities, binds the local CLI and optional benchmark to the
same release, rejects package-version skew, and writes the typed report with
owner-only permissions. A manually copied identity map is not sufficient.

Generate the deterministic preliminary Rust dependency SBOM, then use
`scripts/release/build_review_bundle.py` to assemble review materials. The
bundle command rejects a missing, malformed, or symlinked SBOM:

```bash
created="$(git show -s --format=%cI "$HC_RELEASE_SHA")"
python3 scripts/release/build_preliminary_sbom.py \
  --release-sha "$HC_RELEASE_SHA" \
  --created "$created" \
  --output raw-reports/tinyzkp-backend-preliminary.spdx.json
python3 scripts/release/build_review_bundle.py \
  --release-sha "$HC_RELEASE_SHA" \
  --sbom raw-reports/tinyzkp-backend-preliminary.spdx.json \
  --output raw-reports/tinyzkp-backend-review.zip
```

External review and design-partner records must be added by an authorized
operator; the gate rejects handwritten `passed: true` flags.

Resource evidence must include both Fibonacci and Poseidon2. Prefix every role
with `fibonacci_` or `poseidon2_`: `manifest`, `candidate_report`, and
`candidate_normalized_manifest`; the one-million gate also requires each
workload's `baseline_report` and `baseline_normalized_manifest`. The gate
recomputes every digest and permits normalization to change only `scratch_dir`.

Independent reproduction is a separate release gate, not a metadata flag on
TinyZKP's own benchmark. It requires a hashed `reproduction_record` plus both
workloads at both resource gates, nested under `one_million_` and
`ten_million_` before the workload-prefixed roles. The record binds the
reproducer, organization, release, profile, workloads, completion time, and
official-verification result. It also contains an exact `artifact_sha256` map
for every independently produced resource artifact; co-locating unbound files
is not sufficient.

Each external review requires separately hashed `review_report` and
`remediation_ledger` roles. The ledger is release/profile/scope-bound and uses
stable finding IDs, and `review_report_sha256` binds it to the reviewed report
bytes. Critical/high findings pass only when their status is
`remediated` and `reviewer_verified` is true; risk acceptance cannot waive a
release-blocking finding.

Crash/recovery evidence uses both `crash_matrix` and `fuzz_smoke` roles. The
crash matrix must contain every durable phase, the integrity cases, and the
Linux disk-full recovery case from `scripts/release/run_crash_matrix.py`. Fuzz
smoke must include all nine backend targets, each run from the deterministic,
version-controlled seed sample emitted by `scripts/release/run_fuzz_smoke.py`; a report
that omits its profile, exact Rust/cargo-fuzz identities, or corpus/log digests
does not pass. LibFuzzer discoveries use a separate disposable corpus, while
crash artifacts and all evidence files remain owner-only. Cargo-fuzz is pinned
to `0.13.2`; changing it requires an explicit evidence-policy update.
Design-partner evidence requires three
separately hashed roles: `adapter_result`, `resource_report`, and
`acceptance_record`. All three are machine-readable and release-bound. The
acceptance record contains an opaque partner/acceptance ID, acceptance time,
official-verification and bounded/conventional results, witness-data policy,
and the SHA-256 digests of the adapter and resource artifacts. Customer witness
data must never appear in any evidence file.

Generate the externally owned machine records without hand-copying digests:

```bash
python3 scripts/release/build_external_records.py review-ledger --help
python3 scripts/release/build_external_records.py reproduction --help
python3 scripts/release/build_external_records.py partner-acceptance --help
```

The reproduction command validates all four fixed-host workload gates before
writing its record. Partner acceptance validates the adapter and resource
artifacts before preserving the record. Review-ledger generation permits open
findings so remediation can proceed, but the final release gate still rejects
every unresolved critical/high item.
