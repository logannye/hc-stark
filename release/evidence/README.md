# Backend v1 evidence

`backend-v1-evidence.json` is generated only for a concrete release candidate.
It is intentionally absent while the release is blocked. Every referenced
artifact must be repository-relative, non-symlinked, and bound by SHA-256.

Candidate and final release identities are deliberately distinct. Candidate
artifacts bind `release_sha` to the reviewed source commit and the builder
derives `source_tree_sha256` from Git while excluding only
`release/backend-v1-gates.json` and `release/evidence/`. The evidence/config
commit therefore cannot create a commit-SHA self-reference. Signed finalization
records that candidate SHA as `source_release_sha`, records the immutable tag
commit as `release_sha`, proves the source commit is its ancestor, rejects every
non-evidence path in the transition, and requires both commits to have the same
stable source-tree digest. Both release jobs use full Git history so this proof
cannot silently degrade under a shallow checkout.

Release evidence has two explicit stages. A candidate config has `status` set
to `candidate` and contains exactly the fourteen gates that can exist before
artifact signing; validate it with `backend_prerelease_ready.py`. The backend
release workflow then builds and signs the artifacts, verifies the Sigstore
bundle, and runs `finalize_signed_evidence.py`. That command is the only
supported way to add the signed-release gate and emit the final `ready` config.
The full `backend_release_ready.py` gate is rerun against those generated files
before a draft release can be created.

After that independent rerun succeeds, `build_commercial_authorization.py`
revalidates the final config/evidence, the signed checksum manifest, the SPDX
SBOM, and the frozen Sigstore workflow identity. It emits an owner-only typed
release-ready report plus the exact eleven-field commercial authorization
consumed by TinyZKP annual contract billing. The authorization binds the final
release SHA, stable source-tree digest, final evidence, validator report,
signed checksum manifest, and Sigstore bundle by SHA-256. Both new files are
included in the release workflow's GitHub artifact attestation. The workflow
also keyless-signs the authorization itself and immediately verifies the
resulting `backend-v1-commercial-authorization.sigstore.json` against the
frozen release-workflow identity and GitHub OIDC issuer. The billing operator
must install and independently verify both files. They are not
inserted into the already signed checksum manifest, which would introduce an
ordering/self-reference cycle. An operator must verify the GitHub attestation,
install the authorization with mode `0600`, recompute its SHA-256 locally, and
configure that exact digest. A handwritten authorization is not a supported
release path.

Signed finalization requires the checksum manifest to cover every production
CLI/API/MCP binary, the maintenance OCI archive, compatibility profile,
candidate gate file, embedded CLI identity, and a valid SPDX JSON SBOM. Cosign
verification pins both GitHub's OIDC issuer and the TinyZKP
`release-backend.yml@refs/tags/backend-v*` workflow certificate identity; a
valid signature from an unrelated keyless principal is rejected.

Crate and SDK publication redownload every checksummed artifact and perform a
complete checksum verification without `--ignore-missing`. They repeat the
pinned Cosign identity/issuer check, verify the GitHub attestations for final
evidence and config against the release workflow, tag ref, source digest, and
GitHub-hosted runner policy, and require both the tag target and checked-out
`HEAD` to equal the final evidenced SHA. Downstream WASM and MCP builds check
out that SHA directly rather than resolving the tag again.

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
bundle command rejects a missing, malformed, or symlinked SBOM. `--release-sha`
must be the full canonical Git commit identifier: mutable refs such as `HEAD`,
branch names, tags, and abbreviated object IDs are rejected. Every source file
in the ZIP is read from that commit's Git blobs rather than from the worktree,
and the review manifest records the same stable `source_tree_sha256` used by
candidate evidence.

Review-manifest schema v2 records `source_sha256`/`source_bytes` for the exact
input artifact and `archive_sha256`/`archive_bytes` for the bytes actually
placed in the ZIP. They are identical for committed source. Optional JSON and
text evidence may replace absolute repository/home paths with `$REPO` and
`$HOME`; those entries set `normalized: true` while retaining both digests, so
reviewers can distinguish a portable review copy from the original hashed
release evidence. The bundle includes the source-tree identity implementation
and its tests as part of the reviewed release machinery:

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
The fixed-host harness additionally records and enforces exactly eight logical
CPUs, 16-GB-class RAM, non-rotational NVMe, at least 500 GB available before
the run, and a runner-owned mode-0700 scratch root. Run
`scripts/benchmark/fixed_host_preflight.py` before any expensive proof; the
same facts are embedded in and revalidated from every `BenchmarkReportV1`.

Independent reproduction is a separate release gate, not a metadata flag on
TinyZKP's own benchmark. It requires a hashed `reproduction_record` plus both
workloads at both resource gates, nested under `one_million_` and
`ten_million_` before the workload-prefixed roles. The record binds the
reproducer, organization, release, profile, workloads, completion time, and
official-verification result. It also contains an exact `artifact_sha256` map
for every independently produced resource artifact; co-locating unbound files
is not sufficient.

Each external review requires separately hashed `review_bundle`,
`review_report`, and `remediation_ledger` roles. The ledger is
release/profile/scope-bound and uses stable finding IDs.
`review_bundle_sha256`, `review_manifest_sha256`, and `source_tree_sha256` bind
the reviewer to the deterministic bundle, its embedded manifest, and the exact
candidate source tree; `review_report_sha256` binds the resulting report bytes.
The release gate independently opens the ZIP and recomputes all four hashes.
Critical/high findings pass only when their status is
`remediated` and `reviewer_verified` is true; risk acceptance cannot waive a
release-blocking finding.

Crash/recovery evidence uses both `crash_matrix` and `fuzz_smoke` roles,
separately hashed `crash_tool_identity` and `fuzz_tool_identity` provenance
records, and a separately hashed, uniquely pathed log role for every crash case
and fuzz target. The provenance records capture the exact `-Vv` command,
canonical executable path, executable SHA-256, full version output, frozen
toolchain, source identity, and sanitized-environment digest. The
crash matrix must contain every durable phase, the integrity cases, and the
Linux disk-full recovery case from `scripts/release/run_crash_matrix.py`.
Release-mode crash execution refuses an arbitrary directory: use
`run_crash_matrix_disk_full.sh`, which creates a bounded 128 MiB loop device,
mounts it with `nodev,nosuid,noexec`, makes it owner-only, and cleans it up.
The Python runner independently requires an exact mount point on a different
device, a 64--512 MiB capacity, an empty supported filesystem, and an
owner-only directory before creating its hashed mount sentinel. This prevents
a mistyped disk-full test from exhausting the fixed host's root filesystem.
Every crash log must prove that the exact named Rust test ran once and passed;
Cargo's successful zero-test result is not release evidence.
The disk-full test captures the first failed write and requires Linux error 28
(`ENOSPC`) before it can emit its successful-resume marker; permission, I/O, or
quota failures cannot masquerade as disk exhaustion. Fuzz smoke must include
all nine backend targets, each run from the deterministic,
version-controlled seed sample emitted by `scripts/release/run_fuzz_smoke.py`; a report
that omits its profile, exact Rust/cargo-fuzz identities, or corpus/log digests
does not pass. The validator parses each hashed log and requires LibFuzzer's
DONE marker, elapsed time, executed-unit total, and peak RSS to agree with the
machine report; a claimed duration or arbitrary success log is insufficient.
The final DONE counter, final run count, and final executed-unit statistic must
all agree, and measured process duration must cover LibFuzzer's claimed elapsed
time. Each log also contains exactly one target/corpus/toolchain marker, and
all target commands must use one canonical execution/corpus/artifact root.
Each target embeds the ordered seed sizes and SHA-256 digests so the validator
can recompute the exact corpus descriptor from the committed fixtures. Reports,
cases, targets, and tool records use closed schemas; noncanonical JSON types,
oversized or concurrently changed artifacts, reused paths, and noncanonical
disk device identities fail closed. Both runners require a clean canonical
`HC_RELEASE_SHA == HEAD`, bind
the stable source-tree and dependency-lock digests, execute through hashed
Cargo/Rust identities under a minimal offline environment, and recheck source
identity after execution. Build overrides such as `RUSTFLAGS`, wrappers, target
directories, sanitizer options, and injected libraries are not inherited.
Per-process deadlines kill the entire child process group on timeout.
LibFuzzer discoveries use a separate disposable corpus, while
crash artifacts and all evidence files remain owner-only. Cargo-fuzz is pinned
to `0.13.2` and the fuzz compiler/toolchain to
`nightly-2026-04-15`; changing either requires an explicit evidence-policy
update. Short or disk-full-free diagnostics require explicit `--partial`;
incomplete runs exit nonzero by default and can never set the release-eligible
field.
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
findings so remediation can proceed, but requires `--review-bundle` and an
exact canonical source commit and refuses a bundle/source mismatch. The final
release gate still rejects every unresolved critical/high item.
