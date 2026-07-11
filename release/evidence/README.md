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

The SDK gate has a separate, explicit network preparation step. On the
reviewed CPython 3.12 glibc x86_64 host, materialize the ten committed Python
wheels and seven committed npm tarballs into separate empty owner-only
directories before starting evidence execution. Preparation rejects proxies,
redirects, URL skew, digest/size skew, and unsafe archive metadata. The evidence
runner never downloads dependencies. It copies verified bytes into sealed
Linux memfds, makes the mutable source directories inaccessible to the child,
and executes the SDK gate inside a fresh isolated IP network namespace plus the
Landlock write boundary. This boundary does not yet deny pathname Unix-domain
socket connections, so it is one of the explicit blockers below rather than a
complete no-network sandbox:

```bash
install -d -m 0700 release/evidence/sdk-python-wheelhouse
python3.12 scripts/ci/verify_sdk_python_wheelhouse.py materialize \
  --wheelhouse release/evidence/sdk-python-wheelhouse
python3.12 scripts/ci/verify_sdk_npm_tarballs.py \
  --materialize release/evidence/sdk-npm-tarballs
python3.12 scripts/release/run_evidenced_command.py \
  --gate replacement_sdk_contracts \
  --release-sha "$HC_RELEASE_SHA" \
  --sdk-python-wheelhouse release/evidence/sdk-python-wheelhouse \
  --sdk-npm-tarballs release/evidence/sdk-npm-tarballs \
  --report release/evidence/sdk-contracts/test-report.json \
  --log release/evidence/sdk-contracts/test.log
```

The wheelhouse location is not an authorization or dependency override. Every
byte and package field is recomputed from the exact release commit, and the
runner rejects extra files, path overlap, missing memfd seals, platform skew,
network-namespace failure, and the old environment-flag shortcut. npm is never
executed: the reviewed extractor creates `node_modules`, and the FD-held Node
interpreter invokes the exact TypeScript compiler and tests directly.

The SDK gate also requires the fixed Linux Python runtime to match the reviewed
committed anchor. The repository intentionally ships that anchor as
`unconfigured`. `python3.12 scripts/ci/capture_sdk_python_runtime.py` emits only
a read-only candidate; its output alone must not be promoted to `reviewed`.
Before promotion, the evidence host still needs a hermetic or immutable Python
runtime (including stdlib/shared libraries and the copied venv interpreter), a
dedicated unprivileged identity with no supplementary groups, and denial or
isolation of pathname Unix-domain sockets. These controls close same-UID
swap-and-restore and host-socket escape paths that aggregate pre/post hashing
cannot close.

Ambient Cargo state is also excluded: the runner supplies an empty private
`CARGO_HOME`, so user config, rustc wrappers, linker overrides, source
replacement, and mutable registry caches cannot affect evidence. Consequently,
the SDK gate remains fail-closed until Cargo dependencies are committed as a
reviewed vendor tree/config and wasm-pack's matching wasm-bindgen helper is
added to the committed tool inventory. The native linker, `cc`, `ar`, build
scripts, Rust sysroot libraries, and any other descendant executable must also
be hermetic or added to the reviewed inventory. Neither an ambient cache nor a
helper download can satisfy the SDK evidence gate.

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
release/profile/scope-bound and uses stable finding IDs. A Plonky3 specialist
ledger additionally requires a signed `security_assessment` for the exact
`FriParameters::new_benchmark` values. It records separate consideration of
conjectured and proven FRI bounds, duplicate-query probability, and challenger
capacity, plus the reviewer's minimum-bit conclusion, limitations, and explicit
production-use decision. Missing or negative approval blocks release; an
implementation-review ledger must leave this field null.
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

The cargo-fuzz executable itself is also a reviewed input. On the fixed Linux
evidence host, capture its candidate identity after installing the exact
version:

```bash
HC_RELEASE_SHA="$(git rev-parse HEAD)" \
  python3 scripts/release/fuzz_tool_anchor.py capture \
    --output raw-reports/cargo-fuzz-anchor-candidate.json
```

The candidate always says `status: unreviewed` and cannot authorize an
evidence run. An independent reviewer must reproduce it and deliberately add
the approved host/digest pair under
`toolchains.fuzz.cargo_fuzz_executables` in
`release/release-trust-v1.json` in a separate reviewed commit. The nightly
workflow then runs `fuzz_tool_anchor.py verify` before proof equality, crash,
or fuzz evidence. A missing or different committed anchor blocks the workflow
while preserving the candidate artifact for review; the verifier never copies
the freshly observed digest into trust.

The non-Rust executables used by the six evidence gates are reviewed inputs as
well. Run the capture tool under the exact fixed-host Python and PATH that will
execute the gates:

```bash
HC_RELEASE_SHA="$(git rev-parse HEAD)" \
  python3 scripts/release/gate_tool_anchor.py capture \
    --output release/evidence/work/gate-tool-anchor-candidate.json

HC_RELEASE_SHA="$(git rev-parse HEAD)" \
  python3 scripts/release/gate_tool_anchor.py verify \
    --candidate release/evidence/work/gate-tool-anchor-candidate.json
```

Capture derives the exact tool set from the frozen gate commands: `bash`,
`python3`, `node`, and `wasm-pack`. The candidate is owner-only and always
`unreviewed`; verification intentionally fails while the platform is absent
from `gate_tools.platforms`. After independent reproduction, add only the
reviewed platform-to-digest mapping in a separate trust commit. Verification
requires exact equality, including the absence of extra tools, and never
promotes freshly observed bytes into trust.

Design-partner evidence requires three
separately hashed roles: `adapter_result`, `resource_report`, and
`acceptance_record`. All three are machine-readable and release-bound. The
acceptance record contains an opaque partner/acceptance ID, acceptance time,
official-verification and bounded/conventional results, witness-data policy,
and the SHA-256 digests of the adapter and resource artifacts. Customer witness
data must never appear in any evidence file.

External truth is captured in two stages. Copy one of the tracked, deliberately
incomplete templates, have the named external party complete it, validate its
referenced evidence, and then capture the canonical claim:

```bash
python3 scripts/release/build_external_records.py template \
  --kind plonky3_specialist_review \
  --output release/evidence/work/plonky3-specialist-input.json
python3 scripts/release/build_external_records.py validate-input \
  --input release/evidence/work/plonky3-specialist-input.json
python3 scripts/release/build_external_records.py capture \
  --input release/evidence/work/plonky3-specialist-input.json \
  --output release/evidence/work/plonky3-specialist-ledger.json
```

`release/evidence/work/` is intentionally ignored except for its guard file;
completed inputs and returned signatures stay out of Git. Move only the
validated, sanitized claims and release artifacts into their final evidence
paths. Partner and acceptance IDs must be opaque `partner-<hex>` and
`acceptance-<hex>` tokens. Completed input files must be owned by the invoking
operator, have one hard link, and grant no group/other permissions (for
example, `chmod 600 <input>`).

The available kinds are `plonky3_specialist_review`,
`implementation_review`, `independent_reproduction`, and
`design_partner_acceptance`. The committed templates contain placeholders,
false conclusions, and `completion_status: incomplete`; both `validate-input`
and `capture` reject them unchanged. `capture` emits an owner-only **unsigned**
claim and never asserts, signs, or enrolls a reviewer on anyone's behalf. The
external signer must sign those exact claim bytes. Validate the detached
signature and the complete release semantics on the fixed Linux evidence host:

```bash
python3 scripts/release/build_external_records.py validate-signed \
  --input release/evidence/work/plonky3-specialist-input.json \
  --claim release/evidence/work/plonky3-specialist-ledger.json \
  --signature release/evidence/work/plonky3-specialist-ledger.sigstore.json
```

Input, artifact, claim, and signature bytes are copied from held
`O_NOFOLLOW` descriptors into an owner-only validation snapshot. Single-link
identity and size/time metadata must remain unchanged before and after every
read; path replacement, symlinks, hard links, or concurrent mutation fail
closed. Final release validation independently reopens and rehashes the
promoted artifacts.

The typed `review-ledger`, `reproduction`, and `partner-acceptance` commands
remain capture aliases, but accept only `--input` and `--output`; raw CLI flags
cannot manufacture an external conclusion. Independent reproduction validates
both workloads at both fixed-host gates before capture. Partner capture
validates the adapter and bounded resource report before hashing them. Review
capture permits open findings or a negative specialist conclusion so
remediation can be recorded, while `validate-signed` and the final release gate
still reject unresolved critical/high findings or missing production approval.
Review inputs bind the exact deterministic bundle and canonical source commit.

Detached verification reads `external_signers` from the exact candidate
commit's `release/release-trust-v1.json`. Each allowlist entry has exactly these
four fields:

```json
{
  "id": "reviewed-opaque-signer-id",
  "purposes": ["review:plonky3_specialist"],
  "certificate_identity_regexp": "reviewed-certificate-identity-regexp",
  "oidc_issuer": "reviewed-OIDC-issuer"
}
```

The only supported purpose strings are `review:plonky3_specialist`,
`review:implementation`, `independent_reproduction`, and
`partner_acceptance`. Enrolling or changing a signer is a separate reviewed
source commit. Template creation, validation, and capture never edit the trust
allowlist, create a signature, or copy a freshly observed signer into trust.
Keep partner identifiers opaque and never place customer witness data, private
source, credentials, or contact details in any template or evidence artifact.
