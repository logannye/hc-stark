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
to `candidate` and contains exactly the nine automated gates that can exist before
artifact construction. It is not prerelease-ready until the owner-dispatched
assembly workflow has bound the exact config, evidence manifest, artifacts,
closed qualification checksum inventories, and both source workflow runs in
`backend-candidate-assembly-v1.json` and keyless-signed that envelope. The
canonical `backend_prerelease_ready.py` path verifies that signature with the
anchored Cosign binary and constrains the certificate identity, issuer, source
SHA, main ref, repository, and `workflow_dispatch` trigger; there is no unsigned
CLI bypass. Pull-request CI and the engine release job both execute this gate.
The
release workflow then builds the engine CLI and OCI archive, creates their
typed identity report, executes the standalone CLI and the locally imported
OCI image under a confined no-network runtime, and signs the exact artifact
inventory including that runtime-smoke report. It verifies the Sigstore bundle
and runs `finalize_signed_evidence.py`. That command adds the post-build
identity and signed-release gates and emits the final `ready` config. The full
`backend_release_ready.py` gate is rerun against those files before a draft
release can be created. No billing or commercial authorization artifact is
part of the public engine release.

Signed finalization requires the checksum manifest to contain exactly the
public engine binary, customer-operated engine OCI archive, compatibility
profile, candidate gate file, engine identity files, and valid SPDX JSON SBOM.
Hosted API, MCP, beta, SDK, and billing artifacts are rejected. Cosign
verification pins both GitHub's OIDC issuer and the TinyZKP
`release-backend.yml@refs/tags/backend-v*` workflow certificate identity; a
valid signature from an unrelated keyless principal is rejected.

Crate publication redownloads every checksummed artifact and performs a
complete checksum verification without `--ignore-missing`. They repeat the
pinned Cosign identity/issuer check, verify the GitHub attestations for final
evidence and config against the release workflow, tag ref, source digest, and
GitHub-hosted runner policy, and require both the tag target and checked-out
`HEAD` to equal the final evidenced SHA.

Do not hand-author digests. Run `build_candidate_evidence.py template` to create
an unhashed input skeleton, fill its required metadata/roles, then run
`build_candidate_evidence.py build`. The builder rejects manual digest/pass
fields, unknown or missing gates, duplicate roles, symlinks, unsafe paths, and
semantically invalid evidence before emitting an owner-only candidate manifest
and config.

For source, compatibility, verifier, deterministic-proof, and AIR job-contract
gates, run the exact template command through `run_evidenced_command.py`. The
resulting `test_report` binds the command, release SHA, compatibility profile,
execution profile, exit status, timestamps, duration, and SHA-256 of the
separately hashed `test_log`; typed metadata alone cannot claim a successful
test run. The AIR contract gate is local and has no SDK dependency inputs:

```bash
python3 scripts/release/run_evidenced_command.py \
  --gate air_job_contracts \
  --release-sha "$HC_RELEASE_SHA" \
  --report release/evidence/air-job-contracts/test-report.json \
  --log release/evidence/air-job-contracts/test.log
```

Release-identity evidence is created after both public artifacts exist. Generate
the owner-only `identity_report` with:

```bash
python3 scripts/release/build_engine_identity_report.py \
  --release-sha "$HC_RELEASE_SHA" \
  --release-ref "$HC_RELEASE_REF" \
  --engine release-artifacts/tinyzkp-engine-linux-x86_64 \
  --engine-release release-artifacts/engine-release.json \
  --oci-archive release-artifacts/tinyzkp-engine.oci.tar \
  --compatibility-manifest release-artifacts/plonky3-compatibility-v1.json \
  --output release-artifacts/engine-identity.json
```

The checker binds the engine metadata, OCI configuration and digests,
compatibility profile, non-root runtime contract, and signed artifact hashes.
A manually copied identity map or pre-build placeholder is not sufficient.

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
  --output raw-reports/tinyzkp-engine-preliminary.spdx.json
python3 scripts/release/build_review_bundle.py \
  --release-sha "$HC_RELEASE_SHA" \
  --sbom raw-reports/tinyzkp-engine-preliminary.spdx.json \
  --output raw-reports/tinyzkp-engine-review.zip
```

External-review, reproduction, and design-partner tooling is retained for
optional advisory collection. Those records are not members of backend
candidate or final gate inventory and cannot authorize publication. The Guard
launch ledger truthfully records them as `not_completed` until real evidence
exists.

Scoped production resource evidence includes Fibonacci and Poseidon2 at
1,048,576 rows and Fibonacci at 16,777,216 rows. Prefix every role with
`fibonacci_` or `poseidon2_`: `manifest`, `candidate_report`, and
`candidate_normalized_manifest`; the one-million gate also requires each
workload's `baseline_report` and `baseline_normalized_manifest`. The
16,777,216-row gate accepts Fibonacci roles only. The gate recomputes every
digest and permits normalization to change only `scratch_dir`.

The owner-dispatched qualification workflow runs the three-entry matrix on an
ephemeral public-repository `ubuntu-24.04` GitHub-hosted runner. The harness
records and enforces four effective CPUs, 15--17 GiB effective RAM,
non-rotational storage, at least 12,000,000,000 scratch bytes available before
the run, and runner-owned mode-0700 scratch roots. It rejects a commit other
than the exact current `main` SHA. `scripts/benchmark/fixed_host_preflight.py`
runs before each expensive proof; the same facts and exact estimator outputs
are embedded in and revalidated from every `BenchmarkReportV1`. Poseidon2 at
16,777,216 rows requires about 169 GB of scratch before headroom and is
explicitly a post-GA capacity expansion, not a supported production workload.

Optional independent reproduction is an advisory metric, not a metadata flag
on TinyZKP's own benchmark or an engine release gate. If the retained broad
research reproduction is collected, it may include both workloads at both
resource sizes, nested under `one_million_` and `ten_million_` before the
workload-prefixed roles. Its Poseidon2 16,777,216-row result remains advisory
and cannot expand the production scope. The hashed `reproduction_record` binds
the reproducer, organization, release, profile, workloads, completion time,
official-verification result, and the exact SHA-256 of every independently
produced resource artifact; co-locating unbound files is not sufficient.

Each external review requires separately hashed `review_bundle`,
`review_report`, and `remediation_ledger` roles. The ledger is
release/profile/scope-bound and uses stable finding IDs. A Plonky3 specialist
ledger additionally requires a signed `security_assessment` for the exact
`FriParameters::new_benchmark` values. It records separate consideration of
conjectured and proven FRI bounds, duplicate-query probability, and challenger
capacity, plus the reviewer's minimum-bit conclusion, limitations, and explicit
production-use decision. Missing or negative approval prevents marking that
advisory complete; an
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
all fourteen backend targets, each run from the deterministic,
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

Owner evidence workflows install exact declared tool versions through
SHA-pinned actions or locked package commands. Every report captures each
resolved executable's absolute path, full version output, and SHA-256, executes
the already-opened descriptor, and rehashes that descriptor after execution.
The final candidate binds those reports and logs to the exact source, lockfiles,
workflow run, and attested checksum inventory. It deliberately does not compare
host-built Cargo, rustc, cargo-fuzz, Bash, or Python bytes with a digest captured
on a different machine; such cross-host byte anchors are not reproducible.

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
cannot manufacture an external conclusion. The retained broad independent
reproduction validates both workloads at both research sizes before capture;
it does not enlarge the three-entry production qualification scope. Partner capture
validates the adapter and bounded resource report before hashing them. Review
capture permits open findings or a negative specialist conclusion so
remediation can be recorded, while `validate-signed` rejects unresolved
critical/high findings or missing production approval. Backend publication
does not consume these optional records.
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
