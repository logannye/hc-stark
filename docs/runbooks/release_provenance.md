# TinyZKP engine and Guard release provenance

Status: active release-control runbook. SDK, MCP, maintenance-server, hosted
beta, and crates.io publication are not production release surfaces.

## External protection required

CODEOWNERS records intended review but does not configure GitHub protection.
Before any passing evidence or promotion:

1. Require pull-request review and CODEOWNERS review on `main`.
2. Protect `tinyzkp-launch-trust`, `tinyzkp-evaluation-release`,
   `tinyzkp-guard-candidate`, `tinyzkp-release-promotion`, and
   `tinyzkp-production` environments.
3. Put the independently reviewed SHA-256 of
   `GuardLaunchTrustV1`/`GuardMarketTrustV1` in the applicable protected
   environment variables `GUARD_LAUNCH_TRUST_POLICY_SHA256` and
   `GUARD_MARKET_TRUST_POLICY_SHA256`. Use separate protected environments
   where appropriate.
4. Generate the Guard signing key in an owner-controlled key ceremony. Commit
   only its public key at `release/guard-signing-public-key.pem`, set
   `GuardSigningTrustV1` to `configured`, and put the independently reviewed
   policy digest in the protected
   `GUARD_SIGNING_TRUST_POLICY_SHA256` environment variable. Never commit the
   private key.
5. Restrict manual signing, evaluation, candidate, and promotion environments
   to protected `main`; require a reviewer and prevent self-review where
   GitHub supports it. Public `tinyzkp-production` is deliberately automatic:
   it is protected-`main` only and has no manual reviewer. The private Guard
   production/candidate environments are also protected-`main` only.
6. Restrict `tinyzkp-pages-preview` to `refs/pull/*/merge`. GitHub evaluates
   the workflow `GITHUB_REF`, not a `codex/*` head branch. The workflow's
   same-repository pull-request condition remains the boundary that prevents
   forked code from receiving preview credentials.
7. Record screenshots/API reads of the actual settings whenever they change.
8. Protect `tinyzkp-release-index-promotion`, require an independent reviewer,
   and store a least-privilege private-repository token as
   `GUARD_PRIVATE_HANDOFF_TOKEN`. It may read workflow artifacts from
   `logannye/tinyzkp-guard`; it must not hold a Guard signing key.

Passing launch or market evidence cannot rely only on a policy digest inside
the same repository source. The validator requires the exact independently
protected digest. The checked-in launch, market, and signing policies are
unconfigured, all evidence is blocked, and no clock or checkout is active.

## Candidate and promotion flow

1. `release-backend.yml` builds one immutable `backend-v*` draft candidate with
   the engine binary, OCI archive, compatibility identity, exact final gates,
   checksums, Sigstore bundle, SBOM, and GitHub attestations.
2. Once the engine, legal, merchant-sandbox, and rehearsal source gates pass,
   `guard_launch_gate.py --require-candidate-build-ready` emits a narrowly
   scoped authorization to prepare one signed Guard draft. It does not
   authorize checkout, publication, or a commercial release. The canonical
   Guard signing trust must already be configured and independently anchored.
   Merge this reviewed authorization as public commit **A**. The authorization
   cannot contain its own commit ID, so the protected Guard build supplies A
   and the signed channel records it as
   `public_candidate_authorization_commit`.
3. `.github/workflows/release-ga.yml` in the private Guard source consumes that
   exact authorization and stages one immutable `guard-v*` draft with both
   binaries, channel/index, exact public schemas, EULA/notices, OCI identity,
   checksums, keyed signatures, SBOM, and provenance. Authorization A is itself
   a checksummed, channel-listed artifact; provenance binds both its SHA-256
   and its public commit. Candidate bytes always
   identify themselves as `signed_candidate` and
   `candidate_build_authorized`, with
   `commercial_release_authorized: false`.
4. Signed `GuardLaunchEvidenceV2` then binds the exact Guard/engine source,
   public authorization commit A, artifact,
   OCI, channel, embedded live Lemon catalog, technical gates, customers,
   legal/merchant lifecycle, retirement, and rehearsal. Promotion-ready
   evidence remains launch-blocked by exactly
   `guard_artifact_published`; checkout stays closed. Merge that evidence as
   later public commit **B**.
5. `promote-guard-release.yml` runs only from `main` in the protected promotion
   environment. It downloads both drafts, verifies inventory, hashes, keyed
   Guard signatures, engine attestations, schemas, channel, OCI digest, legal
   digests, live-hidden site identity, and all protected trust digests. It
   requires the public `guard-v*` tag to target A exactly and A to be an
   ancestor of the executing promotion commit B. It
   copies the already-built OCI archives to immutable GHCR tags, makes the
   existing GitHub releases public, and records publication evidence. It never
   rebuilds, resigns, or changes candidate bytes.
6. Final reviewed evidence moves the public site and catalog from
   `live_hidden` to `public_live` only after the artifact publication gate
   passes. Publication flags and evidence change; the candidate payload does
   not.
7. Never replace a published artifact or delete an old release that owns a
   resumable checkpoint.

The public `guard-v*` tag is a launch-control locator and points to reviewed
candidate-authorization commit A, never promotion-evidence commit B or the
workflow's current SHA. The private Guard source commit is not the public tag
target; it is bound independently in the signed channel, version metadata, OCI
labels, and provenance. The signed Guard release identity is:

`tinyzkp-guard/{guard_version}+guard.{guard_source_sha}.engine.{engine_source_sha}.artifact.{engine_artifact_sha256}`

An unconfigured canonical signing key blocks candidate preparation. A key
bundled inside a candidate can corroborate the canonical public key but cannot
establish trust by itself.

## Evaluation doctor channel

`evaluation-doctor.yml` uses the separate `doctor-eval-v*` namespace and
protected evaluation environment. It runs contract/doctor/source tests,
exports all thirteen Guard/profile schemas plus the seven proof-engine schemas,
builds and runs the complete synthetic
job, and publishes signed binary/OCI/schema/sample/SBOM/provenance assets as an
explicit prerelease. It does not run or claim production performance, FRI,
independent review, full engine qualification, Guard GA, or crates publication.

The market clock starts only after digest-bound evidence for that signed
evaluation artifact and the single moderator-approved Plonky3 announcement.

## Qualification windows and price/catalog changes

There are four qualification windows per year, not four promised releases. A
window may publish no binary. Change classes are:

- `guard_package_only`: reuse engine, standardized-demand, legal-document,
  unchanged Lemon-catalog, and legacy-retirement evidence only when the engine
  SHA and compatibility profile still match; rerun Guard/package/activation/
  OCI identity plus exactly two complete clean-machine smoke journeys.
- `proof_critical`: fresh complete engine and Guard qualification.
- `site_legal_pricing`: retain the exact unchanged engine and Guard software
  identity; rerun static-site contracts/accessibility, exact legal-document
  digests, merchant catalog/lifecycle, deploy-plan, and rollback rehearsal.

Candidate-build, promotion-ready, and production-readiness commands require
the checked-in `evaluated_at` to be no more than 24 hours behind real UTC and
never in the future. Ordinary blocked prelaunch generation remains
reproducible. Starting or updating the signed market clock applies the same
real-time bound.

Each window is capped at eight owner hours and $3,000 external spend and
requires a $6,000 reserve. $499/$4,990 pricing is frozen through GA plus six
months. Any later price change retains the reviewed Lemon monthly and annual
variant IDs. Lemon preserves the original price for existing subscriptions
while new subscribers receive the updated price. Never delete or repurpose
either ID; a new ID requires a new Guard/package release that embeds and
qualifies it.

## Failure handling

Any verifier, proof-equality, signature, provenance, artifact/channel/schema
identity, offline-runtime, checkpoint, legal, merchant-semantic, proof-data,
or high/critical security failure blocks promotion and freezes sales. A local
operations scorecard recommendation never mutates checkout; only separately
signed reviewed evidence can change the generated commerce state.

Superseded and withdrawn index states control ordinary distribution,
recommendation, and support. An already-downloaded activated copy makes no
channel request, cannot learn either state, and remains locally usable; do not
claim a technical resume-only restriction or remote revocation. V1 has no
release-specific activation denylist. A customer who retained an unactivated
copy may still activate it while the merchant reports an active subscription.
Treat that limitation as part of incident response.

## Signed index-only withdrawal and advisory revisions

The current signed Guard release index and its raw keyed signature are served
at the stable URLs:

- `https://tinyzkp.com/guard-release-index-v1.json`
- `https://tinyzkp.com/guard-release-index-v1.json.sig`

Every published index revision is also retained byte-for-byte below
`https://tinyzkp.com/release-index-revisions/{index_sha256}/`. The signed
release asset remains the immutable origin record; a withdrawal or advisory
revision never edits or replaces a GitHub release asset and never rebuilds
Guard or the engine.

Use `import-guard-release-index-revision.yml` only from protected `main`. The
operator supplies the private workflow run ID and both expected index digests.
The workflow downloads exactly the three-file
`guard-release-index-revision-{private_run_id}` artifact from the private
repository, verifies the raw signature against the canonical public key,
binds the protected handoff metadata, and independently checks full index
history and order.

An index-only revision may:

- withdraw a non-current release while preserving its existing successor;
- change only the advisory URL of an already withdrawn release; or
- withdraw the current release, point it to one named prior superseded
  replacement, make only that replacement current, clear the replacement's
  old successor, and change the current pointer.

The advisory URL is plain HTTPS with no credentials, query, fragment,
backslash, whitespace, or non-443 port. Its host is exactly `tinyzkp.com`,
`www.tinyzkp.com`, or `github.com`; a GitHub advisory must remain under
`/logannye/hc-stark/`. All artifact, channel, identity, compatibility, date,
hash, release-order, and unrelated-entry fields remain immutable.

After verification the workflow copies the exact signed bytes to the stable
and digest-addressed static paths, regenerates only latest-index public
metadata, reruns launch/site controls, and opens a pull request. Protected
branch review and the ordinary automatic `tinyzkp-production` deployment
remain the publication boundary.
