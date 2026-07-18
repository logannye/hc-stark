# TinyZKP Guard implementation status

Updated: 2026-07-18. This is a gap ledger, not a release announcement or
production qualification.

## Implemented in source

- The public MIT engine is pinned to Plonky3 `0.6.1` and the
  `tinyzkp-p3-goldilocks-v1` Linux x86-64 profile. Conventional and bounded
  proof paths, official verification, deterministic checkpoints, resource
  estimation, scratch preflight, and the fixed-host evidence harness exist.
- The public engine CLI has a local `doctor --job` contract and exports the
  exact public schema inventory: seven proof-engine schemas plus thirteen
  Guard/profile schemas. The doctor does not upload a trace or create a proof
  job.
- Proof-critical code remains in the public repository. Hosted proving, hosted
  verification, account, usage-meter, SDK-publication, MCP-commerce, and
  maintenance-server release workflows are not active product workflows.
- Guard is implemented as a separate private object-code product that consumes
  the public engine contracts. Its source can build a signed candidate, but no
  candidate is a public or commercially authorized release merely because it
  builds.
- `GuardLaunchEvidenceV2` derives the launch, commerce, pricing, discovery,
  compatibility, and candidate-build documents. Signed gate evidence is
  release-bound, age-limited, digest-bound, and checked against an independently
  protected launch-trust digest.
- Candidate preparation, no-rebuild promotion, and final launch are distinct:
  a closed-checkout candidate authorization may prepare one signed draft;
  promotion requires every launch gate passed with only exact artifact
  publication blocked; a later evidence-only commit may enable checkout after
  the published bytes and OCI digests are observed.
- Guard signatures use a canonical public key and separately protected signing
  trust. The key is intentionally unconfigured in the checked-in prelaunch
  state. Promotion verifies the keyed checksums, channel, index, candidate
  provenance, legal hashes, schemas, OCI labels, private Guard source identity,
  public engine identity, and merchant catalog before publishing without a
  rebuild.
- The Cloudflare Pages site is static and fail-closed. It exposes compatibility,
  benchmarks, pricing, documentation, security, release status, troubleshooting,
  and legal-status pages; retired hosted routes and the three retired hostnames
  have an origin-free `410 Gone` implementation and canary.
- The four evergreen acquisition pages are staged but remain generated
  `noindex,nofollow` surfaces and are absent from the sitemap and discovery
  document until signed engine evidence passes. Only the launch-state generator
  can expose them.
- `GuardMarketClockV1` and the passive-operations scorecard are local,
  evidence-derived records. They do not create a CRM, custom telemetry service,
  contact form, or customer proof-data path. The six-month threshold counts
  distinct qualified organizations, not repeat reports or bots.

## Implemented code is not release evidence

The following release requirements remain unexecuted or unreviewed:

- the complete Linux 8-vCPU, 15–17 GiB, swap-disabled NVMe matrix for Fibonacci
  and Poseidon2 at 1,048,576 and 16,777,216 rows;
- the 4× peak-RSS / 3× wall-time gate at 1,048,576 rows and the 2 GiB/scratch
  gate at 16,777,216 rows;
- the durable-phase interruption, corruption, stale-release, symlink, traversal,
  signal, and Linux `ENOSPC` release matrix on the qualified host;
- the independently reviewed cargo-fuzz executable and required campaigns;
- independent reproduction, Plonky3 specialist approval of the production FRI
  profile, and implementation review with no unresolved critical or high
  findings;
- the external non-reference workload, exactly three founding workloads, two
  ordinary $4,990 annual purchases, and five clean-machine journeys;
- the signed Community doctor evaluation artifact, public engine candidate,
  private Guard candidate, canonical Guard signing key, public OCI digests,
  and final channel/index;
- Lemon Squeezy merchant approval, exact live catalog IDs, sandbox lifecycle,
  live owner purchase/cancellation/refund smoke, and live customer portal;
- owner- and counsel-supplied seller identity, address, jurisdiction, governing
  law, EULA, privacy, terms, refunds, export, and sanctions approval;
- resolution of every external legacy obligation and evidence that the hosted
  servers, databases, workers, queues, monitors, backups, buckets, OAuth apps,
  credentials, and customer artifacts have been decommissioned under the
  retention policy.

No checked-in placeholder, local macOS run, draft candidate, or self-authored
claim satisfies one of those gates.

## External actions that remain

- The owner must complete the read-only external inventory before authorizing
  any provider mutation. Stripe, Cloudflare, Hetzner, R2, DNS, OAuth, secrets,
  backups, monitoring, and customer records must be treated as potentially
  obligation-bearing until the inventory proves otherwise.
- The owner and counsel must provide the legal seller facts and approve the
  production legal documents. The Stripe display name is not evidence of the
  seller's legal identity.
- Lemon Squeezy must approve the merchant account and expose the reviewed test
  and live product/variant identities.
- Qualified reviewers must sign the FRI, implementation, reproduction, legal,
  Linux resource, recovery, and release evidence. The release gate cannot
  substitute repository-controlled signers for the protected trust root.
- Technically qualified users may arrive through one moderator-approved
  Plonky3 community announcement after the signed Community doctor evaluation
  release exists. TinyZKP does not use direct messages, cold outreach,
  recurring campaigns, newsletters, an ongoing blog, or repeated ecosystem
  submissions.
- Founding organizations run the public doctor and share only the scrubbed
  compatibility report. TinyZKP does not accept witnesses, custom branches,
  unsupported AIR work, or more than four assistance hours per organization.

## Current authority

Checkout is closed. The canonical machine state is
[`release/guard-launch-state-v2.json`](../../release/guard-launch-state-v2.json);
its source is
[`release/guard-launch-evidence-v2.json`](../../release/guard-launch-evidence-v2.json).
Engine qualification remains independently governed by
[`release/backend-v1-gates.json`](../../release/backend-v1-gates.json).
Commercial launch requires the final evidence-derived state to be
`public_live`; source code, a draft GitHub Release, or a pushed OCI tag cannot
enable sales on its own.
