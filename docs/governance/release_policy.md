# TinyZKP engine and Guard release policy

Status: active policy for the `hc-stark` production repository.

TinyZKP ships a public MIT engine and a separately licensed, customer-operated
Guard supervisor. Hosted proving, hosted verification, customer accounts,
usage billing, SDK publication, and MCP commerce are retired release surfaces.
Their retained source and infrastructure have no authority to enable Guard.

The authoritative operating documents are:

- `docs/strategy/GUARD_PRODUCT_BOUNDARY.md` for product and compatibility scope;
- `docs/runbooks/release_provenance.md` for build, candidate, promotion, and
  withdrawal controls; and
- `docs/validation/FOUNDING_VALIDATION_PROTOCOL.md` for transparent advisory
  adoption metrics that do not authorize or block checkout.

## Active release surfaces

Every pull request must identify the surfaces it changes.

| Surface | Examples | Primary risk |
|---|---|---|
| Public contracts and engine | `tinyzkp-contracts`, `hc-stream`, `hc-plonky3`, `hc-cli`, schemas, proof bytes | A supported job changes meaning, a proof stops verifying, or resource/recovery claims become false |
| Guard package | Private supervisor, activation, release channel, OCI package | Commercial code changes proof semantics, leaks data, or accepts the wrong release |
| Site, legal, and commerce | `site/`, legal documents, pricing, Lemon Squeezy catalog | A buyer sees an unsupported claim, wrong price, or checkout without a qualified release |
| Release evidence and operations | `release/`, qualification, signing, promotion, retirement | Evidence is forged, stale, rebuilt after review, or published without owner authorization |

The legacy API, MCP, Stripe usage billing, account database, worker fleet, and
SDK package trains may be changed only for containment, export, retention, or
decommissioning. They cannot authorize a product launch.

## Coordinated release classes

| Class | Use | Required gates |
|---|---|---|
| `proof_critical` | Engine, verifier, compatibility, proof, checkpoint, or resource behavior changes | Complete automated engine and Guard qualification, signed provenance, and immutable publication |
| `guard_package_only` | Guard behavior changes while the exact engine and profile remain unchanged | Guard/package/activation/OCI checks and signed provenance |
| `site_legal_pricing` | Site, legal, or catalog changes with unchanged software identity | Static-site contracts, exact legal digests, merchant lifecycle, deploy plan, and rollback rehearsal |

The first generally available release is `proof_critical`.

## Compatibility and interface policy

- `tinyzkp-contracts` is the Rust source of truth for Guard-facing JSON
  contracts. Generated public schemas must match it byte-for-byte.
- The supported production profile is exactly
  `tinyzkp-p3-goldilocks-v1`. Unsupported profiles fail closed.
- Proof bytes must remain accepted by the ordinary pinned Plonky3 verifier.
  Guard must never change proof semantics or verification.
- Public contract changes require a new versioned schema when they are not
  backward compatible. Existing signed release schemas remain immutable.
- A checkpoint may resume only with its exact release identity. Never replace
  or delete a release that owns an unfinished checkpoint.
- Guard activation is the only network-capable product command. Doctor, run,
  resume, policy, diagnostics, and verification operate offline after
  activation and never transmit proof data.

## Pricing and merchant policy

- `site/pricing.json` is the public price source; `site/commerce.json` is
  generated from reviewed `GuardLaunchEvidenceV2`.
- Guard costs $499 monthly or $4,990 annually for one legal organization.
  Annual is the default and founding customers receive no discount.
- There are no trials, coupons, add-ons, usage meters, enterprise variants,
  included services, or hosted compute.
- Lemon Squeezy is the merchant of record and owns tax, receipts, invoices,
  renewal, dunning, payment changes, cancellation, eligible refunds, portal,
  and subscription license-key lifecycle.
- Existing merchant variant IDs are never deleted or repurposed. A new variant
  requires a reviewed catalog change and applicable release class.
- Checkout remains fail-closed unless signed evidence derives
  `launch_state: qualified`, `sales_state: live`,
  `commerce_state: public_live`, and exact release/catalog identity parity.

## Build and promotion control

1. Protect `main`, trust, signing, evaluation, candidate, release-index,
   promotion, preview, and production environments as described in the release
   provenance runbook.
2. Restrict launch evidence to the repository owner's main-only OIDC workflow,
   exact protected trust digests, and strict typed evidence envelopes.
3. Build the engine and Guard candidate once. Record source SHAs, checksums,
   signatures, OCI digests, schemas, SBOM, provenance, attestations, legal
   digests, and merchant catalog.
4. Keep commerce `live_hidden` while the signed candidate, live merchant
   configuration, decommission state, and rollback target are verified. Public
   TinyZKP.com checkout remains closed.
5. Promotion verifies and publishes the reviewed draft bytes without rebuilding
   or resigning them.
6. A later evidence-only change may derive `public_live`; a local scorecard or
   workflow artifact cannot enable checkout.

Source-controlled trust-policy digests are insufficient by themselves. The
same exact digests must be protected in owner-controlled GitHub environments.
Secrets, private signing keys, customer data, license keys, or payment data
must never be committed.

## Required validation

Before merging a release change, run the complete CI suites for all affected
surfaces, including:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
python3 -m pytest scripts/ci scripts/release -q
git diff --check
```

The release workflows add Linux x86-64 qualification, verifier, determinism,
resource, recovery, fuzz, artifact inventory, signature, OCI/CLI identity,
SBOM, provenance, owner-approved legal-digest, merchant lifecycle, static-site,
deployment, and rollback checks. External reviews and adoption metrics remain
visible as `not_completed` advisory status and do not satisfy a technical gate.

## Rollback, withdrawal, and sales freeze

- A site-only rollback must keep checkout fail-closed unless its commerce and
  release manifests still match the published release.
- Published artifacts are immutable. Supersede or withdraw them through the
  signed release index; never replace their bytes.
- Immediately freeze sales for verifier/correctness, signature, provenance,
  artifact identity, offline-runtime, checkpoint, legal, merchant-semantic,
  proof-data, or high/critical security failures.
- Already activated releases cannot be remotely disabled. Incident response
  must state that limitation explicitly.
- Retired `api`, `mcp`, and `webhook` hostnames switch immediately to static
  `410 Gone` plus `X-Robots-Tag: noindex` after writes, jobs, and credentials are
  disabled. Keep that edge for 90 days of post-launch monitoring before removal.

## Changelog policy

Every user-visible contract, proof, Guard, release, pricing, legal, commerce,
site, or operational change receives an entry under `Unreleased` in
`CHANGELOG.md`. Internal refactors may omit an entry only when the pull request
explains why behavior and evidence remain unchanged.
