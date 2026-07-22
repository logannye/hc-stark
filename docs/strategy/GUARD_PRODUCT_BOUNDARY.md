# TinyZKP Guard product boundary

Status: approved implementation boundary for the self-hosted product.

TinyZKP is not a hosted proving service. The public project contains the
proof-critical engine, verifier, schemas, compatibility checker, and evidence
tooling. A separately licensed Guard supervisor may orchestrate this engine,
but it must not change proof semantics or verification.

## Supported v1 profile

The only production target is Linux x86-64 and the exact profile published in
`release/plonky3-compatibility-v1.json`. Declarative AIR v1 supports
current/next/public/constants and add/subtract/multiply expressions, degree at
most three, width at most 256, and row counts from 2^10 through 2^24.

Lookups, buses, permutations, multi-table AIRs, periodic or preprocessed
columns, custom fields, recursion profiles, arbitrary Plonky3 forks, GPUs,
Windows, and macOS proving are incompatible unless a later signed profile
explicitly adds them.

Demand alone cannot add a profile. The privacy-minimal gate in
`docs/validation/PROFILE_EXPANSION_DEMAND_GATE.md` may only admit one candidate
to a scheduled quarterly qualification window after at least five distinct
qualified organizations share one structured incompatibility reason and at
least three conditionally accept the standard USD 4,990 annual price. The
complete profile-specific release gate must still be repeated.

## Commercial boundary

- Community: MIT engine, verifier, schemas, reference workloads, doctor, and
  public evidence.
- Guard: commercially licensed local orchestration, automatic mode selection,
  recovery supervision, CI policies, signed qualification, and release
  updates.
- Customer compute, witnesses, scratch data, and proofs stay on
  customer-controlled infrastructure.
- There is no hosted job API, account database, usage meter, worker fleet,
  proof storage, service-level agreement, or included integration work.

The public site and release tooling must not claim zero-knowledge privacy,
O(sqrt T) production storage, arbitrary Plonky3 compatibility, or uniqueness.
Performance claims require a signed release evidence bundle.

## Owner-attested launch gates

Public checkout remains fail-closed until strict, signed evidence establishes:

1. Automated engine verifier, determinism, resource, recovery, fuzz,
   provenance, SBOM, signature, CLI, and OCI checks.
2. Private Guard qualification and publication of the exact no-rebuild signed
   candidate.
3. LN Holdings owner approval of exact seller facts, Terms, Privacy, Refund
   Policy, EULA, and third-party notices bound by digest.
4. The complete Lemon Squeezy sandbox lifecycle and an owner inspection of the
   exact live variants, prices, checkout rendering, portal, and license settings.
5. Resolution of legacy obligations; immediate shutdown of hosted writes,
   jobs, and credentials; retained records; and static `410/noindex` legacy
   hosts.
6. Technical build, deploy, artifact-identity, and rollback rehearsal.

Independent reproduction, specialist and implementation reviews, a design
partner integration, three external workloads, two customers, and five unaided
installs are transparent `advisory_status` metrics. The first release records
all seven as `not_completed`; they neither authorize nor block checkout.
