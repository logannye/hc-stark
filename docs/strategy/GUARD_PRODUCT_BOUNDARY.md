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

## Launch gates

Public checkout remains disabled until all of the following are real:

1. Engine correctness, resource, recovery, independent reproduction, specialist
   review, implementation review, and external workload gates pass.
2. Three external workloads from at least two organizations use one standard
   adapter without customer-specific source changes.
3. Five unaided installations complete the documented journey, with four
   reaching an officially verified proof within 60 minutes.
4. Counsel supplies the legal seller facts and approves the commercial terms.
5. Merchant-of-record sandbox and live purchase/cancel/refund tests pass.
6. Two organizations purchase the ordinary annual product without a custom
   contract.

If integration repeatedly takes more than four engineering hours per customer,
the product is not self-service and must not be launched as passive revenue.
