# New compatibility profile demand gate

Status: blocked. The current input contains no organization records.

TinyZKP supports exactly one production compatibility profile:
`tinyzkp-p3-goldilocks-v1`. Demand for another profile does not modify that
profile, authorize an implementation, or make a candidate supported. It can
only make one proposed profile eligible to enter the next scheduled quarterly
qualification window.

## Eligibility rule

A candidate becomes eligible only when one valid local input contains:

1. at least five distinct technically qualified legal organizations;
2. one shared proposed profile ID;
3. one shared rejection reason from the existing incompatibility vocabulary;
4. at least three conditional acceptances of the unmodified standard annual
   Guard price of USD 4,990.

The only accepted rejection reasons are:

- `unsupported_air_feature`;
- `unsupported_platform`;
- `unsupported_profile`.

All five or more organizations must share the exact same reason and proposed
profile. Four organizations are insufficient. Five organizations with only
two price acceptances are insufficient. More than five organizations are
allowed because this is a minimum-demand threshold, not a cohort cap.

`eligible` means only that TinyZKP may schedule the complete profile-specific
correctness, resource, recovery, security-review, partner, packaging, and
release qualification gates. It does not change
`release/plonky3-compatibility-v1.json`, the website compatibility claim, the
engine, or Guard.

## Technically qualified organization

Record an organization only after it has applied the public compatibility
checker to a real intended workload and its blocking outcome reduces to one of
the three reason codes above. Do not retain or ingest its workload, witness,
trace chunks, proof, AIR source, raw compatibility report, or free-form
description for this gate.

An organization that requests custom work, hosted proving, a private branch,
an SLA, or a nonstandard commercial arrangement is not evidence for this
standard-product gate.

## Privacy-minimal input

The local source is
`release/profile-expansion-demand-input-v1.json`; its closed schema is
`release/profile-expansion-demand-input-v1.schema.json`.

Each record contains exactly:

- `organization_id`: a randomly generated opaque `org-<32 lowercase hex>`
  token. Do not derive it from a name, domain, email address, account ID, or
  other personal or company data.
- `qualification`: the constant `technically_qualified`.
- `proposed_profile_id`: a structured TinyZKP profile identifier other than
  the current v1 profile.
- `rejection_reason`: one allowed reason code.
- `conditional_annual_price_usd`: integer `4990` only when that organization
  conditionally accepts the standard annual price; otherwise `null`.

Records must be sorted by opaque organization ID. Duplicate organization IDs,
mixed profiles, mixed reasons, unknown reasons, another price, and any extra
field fail closed.

Never add names, emails, domains, contact routes, notes, free text, report
content, witness material, secrets, URLs, CRM identifiers, or a lookup table
from opaque IDs to real organizations. This workflow reads local files only.
It has no network, CRM, mailbox, analytics, or outreach integration.

## Generated status and source binding

Generate the aggregate status locally:

```text
python3 scripts/ci/profile_expansion_demand_gate.py --generate
```

Then validate that the tracked status is the exact aggregate of the input and
schema:

```text
python3 scripts/ci/profile_expansion_demand_gate.py
```

To use the gate as a quarterly-window precondition:

```text
python3 scripts/ci/profile_expansion_demand_gate.py --require-eligible
```

`release/profile-expansion-demand-status-v1.json` contains only the candidate
profile, shared reason, counts, fixed thresholds, and SHA-256/byte-length
bindings for the exact source input and schema. It never copies organization
identifiers or records. Editing the source or schema without regenerating the
status produces a source/digest mismatch and fails CI.

The repository default is intentionally:

- current profile: `tinyzkp-p3-goldilocks-v1`;
- input records: empty;
- distinct qualified organizations: zero;
- conditional USD 4,990 acceptances: zero;
- quarterly qualification eligibility: false;
- status: `blocked`.
