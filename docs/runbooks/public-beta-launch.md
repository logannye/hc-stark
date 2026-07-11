# TinyZKP paid public-beta launch

This runbook is intentionally fail-closed. The production channel remains
`containment` until the hash-bound public-beta gate reports `ready`. Public beta
means no SLA, not independently audited, and support only for the frozen
Goldilocks/Plonky3 0.6.1 profile documented by `AirPackageV1`.

## Channel and rollback

`release/release-channels-v1.json` defines `containment`, `public_beta`, and
`ga`. A release may move only one step at a time. GA additionally requires the
independent audit, independent reproduction, and design-partner gates.

The rollback target is always containment. It must disable signup, Checkout,
new uploads, and new proof jobs while preserving account access, balances,
invoices, completed proof downloads, and free official verification. Never
delete ledger events or retained proof bundles during rollback.

## Customer artifact preflight

Validate the AIR locally:

```sh
hc-cli plonky3 validate-air --air air-package-v1.json
```

Pack a row-major `u64` little-endian trace into fixed-size Zstandard chunks:

```sh
hc-cli plonky3 pack-trace \
  --air air-package-v1.json \
  --trace trace.bin \
  --rows 1048576 \
  --output-dir packed-trace
```

The CLI rejects noncanonical field elements, wrong expanded lengths, unsafe
row counts, and unsupported AIR shapes before any upload. Hosted submission
requires an official 1,024-row local proof for the same AIR digest. Estimate,
prove, and verify it with:

```sh
hc-cli plonky3 estimate-air \
  --air air-package-v1.json \
  --trace-manifest packed-trace/trace-manifest-v1.json \
  --public-inputs public-inputs-v1.json \
  --policy resource-policy-v1.json

hc-cli plonky3 prove-air \
  --air air-package-v1.json \
  --trace-manifest packed-trace/trace-manifest-v1.json \
  --chunks-dir packed-trace \
  --public-inputs public-inputs-v1.json \
  --policy resource-policy-v1.json \
  --output air-proof-bundle-v1.json

hc-cli plonky3 verify-air --bundle air-proof-bundle-v1.json
```

Public-input names are declared by the AIR; canonical Goldilocks values are
supplied separately in slot order and hash-bound into each proof bundle.

## Data and worker prerequisites

Before enabling any beta route:

1. Provision a dedicated worker with 8 vCPU, 16 GiB RAM, and at least 1 TB of
   non-rotational NVMe. Do not place it on the web/billing host.
2. Apply `crates/hc-server/sql/tenant_auth_pg.sql` and then
   `crates/hc-beta-api/migrations/0001_public_beta.sql` to the shared PostgreSQL database.
3. Create a private Cloudflare R2 bucket. Upload grants must be scoped to one
   tenant, upload ID, object prefix, exact content length, checksum, and a short
   expiry. The API must never accept archive paths or executable payloads.
4. Configure encrypted off-box backups for PostgreSQL and the API-key store.
   Include the tenant, upload, job, idempotency, credit-account, and immutable
   credit-event tables. Restore into an isolated database and reconcile every
   account balance from events before recording recovery evidence.
5. Configure worker admission to reject predicted RSS above 2 GiB, predicted
   wall time above 60 minutes, or scratch use above 70% of currently free NVMe.
   Local scratch is disposable and must be cleaned after completion, failure,
   cancellation, and expired leases.

## Stripe catalog and checkout

`billing/public_beta_catalog.json` is the only beta catalog source. It uses the
`tinyzkp_public_beta_v1` metadata namespace and never reuses legacy prices.

Preview without writing:

```sh
PYTHONPATH=billing python3 billing/public_beta_catalog.py
```

Test-mode creation requires the Stripe key, exact account ID/display name, and
`TINYZKP_ALLOW_BETA_CATALOG_WRITE=1`. Live creation requires either the ready
public-beta authorization or the signed exact-SHA `dark_canary` authorization
emitted by `public-beta-candidate.yml`. The latter permits only isolated live
billing canaries and explicitly cannot activate public API mode. The tool
verifies the Sigstore bundle before writing and does not archive or alter
legacy products, subscriptions, or the unrelated Casino Coach catalog.

Use Checkout Sessions for subscriptions and one-time top-ups. Create Customer
Portal sessions only for an authenticated tenant's Stripe customer. Grant
monthly credits only after `invoice.paid`; freeze new paid work after
`invoice.payment_failed`; process every webhook through the immutable Stripe
event/idempotency records. Never grant credits from the browser redirect.

## Evidence and release authorization

Copy `release/public-beta-evidence.template.json` into a private
`release-evidence/` workspace. Replace every empty gate with one or more
repository-local, reviewed artifacts and their SHA-256 digests, then run:

```sh
python3 scripts/ci/public_beta_gate.py \
  --evidence /path/to/public-beta-evidence.json \
  --release-sha "$(git rev-parse HEAD)" \
  --output /path/to/public-beta-authorization.json
```

The gate fails if any artifact is missing, changed, outside the repository, or
bound to another commit. Package the workspace as
`public-beta-evidence.tar.gz` with all paths rooted beneath
`release-evidence/`. The authorization workflow safely extracts that private
bundle and signs authorization for the unchanged candidate without rebuilding
it. Required evidence covers merged CI; official verifier
and proof-byte equality; 1M/16M fixed-host measurements; crash, corruption,
disk-full, cancellation, and fuzz results; internal security review; SDK golden
vectors; signed artifacts/SBOM/provenance; release identity; restore, queue, and
billing replay; advertised-concurrency load; and the 24-hour canary.

## Launch sequence

1. Keep the containment audit green while infrastructure and test-mode billing
   are prepared.
2. Run one tagged test-mode subscription and each top-up path, including
   duplicate webhooks, payment failure, cancellation, and Customer Portal.
3. Produce and review all gate evidence from one signed release identity.
4. Create the isolated live Stripe beta catalog. Perform one tagged live
   top-up and one tagged live subscription; refund and exclude both canaries
   from revenue reporting.
5. Deploy the API, worker, MCP, dashboard, SDKs, docs, pricing, and status from
   the same signed release. Explicitly change the channel to `public_beta`.
6. Run the complete self-serve audit and start the 24-hour production canary.
   Any proof verification failure, unexplained credit delta, identity mismatch,
   or unsupported-workload success triggers immediate containment rollback.

## Retention and deletion

- incomplete or failed uploads: 24 hours;
- completed input traces: 24 hours;
- Builder proofs: 7 days;
- Pro proofs: 30 days;
- Scale Beta proofs: 90 days.

Beta signup and upload copy must reject regulated, highly sensitive, or
irreplaceable data. Tenant deletion revokes API keys immediately, schedules
retained objects for deletion, and preserves only legally required billing and
immutable accounting records.
