# TinyZKP Guard refinement: external-state inventory

Captured read-only on 2026-07-18. This record contains no secrets and does not
authorize deletion, migration, cancellation, refund, DNS changes, or customer
communication. External state remains authoritative for decommissioning.

## Public site and Cloudflare

- Cloudflare OAuth access is present for the owner's account.
- The Pages project is `tinyzkp`, with `tinyzkp.pages.dev`, `tinyzkp.com`, and
  `www.tinyzkp.com`.
- Pages is configured as a direct-upload project rather than a connected Git
  provider.
- The newest observed production deployment is source revision `e24538b`.
- `https://tinyzkp.com/api/release` returns static `410 Gone`.
- `https://tinyzkp.com/pricing.json` returns the prelaunch Guard catalog with
  `checkout_enabled: false`.
- Cloudflare Web Analytics is the only permitted future site analytics
  mechanism. No customer proof or license data may be sent to it.

Visible R2 buckets:

- `tinyzkp-backups`
- `tinyzkp-beta-artifacts`
- `tinyzkp-beta-pgbackrest`
- `tinyzkp-proofs`

No bucket may be deleted until a reviewed inventory identifies its contents,
retention basis, required export, deletion authority, and resulting deletion
evidence.

## Live legacy origins

These origin-backed routes still returned HTTP 200:

- `https://api.tinyzkp.com/version`
- `https://api.tinyzkp.com/healthz`
- `https://mcp.tinyzkp.com/version`
- `https://webhook.tinyzkp.com/health`

The API and MCP report legacy release
`5719292ad0c8c4b5f0f6b0500db41cdf6888134c`. Responses pass through Caddy and
Cloudflare. The active Caddy configuration contains API, MCP, and webhook
reverse proxies, including legacy Stripe and OAuth callback paths.

The plan calls for origin-free static `410 Gone` responses for 90 days, then
DNS removal. That change is blocked until the Stripe, customer, records, and
origin inventories below prove that no durable webhook or customer obligation
would be interrupted.

## GitHub

- GitHub CLI access is authenticated as `logannye`.
- The `logannye/hc-stark` description, homepage, and topics now describe the
  pre-release local resource-bounded engine rather than a hosted service.
- Private vulnerability reporting is enabled.
- Published `v0.1.0` and `v0.1.1` MCP releases are marked as unsupported legacy
  prereleases and are not designated “Latest.” The duplicate `v0.1.1` draft is
  also labeled unsupported legacy.
- The annotated historical tag `archive/hosted-beta-2026-07-17` is present
  locally and on `origin` at hosted-beta commit
  `7a1b9db80f26a2fd713bef44e54faea6ccaba578`.
- Repository-level Actions secrets visible by name are `CRATES_IO_TOKEN`,
  `NPM_TOKEN`, and `PYPI_TOKEN`. No Cloudflare deployment credential is
  configured at repository scope.
- At initial capture, no protected `tinyzkp-production` GitHub environment was
  returned by the repository API.
- The current `main` protection requires the `validate` status check and
  rejects force-pushes and branch deletion, but does not require a pull-request
  review or enforce protection against administrators.
- Active workflows are limited to engine/site CI, fixed-host reports, manual
  qualification, engine release, historical crate publication, static-site
  deployment, and GitHub's Copilot agent. No hosted proving deployment
  workflow is active.

Hosted-beta workflows and package-publication paths must remain unable to
activate production. Existing secrets are not to be revoked until the active
workflow inventory identifies whether they protect unrelated historical
release obligations.

### Repository controls applied on 2026-07-18

After the read-only inventory, the following fail-closed GitHub environments
were created or tightened without adding credentials, publishing artifacts, or
enabling a deployment:

- Public `tinyzkp-production`, `tinyzkp-release-promotion`, and
  `tinyzkp-evaluation-release` accept protected branches only.
- Public `tinyzkp-pages-preview` accepts only pull-request merge refs matching
  `refs/pull/*/merge`; the workflow separately rejects pull requests from
  untrusted forks.
- Private `guard-production` and legacy `guard-release-candidate` accept
  protected branches only.

The environments have no recorded launch approval, merchant configuration, or
Cloudflare credential. Repository variables that authorize evidence trust or
site deployment remain intentionally unset until their exact reviewed source
files and deployment credentials exist.

## Email and disclosure

- Mail for `tinyzkp.com` is routed to IONOS MX hosts.
- SPF exists and DMARC is `p=reject`.
- The existence, forwarding destination, auto-response, retention, and access
  controls for `support@tinyzkp.com` and `security@tinyzkp.com` have not been
  verified.

Mailbox creation and the required “do not send witnesses, traces, keys,
credentials, or proprietary source” warning remain owner actions.

## Stripe and Lemon Squeezy

- The local Stripe CLI has no usable authenticated TinyZKP project context.
- The repository's zero-revenue ledger is not authoritative evidence of zero
  subscriptions, invoices, refunds, credits, disputes, or webhook obligations.
- Lemon Squeezy seller approval, store/product/variant IDs, live checkout
  links, lifecycle exercises, and customer portal evidence are absent.
- The exact legal seller, jurisdiction, address, and governing law are
  unconfirmed.

Public checkout and commercial activation remain fail-closed. No legacy Stripe
endpoint may be retired until a read-only live inventory and obligation
resolution record exists.

## Hetzner and hosted state

The local `hcloud` CLI has no active context. Server, volume, snapshot,
firewall, network, database, monitoring, backup, and customer-artifact
inventories remain unresolved. No server, volume, database, backup, OAuth
application, or credential may be removed until required exports are verified
and customer/statutory obligations are resolved.

## Required evidence before decommissioning

1. Live Stripe catalog, subscription, invoice, refund, dispute, credit, meter,
   and webhook inventory.
2. Hetzner server, volume, snapshot, firewall, network, and service inventory.
3. R2 object-class and retention inventory for every bucket.
4. Customer and statutory-record obligation ledger.
5. Verified exports and restoration checks for records that must be retained.
6. Owner-approved deletion schedule and evidence capture.
7. Confirmed static-410 start time for each retired hostname.
8. Credential and OAuth revocation ledger after the live smoke succeeds.

Until all eight records exist, the correct production state is a blocked Guard
launch with checkout closed and the legacy origins explicitly treated as
unresolved external dependencies.
