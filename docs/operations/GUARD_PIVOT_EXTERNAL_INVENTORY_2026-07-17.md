# TinyZKP Guard pivot: external-state inventory

Captured read-only on 2026-07-17. This document records non-secret facts only.
It is not authorization to delete, archive, migrate, refund, or cancel any
external resource.

## Cloudflare

- OAuth access is present for the owner Cloudflare account.
- Pages project: `tinyzkp`.
- Domains: `tinyzkp.pages.dev`, `tinyzkp.com`, and `www.tinyzkp.com`.
- The project is direct-upload rather than provider-connected.
- Production is still release `5719292ad0c8c4b5f0f6b0500db41cdf6888134c`.
- Current preview deployments include repository main release `7a1b9db`.
- R2 buckets visible to the account:
  - `tinyzkp-backups`
  - `tinyzkp-beta-artifacts`
  - `tinyzkp-beta-pgbackrest`
  - `tinyzkp-proofs`
- No D1 database or Queue was returned by the account-level Wrangler inventory.

Do not delete any bucket until a reviewed retention/export record proves it
contains no customer or statutory data.

## Live routes

The following routes all returned HTTP 200 during the inventory:

- `https://tinyzkp.com/api/release`
- `https://tinyzkp.com/pricing.json`
- `https://api.tinyzkp.com/version`
- `https://webhook.tinyzkp.com/health`
- `https://mcp.tinyzkp.com/version`

The site, API, and MCP report the same stale release `5719292`. API, webhook,
and MCP remain external dependencies until their origins and obligations are
inventoried, then deliberately retired.

## GitHub

- GitHub CLI access is authenticated as `logannye`.
- The repository contains only package-publication secrets by name; no
  Cloudflare deployment secret is configured.
- A local annotated archive tag,
  `archive/hosted-beta-2026-07-17`, points to the pre-pivot main commit
  `7a1b9db80f26a2fd713bef44e54faea6ccaba578`.

The automatic Pages workflow must remain disabled until a least-privilege
Cloudflare Pages token and account ID are stored in the protected production
environment.

## Stripe

The local Stripe CLI has no usable authenticated `tinyzkp` project profile and
no `STRIPE_SECRET_KEY` is available to the read-only inventory tool. The
repository ledger reports no realized revenue, but that is not authoritative
external evidence. Live products, prices, links, subscriptions, invoices,
meters, credits, and webhook destinations remain an unresolved launch blocker.

## Hetzner

The local `hcloud` CLI has no active context. Server, volume, firewall, network,
and snapshot inventory therefore remains unresolved. No Hetzner resource may
be cancelled until credentials are supplied and a read-only inventory plus
verified export is reviewed.

## Legal and merchant

- Exact seller entity, jurisdiction, address, and governing law are not
  confirmed.
- Merchant-of-record approval and product configuration are not complete.
- Public checkout and proprietary commercial distribution must remain blocked.
