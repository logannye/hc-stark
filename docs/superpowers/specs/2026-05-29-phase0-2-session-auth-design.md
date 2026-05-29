# Phase 0.2 — Account-Security Session Layer — Design Spec

- **Status:** Draft for review (precedes the implementation plan)
- **Date:** 2026-05-29
- **Branch:** `phase0.2-account-security` (off `main` @ `47f3f4f`)
- **Closes audit findings:** G3 (Stripe-portal takeover by email), G4 (magic-link returns the raw long-lived API key), G10 (`/metrics` unauthenticated). Reference: `project_hc_stark_audit_2026-05-29.md`.

## 1. Problem

The dashboard (`site/account.html`) has **no session**: it stores the raw `tzk_` API key (returned by `/verify-magic-link`) in `localStorage`/`sessionStorage` and uses it as the `Bearer` for every call. Consequences:
- **G4:** a magic link — requestable by email alone, 15-min TTL — when completed hands the **long-lived raw key** to the browser, where it lives indefinitely as the ambient credential.
- **G3:** `create-portal-session.js` mints a Stripe billing-portal URL from an **email in the request body with no auth** (only an IP rate-limit) — anyone can open a customer's portal.
- **G10:** `hc-server` `/metrics` is registered with `get(metrics)` and **no auth**, exposing per-tenant revenue counters.

## 2. Decisions (approved)

- **Proxy through CF Functions.** The browser holds only a session; all management calls go through Cloudflare Pages Functions that validate the session via the webhook and act server-side. The raw API key never enters the browser as a credential. `hc-server`'s auth path is unchanged.
- **Server-stored, revocable sessions.** A `sessions` table in `tenant_store.sqlite` (migrates with the Phase-3 Postgres cutover). Real logout + revocation on suspension.

**Refinement — httpOnly cookie (not JS-readable storage).** The session token is delivered as an **`HttpOnly; Secure; SameSite=Strict` cookie** set by the CF Function on magic-link verification, scoped to `tinyzkp.com`. The dashboard's JS never reads or stores the token; same-origin `/api/*` calls carry the cookie automatically. This removes the session from the XSS-reachable surface entirely — strictly better than returning a token for JS to store.

## 3. Data model

New table in `billing/tenant_store.py` (mirrors the `magic_links` pattern):

```sql
CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,   -- sha256(session_token)
  tenant_id     TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
```

Functions: `create_session(conn, token_hash, tenant_id, ttl_ms=24h) -> None`; `validate_session(conn, token_hash) -> Optional[tenant_id]` (returns tenant only if not expired AND the tenant is `status='active'`; opportunistically GC expired rows); `delete_session(conn, token_hash)` (logout); `delete_sessions_for_tenant(conn, tenant_id)` (revoke-all, called on suspend). Token = `secrets.token_hex(32)` (64 hex), stored only as `sha256`.

**Lifecycle:** minted on magic-link verification (24h fixed TTL); validated on every management call; deleted on logout; all-for-tenant deleted when `suspend_tenant` runs (so suspension kills active sessions). Key **rotation does NOT invalidate sessions** (you stay logged in; the key is a separate artifact).

## 4. Webhook (`billing/provision_tenant.py`) — endpoint changes

All gated by `X-Internal-Secret` (as today). Session-bearing endpoints also require a valid `session_token` (the CF function forwards the cookie value).

| Endpoint | Change | Behavior |
|---|---|---|
| `POST /verify-magic-link` | **Changed (G4)** | Consume the magic link → `create_session` → return `{session_token, email, plan, api_key_prefix}` — **never `api_key`**. (`_recover_api_key` call removed from this path.) |
| `POST /session/resolve` | **New** | `{session_token}` → `validate_session` → `{tenant_id, email, plan, api_key_prefix, status}` or 401. Used by CF functions to authenticate the session and by the dashboard to check login state. No key. |
| `POST /session/reveal-key` | **New** | `{session_token}` → validate → return `{api_key}` (the raw key, via `_recover_api_key`). The **only** path that returns the key, on explicit user action. |
| `POST /session/usage` | **New** | `{session_token}` → validate → look up the tenant's key server-side → call `hc-server /usage` → return the usage JSON. (Key stays on the webhook box.) |
| `POST /rotate` | **Changed (G4)** | Accept `{session_token}` (validate → rotate that tenant's key). Drop the `current_key` requirement for the dashboard path. Returns the new key once (display) + new prefix. |
| `POST /logout` | **New** | `{session_token}` → `delete_session`. |
| `suspend_tenant(...)` | **Changed** | Also `delete_sessions_for_tenant` so suspension/cancellation kills live sessions. |

## 5. Cloudflare Pages Functions (`site/functions/api/`)

A shared helper `_session.js` (or inline) reads the `tz_session` cookie and calls webhook `/session/resolve`; returns the tenant or a 401.

| Function | Change |
|---|---|
| `verify-magic-link.js` | **Changed:** on success, `Set-Cookie: tz_session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`; return only the non-secret metadata (`email`, `plan`, `api_key_prefix`) to the page. |
| `session-resolve.js` | **New:** reads cookie → webhook `/session/resolve` → returns `{email, plan, api_key_prefix, status}` (login-state check on page load). 401 if no/invalid session. |
| `reveal-key.js` | **New:** cookie-gated → webhook `/session/reveal-key` → `{api_key}`. |
| `usage.js` | **New:** cookie-gated → webhook `/session/usage` → usage JSON. (Replaces the dashboard's direct `Bearer` call to `api.tinyzkp.com/usage`.) |
| `rotate-key.js` | **Changed (G4):** authenticate via the **cookie/session** (not `Authorization: Bearer <key>`); forward session to webhook `/rotate`. |
| `create-portal-session.js` | **Changed (G3):** **remove the client-supplied `email`**; require the session cookie → `/session/resolve` → use the **server-resolved email** to find the Stripe customer → mint the portal. Tighten the CORS off `*` (it's same-origin). Also fix the single-quoted Stripe search query → double-quoted. |
| `logout.js` | **New:** cookie → webhook `/logout`; clear the cookie (`Max-Age=0`). |
| `create-checkout.js`, `create-free-account.js`, `send-magic-link.js`, `contact.js`, `demo-*.js` | **Unchanged** (pre-session / anonymous flows). |

## 6. Dashboard (`site/account.html`)

- Stop reading/storing the raw key. On load, call `/api/session-resolve`; if 200, render logged-in (show `api_key_prefix` masked, plan, usage via `/api/usage`); if 401, show the magic-link request UI.
- Magic-link landing (`?token=`): POST `/api/verify-magic-link` (sets the cookie); then resolve.
- **"Reveal API key"** button → `/api/reveal-key` → display + copy (never persisted in storage). Default view shows only the prefix.
- **Rotate** → `/api/rotate-key` (cookie); show the new key once.
- **Logout** → `/api/logout`.
- Remove `SESSION_KEY` localStorage/sessionStorage of `api_key`; the only client state is "are we logged in" (derived from the resolve call), not the key.

## 7. hc-server — G10 (`crates/hc-server/src/lib.rs`)

Gate `/metrics`. Add `HC_METRICS_TOKEN` (env). If set, `/metrics` requires `Authorization: Bearer <HC_METRICS_TOKEN>` (Prometheus configured with `bearer_token`); if unset, default-deny from non-loopback — i.e. keep it simple: **require the token; if `HC_METRICS_TOKEN` is unset, return 404/disabled** so it's never unauthenticated in prod. Update `deploy/prometheus/prometheus.yml` to send the bearer, and document the env var. (Independent of the session work; can be its own task/commit.)

## 8. Security properties achieved

- **G3 closed:** portal requires a valid session; the email is server-resolved from the session, never client-supplied → no cross-account portal access.
- **G4 closed:** the raw key is never the ambient credential and never auto-returned; it's disclosed only on an explicit, session-authenticated reveal. A stolen/expired session can be revoked; the key can rotate independently. The session cookie is `HttpOnly` (not XSS-readable).
- **G10 closed:** `/metrics` requires a token (or is disabled), so per-tenant revenue is not public.

## 9. Threats considered / residual

- **Magic-link still email-triggerable** (anyone can request a link to a victim's address): acceptable for magic-link auth — possession of the email inbox is the factor; we keep the existing rate-limit + 15-min single-use TTL. (Not regressed by this work.)
- **CSRF:** `SameSite=Strict` + the existing strict `Origin` allowlist on the CF functions mitigate cross-site use of the cookie.
- **`INTERNAL_SECRET` remains the single shared CF↔webhook secret** (a known audit item, G-series); out of scope here — 0.2 does not change that trust model, only what rides on it.

## 10. Out of scope (other phases)
- API key *hashing-only* storage / retiring the plaintext `api_keys.txt` as the auth source (Phase 3 auth hardening).
- `INTERNAL_SECRET` → per-purpose signed tokens (later).
- Free-tier re-signup uniqueness (G8), `/aggregate`+zkML metering (G9), billing reconciliation (G11/G12) — Phase 0.3.

## 11. Implementation order (preview for the plan)
1. `tenant_store.py` sessions table + functions (+ tests).
2. `provision_tenant.py` endpoints (verify-magic-link change, session/resolve, reveal-key, usage, rotate, logout; suspend revokes).
3. CF Functions (helper + the 7 changed/new functions).
4. `account.html` dashboard rewrite.
5. hc-server G10 metrics token (+ prometheus.yml + README).
6. End-to-end verification (the daily-audit `api_health_audit.sh` free-signup E2E must be updated to the session flow).
