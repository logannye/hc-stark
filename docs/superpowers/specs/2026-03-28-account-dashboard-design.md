# Account Dashboard — Design Spec

## Overview

A full-featured account dashboard at `/account` for TinyZKP users to manage their API key, monitor usage, inspect proof jobs, and handle billing. Authentication via email magic links — no passwords, no pasting API keys.

## Authentication: Email Magic Links

### Flow: Returning User

1. User visits `/account` (not authenticated)
2. Sees a clean login card: "Enter your email to access your dashboard"
3. Submits email
4. Cloudflare Function `POST /api/send-magic-link` calls billing webhook `POST /send-magic-link`
5. Webhook looks up tenant by email, generates a random token (32 bytes hex), stores it in `magic_links` table with 15-minute TTL, sends email with link: `https://tinyzkp.com/account?token=<token>`
6. User clicks link in email
7. Dashboard page detects `?token=` param, calls Cloudflare Function `POST /api/verify-magic-link`
8. Webhook validates token (exists, not expired, not used), returns `{ tenant_id, email, plan, api_key, api_key_prefix }`, marks token as used
9. Dashboard stores `{ api_key, tenant_id, email, plan }` in sessionStorage
10. Dashboard renders with all data, fetched client-side from the API using the API key

### Flow: Just Signed Up (Free Tier)

1. User submits email on `/signup` (free plan selected)
2. `POST /api/create-free-account` provisions tenant as before
3. Response now includes a `dashboard_token` — a magic link token auto-generated during provisioning
4. Frontend redirects to `/account?token=<dashboard_token>` instead of `/welcome`
5. User lands directly in their authenticated dashboard — sees their API key, first steps, everything
6. No email round-trip needed for the initial login

### Flow: Just Signed Up (Paid Plan)

1. User completes Stripe checkout
2. Stripe redirects to `https://tinyzkp.com/account?checkout=success`
3. Dashboard shows success banner: "Account created! Check your email for your API key, or enter your email below to access your dashboard."
4. User enters email → magic link flow

### Session Persistence

- Session stored in sessionStorage (survives page refreshes within the same tab, clears on tab close)
- "Remember me" checkbox stores session in localStorage instead (persists across browser sessions, 30-day expiry enforced client-side)
- No server-side sessions — the API key IS the session credential, used directly for all API calls
- Logout = clear storage + redirect to `/account`

### Security

- Magic link tokens: 32 bytes random hex, single-use, 15-minute expiry
- Tokens stored as SHA-256 hashes in the database (plaintext never persisted)
- Rate limit on send-magic-link: 3 emails per 10 minutes per email address (Cloudflare Cache API, same pattern as signup)
- API key in sessionStorage/localStorage is the same key the user already has in their `.env` files — no new attack surface
- CSRF protection: all API calls are same-origin fetch with JSON content type

## Database Changes

### New table: `magic_links` (in tenant_store.sqlite)

```sql
CREATE TABLE IF NOT EXISTS magic_links (
    token_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_magic_links_tenant ON magic_links(tenant_id);
```

- `token_hash`: SHA-256 of the random token (plaintext never stored)
- `expires_at_ms`: created_at_ms + 900000 (15 minutes)
- `used`: 0 = available, 1 = consumed
- Cleanup: delete rows where `expires_at_ms < now` on every insert (piggyback GC)

## New Backend Endpoints

### Billing Webhook: `POST /send-magic-link`

- Auth: `X-Internal-Secret` header (same as `/provision-free`)
- Body: `{ "email": "user@example.com" }`
- Logic:
  1. Look up tenant by email
  2. If not found: return `{ "error": "No account found for this email" }` 404
  3. If tenant suspended: return `{ "error": "Account suspended" }` 403
  4. Generate 32-byte random token
  5. Store SHA-256(token) in `magic_links` with 15-min TTL
  6. GC expired tokens (DELETE WHERE expires_at_ms < now)
  7. Send email with link to `https://tinyzkp.com/account?token=<token>`
  8. Return `{ "ok": true }`

### Billing Webhook: `POST /verify-magic-link`

- Auth: `X-Internal-Secret` header
- Body: `{ "token": "<hex token>" }`
- Logic:
  1. Compute SHA-256(token)
  2. Look up in `magic_links` WHERE token_hash = hash AND used = 0 AND expires_at_ms > now
  3. If not found: return `{ "error": "Invalid or expired link" }` 401
  4. Mark token as used (UPDATE SET used = 1)
  5. Look up tenant by tenant_id
  6. Recover plaintext API key from `api_keys.txt` (same approach as `/rotate`)
  7. Return `{ "tenant_id", "email", "plan", "api_key", "api_key_prefix" }`

### Billing Webhook: `POST /provision-free` (modified)

- After creating tenant and regenerating api_keys.txt, also generate a magic link token
- Return `{ "ok": true, "dashboard_token": "<hex token>" }` instead of just `{ "ok": true }`

### Cloudflare Functions

**`/api/send-magic-link`** — proxies to `webhook.tinyzkp.com/send-magic-link` with `X-Internal-Secret`. Rate limited: 3 per 10 min per IP. CORS restricted to tinyzkp.com.

**`/api/verify-magic-link`** — proxies to `webhook.tinyzkp.com/verify-magic-link` with `X-Internal-Secret`. Rate limited: 10 per 5 min per IP. CORS restricted to tinyzkp.com.

### Cloudflare Function: `create-free-account.js` (modified)

- Pass through the `dashboard_token` from the webhook response to the frontend
- Frontend redirects to `/account?token=<dashboard_token>` instead of `/welcome`

## Dashboard Page: `/account`

### Layout

Single-page app in `account.html`. Two states: unauthenticated (login card) and authenticated (full dashboard). Same dark theme, nav, and footer as all other pages.

### Unauthenticated State: Login Card

Centered card (max-width 440px), same visual treatment as signup page:

- Heading: "Your Dashboard"
- Subtext: "Enter your email to receive a login link."
- Email input + "Send Login Link" button
- After submit: "Check your email for a login link. It expires in 15 minutes."
- Below form: "Don't have an account? [Get a free API key](/signup)"
- Success banner if `?checkout=success` in URL

### Authenticated State: Dashboard

Top-level layout: full-width nav, then a content area (max-width 1080px) with a grid of sections.

#### Section 1: Overview Bar

Horizontal bar at the top with 4-5 key metrics in a row:

| Plan | Proofs This Month | Cost This Month | Monthly Cap | Status |
|------|------------------|-----------------|-------------|--------|
| `Team` | `247` | `$18.45` | `$2,500` | `Active` |

- Plan shown as a colored badge (free=green, developer=default, team=accent, scale=amber)
- Cost shown as `$18.45 / $2,500` with a thin progress bar underneath
- Status: green dot + "Active" (pulled from whether API calls succeed)

#### Section 2: API Key

Card with:
- Masked key display: `tzk_Uw4vpM3F••••••••••••••••••••••••` with a "Reveal" toggle
- When revealed: full key with "Copy" button
- "Rotate Key" button (danger styling, requires confirmation dialog)
- Warning text: "Rotating invalidates your current key immediately. Update all integrations before rotating."
- After rotation: shows new key with prominent "Copy your new key now — it won't be shown again" banner

#### Section 3: Usage & Cost

Two sub-sections:

**Current Period** (auto-loads current month):
- Big number cards: Total Proofs, Total Verifies, Failed Proofs, Estimated Cost
- Date range picker (two date inputs) to query custom periods via `/usage?since=&until=`
- "Refresh" button

**Cost Breakdown Table** (computed client-side from job data):
- Rows by trace size tier: < 10K, 10K-100K, 100K-1M, 1M-10M, > 10M
- Columns: Proof Count, Avg Duration, Base Cost, Discount, Final Cost
- Discount column shows plan discount (25% for team, 40% for scale)
- Footer row: Total

#### Section 4: Recent Proof Jobs

Paginated table:
- Columns: Job ID (truncated, copy-on-click), Status (badge), Workload, Trace Length, Duration, Timestamp
- Status badges: pending (amber pulse), running (blue pulse), succeeded (green), failed (red)
- Filter tabs: All | Succeeded | Failed | Running
- Click row to expand: full job ID, error message (if failed), proof size, inspect link
- "Load More" pagination (50 per page)
- Empty state: "No proofs yet. [Submit your first proof](/docs)"

#### Section 5: Plan & Billing

Two-column card:

**Left: Current Plan**
- Plan name and badge
- Limits table: Prove RPM, Verify RPM, Max Inflight, Monthly Cap, Max Duration
- For free/developer: "Upgrade to Team" CTA button → links to `/signup?plan=team`
- For team: "Upgrade to Scale" CTA

**Right: Billing**
- "Manage Billing" button → calls `/api/create-portal-session` → redirects to Stripe portal
- Text: "View invoices, update payment method, or manage your subscription."
- For free tier: "You're on the free plan. No billing set up." with upgrade CTA instead.

#### Section 6: Quick Reference

Compact card with:
- Base URL: `https://api.tinyzkp.com` (copy button)
- Auth header: `Authorization: Bearer tzk_...` (copy button, uses their actual key)
- Quick links: Quickstart, API Reference, Templates, Cost Estimation
- Example curl (pre-filled with their API key):
  ```
  curl -X POST https://api.tinyzkp.com/prove/template/range_proof \
    -H "Authorization: Bearer tzk_YOUR_KEY" \
    -H "Content-Type: application/json" \
    -d '{"params":{"min":0,"max":100,"witness_steps":[42]}}'
  ```

### Auto-Refresh

- Usage stats refresh every 60 seconds (quiet background fetch, no spinner)
- Job list refreshes every 15 seconds if any jobs are in pending/running state
- No refresh if all jobs are terminal (succeeded/failed)

### Responsive

- Overview bar: wraps to 2 rows on mobile
- Job table: horizontal scroll on mobile, key columns (status, ID, time) always visible
- Plan/Billing: stacks vertically on mobile
- Quick Reference: full width on mobile

## Email Templates

### Magic Link Email

Subject: "Log in to your TinyZKP dashboard"

Body:
```
Click the link below to access your TinyZKP dashboard:

https://tinyzkp.com/account?token=<TOKEN>

This link expires in 15 minutes and can only be used once.

If you didn't request this, you can safely ignore this email.

— TinyZKP
https://tinyzkp.com
```

## Navigation Changes

- Add "Dashboard" link to the nav bar on all pages (between "Contact" and "Status")
- Points to `/account`
- On `/account` itself, the "GET API KEY" CTA button changes to "Log Out" when authenticated (clears session, reloads page)

## Files to Create/Modify

### Create:
- `site/account.html` — the dashboard page
- `site/functions/api/send-magic-link.js` — Cloudflare Function
- `site/functions/api/verify-magic-link.js` — Cloudflare Function
- `billing/templates/magic_link.txt` — email template

### Modify:
- `billing/provision_tenant.py` — add `/send-magic-link`, `/verify-magic-link` endpoints, modify `/provision-free` to return dashboard_token, add `magic_links` table init
- `billing/tenant_store.py` — add magic_links table schema, add `get_by_email()` lookup, add magic link CRUD functions
- `site/functions/api/create-free-account.js` — pass through dashboard_token, redirect to `/account`
- `site/signup.html` — modify free signup flow to redirect to `/account?token=...`
- `site/index.html` — add "Dashboard" to nav
- `site/docs.html` — add "Dashboard" to nav
- `site/signup.html` — add "Dashboard" to nav (already modifying)
- `site/welcome.html` — add "Dashboard" to nav, add "Go to Dashboard" CTA
- `site/contact.html` — add "Dashboard" to nav
- `site/terms.html` — add "Dashboard" to nav
- `site/privacy.html` — add "Dashboard" to nav
- `site/functions/api/create-portal-session.js` — change return_url to `/account`
