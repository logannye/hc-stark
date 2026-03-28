# Account Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an account dashboard at `/account` with magic-link email auth, usage analytics, job history, API key management, and Stripe billing portal.

**Architecture:** Static HTML page (`account.html`) authenticates via email magic links backed by two new billing webhook endpoints. After auth, all data is fetched client-side from existing API endpoints (`/usage`, `/prove`). Session state lives in sessionStorage/localStorage. No new server infrastructure.

**Tech Stack:** HTML/CSS/JS (same static pattern as rest of site), Python/Flask (billing webhook), Cloudflare Pages Functions (JS), SQLite (magic_links table).

**Spec:** `docs/superpowers/specs/2026-03-28-account-dashboard-design.md`

---

### Task 1: Magic Links — Database & Tenant Store

**Files:**
- Modify: `billing/tenant_store.py`

- [ ] **Step 1: Add magic_links table to schema and get_by_email function**

In `billing/tenant_store.py`, add to `_SCHEMA` string (after the `processed_events` table):

```sql
CREATE TABLE IF NOT EXISTS magic_links (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_magic_links_tenant ON magic_links(tenant_id);
```

Add these functions after `mark_event_processed`:

```python
def get_by_email(conn: sqlite3.Connection, email: str) -> Optional[sqlite3.Row]:
    """Fetch a tenant by email address."""
    return conn.execute(
        "SELECT * FROM tenants WHERE email = ?", (email,)
    ).fetchone()


def create_magic_link(conn: sqlite3.Connection, token_hash: str, tenant_id: str, ttl_ms: int = 900_000) -> None:
    """Store a magic link token hash with a 15-minute TTL."""
    now = _now_ms()
    with conn:
        # GC expired tokens on every insert.
        conn.execute("DELETE FROM magic_links WHERE expires_at_ms < ?", (now,))
        conn.execute(
            "INSERT INTO magic_links (token_hash, tenant_id, created_at_ms, expires_at_ms, used) VALUES (?, ?, ?, ?, 0)",
            (token_hash, tenant_id, now, now + ttl_ms),
        )


def verify_magic_link(conn: sqlite3.Connection, token_hash: str) -> Optional[str]:
    """Verify and consume a magic link. Returns tenant_id or None."""
    now = _now_ms()
    row = conn.execute(
        "SELECT tenant_id FROM magic_links WHERE token_hash = ? AND used = 0 AND expires_at_ms > ?",
        (token_hash, now),
    ).fetchone()
    if not row:
        return None
    with conn:
        conn.execute("UPDATE magic_links SET used = 1 WHERE token_hash = ?", (token_hash,))
    return row["tenant_id"]
```

- [ ] **Step 2: Run existing billing tests to verify no breakage**

Run: `cd /Users/logannye/hc-stark/billing && python3 -m pytest tests/ -v 2>/dev/null || echo "No test suite — verify manually"`

Verify the schema migration is backward-compatible (it is — CREATE TABLE IF NOT EXISTS).

- [ ] **Step 3: Commit**

```bash
git add billing/tenant_store.py
git commit -m "feat(billing): add magic_links table and get_by_email lookup"
```

---

### Task 2: Magic Links — Webhook Endpoints

**Files:**
- Modify: `billing/provision_tenant.py`
- Create: `billing/templates/magic_link.txt`

- [ ] **Step 1: Create magic link email template**

Create `billing/templates/magic_link.txt`:

```
Log in to your TinyZKP dashboard:

  {link}

This link expires in 15 minutes and can only be used once.
If you didn't request this, you can safely ignore this email.

— TinyZKP
https://tinyzkp.com
```

- [ ] **Step 2: Add helper to look up plaintext API key from api_keys.txt**

In `billing/provision_tenant.py`, add this function after `_send_welcome_email`:

```python
def _recover_api_key(tenant_id: str) -> Optional[str]:
    """Recover plaintext API key from api_keys.txt for a given tenant."""
    if not os.path.exists(API_KEYS_FILE):
        return None
    with open(API_KEYS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[0] == tenant_id:
                return parts[1]
    return None
```

- [ ] **Step 3: Add /send-magic-link endpoint**

In `billing/provision_tenant.py`, add this route after the `/provision-free` route:

```python
@app.route("/send-magic-link", methods=["POST"])
def send_magic_link():
    """Send a magic login link to the user's email."""
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()

    if not email or "@" not in email or len(email) > 254:
        return flask.jsonify(error="valid email required"), 400

    conn = tenant_store.open_db()
    tenant = tenant_store.get_by_email(conn, email)

    if not tenant:
        conn.close()
        # Don't reveal whether the email exists — return success either way.
        return flask.jsonify(ok=True), 200

    if tenant["status"] != "active":
        conn.close()
        return flask.jsonify(ok=True), 200

    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    tenant_store.create_magic_link(conn, token_hash, tenant["tenant_id"])
    conn.close()

    link = f"https://tinyzkp.com/account?token={token}"

    # Send email in background thread.
    def _bg_send():
        try:
            _send_magic_link_email(email, link)
        except Exception as e:
            print(f"WARNING: Magic link email failed for {email}: {e}", file=sys.stderr)

    threading.Thread(target=_bg_send, daemon=True).start()
    return flask.jsonify(ok=True), 200
```

- [ ] **Step 4: Add the magic link email sender**

Add this function near `_send_welcome_email`:

```python
def _send_magic_link_email(email: str, link: str) -> bool:
    """Send a magic login link email. Returns True on success."""
    if not SMTP_HOST:
        print("SMTP not configured, skipping magic link email", file=sys.stderr)
        return False

    template_path = TEMPLATES_DIR / "magic_link.txt"
    if template_path.exists():
        body = template_path.read_text().format(link=link)
    else:
        body = f"Log in to your TinyZKP dashboard:\n\n  {link}\n\nThis link expires in 15 minutes.\n"

    msg = MIMEText(body)
    msg["Subject"] = "Your TinyZKP login link"
    msg["From"] = SMTP_FROM
    msg["To"] = email

    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        with server:
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Magic link email sent to {email}")
        return True
    except Exception as e:
        print(f"WARNING: Failed to send magic link to {email}: {e}", file=sys.stderr)
        return False
```

- [ ] **Step 5: Add /verify-magic-link endpoint**

Add this route after `/send-magic-link`:

```python
@app.route("/verify-magic-link", methods=["POST"])
def verify_magic_link():
    """Verify a magic link token and return tenant credentials."""
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not token or len(token) != 64:
        return flask.jsonify(error="invalid token"), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = tenant_store.open_db()
    tenant_id = tenant_store.verify_magic_link(conn, token_hash)

    if not tenant_id:
        conn.close()
        return flask.jsonify(error="Invalid or expired link"), 401

    tenant = tenant_store.get_tenant(conn, tenant_id)
    conn.close()

    if not tenant or tenant["status"] != "active":
        return flask.jsonify(error="Account not active"), 403

    api_key = _recover_api_key(tenant_id)

    return flask.jsonify(
        tenant_id=tenant_id,
        email=tenant["email"],
        plan=tenant["plan"],
        api_key=api_key or "",
        api_key_prefix=tenant["api_key_prefix"],
    ), 200
```

- [ ] **Step 6: Add `import hashlib` to the top of provision_tenant.py**

`hashlib` is already used in the `/rotate` endpoint but imported locally there. Add it to the top-level imports alongside the others:

```python
import hashlib
```

(Check first — if it's already there, skip.)

- [ ] **Step 7: Modify /provision-free to return a dashboard_token**

In the `provision_free()` function, after `sync_keys.regenerate(...)` and before `conn.close()`, add:

```python
    # Generate a magic link token for immediate dashboard access.
    dashboard_token = secrets.token_hex(32)
    dashboard_token_hash = hashlib.sha256(dashboard_token.encode()).hexdigest()
    tenant_store.create_magic_link(conn, dashboard_token_hash, tenant_id)
```

Change the return statement from:
```python
    return flask.jsonify(ok=True), 200
```
to:
```python
    return flask.jsonify(ok=True, dashboard_token=dashboard_token), 200
```

- [ ] **Step 8: Test the endpoints manually on the Hetzner server**

After deploying (Task 6), test:
```bash
# send-magic-link
curl -s -X POST http://localhost:5001/send-magic-link \
  -H "Content-Type: application/json" \
  -H "X-Internal-Secret: $INTERNAL_SECRET" \
  -d '{"email":"audit-bot@tinyzkp.com"}'

# verify-magic-link (use token from email or DB)
```

- [ ] **Step 9: Commit**

```bash
git add billing/provision_tenant.py billing/templates/magic_link.txt
git commit -m "feat(billing): add magic link auth endpoints and dashboard_token on signup"
```

---

### Task 3: Cloudflare Functions — Magic Link Proxies

**Files:**
- Create: `site/functions/api/send-magic-link.js`
- Create: `site/functions/api/verify-magic-link.js`
- Modify: `site/functions/api/create-free-account.js`
- Modify: `site/functions/api/create-portal-session.js`

- [ ] **Step 1: Create send-magic-link.js**

Create `site/functions/api/send-magic-link.js`:

```javascript
// Cloudflare Pages Function — sends a magic login link to the user's email.

const RATE_LIMIT_MAX = 3;
const RATE_LIMIT_WINDOW_S = 600;

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/magic-link/${ip}`);
  const cached = await cache.match(key);
  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;
  await cache.put(key, new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  }));
  return true;
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "Too many requests. Try again later." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    const { email } = await context.request.json();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "Valid email required." }), {
        status: 400, headers: jsonHeaders,
      });
    }

    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/send-magic-link`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ email }),
    });

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return new Response(JSON.stringify({ error: body.error || "Failed to send login link." }), {
        status: 502, headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("send-magic-link error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
```

- [ ] **Step 2: Create verify-magic-link.js**

Create `site/functions/api/verify-magic-link.js`:

```javascript
// Cloudflare Pages Function — verifies a magic link token and returns credentials.

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_S = 300;

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/verify-link/${ip}`);
  const cached = await cache.match(key);
  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;
  await cache.put(key, new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  }));
  return true;
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({ error: "Too many attempts. Try again later." }), {
        status: 429, headers: jsonHeaders,
      });
    }

    const { token } = await context.request.json();
    if (!token || token.length !== 64) {
      return new Response(JSON.stringify({ error: "Invalid token." }), {
        status: 400, headers: jsonHeaders,
      });
    }

    const WEBHOOK_URL = context.env.WEBHOOK_BASE_URL || "https://webhook.tinyzkp.com";
    const resp = await fetch(`${WEBHOOK_URL}/verify-magic-link`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Internal-Secret": context.env.INTERNAL_SECRET || "",
      },
      body: JSON.stringify({ token }),
    });

    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return new Response(JSON.stringify({ error: body.error || "Invalid or expired link." }), {
        status: resp.status, headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify(body), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("verify-magic-link error:", err);
    return new Response(JSON.stringify({ error: "Internal error." }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("Origin") || "";
  const allowedOrigin = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
```

- [ ] **Step 3: Modify create-free-account.js to pass through dashboard_token**

In `site/functions/api/create-free-account.js`, change the success handler from:

```javascript
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: jsonHeaders,
    });
```

to:

```javascript
    const result = await resp.json().catch(() => ({ ok: true }));
    return new Response(JSON.stringify({ ok: true, dashboard_token: result.dashboard_token || null }), {
      status: 200,
      headers: jsonHeaders,
    });
```

- [ ] **Step 4: Modify create-portal-session.js return_url**

In `site/functions/api/create-portal-session.js`, change:

```javascript
    params.append("return_url", "https://tinyzkp.com/docs");
```

to:

```javascript
    params.append("return_url", "https://tinyzkp.com/account");
```

- [ ] **Step 5: Commit**

```bash
git add site/functions/api/send-magic-link.js site/functions/api/verify-magic-link.js \
  site/functions/api/create-free-account.js site/functions/api/create-portal-session.js
git commit -m "feat(functions): add magic link auth functions, dashboard_token passthrough"
```

---

### Task 4: Modify Signup Flow to Redirect to Dashboard

**Files:**
- Modify: `site/signup.html`

- [ ] **Step 1: Update the free signup success handler**

In `site/signup.html`, find the free signup success handler:

```javascript
      .then(function() {
        try { sessionStorage.setItem('tinyzkp_email', email); } catch(e) {}
        window.location.href = '/welcome?plan=free';
      })
```

Replace with:

```javascript
      .then(function(data) {
        try { sessionStorage.setItem('tinyzkp_email', email); } catch(e) {}
        if (data.dashboard_token) {
          window.location.href = '/account?token=' + data.dashboard_token;
        } else {
          window.location.href = '/welcome?plan=free';
        }
      })
```

- [ ] **Step 2: Commit**

```bash
git add site/signup.html
git commit -m "feat(signup): redirect free signups to dashboard with auto-login token"
```

---

### Task 5: Add Dashboard Nav Link to All Pages

**Files:**
- Modify: `site/index.html`, `site/docs.html`, `site/signup.html`, `site/welcome.html`, `site/contact.html`, `site/terms.html`, `site/privacy.html`

- [ ] **Step 1: Add "Dashboard" link to nav on all 7 pages**

On every page, find the nav links section. Add a "Dashboard" link between "Contact" and the "Status" link. The link text and placement:

Find:
```html
    <a href="/contact">Contact</a>
    <a class="status-link"
```

Replace with:
```html
    <a href="/contact">Contact</a>
    <a href="/account">Dashboard</a>
    <a class="status-link"
```

Do this for all 7 HTML files. The status link formatting varies slightly between pages (some use inline styles) — only insert the Dashboard link, don't change the status link.

- [ ] **Step 2: Commit**

```bash
git add site/index.html site/docs.html site/signup.html site/welcome.html \
  site/contact.html site/terms.html site/privacy.html
git commit -m "feat(nav): add Dashboard link to navigation on all pages"
```

---

### Task 6: Build the Dashboard Page

**Files:**
- Create: `site/account.html`

- [ ] **Step 1: Create account.html**

This is the largest task. Create `site/account.html` — a complete static HTML page with the same dark theme, nav, and footer as the rest of the site. The page has two states:

**Unauthenticated state:** Login card centered on the page with email input and "Send Login Link" button.

**Authenticated state:** Full dashboard with 6 sections — Overview Bar, API Key, Usage & Cost, Recent Jobs, Plan & Billing, Quick Reference.

The page uses the existing API (`GET /usage`, `GET /prove`) via `fetch` with the stored API key. Usage auto-refreshes every 60 seconds. Job list refreshes every 15 seconds if any jobs are pending/running.

The full HTML for this file is too large to inline in a plan. Build it following these rules:
- Same CSS variables, fonts, nav, footer, dot-grid background as `index.html`
- Same responsive breakpoints (`@media(max-width:768px)`)
- Login state: max-width 440px card, same input/button styling as `signup.html`
- Dashboard state: max-width 1080px, grid layout
- Overview bar: horizontal flex with 5 metric cards
- API Key section: masked key with reveal toggle, copy button, rotate button with confirm dialog
- Usage section: 4 big-number cards + date range picker + cost breakdown table
- Jobs section: paginated table with status badges, filter tabs, click-to-expand
- Plan section: two-column — plan details + billing portal button
- Quick Reference: compact card with copy-ready curl commands using the user's actual API key
- All API calls use `Authorization: Bearer <key>` header to `https://api.tinyzkp.com`
- Key rotation calls `POST /api/rotate-key` (proxied to billing webhook `/rotate`)
- Billing portal calls `POST /api/create-portal-session` with the user's email
- Logout clears sessionStorage/localStorage and reloads

Use the `frontend-design` skill to build this page with production-quality aesthetics matching the existing site's dark theme.

- [ ] **Step 2: Commit**

```bash
git add site/account.html
git commit -m "feat: add account dashboard page with usage analytics and key management"
```

---

### Task 7: Deploy Backend to Hetzner

**Files:** (remote deployment, no local file changes)

- [ ] **Step 1: Deploy updated billing code to Hetzner**

```bash
scp billing/provision_tenant.py root@46.225.78.136:/opt/hc-stark/billing/provision_tenant.py
scp billing/tenant_store.py root@46.225.78.136:/opt/hc-stark/billing/tenant_store.py
scp billing/templates/magic_link.txt root@46.225.78.136:/opt/hc-stark/billing/templates/magic_link.txt
ssh root@46.225.78.136 'systemctl restart hc-billing-webhook.service && sleep 2 && systemctl is-active hc-billing-webhook.service'
```

Expected: `active`

- [ ] **Step 2: Verify new endpoints work**

```bash
ssh root@46.225.78.136 'curl -s -X POST http://localhost:5001/send-magic-link \
  -H "Content-Type: application/json" \
  -H "X-Internal-Secret: $(grep INTERNAL_SECRET /opt/hc-stark/.env | cut -d= -f2)" \
  -d "{\"email\":\"audit-bot@tinyzkp.com\"}"'
```

Expected: `{"ok":true}`

- [ ] **Step 3: Deploy site to Cloudflare Pages**

```bash
cd site && npx wrangler pages deploy . --project-name tinyzkp --branch main --commit-dirty=true
```

- [ ] **Step 4: Test full magic link flow**

```bash
# Send magic link
curl -s -X POST https://tinyzkp.com/api/send-magic-link \
  -H "Content-Type: application/json" \
  -H "Origin: https://tinyzkp.com" \
  -d '{"email":"audit-bot@tinyzkp.com"}'

# (Check email for token, or query DB directly for testing)
```

---

### Task 8: End-to-End Verification

- [ ] **Step 1: Verify all pages load**

```bash
for page in / /docs /signup /welcome /contact /terms /privacy /account; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://tinyzkp.com$page")
  echo "$code  $page"
done
```

Expected: all 200.

- [ ] **Step 2: Verify magic link flow end-to-end via browser**

Use `agent-browser` to:
1. Navigate to `https://tinyzkp.com/account`
2. Screenshot the login card
3. Navigate to `https://tinyzkp.com/signup`, select Free, enter a test email, submit
4. Verify redirect to `/account?token=...`
5. Screenshot the authenticated dashboard

- [ ] **Step 3: Update the daily audit script**

Add `/account` to the website pages test in `scripts/monitoring/api_health_audit.sh`:

Find:
```bash
for path in / /docs /signup /welcome /contact /terms /privacy; do
```

Replace with:
```bash
for path in / /docs /signup /welcome /contact /terms /privacy /account; do
```

- [ ] **Step 4: Run the audit to confirm all green**

```bash
TINYZKP_AUDIT_API_KEY=tzk_Uw4vpM3FkBLyM4CGfID9me0ziiNliRwK \
/bin/bash scripts/monitoring/api_health_audit.sh 2>&1
```

Expected: 22/22 passed, 0 failed (one more than before — `/account` page).

- [ ] **Step 5: Final commit and push**

```bash
git add scripts/monitoring/api_health_audit.sh
git commit -m "feat(audit): add /account to daily health check"
git push origin main
```
