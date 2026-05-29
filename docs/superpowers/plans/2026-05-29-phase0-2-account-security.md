# Phase 0.2 — Account-Security Session Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Introduce a server-stored, httpOnly-cookie session layer so the dashboard never holds the raw API key; gate the Stripe portal and key-reveal on a validated session; authenticate `/metrics`. Closes audit findings **G3** (portal-by-email), **G4** (magic-link returns raw key), **G10** (`/metrics` unauth).

**Architecture:** Approved design spec at `docs/superpowers/specs/2026-05-29-phase0-2-session-auth-design.md`. Sessions live in `tenant_store.sqlite`; the webhook (`provision_tenant.py`) owns session lifecycle + key access; Cloudflare Pages Functions proxy all dashboard management calls carrying an `HttpOnly` cookie; `account.html` holds no key.

**Tech stack:** Python (Flask webhook + sqlite tenant store), Cloudflare Pages Functions (JS), static HTML/JS dashboard, Rust (hc-server metrics), bash (health audit), YAML (prometheus).

**Branch:** `phase0.2-account-security` (off `main` @ `47f3f4f`, which includes #19).

**Key facts (verified):** `tenant_store` mirrors a clean `magic_links` pattern; `_hash_key` = sha256; `get_tenant` returns `email, plan, api_key_prefix, status, stripe_customer_id`. Webhook routes use `secrets.compare_digest(req_secret, INTERNAL_SECRET)`; `_recover_api_key(tenant_id)` exists; suspends happen via `tenant_store.suspend_tenant`. `rotate-key.js` is used by BOTH the dashboard and direct API users (must keep a key-based path). `account.html` currently stores `{api_key}` in `SESSION_KEY` storage and sends `Bearer session.api_key`.

---

## Task 1: `sessions` table + functions in `tenant_store.py`

**Files:** Modify `billing/tenant_store.py`; Test `billing/tests/test_sessions.py` (create).

- [ ] **Step 1: Write the failing test** — create `billing/tests/test_sessions.py`:

```python
import os, tempfile, hashlib
import tenant_store as ts  # billing/ is on path in CI (see existing billing/tests)

def _mk():
    fd, path = tempfile.mkstemp(suffix=".sqlite"); os.close(fd)
    conn = ts.open_db(path)
    ts.create_tenant(conn, "t_x", "a@b.co", "tzk_secret123", plan="free")
    return conn

def _h(tok): return hashlib.sha256(tok.encode()).hexdigest()

def test_create_and_validate_session():
    conn = _mk()
    ts.create_session(conn, _h("tok1"), "t_x", ttl_ms=60_000)
    assert ts.validate_session(conn, _h("tok1")) == "t_x"
    assert ts.validate_session(conn, _h("nope")) is None

def test_expired_session_invalid():
    conn = _mk()
    ts.create_session(conn, _h("tok2"), "t_x", ttl_ms=-1)  # already expired
    assert ts.validate_session(conn, _h("tok2")) is None

def test_suspended_tenant_session_invalid_and_revoked():
    conn = _mk()
    ts.create_session(conn, _h("tok3"), "t_x", ttl_ms=60_000)
    ts.suspend_tenant(conn, "t_x")           # must revoke sessions
    assert ts.validate_session(conn, _h("tok3")) is None

def test_logout_and_delete_for_tenant():
    conn = _mk()
    ts.create_session(conn, _h("a"), "t_x", 60_000)
    ts.create_session(conn, _h("b"), "t_x", 60_000)
    ts.delete_session(conn, _h("a"))
    assert ts.validate_session(conn, _h("a")) is None
    assert ts.validate_session(conn, _h("b")) == "t_x"
    ts.delete_sessions_for_tenant(conn, "t_x")
    assert ts.validate_session(conn, _h("b")) is None
```

- [ ] **Step 2: Run, expect fail** — `cd billing && python -m pytest tests/test_sessions.py -q` → fails (no `create_session`). (If the repo runs billing tests differently, match `billing/tests/`'s existing invocation.)

- [ ] **Step 3: Implement.** In `billing/tenant_store.py`:
  (3a) Add to `_SCHEMA` (after the `magic_links` block):
```sql
CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
```
  (3b) Add functions (after `verify_magic_link`):
```python
def create_session(conn: sqlite3.Connection, token_hash: str, tenant_id: str, ttl_ms: int = 86_400_000) -> None:
    """Store a session token hash (default 24h TTL). GCs expired rows."""
    now = _now_ms()
    with conn:
        conn.execute("DELETE FROM sessions WHERE expires_at_ms < ?", (now,))
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token_hash, tenant_id, created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)",
            (token_hash, tenant_id, now, now + ttl_ms),
        )


def validate_session(conn: sqlite3.Connection, token_hash: str) -> Optional[str]:
    """Return tenant_id for a live session whose tenant is active, else None."""
    now = _now_ms()
    row = conn.execute(
        """SELECT s.tenant_id FROM sessions s
           JOIN tenants t ON t.tenant_id = s.tenant_id
           WHERE s.token_hash = ? AND s.expires_at_ms > ? AND t.status = 'active'""",
        (token_hash, now),
    ).fetchone()
    return row["tenant_id"] if row else None


def delete_session(conn: sqlite3.Connection, token_hash: str) -> None:
    with conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_sessions_for_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    with conn:
        conn.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
```
  (3c) Make `suspend_tenant` revoke sessions — change it to:
```python
def suspend_tenant(conn: sqlite3.Connection, tenant_id: str) -> None:
    set_status(conn, tenant_id, "suspended")
    delete_sessions_for_tenant(conn, tenant_id)
```
  (3d) In `delete_tenant`, also delete sessions (add alongside the magic_links delete):
```python
        conn.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
```

- [ ] **Step 4: Run tests → pass.** `cd billing && python -m pytest tests/test_sessions.py -q` → 4 passed.
- [ ] **Step 5: Commit** `feat(billing): sessions table + functions in tenant_store (revoked on suspend)` (+ Co-Authored-By trailer).

---

## Task 2: Webhook session endpoints (`provision_tenant.py`)

**Files:** Modify `billing/provision_tenant.py`.

Context: routes use `req_secret = flask.request.headers.get("X-Internal-Secret",""); if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET): return ...403`. `import secrets, hashlib` already present (verify; add if missing). Session token issuance = `secrets.token_hex(32)`, stored as `hashlib.sha256(token).hexdigest()`.

- [ ] **Step 1:** Add a small helper near the top (after `INTERNAL_SECRET`):
```python
def _require_internal_secret() -> bool:
    req = flask.request.headers.get("X-Internal-Secret", "")
    return bool(INTERNAL_SECRET) and secrets.compare_digest(req, INTERNAL_SECRET)

def _session_tenant(conn) -> "Optional[str]":
    """Resolve the session_token in the request body to a tenant_id, or None."""
    data = flask.request.get_json(silent=True) or {}
    tok = (data.get("session_token") or "").strip()
    if not tok or len(tok) != 64:
        return None
    return tenant_store.validate_session(conn, hashlib.sha256(tok.encode()).hexdigest())
```

- [ ] **Step 2: Change `/verify-magic-link`** (lines ~595-630) — after `tenant_id = tenant_store.verify_magic_link(conn, token_hash)` succeeds and the tenant is active, MINT A SESSION and DROP the key:
```python
    # Mint a session (httpOnly cookie set by the CF function). Do NOT return the raw key.
    session_token = secrets.token_hex(32)
    tenant_store.create_session(conn, hashlib.sha256(session_token.encode()).hexdigest(), tenant_id)
    conn.close()
    return flask.jsonify(
        session_token=session_token,
        tenant_id=tenant_id,
        email=tenant["email"],
        plan=tenant["plan"],
        api_key_prefix=tenant["api_key_prefix"],
    ), 200
```
(Remove the `api_key=_recover_api_key(...)` line from this response.)

- [ ] **Step 3: Add new session endpoints** (place near `/verify-magic-link`):
```python
@app.route("/session/resolve", methods=["POST"])
def session_resolve():
    if not _require_internal_secret():
        return flask.jsonify(error="unauthorized"), 403
    conn = tenant_store.open_db()
    tid = _session_tenant(conn)
    if not tid:
        conn.close(); return flask.jsonify(error="invalid session"), 401
    t = tenant_store.get_tenant(conn, tid); conn.close()
    if not t:
        return flask.jsonify(error="invalid session"), 401
    return flask.jsonify(tenant_id=tid, email=t["email"], plan=t["plan"],
                         api_key_prefix=t["api_key_prefix"], status=t["status"]), 200

@app.route("/session/reveal-key", methods=["POST"])
def session_reveal_key():
    if not _require_internal_secret():
        return flask.jsonify(error="unauthorized"), 403
    conn = tenant_store.open_db()
    tid = _session_tenant(conn); conn.close()
    if not tid:
        return flask.jsonify(error="invalid session"), 401
    key = _recover_api_key(tid)
    if not key:
        return flask.jsonify(error="key unavailable"), 500
    return flask.jsonify(api_key=key), 200

@app.route("/session/usage", methods=["POST"])
def session_usage():
    if not _require_internal_secret():
        return flask.jsonify(error="unauthorized"), 403
    conn = tenant_store.open_db()
    tid = _session_tenant(conn); conn.close()
    if not tid:
        return flask.jsonify(error="invalid session"), 401
    key = _recover_api_key(tid)
    if not key:
        return flask.jsonify(error="key unavailable"), 500
    try:
        r = requests.get("http://localhost:8080/usage",
                         headers={"Authorization": f"Bearer {key}"}, timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        print(f"session/usage upstream error: {e}", file=sys.stderr)
        return flask.jsonify(error="usage unavailable"), 502

@app.route("/logout", methods=["POST"])
def logout():
    if not _require_internal_secret():
        return flask.jsonify(error="unauthorized"), 403
    data = flask.request.get_json(silent=True) or {}
    tok = (data.get("session_token") or "").strip()
    if tok and len(tok) == 64:
        conn = tenant_store.open_db()
        tenant_store.delete_session(conn, hashlib.sha256(tok.encode()).hexdigest())
        conn.close()
    return flask.jsonify(ok=True), 200
```
(Confirm `import requests, sys` are present at top of file; the webhook already does outbound work — add if missing. Use `http://localhost:8080/usage` since the webhook runs on the same Hetzner box as hc-server.)

- [ ] **Step 4: Change `/rotate`** (lines ~465-520) to accept EITHER a `session_token` OR the existing `current_key` (keep the API-user path). Resolve the tenant: if `session_token` present+valid → that tenant; else fall back to the existing `current_key` lookup. Then rotate as today (`generate_api_key`, `update_api_key`, regenerate keys file) and return the new key + prefix. (Read the current handler; add the session branch at the top, keep the current_key branch as the `else`.)

- [ ] **Step 5: Tests/verify.** Add `billing/tests/test_session_endpoints.py` using Flask's `app.test_client()` (mirror any existing webhook test style): assert `/session/resolve` → 401 on a bad token, 200 + no `api_key` field on a good one; `/verify-magic-link` response has `session_token` and NO `api_key`. Run `cd billing && python -m pytest tests/ -q`.
- [ ] **Step 6: Commit** `feat(billing): session endpoints (resolve/reveal-key/usage/logout) + magic-link mints session, rotate accepts session`.

---

## Task 3: Cloudflare Pages Functions

**Files:** Create `site/functions/api/_session.js`, `session-resolve.js`, `reveal-key.js`, `usage.js`, `logout.js`; Modify `verify-magic-link.js`, `rotate-key.js`, `create-portal-session.js`.

Shared cookie name: `tz_session`. Cookie attributes on set: `HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`.

- [ ] **Step 1 — `_session.js` helper** (create): exports `readSessionCookie(request)` (parse `Cookie` header for `tz_session`) and `resolveSession(env, token)` (POST `${WEBHOOK_BASE_URL||"https://webhook.tinyzkp.com"}/session/resolve` with `X-Internal-Secret` + `{session_token}`; return parsed `{tenant_id,email,plan,api_key_prefix,status}` or `null`). Plus `sessionCookie(token)` / `clearCookie()` returning the `Set-Cookie` strings above.

- [ ] **Step 2 — `verify-magic-link.js`** (modify): on webhook success, the body now has `session_token` (+ metadata, no key). Set the cookie and return ONLY metadata to the page:
```javascript
    const setCookie = `tz_session=${body.session_token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`;
    const { session_token, ...safe } = body;   // strip the token from the JSON body
    return new Response(JSON.stringify(safe), { status: 200, headers: { ...jsonHeaders, "Set-Cookie": setCookie } });
```

- [ ] **Step 3 — `session-resolve.js`** (create): read cookie → `resolveSession` → return `{email,plan,api_key_prefix,status}` (200) or `{error}` (401). Used by the dashboard on load.

- [ ] **Step 4 — `reveal-key.js`** (create): read cookie; if no session → 401. Else POST webhook `/session/reveal-key` with `{session_token}` + secret → return `{api_key}`. Strict origin + a modest IP rate-limit.

- [ ] **Step 5 — `usage.js`** (create): read cookie → POST webhook `/session/usage` → pass through the usage JSON. 401 if no session.

- [ ] **Step 6 — `logout.js`** (create): read cookie → webhook `/logout` → respond 200 with `Set-Cookie: tz_session=; Max-Age=0; Path=/`.

- [ ] **Step 7 — `rotate-key.js`** (modify, G4): accept the session cookie. If a `tz_session` cookie is present, forward `{session_token}` to webhook `/rotate` (no `Authorization` needed). Keep the existing `Authorization: Bearer tzk_...` → `{current_key}` path as a fallback for direct API users. Tighten CORS off `*` to the tinyzkp.com allowlist (the dashboard is same-origin).

- [ ] **Step 8 — `create-portal-session.js`** (modify, G3): **remove the `email` request-body input entirely.** Require the `tz_session` cookie → `resolveSession`. Then fetch the tenant's Stripe customer id via the webhook `/session/resolve` (extend it to also return `stripe_customer_id`) — OR, since `resolveSession` returns the email, look up the customer by the **server-resolved** email. Prefer the stored `stripe_customer_id`: extend `/session/resolve` to include it, and pass `customer=<id>` directly to `billing_portal/sessions` (no Stripe search). Fix the CORS off `*`. (If `stripe_customer_id` is null, return 404 "no billing account".)

- [ ] **Step 9: Verify** — `rg -n "request.json\(\).*email|searchResult|query=email" site/functions/api/create-portal-session.js` → no client-email path remains. `rg -n "Bearer ' \+ \(session" site/account.html` (checked in Task 4). Lint: confirm each new `.js` has `onRequestPost`/`onRequestOptions` exports and valid JS (node --check).
- [ ] **Step 10: Commit** `feat(site): session-cookie CF functions; portal+rotate gated by session (G3,G4)`.

> NOTE for Step 8: this requires `/session/resolve` to return `stripe_customer_id`. Add it to the Task-2 `/session/resolve` response (`stripe_customer_id=t["stripe_customer_id"]`) — fold that one-line change in here or back in Task 2.

---

## Task 4: Dashboard rewrite (`site/account.html`)

**Files:** Modify `site/account.html`.

- [ ] **Step 1:** Replace the key-as-credential model:
  - Delete `getSession`/`saveSession`/`clearSession` storing `{api_key}` in `SESSION_KEY`. The browser no longer stores the key or the session token (the cookie is `HttpOnly`).
  - On load: `fetch('/api/session-resolve', {method:'POST', credentials:'include'})`. 200 → logged in: render plan, `api_key_prefix` (masked), and usage via `fetch('/api/usage', {credentials:'include'})`. 401 → show the magic-link request UI.
  - Magic-link landing (`?token=`): POST `/api/verify-magic-link` (`credentials:'include'`) — the cookie gets set; then resolve + render.
  - `apiHeaders()` → `{'Content-Type':'application/json'}` only (no `Authorization`); add `credentials:'include'` to all `/api/*` fetches.
  - **Reveal key:** a "Reveal API key" button → `fetch('/api/reveal-key', {method:'POST', credentials:'include'})` → display + copy; never persist. Default UI shows only the prefix.
  - **Rotate:** `fetch('/api/rotate-key', {method:'POST', credentials:'include'})`; show the returned new key once.
  - **Logout:** `fetch('/api/logout', {method:'POST', credentials:'include'})` → clear UI, show login.
  - Remove any code path that reads `session.api_key` for the curl/copy snippets — instead show `tzk_...` placeholder until "Reveal" is clicked.
- [ ] **Step 2: Verify** `rg -n "session.api_key|SESSION_KEY|localStorage|Bearer ' \+" site/account.html` → no key-storage/Bearer-key residue (the only auth is the cookie). Manual read of the load + reveal + rotate handlers.
- [ ] **Step 3: Commit** `feat(site): dashboard uses httpOnly session cookie, never stores the API key (G4)`.

---

## Task 5: hc-server `/metrics` auth (G10)

**Files:** Modify `crates/hc-server/src/lib.rs`; `deploy/prometheus/prometheus.yml`; `README.md` (env table).

- [ ] **Step 1: Test** — add a unit test for a `metrics_authorized(headers, expected_token)` helper (true iff `Authorization: Bearer <token>` matches; false if token unset/empty). 
- [ ] **Step 2: Implement** — read `HC_METRICS_TOKEN` env. In the `metrics` handler (~line 949), if `HC_METRICS_TOKEN` is set, require `Authorization: Bearer <it>` (constant-time compare); if it does NOT match → `401`. If `HC_METRICS_TOKEN` is **unset/empty**, return `404` (metrics disabled) so it is never unauthenticated in production. (Mirror the existing `guarded_auth`/header-reading style in the file.)
- [ ] **Step 3:** `deploy/prometheus/prometheus.yml`: add `authorization: { credentials: <token> }` (or `bearer_token`) to the hc-server scrape job, sourced from an env/file. `README.md`: document `HC_METRICS_TOKEN` in the server-config table. `docker-compose.yml` / prod compose: pass `HC_METRICS_TOKEN=${HC_METRICS_TOKEN}` to hc-server and the Prometheus job.
- [ ] **Step 4: Verify** `cargo test -p hc-server metrics 2>&1 | tail`; `cargo clippy -p hc-server --all-targets -- -D warnings`; `cargo fmt --all`.
- [ ] **Step 5: Commit** `feat(server): require HC_METRICS_TOKEN on /metrics; disabled if unset (G10)`.

---

## Task 6: Update the daily health audit E2E (`scripts/monitoring/api_health_audit.sh`)

**Files:** Modify `scripts/monitoring/api_health_audit.sh`.

- [ ] **Step 1:** The free-signup E2E currently asserts `/verify-magic-link` returns an `api_key` and uses that key for `/usage`. Update it to the session flow:
  - `/verify-magic-link` (via the webhook with the internal secret) now returns `session_token` and **must NOT** contain `api_key` — assert the absence of `api_key` and the presence of `session_token`.
  - Use the `session_token` to call `/session/resolve` (expect 200 + `api_key_prefix`) and `/session/usage` (expect 200) instead of the old key-based `/usage`.
  - Keep the `/tenant-purge` cleanup (guarded: free plan + `audit+` email).
  - Add a check that the new endpoints reject a bad/empty session with 401.
- [ ] **Step 2: Verify** by reading; (the script runs against live prod, so full execution is post-deploy — confirm the shape matches the Task-2 endpoints).
- [ ] **Step 3: Commit** `fix(audit): update free-signup E2E to the session flow (no raw key)`.

---

## Task 7: Final verification

- [ ] **Step 1:** `cd billing && python -m pytest tests/ -q` (sessions + endpoints green). `cargo test -p hc-server -q` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all --check`. `node --check` each new/changed CF `.js`.
- [ ] **Step 2:** Grep the dashboard + CF surface for residual raw-key handling: `rg -n "session.api_key|Bearer ' \+ \(session|request.json\(\).*\bemail\b" site/account.html site/functions/api/` → none (portal/dashboard no longer key-or-email-driven).
- [ ] **Step 3:** Holistic security review of the whole 0.2 diff (a subagent): confirm (a) the raw key is never returned except via session-gated `/session/reveal-key`, (b) the portal cannot be opened without a valid session, (c) `/metrics` is never unauthenticated, (d) no session/cookie handling fails open, (e) `suspend` revokes sessions.

## Acceptance criteria
- Magic-link verification returns **no** `api_key`; sets an `HttpOnly` `tz_session` cookie; the dashboard works without ever storing a key.
- Portal requires a valid session; the Stripe customer is server-resolved (no client email). G3 closed.
- The raw key is disclosed only via session-gated `/api/reveal-key`. G4 closed.
- `/metrics` requires `HC_METRICS_TOKEN` or is 404. G10 closed.
- `suspend_tenant` revokes sessions; rotation does not. Direct-API-user key rotation still works.
- All tests + clippy + fmt green; health-audit E2E updated to the session flow.

## Out of scope (other phases)
- Plaintext `api_keys.txt` retirement (Phase 3); `INTERNAL_SECRET` → signed tokens; G8/G9/G11/G12 (Phase 0.3).
