#!/usr/bin/env python3
"""Flask webhook: handles Stripe lifecycle events for tenant provisioning.

Events handled:
  - checkout.session.completed → create tenant, deliver API key
  - customer.subscription.deleted → suspend tenant
  - customer.subscription.updated → plan change, or suspend on terminal dunning state
  - invoice.payment_failed → log only; Stripe dunning retries (no hard suspend)
"""

import hashlib
import json
import os
import secrets
import smtplib
import string
import sys
import threading
import time
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import flask
import requests
import stripe

import tenant_store
import sync_keys

app = flask.Flask(__name__)

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

API_KEYS_FILE = os.environ.get("HC_API_KEYS_FILE", "/opt/hc-stark/data/api_keys.txt")

# SMTP config (optional — graceful fallback if not configured).
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@tinyzkp.com")

TEMPLATES_DIR = Path(__file__).parent / "templates"


def generate_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "tzk_" + "".join(secrets.choice(alphabet) for _ in range(length))


def generate_tenant_id() -> str:
    return "t_" + secrets.token_hex(8)


def _send_welcome_email(email: str, tenant_id: str, api_key: str) -> bool:
    """Send welcome email with API key. Returns True on success."""
    if not SMTP_HOST:
        print("SMTP not configured, skipping email delivery", file=sys.stderr)
        return False

    template_path = TEMPLATES_DIR / "welcome.txt"
    if template_path.exists():
        body = template_path.read_text().format(
            tenant_id=tenant_id, api_key=api_key, email=email,
        )
    else:
        body = (
            f"Welcome to TinyZKP!\n\n"
            f"Your tenant ID: {tenant_id}\n"
            f"Your API key: {api_key}\n\n"
            f"API endpoint: https://api.tinyzkp.com\n"
            f"Docs: https://api.tinyzkp.com/docs\n\n"
            f"Keep your API key secret. You can rotate it at any time by contacting support.\n"
        )

    msg = MIMEText(body)
    msg["Subject"] = "Your TinyZKP API Key"
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
        print(f"Welcome email sent to {email}")
        return True
    except Exception as e:
        print(f"WARNING: Failed to send welcome email to {email}: {e}", file=sys.stderr)
        return False


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


CONTACT_RECIPIENT = "logan@galenhealth.org"


def _send_contact_email(name: str, sender_email: str, category: str, message: str) -> bool:
    """Forward a contact-form submission to the support inbox. Returns True on success."""
    if not SMTP_HOST:
        print("SMTP not configured, skipping contact email", file=sys.stderr)
        return False

    body = (
        f"Name: {name}\n"
        f"Email: {sender_email}\n"
        f"Category: {category}\n"
        f"\n"
        f"{message}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = f"[TinyZKP {category}] from {name[:100]}"
    msg["From"] = SMTP_FROM
    msg["To"] = CONTACT_RECIPIENT
    # Reply-To set to submitter so hitting Reply in the inbox responds to them, not the noreply box.
    msg["Reply-To"] = f"{name[:100]} <{sender_email[:254]}>"

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
        print(f"Contact email forwarded for {sender_email}")
        return True
    except Exception as e:
        print(f"WARNING: Failed to forward contact email from {sender_email}: {e}", file=sys.stderr)
        return False


def _deliver_key_via_stripe(customer_id: str, tenant_id: str, api_key: str) -> bool:
    """Store tenant_id in Stripe customer metadata (NOT the API key — security risk).

    The API key is delivered only via email. Stripe metadata stores the tenant_id
    and a masked key prefix so support can identify the customer.
    """
    try:
        stripe.Customer.modify(
            customer_id,
            metadata={
                "tenant_id": tenant_id,
                "api_key_prefix": api_key[:8] + "...",
            },
        )
        print(f"Stripe metadata updated for {tenant_id}")
        return True
    except stripe.error.StripeError as e:
        print(f"WARNING: Failed to set Stripe metadata for {tenant_id}: {e}", file=sys.stderr)
        return False


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


# Canonical paid plans (pricing.json) the webhook may store, plus legacy aliases.
# Storefront checkout emits {developer, pro, scale, compute}. Older Team links or
# admin-provisioned rows still resolve to Pro's limits/rates.
_PLAN_ALIASES = {"team": "pro", "standard": "developer"}
_CANONICAL_PAID_PLANS = {"developer", "pro", "scale", "compute"}


def _normalize_plan(raw: str | None, default: str = "developer") -> str:
    """Resolve a checkout/subscription plan slug to a canonical stored plan.

    Applies pricing.json plan_aliases (team -> pro, standard -> developer) and
    falls back to `default` for missing/unrecognized slugs.
    """
    if not raw:
        return default
    plan = _PLAN_ALIASES.get(raw, raw)
    return plan if plan in _CANONICAL_PAID_PLANS else default


def _handle_checkout_completed(event: dict) -> tuple[str, int]:
    """Handle checkout.session.completed — provision new tenant."""
    conn = tenant_store.open_db()

    event_id = event["id"]
    if tenant_store.is_event_processed(conn, event_id):
        conn.close()
        return "already processed", 200

    session = event["data"]["object"]
    subscription_id = session.get("subscription")
    customer_id = session.get("customer")
    email = session.get("customer_email") or session.get("customer_details", {}).get("email", "unknown")

    if not subscription_id:
        conn.close()
        return "No subscription in session", 200

    # Idempotency: check if tenant already exists for this subscription.
    existing = tenant_store.get_by_subscription_id(conn, subscription_id)
    if existing:
        tenant_store.mark_event_processed(conn, event_id)
        conn.close()
        return "tenant already exists for this subscription", 200

    # Get the subscription item ID for metered billing.
    sub = stripe.Subscription.retrieve(subscription_id)
    si_id = sub["items"]["data"][0]["id"] if sub["items"]["data"] else None

    if not si_id:
        print(f"WARNING: No subscription item for {subscription_id}", file=sys.stderr)
        conn.close()
        return "No subscription item", 200

    tenant_id = generate_tenant_id()
    api_key = generate_api_key()

    # Extract plan from checkout session metadata (set by create-checkout.js).
    # Normalize storefront and legacy slugs instead of silently downgrading a
    # paying Pro/Scale/Compute customer to developer (BILL-01).
    plan = _normalize_plan((session.get("metadata") or {}).get("plan"))

    tenant_store.create_tenant(
        conn,
        tenant_id=tenant_id,
        email=email,
        api_key=api_key,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
        stripe_subscription_item_id=si_id,
        plan=plan,
    )
    tenant_store.mark_event_processed(conn, event_id)

    # Regenerate api_keys.txt with the new tenant.
    sync_keys.regenerate(conn, API_KEYS_FILE, active_keys={tenant_id: (api_key, plan)})

    print(f"Provisioned tenant={tenant_id} email={email} si={si_id}")

    conn.close()

    # Deliver API key in background thread (SMTP may hang if port 465 is blocked).
    def _bg_deliver():
        try:
            if customer_id:
                _deliver_key_via_stripe(customer_id, tenant_id, api_key)
            _send_welcome_email(email, tenant_id, api_key)
        except Exception as e:
            print(f"WARNING: Key delivery failed for {email}: {e}", file=sys.stderr)

    threading.Thread(target=_bg_deliver, daemon=True).start()
    return "", 200


def _handle_subscription_deleted(event: dict) -> tuple[str, int]:
    """Handle customer.subscription.deleted — suspend tenant."""
    conn = tenant_store.open_db()

    event_id = event["id"]
    if tenant_store.is_event_processed(conn, event_id):
        conn.close()
        return "already processed", 200

    subscription_id = event["data"]["object"]["id"]
    tenant = tenant_store.get_by_subscription_id(conn, subscription_id)

    if tenant:
        tenant_store.suspend_tenant(conn, tenant["tenant_id"])
        tenant_store.mark_event_processed(conn, event_id)
        sync_keys.regenerate(conn, API_KEYS_FILE)
        print(f"Suspended tenant={tenant['tenant_id']} (subscription deleted)")
    else:
        tenant_store.mark_event_processed(conn, event_id)
        print(f"WARNING: No tenant found for subscription {subscription_id}", file=sys.stderr)

    conn.close()
    return "", 200


def _handle_payment_failed(event: dict) -> tuple[str, int]:
    """Handle invoice.payment_failed — log only; let Stripe dunning retry (BILL-07)."""
    conn = tenant_store.open_db()

    event_id = event["id"]
    if tenant_store.is_event_processed(conn, event_id):
        conn.close()
        return "already processed", 200

    subscription_id = event["data"]["object"].get("subscription")
    if not subscription_id:
        tenant_store.mark_event_processed(conn, event_id)
        conn.close()
        return "no subscription on invoice", 200

    tenant = tenant_store.get_by_subscription_id(conn, subscription_id)

    if tenant:
        # BILL-07: do NOT hard-suspend on a failed charge. Stripe Smart Retries
        # recover most transient declines (expired cards, momentary insufficient
        # funds); suspending here turns a recoverable hiccup into involuntary
        # churn. Keep the tenant active through dunning — we suspend only on the
        # terminal signals (subscription.deleted, or subscription.updated ->
        # unpaid/canceled).
        tenant_store.mark_event_processed(conn, event_id)
        print(f"Payment failed for tenant={tenant['tenant_id']}; leaving active for Stripe dunning")
    else:
        tenant_store.mark_event_processed(conn, event_id)
        print(f"WARNING: No tenant found for subscription {subscription_id}", file=sys.stderr)

    conn.close()
    return "", 200


def _plan_from_subscription(subscription: dict) -> str:
    """Determine plan from subscription metadata or items."""
    # Check metadata first (set during checkout). Normalize legacy team -> pro;
    # only fall through to the item-count
    # heuristic when metadata carries no recognizable plan.
    raw = (subscription.get("metadata") or {}).get("plan")
    normalized = _PLAN_ALIASES.get(raw, raw) if raw else None
    if normalized in _CANONICAL_PAID_PLANS:
        return normalized
    # Fallback: count line items — 1 item = developer, 2+ = pro.
    items = subscription.get("items", {}).get("data", [])
    if len(items) >= 2:
        # If there's a flat-rate item alongside metered, it's a paid self-serve
        # plan. Check metadata on the subscription for specifics; default to Pro.
        return "pro"
    return "developer"


def _handle_subscription_updated(event: dict) -> tuple[str, int]:
    """Handle customer.subscription.updated — plan changes; suspend on terminal dunning state (BILL-07)."""
    conn = tenant_store.open_db()

    event_id = event["id"]
    if tenant_store.is_event_processed(conn, event_id):
        conn.close()
        return "already processed", 200

    subscription = event["data"]["object"]
    subscription_id = subscription["id"]
    tenant = tenant_store.get_by_subscription_id(conn, subscription_id)

    if tenant:
        # BILL-07: terminal dunning states arrive as a status change — suspend
        # when Stripe gives up (unpaid/canceled/incomplete_expired). Otherwise
        # this is a normal plan change from the customer portal.
        status = subscription.get("status")
        if status in ("unpaid", "canceled", "incomplete_expired"):
            tenant_store.suspend_tenant(conn, tenant["tenant_id"])
            tenant_store.mark_event_processed(conn, event_id)
            sync_keys.regenerate(conn, API_KEYS_FILE)
            print(f"Suspended tenant={tenant['tenant_id']} (subscription {status})")
        else:
            plan = _plan_from_subscription(subscription)
            tenant_store.set_plan(conn, tenant["tenant_id"], plan)
            tenant_store.mark_event_processed(conn, event_id)
            sync_keys.regenerate(conn, API_KEYS_FILE)
            print(f"Updated plan for tenant={tenant['tenant_id']} to '{plan}'")
    else:
        tenant_store.mark_event_processed(conn, event_id)
        print(f"WARNING: No tenant found for subscription {subscription_id}", file=sys.stderr)

    conn.close()
    return "", 200


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = flask.request.get_data(as_text=True)
    sig = flask.request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        return "Invalid signature", 400

    event_type = event["type"]

    if event_type == "checkout.session.completed":
        return _handle_checkout_completed(event)
    elif event_type == "customer.subscription.updated":
        return _handle_subscription_updated(event)
    elif event_type == "customer.subscription.deleted":
        return _handle_subscription_deleted(event)
    elif event_type == "invoice.payment_failed":
        return _handle_payment_failed(event)

    return "", 200


INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "")


def _require_internal_secret() -> bool:
    req = flask.request.headers.get("X-Internal-Secret", "")
    return bool(INTERNAL_SECRET) and secrets.compare_digest(req, INTERNAL_SECRET)


def _session_tenant(conn):
    """Resolve the request body's session_token to a tenant_id, or None."""
    data = flask.request.get_json(silent=True) or {}
    tok = (data.get("session_token") or "").strip()
    if not tok or len(tok) != 64:
        return None
    return tenant_store.validate_session(conn, hashlib.sha256(tok.encode()).hexdigest())


@app.route("/provision-free", methods=["POST"])
def provision_free():
    """Create a free-tier tenant (no Stripe subscription).

    Requires X-Internal-Secret header matching INTERNAL_SECRET env var.
    Called by the Cloudflare Pages Function, not directly by clients.
    """
    # Verify internal auth — reject requests without a valid secret.
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    email = data.get("email", "").strip()

    if not email or "@" not in email or len(email) > 254:
        return flask.jsonify(error="valid email required"), 400

    conn = tenant_store.open_db()

    # G8: one free tenant per email — reject duplicates before create_tenant.
    existing = tenant_store.get_by_email(conn, email)
    if existing:
        conn.close()
        return flask.jsonify(error="account already exists for this email"), 409

    tenant_id = generate_tenant_id()
    api_key = generate_api_key()

    try:
        tenant_store.create_tenant(
            conn,
            tenant_id=tenant_id,
            email=email,
            api_key=api_key,
            plan="free",
        )
    except Exception:
        conn.close()
        return flask.jsonify(error="account already exists for this email"), 409

    # Regenerate api_keys.txt with the new free tenant.
    sync_keys.regenerate(conn, API_KEYS_FILE, active_keys={tenant_id: (api_key, "free")})

    # Generate a magic link token for immediate dashboard access.
    dashboard_token = secrets.token_hex(32)
    dashboard_token_hash = hashlib.sha256(dashboard_token.encode()).hexdigest()
    tenant_store.create_magic_link(conn, dashboard_token_hash, tenant_id)

    print(f"Provisioned free tenant={tenant_id} email={email}")

    conn.close()

    # Send welcome email in background thread (SMTP may hang if port 465 is blocked).
    def _bg_email():
        try:
            _send_welcome_email(email, tenant_id, api_key)
        except Exception as e:
            print(f"WARNING: Welcome email failed for {email}: {e}", file=sys.stderr)

    threading.Thread(target=_bg_email, daemon=True).start()
    return flask.jsonify(ok=True, dashboard_token=dashboard_token), 200


@app.route("/rotate", methods=["POST"])
def rotate_key():
    """Rotate a tenant's API key. Authenticates via session_token or current_key.

    Called by the Cloudflare Pages Function, not directly by clients.
    Accepts either:
      - session_token (64-hex chars) — session-based auth (new path)
      - current_key (tzk_...) — direct API-key auth (legacy path, no regression)
    """
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    conn = tenant_store.open_db()

    # --- session_token path (new) ---
    session_tok = (data.get("session_token") or "").strip()
    if session_tok and len(session_tok) == 64:
        tid = tenant_store.validate_session(conn, hashlib.sha256(session_tok.encode()).hexdigest())
        if not tid:
            conn.close()
            return flask.jsonify(error="invalid session"), 401
        row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tid,)
        ).fetchone()
        if not row or row["status"] != "active":
            conn.close()
            return flask.jsonify(error="account is not active"), 403
    else:
        # --- current_key path (legacy — no regression) ---
        current_key = data.get("current_key", "").strip()
        if not current_key or not current_key.startswith("tzk_"):
            conn.close()
            return flask.jsonify(error="valid current API key or session_token required"), 400

        current_hash = hashlib.sha256(current_key.encode()).hexdigest()
        row = conn.execute(
            "SELECT * FROM tenants WHERE api_key_hash = ?", (current_hash,)
        ).fetchone()

        if not row:
            conn.close()
            return flask.jsonify(error="invalid API key"), 401

        if row["status"] != "active":
            conn.close()
            return flask.jsonify(error="account is not active"), 403

    # Rate limit: max 1 rotation per 24 hours.
    now_ms = int(time.time() * 1000)
    last_updated = row["updated_at_ms"]
    if (now_ms - last_updated) < 86_400_000:  # 24 hours in ms
        conn.close()
        return flask.jsonify(error="key rotation limited to once per 24 hours"), 429

    # Generate new key.
    new_key = generate_api_key()
    tenant_id = row["tenant_id"]
    plan = row["plan"]

    tenant_store.update_api_key(conn, tenant_id, new_key)
    sync_keys.regenerate(conn, API_KEYS_FILE, active_keys={tenant_id: (new_key, plan)})

    print(f"Rotated key for tenant={tenant_id}")

    conn.close()
    return flask.jsonify(
        api_key=new_key,
        prefix=new_key[:8] + "...",
        message="Key rotated successfully. Your old key is now invalid.",
    ), 200


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
        return flask.jsonify(ok=True), 200

    if tenant["status"] != "active":
        conn.close()
        return flask.jsonify(ok=True), 200

    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    tenant_store.create_magic_link(conn, token_hash, tenant["tenant_id"])
    conn.close()

    link = f"https://tinyzkp.com/account?token={token}"

    def _bg_send():
        try:
            _send_magic_link_email(email, link)
        except Exception as e:
            print(f"WARNING: Magic link email failed for {email}: {e}", file=sys.stderr)

    threading.Thread(target=_bg_send, daemon=True).start()
    return flask.jsonify(ok=True), 200


@app.route("/send-contact", methods=["POST"])
def send_contact():
    """Forward a contact-form submission to the support inbox."""
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    category = (data.get("category") or "General Inquiry").strip()
    message = (data.get("message") or "").strip()

    if not name or not email or not message:
        return flask.jsonify(error="name, email, and message are required"), 400
    if "@" not in email or len(email) > 254 or len(name) > 200 or len(message) > 5000:
        return flask.jsonify(error="invalid input"), 400

    valid_categories = {"General Inquiry", "Bug Report", "Feature Request", "Billing", "Enterprise"}
    safe_category = category if category in valid_categories else "General Inquiry"

    def _bg_send():
        try:
            _send_contact_email(name, email, safe_category, message)
        except Exception as e:
            print(f"WARNING: Contact email failed from {email}: {e}", file=sys.stderr)

    threading.Thread(target=_bg_send, daemon=True).start()
    return flask.jsonify(ok=True), 200


@app.route("/verify-magic-link", methods=["POST"])
def verify_magic_link_route():
    """Verify a magic link token; mint a session and return safe metadata (no API key)."""
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

    if not tenant or tenant["status"] != "active":
        conn.close()
        return flask.jsonify(error="Account not active"), 403

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
                         api_key_prefix=t["api_key_prefix"], status=t["status"],
                         stripe_customer_id=t["stripe_customer_id"]), 200


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
    data = flask.request.get_json(silent=True) or {}
    params = {}
    for _k in ("since", "until"):
        _v = data.get(_k)
        if _v is not None:
            try:
                params[_k] = int(_v)
            except (TypeError, ValueError):
                pass
    try:
        r = requests.get("http://localhost:8080/usage", params=params,
                         headers={"Authorization": f"Bearer {key}"}, timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        print(f"session/usage upstream error: {e}", file=sys.stderr)
        return flask.jsonify(error="usage unavailable"), 502


@app.route("/session/jobs", methods=["POST"])
def session_jobs():
    if not _require_internal_secret():
        return flask.jsonify(error="unauthorized"), 403
    conn = tenant_store.open_db()
    tid = _session_tenant(conn); conn.close()
    if not tid:
        return flask.jsonify(error="invalid session"), 401
    key = _recover_api_key(tid)
    if not key:
        return flask.jsonify(error="key unavailable"), 500
    data = flask.request.get_json(silent=True) or {}
    try:
        limit = max(1, min(100, int(data.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    params = {"limit": limit}
    if data.get("offset") is not None:
        try:
            params["offset"] = max(0, int(data["offset"]))
        except (TypeError, ValueError):
            pass
    try:
        r = requests.get("http://localhost:8080/prove", params=params,
                         headers={"Authorization": f"Bearer {key}"}, timeout=10)
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        print(f"session/jobs upstream error: {e}", file=sys.stderr)
        return flask.jsonify(error="jobs unavailable"), 502


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


@app.route("/tenant-purge", methods=["POST"])
def tenant_purge():
    """Permanently delete an audit-test tenant.

    Gated by INTERNAL_SECRET. As a defense-in-depth measure, the endpoint
    refuses to delete anything that isn't an obviously-test tenant: the
    plan must be "free" AND the email must start with "audit+" (the prefix
    used by the daily health audit's free-signup E2E check). This way, even
    if INTERNAL_SECRET were to leak, this endpoint cannot reach a paying
    customer's row.
    """
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    tenant_id = (data.get("tenant_id") or "").strip()
    if not tenant_id or not tenant_id.startswith("t_"):
        return flask.jsonify(error="valid tenant_id required"), 400

    conn = tenant_store.open_db()
    tenant = tenant_store.get_tenant(conn, tenant_id)
    if not tenant:
        conn.close()
        return flask.jsonify(error="not found"), 404

    if tenant["plan"] != "free" or not (tenant["email"] or "").startswith("audit+"):
        conn.close()
        return flask.jsonify(error="refusing to purge non-audit tenant"), 403

    deleted = tenant_store.delete_tenant(conn, tenant_id)
    sync_keys.regenerate(conn, API_KEYS_FILE)
    conn.close()

    print(f"Purged audit tenant={tenant_id} email={tenant['email']} rows={deleted}")
    return flask.jsonify(ok=True, deleted=deleted), 200


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
