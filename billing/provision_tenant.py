#!/usr/bin/env python3
"""Flask webhook: handles Stripe lifecycle events for tenant provisioning.

Events handled:
  - checkout.session.completed → create tenant, deliver API key
  - customer.subscription.deleted → suspend tenant
  - invoice.payment_failed → suspend tenant
"""

import json
import os
import secrets
import smtplib
import string
import sys
import time
from email.mime.text import MIMEText
from pathlib import Path

import flask
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
    plan = (session.get("metadata") or {}).get("plan", "developer")
    if plan not in ("developer", "team", "scale"):
        plan = "developer"

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

    # Deliver API key to customer.
    if customer_id:
        _deliver_key_via_stripe(customer_id, tenant_id, api_key)
    _send_welcome_email(email, tenant_id, api_key)

    conn.close()
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
    """Handle invoice.payment_failed — suspend tenant."""
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
        tenant_store.suspend_tenant(conn, tenant["tenant_id"])
        tenant_store.mark_event_processed(conn, event_id)
        sync_keys.regenerate(conn, API_KEYS_FILE)
        print(f"Suspended tenant={tenant['tenant_id']} (payment failed)")
    else:
        tenant_store.mark_event_processed(conn, event_id)
        print(f"WARNING: No tenant found for subscription {subscription_id}", file=sys.stderr)

    conn.close()
    return "", 200


def _plan_from_subscription(subscription: dict) -> str:
    """Determine plan from subscription metadata or items."""
    # Check metadata first (set during checkout).
    plan = (subscription.get("metadata") or {}).get("plan")
    if plan in ("developer", "team", "scale"):
        return plan
    # Fallback: count line items — 1 item = developer, 2+ = team/scale.
    items = subscription.get("items", {}).get("data", [])
    if len(items) >= 2:
        # If there's a flat-rate item alongside metered, it's team or scale.
        # Check metadata on the subscription for specifics; default to team.
        return "team"
    return "developer"


def _handle_subscription_updated(event: dict) -> tuple[str, int]:
    """Handle customer.subscription.updated — plan changes via Stripe Portal."""
    conn = tenant_store.open_db()

    event_id = event["id"]
    if tenant_store.is_event_processed(conn, event_id):
        conn.close()
        return "already processed", 200

    subscription = event["data"]["object"]
    subscription_id = subscription["id"]
    tenant = tenant_store.get_by_subscription_id(conn, subscription_id)

    if tenant:
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

    print(f"Provisioned free tenant={tenant_id} email={email}")

    # Deliver API key via email.
    _send_welcome_email(email, tenant_id, api_key)

    conn.close()
    return flask.jsonify(ok=True), 200


@app.route("/rotate", methods=["POST"])
def rotate_key():
    """Rotate a tenant's API key. Authenticates via the current Bearer token.

    Called by the Cloudflare Pages Function, not directly by clients.
    """
    req_secret = flask.request.headers.get("X-Internal-Secret", "")
    if not INTERNAL_SECRET or not secrets.compare_digest(req_secret, INTERNAL_SECRET):
        return flask.jsonify(error="unauthorized"), 403

    data = flask.request.get_json(silent=True) or {}
    current_key = data.get("current_key", "").strip()

    if not current_key or not current_key.startswith("tzk_"):
        return flask.jsonify(error="valid current API key required"), 400

    import hashlib

    current_hash = hashlib.sha256(current_key.encode()).hexdigest()

    conn = tenant_store.open_db()

    # Find tenant by key hash.
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


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
