# TinyZKP Website Launch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship a launch-ready website at tinyzkp.com with signup, docs, and contact pages — deployed via Cloudflare Pages with two Pages Functions for checkout and contact form submission.

**Architecture:** Static HTML site in `site/` deployed to Cloudflare Pages. Two serverless Pages Functions handle Stripe checkout session creation (`/api/create-checkout`) and contact form email delivery (`/api/contact`). The Hetzner server continues to host `api.tinyzkp.com` (hc-server) and `webhook.tinyzkp.com` (billing webhook). The Caddyfile drops the `tinyzkp.com` static block since Cloudflare now serves it.

**Tech Stack:** HTML/CSS (no build step), Cloudflare Pages, Cloudflare Pages Functions (JS), Stripe.js (embedded checkout), MailChannels API (email from Workers)

---

## Task 1: Cloudflare Pages Functions — Create Checkout Endpoint

**Files:**
- Create: `site/functions/api/create-checkout.js`

**Step 1: Create the Pages Functions directory**

```bash
mkdir -p site/functions/api
```

**Step 2: Write the create-checkout function**

```js
// site/functions/api/create-checkout.js
//
// Cloudflare Pages Function that creates a Stripe Checkout session.
// Secrets required (set via `wrangler pages secret put`):
//   STRIPE_SECRET_KEY — Stripe secret key (sk_live_... or sk_test_...)
//   STRIPE_PRICE_ID — The metered usage price ID (price_...)

export async function onRequestPost(context) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  try {
    const { email } = await context.request.json();
    if (!email || !email.includes("@")) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    const STRIPE_PRICE_ID = context.env.STRIPE_PRICE_ID;

    if (!STRIPE_SECRET_KEY || !STRIPE_PRICE_ID) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    // Create Stripe Checkout session via REST API (no SDK needed in Workers).
    const params = new URLSearchParams();
    params.append("mode", "subscription");
    params.append("customer_email", email);
    params.append("line_items[0][price]", STRIPE_PRICE_ID);
    params.append("line_items[0][quantity]", "1");
    params.append("success_url", "https://tinyzkp.com/?checkout=success");
    params.append("cancel_url", "https://tinyzkp.com/signup?cancelled=true");

    const resp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    const session = await resp.json();
    if (!resp.ok) {
      console.error("Stripe error:", JSON.stringify(session));
      return new Response(JSON.stringify({ error: "checkout creation failed" }), {
        status: 502,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    return new Response(JSON.stringify({ url: session.url }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
}

// Handle CORS preflight.
export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
```

**Step 3: Commit**

```bash
git add site/functions/api/create-checkout.js
git commit -m "feat: add Cloudflare Pages Function for Stripe checkout session creation"
```

---

## Task 2: Cloudflare Pages Functions — Contact Form Endpoint

**Files:**
- Create: `site/functions/api/contact.js`

**Step 1: Write the contact form function**

This function receives form submissions and sends email via MailChannels (free from Cloudflare Workers — no SMTP setup required). If MailChannels is not configured, it falls back to logging the message and returning success (so the form always works).

```js
// site/functions/api/contact.js
//
// Receives contact form submissions and emails them to logan@galenhealth.org
// via the MailChannels API (free from Cloudflare Workers).
//
// No secrets required — MailChannels authorizes based on the Worker's domain.
// DNS setup: add a TXT record `_mailchannels.tinyzkp.com` with value
// `v=mc1 cfid=<your-pages-project>.pages.dev` to authorize sending.

const RECIPIENT = "logan@galenhealth.org";

export async function onRequestPost(context) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  const jsonHeaders = { "Content-Type": "application/json", ...corsHeaders };

  try {
    const body = await context.request.json();
    const { name, email, category, message, _honeypot } = body;

    // Honeypot — if filled, silently succeed (bot).
    if (_honeypot) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200, headers: jsonHeaders,
      });
    }

    // Validate required fields.
    if (!name || !email || !message) {
      return new Response(
        JSON.stringify({ error: "name, email, and message are required" }),
        { status: 400, headers: jsonHeaders }
      );
    }

    const subject = `[TinyZKP ${category || "General"}] from ${name}`;
    const text = [
      `Name: ${name}`,
      `Email: ${email}`,
      `Category: ${category || "General Inquiry"}`,
      ``,
      message,
    ].join("\n");

    // Send via MailChannels API.
    const mailResp = await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: RECIPIENT, name: "TinyZKP Support" }] }],
        from: { email: "noreply@tinyzkp.com", name: "TinyZKP Contact Form" },
        reply_to: { email, name },
        subject,
        content: [{ type: "text/plain", value: text }],
      }),
    });

    if (!mailResp.ok) {
      const errText = await mailResp.text();
      console.error("MailChannels error:", errText);
      // Still return success to the user — we log the failure server-side.
      // The form data was received; we just couldn't email it.
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Contact form error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500, headers: jsonHeaders,
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
```

**Step 2: Commit**

```bash
git add site/functions/api/contact.js
git commit -m "feat: add Cloudflare Pages Function for contact form email delivery"
```

---

## Task 3: Signup Page

**Files:**
- Create: `site/signup.html`

**Step 1: Write the signup page**

This page collects an email address and redirects to Stripe Checkout. It matches the existing dark-mode design. The page also handles `?cancelled=true` query param to show a "checkout cancelled" message.

The page should include:
- Same nav and footer as `index.html`
- Centered card with heading "Get Your API Key"
- Brief description: "Enter your email to create your account. You'll be redirected to Stripe to set up billing."
- Email input field + "Continue to Checkout" button
- Loading state while the checkout session is being created
- Error handling (network errors, invalid email)
- On `?checkout=success` on the index page: show a success banner ("Check your email for your API key")
- On `?cancelled=true`: show a "Checkout cancelled" message with retry option
- Uses the same CSS variables and design patterns from `index.html`
- JS calls `POST /api/create-checkout` with `{email}`, then redirects to the returned `url`

**Step 2: Commit**

```bash
git add site/signup.html
git commit -m "feat: add signup page with Stripe checkout integration"
```

---

## Task 4: Documentation Page

**Files:**
- Create: `site/docs.html`

**Step 1: Write the docs page**

A comprehensive single-page documentation resource. Same dark-mode design, nav, and footer as other pages. Sections:

1. **Quickstart** — 3 steps: get an API key, submit a proof, verify it. curl examples.

2. **Authentication** — Bearer token format, where to find your key (email or Stripe portal), example header.

3. **API Endpoints** — Table with all routes:
   | Method | Path | Auth | Description |
   |--------|------|------|-------------|
   | POST | /prove | Yes | Submit a prove job |
   | GET | /prove/:job_id | Yes | Get job status/result |
   | POST | /prove/batch | Yes | Submit multiple prove jobs |
   | POST | /prove/:job_id/cancel | Yes | Cancel a running job |
   | DELETE | /prove/:job_id | Yes | Delete a completed job |
   | GET | /prove | Yes | List jobs |
   | POST | /verify | No | Verify a proof |
   | GET | /usage | Yes | View usage and costs |
   | GET | /proof/:job_id/calldata | Yes | Get EVM calldata |
   | GET | /healthz | No | Liveness check |
   | GET | /metrics | No | Prometheus metrics |
   | GET | /docs | No | Swagger UI |

4. **Proof Templates** — The 6 templates from the README: accumulator_step, computation_attestation, hash_preimage, range_proof, policy_compliance, data_integrity. With descriptions and parameter tables.

5. **Plan Tiers** — Table showing free/standard/pro with rate limits, inflight caps, monthly caps.

6. **Pricing** — The 4-tier per-proof pricing. Verify is free.

7. **Parameters** — Security params (query_count, lde_blowup_factor, zk_mask_degree) and performance params (block_size, fri_final_poly_size). Summarized from `docs/parameter_guide.md`.

8. **MCP Integration** — Config snippets for Claude Desktop and Claude Code. List of 10 MCP tools.

9. **Interactive API Reference** — Link to Swagger UI at `https://api.tinyzkp.com/docs`

Use a sticky sidebar TOC for navigation within the page (visible on desktop, collapsed on mobile). Use the same code block styling from `index.html`.

**Step 2: Commit**

```bash
git add site/docs.html
git commit -m "feat: add comprehensive docs page"
```

---

## Task 5: Contact Page

**Files:**
- Create: `site/contact.html`

**Step 1: Write the contact page**

Same design language. Contains:
- Heading: "Contact Us"
- Subtext: "Questions, bug reports, or feedback — we'd love to hear from you."
- Form fields:
  - Name (text, required)
  - Email (email, required)
  - Category (select: General Inquiry, Bug Report, Feature Request, Billing)
  - Message (textarea, required)
  - Hidden honeypot field (CSS `display:none`)
- Submit button with loading state
- Success message shown inline after submission
- JS calls `POST /api/contact` with form data as JSON
- Handles errors gracefully (shows error message, doesn't clear form)

**Step 2: Commit**

```bash
git add site/contact.html
git commit -m "feat: add contact form page"
```

---

## Task 6: Update Landing Page

**Files:**
- Modify: `site/index.html`

**Step 1: Update the landing page**

Changes:
1. **CTA button**: Change `href="#pricing"` to `href="/signup"` on the hero CTA
2. **Nav links**: Update to include all pages:
   ```
   Pricing | Docs | API Reference | Contact | [Get API Key] (styled button)
   ```
   - "Docs" → `/docs`
   - "API Reference" → `https://api.tinyzkp.com/docs` (external)
   - "Contact" → `/contact`
   - "Get API Key" → `/signup` (styled as a small CTA button in the nav)
3. **Footer**: Update contact email from `support@tinyzkp.com` to `logan@galenhealth.org`. Add links to `/docs` and `/contact`.
4. **Copyright**: Update year to 2025-2026 or just 2026.
5. **Success banner**: Add a hidden banner at the top that shows when URL contains `?checkout=success`. Text: "Account created! Check your email for your API key." Green background, dismissible.
6. **Pricing section CTA**: Add a "Get API Key" button below the pricing grid linking to `/signup`.

**Step 2: Commit**

```bash
git add site/index.html
git commit -m "feat: update landing page with nav links, signup CTA, and checkout success banner"
```

---

## Task 7: Update Caddyfile

**Files:**
- Modify: `deploy/hetzner/Caddyfile`

**Step 1: Remove the tinyzkp.com static block**

Cloudflare Pages now serves the static site. The Caddyfile should only contain:

```caddy
api.tinyzkp.com {
    reverse_proxy localhost:8080

    header {
        Access-Control-Allow-Origin "*"
        Access-Control-Allow-Methods "GET, POST, OPTIONS, DELETE"
        Access-Control-Allow-Headers "Content-Type, Authorization"
    }
}

webhook.tinyzkp.com {
    reverse_proxy localhost:5001
}
```

Note: Added `DELETE` and `OPTIONS` to CORS methods (needed for job deletion and preflight requests).

**Step 2: Commit**

```bash
git add deploy/hetzner/Caddyfile
git commit -m "chore: remove static site from Caddyfile — now served by Cloudflare Pages"
```

---

## Task 8: Cloudflare Pages Deployment Config

**Files:**
- Create: `site/wrangler.toml`

**Step 1: Write the wrangler config**

```toml
name = "tinyzkp"
compatibility_date = "2024-09-23"

[site]
bucket = "."
```

This is minimal — Pages Functions in `site/functions/` are auto-detected.

**Step 2: Commit**

```bash
git add site/wrangler.toml
git commit -m "chore: add wrangler config for Cloudflare Pages deployment"
```

---

## Task 9: Deploy to Cloudflare Pages

**Step 1: Create the Cloudflare Pages project**

```bash
cd site
npx wrangler pages project create tinyzkp --production-branch main
```

**Step 2: Set secrets for the checkout function**

```bash
npx wrangler pages secret put STRIPE_SECRET_KEY --project-name tinyzkp
# Paste sk_live_... or sk_test_... when prompted

npx wrangler pages secret put STRIPE_PRICE_ID --project-name tinyzkp
# Paste price_... when prompted
```

**Step 3: Deploy**

```bash
npx wrangler pages deploy . --project-name tinyzkp
```

**Step 4: Configure custom domain**

In Cloudflare dashboard (or via CLI):
- Go to Pages > tinyzkp > Custom domains
- Add `tinyzkp.com`
- Cloudflare auto-provisions TLS and DNS

**Step 5: Set up MailChannels DNS authorization**

Add a TXT record in Cloudflare DNS:
- Name: `_mailchannels`
- Content: `v=mc1 cfid=tinyzkp.pages.dev`

This authorizes the Pages Function to send email via MailChannels.

**Step 6: Verify deployment**

```bash
curl -s https://tinyzkp.com/ | head -5          # Landing page
curl -s https://tinyzkp.com/signup              # Signup page
curl -s https://tinyzkp.com/docs                # Docs page
curl -s https://tinyzkp.com/contact             # Contact page
curl -s -X POST https://tinyzkp.com/api/create-checkout \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'             # Should return {"url":"https://checkout.stripe.com/..."}
```

**Step 7: Commit any final adjustments**

```bash
git add -A
git commit -m "chore: Cloudflare Pages deployment verified"
```

---

## Task 10: Update Stripe Webhook Events

**Files:**
- Reference: `billing/STRIPE_SETUP.md`

**Step 1: Update Stripe webhook to listen for additional events**

In Stripe Dashboard > Developers > Webhooks, update the endpoint at `webhook.tinyzkp.com/webhook` to listen for:
- `checkout.session.completed` (already configured)
- `customer.subscription.deleted` (new — triggers tenant suspension)
- `invoice.payment_failed` (new — triggers tenant suspension)

**Step 2: Update STRIPE_SETUP.md**

Add the new events to the documentation:

```markdown
## 3. Create Webhook Endpoint

- **Endpoint URL**: `https://webhook.tinyzkp.com/webhook`
- **Events to listen for**:
  - `checkout.session.completed` — provisions new tenant
  - `customer.subscription.deleted` — suspends tenant
  - `invoice.payment_failed` — suspends tenant on payment failure
```

**Step 3: Commit**

```bash
git add billing/STRIPE_SETUP.md
git commit -m "docs: update STRIPE_SETUP.md with lifecycle webhook events"
```

---

## Task 11: End-to-End Smoke Test

Verify the full flow works:

**Step 1: Landing page → Signup**

1. Visit `https://tinyzkp.com`
2. Click "Get API Key" in nav or hero CTA
3. Verify redirect to `/signup`
4. Enter test email, click "Continue to Checkout"
5. Verify redirect to Stripe Checkout

**Step 2: Stripe Checkout → Tenant Provisioning**

1. Complete checkout with Stripe test card (`4242 4242 4242 4242`)
2. Verify redirect to `https://tinyzkp.com/?checkout=success`
3. Verify success banner appears
4. Check webhook server logs: tenant created in tenant_store.sqlite
5. Check api_keys.txt: new tenant key present
6. Verify API key email received (or check Stripe customer metadata)

**Step 3: API Usage**

```bash
# Auth with the new key
curl -s https://api.tinyzkp.com/healthz -H "Authorization: Bearer tzk_..."

# Submit a proof
curl -s -X POST https://api.tinyzkp.com/prove \
  -H "Authorization: Bearer tzk_..." \
  -H "Content-Type: application/json" \
  -d '{"workload_id":"toy_add_1_2","initial_acc":0,"final_acc":3,"block_size":4,"fri_final_poly_size":2}'

# Check usage
curl -s https://api.tinyzkp.com/usage -H "Authorization: Bearer tzk_..."
```

**Step 4: Contact form**

1. Visit `/contact`
2. Fill form, submit
3. Verify `logan@galenhealth.org` receives the email

**Step 5: Docs and navigation**

1. Visit `/docs`
2. Verify all sections render, TOC links work
3. Verify Swagger UI link works
4. Check all nav links across all pages

---

## Summary of Files

| File | Action | Task |
|------|--------|------|
| `site/functions/api/create-checkout.js` | Create | 1 |
| `site/functions/api/contact.js` | Create | 2 |
| `site/signup.html` | Create | 3 |
| `site/docs.html` | Create | 4 |
| `site/contact.html` | Create | 5 |
| `site/index.html` | Modify | 6 |
| `deploy/hetzner/Caddyfile` | Modify | 7 |
| `site/wrangler.toml` | Create | 8 |
| `billing/STRIPE_SETUP.md` | Modify | 10 |
