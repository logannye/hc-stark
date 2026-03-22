// Cloudflare Pages Function — creates a Stripe Customer Portal session.
//
// Allows paying customers to manage billing, update payment methods,
// view invoices, and cancel subscriptions.
//
// Secrets required (set via `wrangler pages secret put`):
//   STRIPE_SECRET_KEY — sk_live_... or sk_test_...

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
    const { email } = await context.request.json();
    if (!email || !email.includes("@") || email.length > 254) {
      return new Response(JSON.stringify({ error: "valid email required" }), {
        status: 400,
        headers: jsonHeaders,
      });
    }

    const STRIPE_SECRET_KEY = context.env.STRIPE_SECRET_KEY;
    if (!STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: "server misconfigured" }), {
        status: 500,
        headers: jsonHeaders,
      });
    }

    // Look up the customer by email.
    const searchResp = await fetch(
      `https://api.stripe.com/v1/customers/search?query=email:'${encodeURIComponent(email)}'`,
      {
        headers: {
          Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        },
      }
    );

    const searchResult = await searchResp.json();
    if (!searchResp.ok || !searchResult.data || searchResult.data.length === 0) {
      return new Response(JSON.stringify({ error: "No billing account found for this email. Free-tier accounts don't have billing." }), {
        status: 404,
        headers: jsonHeaders,
      });
    }

    const customerId = searchResult.data[0].id;

    // Create a portal session using the activated portal configuration.
    const params = new URLSearchParams();
    params.append("customer", customerId);
    params.append("configuration", "bpc_1TDmKKEDs4uiHp8xiHvcZvIb");
    params.append("return_url", "https://tinyzkp.com/docs");

    const portalResp = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    const portalSession = await portalResp.json();
    if (!portalResp.ok) {
      console.error("Stripe portal error:", JSON.stringify(portalSession));
      return new Response(JSON.stringify({ error: "Could not create portal session." }), {
        status: 502,
        headers: jsonHeaders,
      });
    }

    return new Response(JSON.stringify({ url: portalSession.url }), {
      status: 200,
      headers: jsonHeaders,
    });
  } catch (err) {
    console.error("Portal error:", err);
    return new Response(JSON.stringify({ error: "internal error" }), {
      status: 500,
      headers: jsonHeaders,
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
