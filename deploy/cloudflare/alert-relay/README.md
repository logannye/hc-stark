# TinyZKP email alert relay

This Worker accepts only authenticated, bounded TinyZKP alert JSON and sends a
plain-text email to the fixed, account-verified destination
`logan@galenhealth.org`. It is not a general-purpose email API.

## One-time Cloudflare setup

1. Onboard `tinyzkp.com` to Cloudflare Email Routing.
2. Add `logan@galenhealth.org` as a destination address and click the
   verification link Cloudflare sends there.
3. Generate one random relay token of at least 32 characters. Install the same
   value as the Worker's `ALERT_RELAY_TOKEN`, the API's
   `TINYZKP_ALERT_WEBHOOK_TOKEN`, and the uptime probe's
   `ALERT_WEBHOOK_TOKEN`. Never commit or print it.
4. Deploy with the release-trust-pinned Wrangler 4.85.0. Record the resulting
   `/alert` URL as `TINYZKP_ALERT_WEBHOOK_URL` and as the uptime probe's
   `ALERT_WEBHOOK_URL` secret.

```sh
wrangler secret put ALERT_RELAY_TOKEN \
  --config deploy/cloudflare/alert-relay/wrangler.toml
wrangler deploy --config deploy/cloudflare/alert-relay/wrangler.toml
```

The send binding fixes both destination and sender. The relay also requires a
bearer token, accepts only `POST /alert`, caps request bodies at 16 KiB, rejects
unknown fields and control characters, and never includes upstream error
details in its response.

Before the dark canary begins, send a synthetic alert, confirm delivery in the
destination inbox, and verify that missing or changed credentials return `401`
without sending mail.
