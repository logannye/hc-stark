# Smithery.ai submission notes — TinyZKP

Smithery is the largest community MCP catalog. Listings are free.

> **Important — only one submission path exists.** An earlier draft of
> this doc described a "PR path" through `github.com/smithery-ai/registry`
> as a fallback. That repo is *not* a registry — its README explicitly
> says it is "for issue tracking only and does not contain source code"
> (verified 2026-04-28). The web UI is the only path.

## Pre-flight checklist

- [x] `smithery.yaml` at repo root (committed)
- [x] Public repo at https://github.com/logannye/hc-stark
- [x] Hosted endpoint live at https://mcp.tinyzkp.com (HTTPS, valid cert)
- [x] License: MIT
- [x] All 10 tools annotated (title, read_only_hint, destructive_hint) — see `crates/hc-mcp/src/lib.rs`

## Submission steps

1. Sign in at https://smithery.ai with the `logannye` GitHub account.
2. Click **"New Server"** at https://smithery.ai/new.
3. Paste `https://github.com/logannye/hc-stark`.
4. Smithery auto-detects `smithery.yaml` from the repo root. Confirm the parsed metadata (name, description, transport, tools).
5. Hit **"Publish"**. The expected listing URL pattern is `https://smithery.ai/server/@logannye/tinyzkp`.

If the web UI fails to auto-detect (e.g. parser rejects a field), the
fix is to edit `smithery.yaml` in this repo, push to `main`, and retry
— **not** to open a PR against `smithery-ai/*`.

## Verifying the listing went live

```bash
# After clicking Publish, the listing URL becomes a valid 200:
curl -fsSL -o /dev/null -w "%{http_code}\n" "https://smithery.ai/server/@logannye/tinyzkp"
# Expect 200. A 404 means submission did not complete — re-check the web UI flow.
```

## Post-acceptance

- [ ] Add the Smithery badge to `README.md` and `tinyzkp.com/docs`.
- [ ] Watch `Referrer: smithery.ai*` in MCP server logs for first 14 days.
- [ ] Reply to first 3 issues opened on the Smithery server detail page within 24h.

## Submission status

- [ ] Submitted via web UI — date: ____ — listing URL: ____
