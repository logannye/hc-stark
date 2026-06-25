# TinyZKP ChatGPT App Prototype

> Purpose: make TinyZKP ready for ChatGPT app review and agent-commerce
> distribution without changing the existing MCP production boundary.
>
> Last updated: 2026-06-25

## Official App Shape

OpenAI's Apps SDK documentation says ChatGPT apps are built around an MCP server
that exposes tools to ChatGPT, with an optional web component rendered in an
iframe for UI. The TinyZKP prototype uses the existing hosted MCP server and a
small receipt widget:

- MCP server: `https://mcp.tinyzkp.com`
- Streamable HTTP path: `https://mcp.tinyzkp.com/mcp`
- Widget resource: `https://tinyzkp.com/apps/tinyzkp-receipt-widget.html`
- Submission metadata: [`openai_chatgpt_app_submission.json`](./openai_chatgpt_app_submission.json)

Reference docs:

- Apps SDK overview: https://developers.openai.com/apps-sdk
- Apps SDK quickstart: https://developers.openai.com/apps-sdk/quickstart
- Build an MCP server: https://developers.openai.com/apps-sdk/build/mcp-server
- Build ChatGPT UI: https://developers.openai.com/apps-sdk/build/chatgpt-ui
- Connect from ChatGPT: https://developers.openai.com/apps-sdk/deploy/connect-chatgpt
- Submit and maintain your app: https://developers.openai.com/apps-sdk/deploy/submission

## Prototype Scope

The first app should focus on two reviewable jobs:

1. Verify a TinyZKP receipt using `verify_proof`.
2. Mint an `accumulator_step` receipt using `prove_template`, `poll_job`,
   `get_proof_summary`, and `verify_proof`.

It should not claim private-input zero knowledge, arbitrary zkVM execution,
on-chain verification, or general compliance attestation. Default receipts are
transparent state-transition receipts for supported templates.

## Source-Tagged Acquisition Path

Use this signup URL in submission fields, tool descriptions, and widget fallback
CTAs:

```text
https://tinyzkp.com/signup?source=openai_chatgpt_app&medium=chatgpt_app&platform=openai&intent=mcp_install
```

Checkout must remain user-confirmed. The app can recommend a plan using the
agent-readable offer file, but should not initiate paid checkout without clear
human confirmation.

## Test Prompts

- "Use TinyZKP to list proof templates and explain which one is live."
- "Verify this TinyZKP proof receipt and tell me whether it is valid."
- "Mint a TinyZKP accumulator receipt for initial 1000, deltas 10, 20, 15, and final 1045."
- "What should I avoid putting into TinyZKP receipt parameters?"
- "Which TinyZKP plan should I start with for an agent workflow that produces 200 receipts a month?"

## Submission Checklist

- Confirm `https://mcp.tinyzkp.com/.well-known/mcp/server-card.json` lists the
  current tools and optional Bearer-auth language.
- Confirm `https://tinyzkp.com/privacy` and `https://tinyzkp.com/terms` are live.
- Confirm `site/apps/tinyzkp-receipt-widget.html` loads without external build
  tooling and contains no API keys, secrets, or customer data.
- Confirm the source-tagged signup URL appears in the app submission JSON.
- Confirm the app screenshots show transparent-receipt boundaries and free
  verification.
- Run `python3 scripts/ci/openai_chatgpt_app_check.py`.
