# TinyZKP Distribution Expansion — new channels beyond the MCP directories

> **Historical/retired distribution evidence — do not execute, submit, or use
> for outreach.** The channels, hosted endpoints, account funnels, package
> claims, and `ready_to_submit` state below belong to the former business model.
> They are not inputs to the current Community/Guard revenue-readiness ledgers.

> Purpose: broaden reach past the MCP-directory set already covered
> (Smithery, Official MCP Registry, mcp.so, Glama, mcpservers.org, PulseMCP,
> Anthropic Connectors, Cursor, punkpeye/awesome-mcp-servers) into adjacent
> agent, dev-tool, package, and backlink channels. Each entry is a ready-to-use
> submission packet: where, why, exact steps, and the copy to paste.
>
> Reuses the canonical copy in [`MCP_DISTRIBUTION_PACK.md`](./MCP_DISTRIBUTION_PACK.md).
> Created: 2026-07-05.

## Canonical copy (paste-ready)

- **One-liner:** Proof receipts for agent actions, API mutations, and state transitions.
- **Short:** TinyZKP gives agents and backend workflows a native tool for minting transparent STARK state-transition receipts — prove a supported workflow moved from an initial state to a final one by declared steps, then hand the receipt to any human, service, or agent to verify independently, without replaying the producer.
- **Install (MCP):** `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com`
- **Install (CLI):** `npx @tinyzkp/cli` · **SDKs:** `pip install tinyzkp` · `npm i tinyzkp` · `cargo add tinyzkp`
- **Free tier:** 100 proofs/month, no credit card. Verification is always free.
- **Boundary:** transparent state-transition receipts (not generic private-input ZK, zkVM, zkML, or on-chain verification). Don't put secrets into receipt parameters.
- **Tags:** `mcp` `agents` `proof-receipts` `stark` `zero-knowledge` `verification` `audit` `developer-tools` `security` `api`
- **Links:** site `https://tinyzkp.com` · repo `https://github.com/logannye/hc-stark` · docs `https://tinyzkp.com/docs`

Source-tagged signup URL shape (keep in every listing's description/homepage field):
`https://tinyzkp.com/signup?source=<CHANNEL>&medium=<MEDIUM>&platform=<PLATFORM>&intent=<INTENT>`

---

## A. High-reach agent channels (best fit — same audience already converting)

### A1. Cline MCP Marketplace  ·  *I can open the PR*
- **Why:** Cline is a top open-source AI coding agent; its in-editor MCP Marketplace is one of the highest-intent install surfaces for exactly your buyer.
- **Where:** open a submission issue/PR at `https://github.com/cline/mcp-marketplace` (follow its `README` submission template).
- **Submit:** name `TinyZKP`, GitHub `https://github.com/logannye/hc-stark`, one-liner (above), logo (`site/favicon.svg`), install `claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com`.
- **Signup tag:** `source=cline_mcp&medium=mcp_directory&platform=cline&intent=mcp_install`

### A2. More `awesome-mcp-servers` lists  ·  *I can open the PRs*
You're on punkpeye's (PR #8733). Add the other two high-traffic lists:
- `https://github.com/wong2/awesome-mcp-servers` — tag `source=awesome_mcp_servers_wong2&medium=mcp_directory&platform=github&intent=mcp_install`
- `https://github.com/appcypher/awesome-mcp-servers` — tag `source=awesome_mcp_servers_appcypher&medium=mcp_directory&platform=github&intent=mcp_install`

**Entry (match each list's category + bullet format):**
`- [TinyZKP](https://github.com/logannye/hc-stark) — Mint & verify transparent STARK state-transition receipts (proof receipts for agent actions). Hosted MCP, no signup for the anonymous lane.`

### A3. mcp-get  ·  *I can open the PR*
- **Why:** a CLI installer + registry (`npx @michaellatman/mcp-get`).
- **Where:** PR to `https://github.com/michaellatman/mcp-get` adding a package entry (name, description, hosted/remote endpoint, install).
- **Signup tag:** `source=mcp_get&medium=mcp_directory&platform=mcp_get&intent=mcp_install`

### A4. Continue Hub  ·  *operator submit*
- **Why:** Continue.dev supports MCP; Continue Hub (`https://hub.continue.dev`) lets you publish an MCP block devs add in one click.
- **Where:** sign in to hub.continue.dev → create an MCP block → point at `https://mcp.tinyzkp.com` (streamable HTTP), paste the one-liner + boundary.
- **Signup tag:** `source=continue_hub&medium=mcp_directory&platform=continue&intent=mcp_install`

### A5. Composio  ·  *operator submit*
- **Where:** `https://composio.dev` tools/MCP directory — submit the hosted MCP endpoint via their app/console.
- **Signup tag:** `source=composio&medium=mcp_directory&platform=composio&intent=mcp_install`

---

## B. Dev-tool launch & discovery (beyond MCP)

### B1. Product Hunt  ·  *operator launch (I prepped the full kit)*
- **Why:** the biggest non-HN one-shot spike + a permanent, backlinked listing. Schedule for **12:01am PT, Tue–Thu**.
- **Name:** TinyZKP
- **Tagline (≤60):** `Verifiable proof receipts for AI agents & APIs`
- **Topics:** Developer Tools, Artificial Intelligence, GitHub, API, SaaS
- **Description:**
  > TinyZKP is a hosted service for **transparent STARK proof receipts**. One MCP install or one API call mints a tamper-evident receipt that a declared state-transition chain is consistent — start at X, apply these steps, reach Y — and anyone can verify it in milliseconds, in the browser, without trusting you. Built on a height-compressed streaming prover that runs in ~O(√T) memory, so long traces don't need a RAM-heavy prover box. Free tier: 100 proofs/month, no card. Verification is always free.
- **First comment (maker intro):**
  > Hi PH 👋 I built TinyZKP because "trust me, my agent did X" isn't good enough for audit logs, proof-of-reserves checkpoints, or agent-action receipts. It gives agents a native MCP tool (and a plain API/CLI) to mint a transparent, tamper-evident receipt of a state transition that anyone can verify offline — no cryptography degree, no re-running your system. It's open source (STARK-based, no trusted setup, post-quantum). Try it with no signup at tinyzkp.com/try. Happy to go deep on the √T prover or the honest scope (it's state-transition receipts today, not a zkVM). — Logan
- **Gallery:** homepage screenshot, the `/try` playground, the receipt-verify flow, the √T memory chart (`docs/benchmarks/sqrt_memory_scaling`). (`site/og-image.png` for the thumbnail.)
- **Links:** `https://tinyzkp.com/?source=product_hunt&medium=launch&platform=product_hunt&intent=api_key`

### B2. Console.dev  ·  *operator submit*
- **Why:** a respected curated newsletter for developer tools (high-quality dev audience).
- **Where:** submit at `https://console.dev/submit-tool/` — name, URL, one-liner, category "Developer Tools / Security".
- **Link:** `https://tinyzkp.com/?source=console_dev&medium=newsletter&platform=console_dev&intent=api_key`

### B3. Devhunt  ·  *operator launch*
- **Where:** `https://devhunt.org` — launch a dev tool (weekly leaderboard, dofollow backlink). Reuse the Product Hunt tagline + description.
- **Link:** `https://tinyzkp.com/?source=devhunt&medium=launch&platform=devhunt&intent=api_key`

---

## C. SEO / backlink directories (compounding organic)

Each is a listing that ranks and links back to tinyzkp.com. Low effort, durable.

### C1. AlternativeTo — `https://alternativeto.net`
- Add TinyZKP as software; list it as an alternative to **self-hosted zkVM provers**, **signed audit logs**, and **blockchain anchoring** (mirror your `/compare/*` pages).
- Link tag: `source=alternativeto&medium=directory&platform=alternativeto&intent=api_key`

### C2. StackShare — `https://stackshare.io`
- Add TinyZKP as a Tool/Service under "Security" / "Developer Tools"; link the docs + repo.
- Link tag: `source=stackshare&medium=directory&platform=stackshare&intent=api_key`

### C3. SaaSHub — `https://www.saashub.com/submit`
- Submit product; category "Developer Tools / Security". Link + one-liner.
- Link tag: `source=saashub&medium=directory&platform=saashub&intent=api_key`

---

## D. Package-ecosystem & curated GitHub lists

### D1. Homebrew tap for the CLI  ·  *I wrote the formula*
Broadens CLI reach to `brew install`. Create tap repo `github.com/logannye/homebrew-tinyzkp`, add `Formula/tinyzkp.rb` below, then `brew install logannye/tinyzkp/tinyzkp`. (Fill `sha256` from `npm view @tinyzkp/cli dist.tarball` → `shasum -a 256`.)

```ruby
class Tinyzkp < Formula
  desc "Mint & verify transparent STARK state-transition receipts (TinyZKP CLI)"
  homepage "https://tinyzkp.com"
  url "https://registry.npmjs.org/@tinyzkp/cli/-/cli-0.1.0.tgz"
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license "MIT"
  depends_on "node"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    assert_match "tinyzkp", shell_output("#{bin}/tinyzkp --help")
  end
end
```
- Link tag: `source=homebrew&medium=package_manager&platform=homebrew&intent=cli_install`

### D2. awesome-zero-knowledge-proofs  ·  *I can open the PR (optional — research-heavy list)*
- `https://github.com/matter-labs/awesome-zero-knowledge-proofs` (or `ventali/awesome-zk`) — add under an implementations/tools section.
- Entry: `- [TinyZKP](https://tinyzkp.com) — Hosted transparent STARK receipts (state-transition), O(√T)-memory streaming prover, no trusted setup. [[repo]](https://github.com/logannye/hc-stark)`

### D3. awesome-cryptography  ·  *I can open the PR (optional)*
- `https://github.com/sobolevn/awesome-cryptography` — add under a relevant "tools/services" section if one fits; skip if it would be a stretch (maintainers reject off-scope PRs).

---

## E. Already prepped — you just hit submit
These packets exist (`ready_to_submit` in `gtm_pipeline_state.json`); finish them:
- **Anthropic Connectors Directory** — submit the hosted connector (`OPENAI_CHATGPT_APP_*` is the analog; use `server-card.json`). Highest-fit remaining.
- **Cursor Directory** — submit the MCP server at the Cursor directory form.
- **OpenAI ChatGPT App** — `openai_chatgpt_app_submission.json` + `OPENAI_CHATGPT_APP_PROTOTYPE.md` are ready.

---

## Priority order (do the top 3 first)
1. **Cline MCP Marketplace** + the two **awesome-mcp-servers** PRs — highest-intent, same buyer, I can open them now.
2. **Product Hunt** launch — biggest one-shot reach; kit is ready above.
3. Close out the 3 **already-prepped** (Anthropic Connectors, Cursor, ChatGPT app).
Then the SEO directories (C) and Homebrew/awesome-lists (D) as steady low-effort fill.

## After each goes live
Add the public listing URL + `status: active` to `mcp_distribution_targets.json` and run `python3 scripts/monitoring/gtm_distribution_monitor.py --offline` (keeps the growth loop + CI tracking the new channel).
