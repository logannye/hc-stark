# Cold-Email Template — 50-Account Outbound

The math: 50 hand-picked AI agent companies × 10–15% reply rate × 2–3% close rate ≈ 1–2 paying customers per week. Zero CAC.

## Picking the 50

Start with a list of companies that fit ALL three filters:
1. Building AI agent products (autonomous tools, not just chat UIs)
2. Series A or smaller (Series B+ moves slower; Pre-seed has no budget)
3. Have a public engineering blog or contributor on Twitter (signals technical depth and reachability)

Sources for finding them:
- ProductHunt "AI Agents" tag, last 90 days
- HackerNews "Show HN" archive, filter for `agent` keyword in title
- LangChain's "built with LangChain" showcase
- a16z "Top 100 AI Apps" list (pull engineering team contacts)

Find the founder's or lead engineer's direct email via the company's `/about`, GitHub commits, or [Hunter.io](https://hunter.io). DO NOT use generic info@ or hello@ — those go to the void.

## The email

**Subject (≤ 60 chars):**

```
verifiable receipts for [their product name]?
```

(Lowercase intentional — looks like a real human reaching out, not marketing automation.)

**Body (≤ 100 words. Resist adding more):**

```
Hi [first name] —

I built TinyZKP, a hosted ZK proof service that ships as an MCP server. Looked
at [their product] this morning. The [specific feature you actually used] is
exactly the kind of agent action that benefits from a tamper-evident receipt:
"the agent ran X on input Y and got output Z" — verifiable by the user offline.

Install is one line:

  claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com

Free tier (100 proofs/mo, no card). 10-line LangChain integration if you're not on
Claude. Would love your reaction — even a "no thanks" is useful.

— Logan
https://tinyzkp.com
```

Attach: nothing. Embedded images and attachments tank deliverability.

## What good replies look like

You'll get four reply types. Handle each as follows:

| Reply type | Frequency | Action |
|---|---|---|
| "Tell me more / what does it cost?" | ~5–8 / 50 | Send the cost calculator link + a 15-min Calendly. Don't write a deck. |
| "We thought about this but [reason]." | ~3–5 / 50 | Reply same-day with a counter-argument or honest acknowledgment. Often turns into a paid customer 6 weeks later. |
| "We're already on [Sindri/Bonsai/etc.]." | ~2–3 / 50 | Ask what's working / not working. If they have a real complaint, address it. If they're happy, move on — don't try to displace. |
| Silence | ~30–35 / 50 | Send ONE follow-up after 5 business days. Then drop them from the list. |

## Follow-up email (one shot, no more)

**Subject (reply to the original thread):**

(Empty — keep the original subject for threading.)

**Body:**

```
Bumping this up. If "no" is the answer that's fine — I won't email again. If
the install above is the bottleneck, I can send you a hosted demo URL with a
preloaded API key (60-second test, no signup).

— Logan
```

## Tracking

A simple Google Sheet is enough:

| Date sent | Company | Contact | Reply? | Type | Outcome |
|---|---|---|---|---|---|

Review weekly. If reply rate < 8% after 30 emails, the *email* is the problem — rewrite the hook. If reply rate is fine but close rate < 1%, the *product fit* is the problem — listen harder to the "no thanks" replies.

## What NOT to do

- Don't send via Mailchimp / Lemlist / etc. Generic mass-mail tooling is detected by Gmail's spam filters and trashes deliverability for the founder address.
- Don't BCC anyone. Don't CC anyone. One human to one human.
- Don't follow up more than once. Polite people answer the second email. Rude follow-ups burn the brand.
- Don't ask for a meeting in the first email. Lead with the install command. The product sells itself in 30 seconds; the meeting is for closing, not for pitching.
