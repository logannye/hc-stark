# User-interview pipeline

Goal: 5 interviews in 14 days. Output: a synthesis doc that locks in the next two
quarters of product priorities (templates, SDK shape, billing/quota knobs, MCP
ergonomics).

## Why bother

Every feature decision downstream of this loop gets cheaper with five real
conversations. We have 6 templates, 3 SDKs, an MCP server, and three pricing
tiers — but zero verified evidence about what receipts users actually want to
mint, what makes them upgrade from free, and what makes them churn. Five
30-minute calls answers most of it.

## Recruiting

### Source list (in priority order)

1. **Free-tier signups in the last 14 days.** Highest-intent — they actively
   typed their email. Pull from `tenants` table:
   ```sql
   SELECT email, plan, created_at FROM tenants
    WHERE plan = 'free' AND created_at > now() - interval '14 days'
    ORDER BY created_at DESC LIMIT 50;
   ```
2. **MCP installs.** Anyone whose MCP server hit `mcp.tinyzkp.com` in the last
   30 days — they got far enough to wire into Claude/Cursor. Filter by
   `Referrer: claude.ai` in nginx logs.
3. **Browser-playground completions.** Users who hit `/try` and clicked
   "Generate proof" successfully. We don't have analytics on this yet — see
   M2 follow-up below.
4. **Inbound contact-form submissions.** Already self-selected. Highest reply rate.

### Outreach email (verbatim)

Subject: `Quick chat about TinyZKP? (15 min, on me)`

```
Hi [first name] —

You signed up for TinyZKP last [Tuesday / N days ago] and I noticed
you ran [N proofs / 0 proofs / hit the X template]. I'm Logan, the
founder. I'd love to spend 15-20 minutes on what you were trying to
do — what worked, what was confusing, and what would make you actually
use this in production.

In return I'll bump your free-tier quota to 1,000 proofs/month for the
next 6 months, no card required. Even if you decide TinyZKP isn't a
fit, the quota stays.

Calendar link: [Cal.com / Calendly URL]

Thanks for the early signup —
Logan
logan@tinyzkp.com
```

**Send rules:**
- Send Tuesday–Thursday, 10am–12pm in the recipient's local time (infer from
  signup timezone in the tenant row, fall back to PT).
- Send no more than one follow-up, 5 days later.
- Stop after the first 3 send/follow-up cycles even if you have <5 calls — the
  data from "people don't want to talk" is itself a signal worth knowing.

## Interview script (30 min)

The script is 8 questions. Stay under 30 minutes; if you blow through, the
notes get sloppy.

**Setup (2 min)**
> "Thanks for hopping on. I'm going to record audio just so I can write notes
> after — that OK? You'll get a copy of any quotes I want to use, and I'll
> ask before publishing anything. The format is 8 questions, then open Q&A."

### The questions

1. **What were you trying to build when you found TinyZKP?**
   *Probe: language? team size? deployed already, or prototype?*

2. **What proof would actually make your system better tomorrow?**
   *Don't accept "ZK proofs in general." Push for the specific receipt: range
   check on a number, hash preimage of a secret, attestation of a computation,
   etc. If they can't name one, that's the answer — they're exploring, not
   buying.*

3. **Did you make it through the quickstart?**
   *Probe at each step: signup, key in env, first SDK call, first
   `prove_template`, first `verify`. Where did they stop?*

4. **What was confusing?**
   *Specifically about: (a) what `witness_steps` are, (b) which template to
   pick, (c) how to read the proof JSON, (d) pricing tiers, (e) the difference
   between the JSON API and MCP. These are our top suspect-failure-modes —
   probe them by name if they don't volunteer.*

5. **If TinyZKP cost $19/mo, would you pay it tomorrow? Why or why not?**
   *Pricing-sensitivity check. The honest answers tend to come in two
   buckets: "yes, easily" or "I'd need to prove it integrates first." Both
   are useful.*

6. **Where would the receipt go after you mint it?**
   *Probe: stored in DB, attached to a row, posted to a webhook, included in
   API response, written on-chain, sent to a regulator? This dictates whether
   we need calldata, batch verification, signature wrapping, or just a JSON
   blob.*

7. **What's the closest thing you considered before TinyZKP?**
   *Categories to listen for: rolling your own STARK (rare), zkVM frameworks
   (RISC0, SP1), audit logs without crypto, regulatory attestations (SOC 2),
   "nothing — I'd ship without the receipt." Each of those is a different
   competitive frame.*

8. **If we vanished tomorrow, what would you miss?**
   *Sean Ellis's "very disappointed if this went away" filter. The answer
   tells you whether they have product-market fit with you.*

### Wrap-up (open Q)
> "Anything I didn't ask that I should have? Anything you want to know about
> the roadmap?"

**Hard-stop at 30 minutes.** Send a calendar follow-up within 24 hours
thanking them and noting whichever quota or feature you committed to.

## Notes template

For each interview, save a markdown file at
`~/.tinyzkp/interviews/YYYY-MM-DD_<firstname>.md` with:

```markdown
---
date: 2026-04-NN
participant: <first name>
plan: <free|developer|scale>
signup_date: <YYYY-MM-DD>
proofs_run: <N>
duration_min: 30
---

## Use case (Q1, Q2)
- Building: …
- Specific receipt they want: …

## Activation (Q3, Q4)
- Got to: …
- Stuck on: …
- Confusing: …

## Pricing (Q5)
- Verdict: would pay / wouldn't / "depends on X"
- Their X: …

## Distribution (Q6, Q7)
- Receipt destination: …
- Considered alternatives: …

## PMF signal (Q8)
- Very disappointed / somewhat / not really / N/A

## Direct quotes worth saving
> "…"
> "…"

## Action items spawned
- [ ] …
```

## Synthesis (after all 5 calls)

Write `~/.tinyzkp/interviews/2026-MM-synthesis.md` with:

1. **One-liner per interviewee** — who they are, what they want, would-pay verdict.
2. **Top 3 confusion themes** — counts. If 3+ people said the same thing, that's
   a P0. If 1 person said it, ignore for now.
3. **Top 3 missing capabilities.** Same counting threshold.
4. **Pricing read** — yes/no/depends with reasons.
5. **Six-month bet** — pick exactly one product priority that the interviews
   strongly justify. Resist picking three.

## Post-interview follow-throughs (NOT optional)

- [ ] Apply the quota bump (`hc-admin set-quota --tenant <email> --override 1000`).
- [ ] Send the participant a personal thank-you with one specific thing you
  learned from them. (Better than the generic "thanks!" — increases response
  rate on a future round.)
- [ ] Add them to a private "TinyZKP early users" Slack/Discord channel if you
  have one. They become your eventual case-study list.

## Calendar / form artifacts

The outreach email above references a calendar link. Recommended setup:

- **Calendar:** Cal.com (free tier OK; book up to 30-min slots, 3 per day cap,
  Mon–Thu only, 9am–4pm PT).
  - Slug: `cal.com/tinyzkp/user-interview`
  - Buffer: 15 min before/after.
  - Auto-confirmation email includes link to a one-page consent doc:
    `https://tinyzkp.com/interview-consent` (covers recording, anonymity,
    quota bump).
- **Tracking sheet:** Google Sheet with columns:
  `email | signed_up_at | outreach_sent_at | followup_sent_at |
   booked_at | call_date | notes_link | quota_applied | thanked_at`.

## M2 follow-up: instrument /try

We can't recruit from `/try` completions today because the page doesn't track
them server-side (Cloudflare Pages, no analytics). Cheapest fix: have the
"Generate proof" button POST `{event: "try_completed"}` to a tiny Cloudflare
Function that writes to a Postgres table. Pull from there for round 2.
