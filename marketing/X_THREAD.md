# Twitter / X Launch Thread

**When to post:** ~30 minutes after the HN post hits the front page (gives both a coordinated lift and tracks separately). Otherwise, Tuesday/Wednesday 9:30 a.m. ET. This is a **one-time** launch spike, not a recurring cadence — post it, be present for a few hours, then let it become a permanent backlink.

**Tagging:** in a *follow-up reply* on your own tweet (Twitter throttles tag-in-body posts), tag ZK/proving and dev-infra accounts that are genuinely relevant to the post — prover-infra builders, zk-tooling orgs, transparent-STARK people. Don't tag AI-agent influencers; this thread is infra-positioned, and an off-target tag reads as spray.

---

**Post 1/5 (the hook):**

```
Prove a state transition. Anyone verifies it in 5 ms.

TinyZKP mints a transparent ZK-STARK receipt that a committed value went from X to Y
by exactly these steps — your counterparty or auditor checks it offline, with no
access to your system and nothing to re-run.

One API call, or one MCP install:
  $ claude mcp add --transport http tinyzkp https://mcp.tinyzkp.com

Free tier, no card:
https://tinyzkp.com/signup?source=x_launch_thread&medium=social&platform=x&intent=api_key
```

Attach: short screen recording (≤ 30 seconds) showing the *audited* path:
1. The `claude mcp add` command
2. Inside Claude Code, asking "prove that an account moved from 1000 to 1045 via deltas [10, 20, 15]"
3. Claude calling `prove_template` → `poll_job` → `verify_proof`, returning `{ok: true}`

(Use this exact example — it's `accumulator_step`, the one audited, live-by-default template. Don't demo range/policy/zkML; those aren't live.)

---

**Post 2/5 (what it's actually for):**

```
Not "trust my dashboard." Your counterparty verifies the state commitment themselves.

Good for: proof-of-reserves & running ledgers, oracle / data-aggregation attestation,
tamper-evident audit trails — anywhere a third party has to confirm "this state
advanced correctly" without re-running your system.

Transparent (no trusted setup). Post-quantum (hash-based).
```

---

**Post 3/5 (the architecture):**

```
The engine (open-source Rust: hc-stark) is a height-compressed STARK prover —
O(√T) memory instead of O(T).

A heavy state-transition trace runs on a 16 GB box instead of a 256 GB server:
measured ~4,096× smaller commitment working set at 16.7M elements, identical Merkle
root. Honest trade-off: ~√T more compute to use √T less RAM.
```

---

**Post 4/5 (verify anywhere — the part that matters):**

```
Verification never needs us online.

Ship the proof + @tinyzkp/verify (785 KB WASM) and anyone checks it in ~5 ms, in
their own browser, offline, free forever.

That's the difference between a trust *extension* (round-trip to your server) and a
trust *replacement* (they verify it themselves).
```

---

**Post 5/5 (the close — honest scope):**

```
Live today: audited accumulator / state-transition proofs, up to 100M steps,
$0.50 per million trace steps on the usage meter.
In development: zkVM & zkML — not available yet, and we won't pretend otherwise.

Open source: github.com/logannye/hc-stark
Try it, no signup: https://tinyzkp.com/try?source=x_launch_thread&medium=social&platform=x&intent=try_receipt
Free key: https://tinyzkp.com/signup?source=x_launch_thread&medium=social&platform=x&intent=api_key
```

---

**Notes:**

- Pin the thread on the founder profile for a week.
- After 24 hours, if it went well, write a single-tweet update: "X signups today; the most-asked-for next template was [Y]. Building it next." — drives the second wave.
- DO NOT auto-DM new followers. It tanks deliverability and looks desperate.
- If the thread underperforms (< 50 likes after 4 hours), DON'T amplify with a paid boost. Pull it next day and try a different hook the following week. Twitter punishes stale ad-boosted dev-tools posts hard.
- Honesty guardrails for any reply you write live: the audited default path proves a **public** delta chain — do **not** claim it hides inputs, do **not** promise a finished 100M-step proof beyond the live cap, and do **not** imply zkVM/zkML is available.
