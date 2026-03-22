> **Note:** This guide was written before TinyZKP launched. For current pricing, API endpoints, and product details, see the [README](README.md) or [tinyzkp.com](https://tinyzkp.com).

# hc-stark Business Guide (Plain English)

This document explains, in **non-technical** terms, what this code repository is, why it matters, and how you can build a **real business** around it.

If you are reading this and you are not a programmer, that is okay. You do **not** need to understand the math. You only need to understand:

- What the product does for customers
- Why customers will pay for it
- How to run it safely
- How to charge money for it

---

## Important note (honest expectations)

This repo is “ready to ship” as software, meaning:

- It can run as an online service (an API) right now
- It has a dashboard stack (Prometheus + Grafana) for basic monitoring
- It has basic API keys for access control
- It is packaged so someone can deploy it quickly

However, like any business, success depends on:

- Choosing the right market and customer
- Selling and supporting customers
- Handling billing, taxes, legal terms, and reliability

This guide helps with those business steps at a practical level.

---

## 1) What this repo is (in plain English)

### The simplest explanation

This repo builds a system that can create a **digital receipt** that proves a computer task was done correctly.

Think about a restaurant:

- The kitchen cooks a meal.
- The receipt shows what was ordered and paid for.

In this repo:

- The “meal” is a computer computation (a program run, a long calculation, a big batch of work).
- The “receipt” is a **proof**.
- The “cash register” is the software in this repo that produces and checks those proofs.

### Why do we need receipts for computation?

Because many computer tasks are:

- Too expensive for everyone to repeat (hours of work)
- Too big to share openly (private data)
- Too important to “just trust someone” (money, safety, audits)

So we want a way to say:

> “I did the work correctly. Here is a receipt you can check quickly.”

This is called **verifiable compute**.

---

## 2) Why it’s important (and useful)

### The problem in real life: trust is expensive

If someone claims a big computation is correct, you normally have two options:

1. **Trust them** (risky)
2. **Redo the computation yourself** (expensive)

This repo creates a third option:

3. **Check a proof** (fast and cheap compared to redoing)

### Who cares about this?

People care when correctness matters and the work is expensive. Examples:

- **Finance and accounting**: proving numbers are correct without revealing every detail
- **Auditing/compliance**: proving a process was followed correctly
- **Blockchains**: proving a large batch of activity is valid
- **AI / data science**: proving results came from the agreed calculation

---

## 3) What makes this repo special (why it’s valuable software)

### A key practical problem: memory costs

Even if “proofs” are useful, many proof systems are hard to run because they use:

- enormous amounts of computer memory (RAM)
- expensive machines
- fragile long-running jobs that crash if memory runs out

### What hc-stark changes

This repo focuses on making proof creation more practical by using a **streaming / replay** approach:

- Instead of loading “everything” into memory, it tries to work in a bounded memory budget.
- That makes it more feasible to run on cheaper hardware and more reliably.

In business terms:

- Lower infrastructure cost
- Fewer failures
- Ability to serve larger customers or bigger jobs

That is the kind of technical advantage that can become a business advantage.

---

## 4) What product you can sell

The simplest product to sell is:

> **Proofs as a Service** (an online proving API)

Customers send a request, your service returns:

- a job id (because proving can take time)
- later, the proof
- and anyone can verify it using the same service or software

This repo already includes an API server (`hc-server`) with endpoints:

- `POST /prove` (start a proof job)
- `GET /prove/{job_id}` (check job status and retrieve proof)
- `POST /verify` (verify a proof)
- `GET /healthz` and `GET /readyz` (health checks)
- `GET /metrics` (monitoring)
- `GET /docs` (API documentation website)

---

## 5) How to run it (the simplest “ship it” way)

### What you need

- A computer with Docker installed (a common deployment tool)
- Internet access (to pull images)

### Start the full stack (server + monitoring dashboard)

From the repo folder, run:

```bash
docker compose up --build
```

This will start:

- `hc-server` on `http://localhost:8080`
- Prometheus on `http://localhost:9090`
- Grafana on `http://localhost:3000` (login: `admin` / `admin`)

### API keys (basic customer access control)

The server supports API keys. By default, the provided `docker-compose.yml` includes:

- `HC_SERVER_API_KEYS=demo:demo_key`

That means clients must send:

```
Authorization: Bearer demo_key
```

### Safe-by-default workloads (no arbitrary code)

By default, the server is configured to **not accept arbitrary programs**.
Instead, customers must choose a `workload_id` that you ship and support.

This is important for safety: you don’t want strangers sending you “custom code” in production until you intentionally support it.

The sample workload included is:

- `toy_add_1_2`

---

## 6) How customers would use the API (conceptually)

### A. “Prove” (create a proof)

The customer sends a request to start a proof job. Your service responds with a `job_id`.

### B. “Poll” (wait for completion)

The customer checks `GET /prove/{job_id}` until it says “succeeded” or “failed”.

### C. “Verify”

The customer can ask your service to verify the proof using `POST /verify`.

In many businesses, verification is free or cheap, and proving is the paid part.

---

## 7) How to charge money (pricing models)

There are three practical ways to charge.

### Option 1: Charge per proof (simple)

Example:

- $5 per proof for small jobs
- $50 per proof for medium jobs
- custom pricing for large jobs

Pros:

- Simple to explain and sell

Cons:

- You must define “small/medium/large” clearly

### Option 2: Charge per usage unit (more fair)

Example billable units:

- CPU-seconds used
- job duration
- job size
- number of steps in the workload

Pros:

- Customers pay for what they use

Cons:

- Requires careful measurement and billing

### Option 3: Subscription tiers (best for predictable revenue)

Example:

- Starter: $99/month (limited proofs)
- Pro: $999/month (higher limits)
- Enterprise: custom (SLA, support)

Pros:

- Predictable revenue

Cons:

- You need a usage limit system and support expectations

---

## 7A) How big can this become? (opportunity and market sizing, in plain English)

This section answers: **“Is this a small business or a very large one?”**

The honest answer is: it depends on **which market you choose** and whether you become:

- a “nice tool” used by a few teams, or
- a “utility” that many companies depend on for verification.

### First, what is the “market” here?

The market is not “cryptography.” The market is:

> **People and organizations that need trustworthy results from expensive computation.**

When verification is important, someone must pay for:

- the compute itself,
- reliability and uptime,
- and the ability to prove to others that results are correct.

### A simple way to estimate how big the business can be (no math degree required)

There are two common ways.

#### Method 1: Bottom-up (start from customers and usage)

Ask:

- How many customers could you realistically win in 1–3 years?
- How many proof jobs do they run per day or per month?
- How much would they pay per job (or per month)?

Example thought exercise:

- 50 customers × $1,000/month = $50,000/month (~$600,000/year)
- 500 customers × $1,000/month = $500,000/month (~$6,000,000/year)
- 20 enterprise customers × $100,000/year = $2,000,000/year

This is not meant to be “the number.” It is meant to show that this can range from:

- a modest, profitable service, to
- a very large infrastructure business.

#### Method 2: Top-down (start from the cost customers already pay)

Many target customers already pay real money for:

- large machines (RAM/GPUs),
- cloud compute bills,
- engineers to operate provers,
- downtime incidents and failures.

If you can reduce their cost or complexity, you can charge a portion of that saved value. For example, if this software can save Amazon $10,000,000 per year, you can reasonably charge them 25-30% of that savings (a.k.a. $3,000,000 per year) to license it.

### Why this repo can create an outsized opportunity

A big part of the cost of proof systems in real life is **prover infrastructure**.

This repo is designed to make proof generation more practical and reliable by using a more streaming, bounded-memory approach.

In business terms, the value comes from:

- **Lower cost per proof** (cheaper machines, fewer retries)
- **Higher reliability** (fewer crashes due to memory limits)
- **Bigger jobs become possible** (new customers and new use cases)

That is the kind of improvement that can produce a defensible, valuable product—because it changes what customers can afford to do.

### Which markets are plausibly “big enough”?

You do not need to pick all of them. Pick one wedge.

Examples of “big enough” markets:

- **Blockchain scaling** (proving large batches of work): teams already spend heavily on proving infrastructure.
- **Enterprise audit/compliance**: companies pay for systems that make audits cheaper and more trustworthy.
- **AI and data pipelines** (where trust and reproducibility matter): even a small slice of a large compute budget can be meaningful.

### A practical worksheet (fill in the blanks)

You can estimate potential revenue with a simple worksheet:

1. **Customer type**: ____________________________
2. **What you prove** (workload): ____________________________
3. **How many jobs per month per customer**: ____________________________
4. **What you charge** (per job or per month): ____________________________
5. **How many customers in year 1**: ____________________________

Then:

- Revenue per month ≈ (jobs/customer/month × price/job × customers)  
  or (price/month × customers)

### A note about “market size numbers” you’ll see online

You may see large numbers online for “zero-knowledge,” “blockchain,” or “AI.” Those can be useful for context, but they often mix unrelated things.

The best sizing is:

- **How much money your specific customers already spend** on the problem you solve, and
- how much of that you can capture by being clearly better.

---

## 8) How to choose a customer and a “wedge”

A good first business wedge is where:

- correctness matters
- computations are expensive
- customers already pay real money for infrastructure

Common wedges:

- teams that need verifiable batches of compute (analytics pipelines)
- Web3 teams needing proof generation for batches of transactions
- data/AI teams who want verifiable outcomes for sensitive pipelines

You do not need to boil the ocean.

Start with one well-defined workload type and sell that.

---

## 9) What you must do to run this as a business (non-technical checklist)

### Business basics

- Choose a company name and domain
- Create a simple website landing page:
  - what you do
  - who it’s for
  - pricing
  - contact
- Create Terms of Service and Privacy Policy
- Decide your support boundaries (email, response times)

### Money basics

- Set up billing (Stripe is common)
- Decide if you need invoices (enterprise customers often do)

### Trust basics (how you win customers)

Customers will trust you if you provide:

- uptime
- clear incident communication
- honest limits
- predictable pricing

---

## 10) Practical “launch in 7 days” plan

### Day 1: Run it locally

- Start with Docker Compose
- Confirm you can create and verify proofs

### Day 2: Put it on a server

- Rent a VM from a cloud provider
- Install Docker
- Run the same Compose stack

### Day 3: Add a simple API key per customer

- Create unique keys (one per customer)
- Configure `HC_SERVER_API_KEYS` on the server

### Day 4: Add a payment page

- A Stripe checkout page
- After payment, email the API key to the customer

### Day 5: Write a “Getting Started” page for customers

- Explain endpoints and the poll pattern
- Show example requests

### Day 6: Find 3 design partners

- Offer a discount for early feedback
- Learn what they actually need

### Day 7: Start charging

- Keep the first version simple
- Improve based on usage and support questions

---

## 11) Common risks (and how to avoid them)

### Risk: running arbitrary code from strangers

Mitigation:

- Keep `HC_SERVER_ALLOW_CUSTOM_PROGRAMS=false` by default
- Only accept known `workload_id` values

### Risk: runaway compute costs

Mitigation:

- Keep strict timeouts
- Keep strict inflight limits
- Start with subscription tiers and hard caps

### Risk: customers need a specific workload

Mitigation:

- Add new workload IDs gradually
- Treat each new workload as a product line

---

## 12) Where to learn more (if you want the deeper explanation)

- `README.md` — the main technical overview
- `docs/whitepaper.md` — the design philosophy and motivation
- `docs/design_notes/` — deeper internal notes



