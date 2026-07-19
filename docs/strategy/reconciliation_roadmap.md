# TinyZKP reconciliation and production roadmap

> **Legacy research — not production evidence.** This working reconciliation
> record is not the supported Guard release contract or production evidence.

Status: working strategy document for unifying the TinyZKP company story, the
current `hc-stark` product repo, the older
`space-efficient-zero-knowledge-proofs` research repo, and the live website.

## Executive decision

TinyZKP should be unified as one company and one technical thesis, but not as
one merged codebase.

The clean reconciliation is:

- `hc-stark` is the canonical production repo and the engine behind
  TinyZKP.com, the hosted API, MCP server, SDKs, browser verifier, billing,
  operations, and security docs.
- `space-efficient-zero-knowledge-proofs` is legacy research lineage and a
  companion to the early KZG/BN254 paper path. It should point forward to
  `hc-stark` and TinyZKP.com, not compete with them.
- TinyZKP.com should present the company as a space-efficient proving company
  whose first commercial product is transparent STARK state-transition
  receipts.
- The public product should avoid broad privacy claims. The default receipt is
  transparent attestation; privacy-oriented modes are separate, audit-gated
  product work.

This gives the market one story: TinyZKP reduces the memory burden of proving.
The older repository shows where the thesis came from. The newer repository is
where customers build.

## Definition of done

Full reconciliation is complete when a new evaluator can arrive from GitHub,
TinyZKP.com, npm, PyPI, Smithery, or the arXiv paper and answer these questions
without guessing:

1. Which repo do I use today?
2. Which repo is historical research?
3. What does the live product prove?
4. What does it not claim yet?
5. How do I create, verify, price, and operationalize a proof?
6. What security claims are audited, conjectured, or deferred?
7. How do I engage TinyZKP commercially?

Production-grade company readiness is complete when TinyZKP can serve live
users with reliable signup, proving, verification, billing, support, monitoring,
incident response, and documented security boundaries without founder-only
manual intervention for normal traffic.

## Current state

### Strengths

- Live product surface already exists: marketing site, hosted API, MCP server,
  status page, dashboard, SDKs, CLI, WASM verifier, and billing scaffolding.
- `hc-stark` has the stronger production posture: transparent STARK story,
  no trusted setup for the receipt path, security docs, audit checklist,
  operations docs, pricing JSON, and focused integration tests.
- The older repo has market signal and credibility: stars, arXiv linkage, and
  a clear connection to the memory-efficiency thesis.
- The company has a focused wedge: state-transition receipts that verify
  offline and fit AI-agent and audit-checkpoint workflows.
- The local reconciliation branch now has the core public-story and
  production-state pieces wired together:
  - public Research and Security pages;
  - template lifecycle labels in API, MCP, SDK types, and docs;
  - Postgres migration paths for usage reads, billing sync, shared rate
    limits, and the job index;
  - worker request/proof handoff over stdin/stdout instead of transient local
    `request.json` / `proof.json` files;
  - shared job-claim leases plus non-local cancel updates in the job index;
  - `hc-job-worker`, a long-running worker loop that claims jobs, renews
    leases, watches cancellation, executes `hc-worker`, and publishes terminal
    status;
  - release, provenance, incident, restore, and deployment runbooks.

### Gaps

- The two repositories can look like two different products unless their roles
  are explicitly labeled.
- The old repo's README overstates production readiness and memory behavior
  relative to the code paths that still materialize full vectors for openings.
- TinyZKP.com needs a public lineage page so technical evaluators do not treat
  the older KZG repo as the hosted architecture.
- Some roadmap templates and privacy modes are attractive but should remain
  gated until live, documented, and audited.
- The live service has not yet been deployed from this branch. The live canary
  currently fails on `/research`, `/security`, `/docs#template-lifecycle`, and
  `/templates.lifecycle`.
- SQLite still remains the production source of truth until operators provision
  Postgres, run parity checks, and flip the documented read/cutover switches.
- True multi-host proving still needs production cutover and observation:
  `hc-job-worker` exists locally, but the live API still uses local dispatch
  until operators flip `HC_SERVER_PROVE_DISPATCH=shared` and run the
  `shared-workers` compose profile.

## Launch gate matrix

Use this matrix as the practical bridge from this branch to "serve live users
immediately."

| Gate | Required state | Current branch status | Production action |
| --- | --- | --- | --- |
| Company story | One website story; `hc-stark` is production; legacy repo is research lineage | Implemented locally | Merge both repo branches and deploy website |
| Website usability | `/try`, `/verify`, `/docs`, `/compute`, `/research`, `/security`, `/signup`, `/contact`, `/status` all route correctly | Implemented locally and guarded by `scripts/ci/site_route_check.py` | Cloudflare Pages deploy from clean `main`; run live canary |
| API discovery | `/templates` includes `lifecycle` and exposes only live templates by default | Implemented locally | Deploy API/MCP before or with website |
| Billing | Pricing source of truth, Stripe sync, contact qualification, usage parity tests | Implemented locally | Run production Stripe smoke tests and billing sync dry run |
| Shared usage state | Usage dual-write, Postgres read switch, billing Postgres source | Implemented locally | Provision Postgres, observe parity, flip reads and cron |
| Shared tenant auth | Billing webhook mirrors tenant/auth mutations; API and MCP can resolve auth from shared Postgres state | Implemented locally; not deployed/observed | Backfill tenant store, set `HC_TENANT_PG_URL`, compare parity, then set `HC_SERVER_AUTH_PG_URL` in both processes |
| Shared quota | HTTP and MCP authenticated prove quotas share a Postgres fixed window | Implemented locally | Set `HC_RATE_LIMIT_PG_URL` in both processes; drill rollback |
| Shared job index | Submitted/completed status and proof bytes can be stored in Postgres | Implemented locally | Set `HC_SERVER_JOB_INDEX_SOURCE=postgres`; run proof poll/download smoke |
| Worker execution | No transient request/proof files in worker hot path | Implemented locally | Deploy binaries together; confirm prove roundtrip |
| Multi-host proving | Any worker host can claim, run, cancel, and publish a job | Implemented locally through `hc-job-worker`; not deployed/observed | Enable shared dispatch, run `shared-workers`, observe claims/completions/cancellations |
| Trust posture | Public security page, audit scope, disclosure channel, release provenance | Implemented locally | Commission external review before expanding claims |

Do not call the company "fully production-grade at scale" until every gate
through shared job index is deployed and observed. Do not call it "multi-host"
until the `hc-job-worker` loop is deployed and observed against Postgres.

## Phase 0: Canonical taxonomy

Goal: remove ambiguity before doing deeper engineering.

Actions:

- Add a TinyZKP.com Research & Lineage page.
- Update `hc-stark` README and business docs with the repo taxonomy.
- Update the old repo README with a legacy/research banner.
- Point both repos to the same public product story.
- Add the research page to sitemap and footer navigation.

Exit criteria:

- The first screen of each repo answers "current product or research lineage?"
- TinyZKP.com has a public page that explains the two repos without apology or
  technical overreach.
- No page implies the hosted service uses the old KZG/BN254 path.

## Phase 1: Legacy repo hygiene

Goal: retain the old repo's credibility while preventing product confusion.

Actions:

- Reposition the repo as an archived or legacy-active research prototype.
- Correct claims around O(sqrt(T)) memory so they distinguish the intended
  architecture from the current implementation's full-IFFT/full-vector paths.
- Update quickstart commands to run reliably from a fresh clone.
- Stop tracking generated proof artifacts such as `proof.bin`.
- Add license metadata that matches the company's intended reuse posture.
- Add a short "Where to go next" section linking to TinyZKP.com, `hc-stark`,
  docs, and the research lineage page.

Exit criteria:

- The old repo remains useful to readers of the paper.
- Nobody can mistake it for the current hosted TinyZKP engine.
- Fresh-clone commands work or explicitly state required flags/features.

## Phase 2: Product repo positioning

Goal: make `hc-stark` read as a production product repo, not only a protocol
experiment.

Actions:

- Keep the first README path focused on the user journey: get key, prove,
  verify, inspect, and price.
- Add a "Research lineage" section near the architecture description.
- Keep security language precise: transparent receipt by default, privacy
  templates gated, soundness argument audit-pending.
- Link `docs/strategy/reconciliation_roadmap.md` from the README and business
  guide.
- Make `ROADMAP_EXTENSIONS.md` clearly subordinate to the live product, not a
  promise that zkML/zkVM/rollup APIs are already self-serve.

Exit criteria:

- A developer can integrate from the README without reading strategy docs.
- An investor or enterprise evaluator can follow the company story from README
  to business guide to security docs.
- Future work is exciting but visibly fenced from current guarantees.

## Phase 3: Live website and usability

Goal: convert confusion into a coherent public funnel.

Actions:

- Maintain a primary navigation hierarchy:
  - Try
  - Verify
  - Docs
  - Compute
  - Research
  - Signup
- Keep the homepage focused on the current product, not the repo history.
- Use the Research page for lineage, tradeoffs, and links to the older repo.
- Make the docs sidebar include "Research Lineage" near the API reference.
- Add a concise "What is live now" section to research and compute pages.
- Ensure the typo domain `tnyzkp.com`, if owned or referenced, redirects to
  `tinyzkp.com`. If not owned, avoid using it in public copy.
- Add analytics events for:
  - playground completion
  - signup completion
  - proof creation
  - proof verification
  - docs copy-button usage
  - research page outbound clicks
  - billing checkout start and success

Exit criteria:

- A cold visitor can try the product in under one minute.
- A technical visitor can understand the old-vs-new repo relationship in under
  two minutes.
- A buyer can identify whether they need self-serve receipts, Compute, or a
  design-partner conversation.

## Phase 4: Production service hardening

Goal: move from "live and impressive" to "reliable enough for unknown users."

Actions:

- Complete Postgres cutover for jobs, usage, tenants, API keys, and billing
  state.
- Add a dual-write migration window with reconciliation jobs before cutover.
- Move cross-process tenant quota to a shared backing store such as Redis or
  Postgres advisory locks, depending on latency needs.
- Add worker warm pool or equivalent process reuse once traffic justifies it.
- Define per-plan queueing behavior, timeout behavior, and retry semantics.
- Add synthetic monitors for:
  - signup
  - API key issuance
  - template listing
  - proof creation
  - proof polling
  - proof download
  - browser/WASM verification
  - MCP list/prove/verify path
- Add customer-visible incident categories and response targets.

Exit criteria:

- A single host failure does not corrupt billing or proof state.
- Operators can answer whether an incident is website, API, MCP, worker,
  billing, or verifier related within minutes.
- Normal user traffic does not require SSH debugging.

## Phase 5: Security, audit, and trust

Goal: make security claims reviewable by customers and auditors.

Actions:

- Commission an external cryptography review of the current STARK receipt path.
- Separate audits by scope:
  - protocol soundness
  - implementation correctness
  - hosted API and multi-tenant security
  - billing and account security
  - WASM verifier supply chain
- Publish an audit status page or security page that distinguishes complete,
  in-progress, and planned work.
- Keep KZG/BN254 legacy research clearly out of the production trust boundary.
- Add signed release artifacts for CLI, MCP binaries, and WASM verifier.
- Add SBOM and dependency vulnerability monitoring.
- Add abuse controls for anonymous MCP/playground proving.

Exit criteria:

- Security language on the website matches the audit scope exactly.
- Enterprise users can review a threat model, auditor guide, and current audit
  status without private explanation.
- Release integrity is verifiable.

## Phase 6: Developer experience

Goal: make TinyZKP easy to adopt without founder help.

Actions:

- Keep one canonical example across website, README, docs, SDK tests, and MCP
  tool examples.
- Add copy buttons and runnable snippets for curl, Python, TypeScript, Rust,
  CLI, and MCP.
- Add proof object examples with both valid and invalid verification results.
- Add "when not to use TinyZKP" guidance to reduce bad-fit support load.
- Add templates documentation that shows live, gated, and roadmap states.
- Add SDK version compatibility tables.
- Add local development quickstart for contributors and self-hosters.

Exit criteria:

- A developer can create and verify their first proof without reading protocol
  internals.
- Docs examples are tested in CI.
- Support questions shift from setup confusion to use-case design.

## Phase 7: Commercial packaging

Goal: align technology, pricing, and customer pain.

Actions:

- Keep self-serve receipts priced for repeated developer usage.
- Position Compute as the high-RAM replacement product for long traces.
- Create design-partner packages for:
  - AI-agent state receipts
  - audit-log checkpoints
  - proof-of-reserves checkpoints
  - long accumulator traces
  - custom state machines
- Treat zkML, zkVM, and rollup proving as early-access verticals until product
  scope and support economics are proven.
- Add a lightweight sales/contact workflow with qualification fields:
  - trace length
  - proof frequency
  - verification environment
  - privacy requirement
  - latency requirement
  - current alternative
  - budget owner

Exit criteria:

- The website makes it obvious which tier or conversation a user needs.
- Pricing maps to customer cost avoidance, not only proof-system novelty.
- Founder sales calls produce structured product input.

## Phase 8: Governance and release process

Goal: make the unified company maintainable.

Actions:

- Add repo-level ownership rules for protocol, API, website, billing, SDKs,
  operations, and security docs.
- Establish release trains:
  - protocol/verifier releases
  - API/server releases
  - SDK releases
  - website copy releases
  - billing/pricing releases
- Add changelog entries for user-visible proof-format or API changes.
- Add compatibility policy for proof versions and verifier packages.
- Keep old repo changes limited to research corrections, paper support, and
  forward links.

Exit criteria:

- A production release can be reviewed and rolled back without mixing unrelated
  website, protocol, and billing changes.
- Proof-format compatibility is documented before users depend on it.
- The old repo stops creating maintenance drag.

## Phase 9: Metrics and learning loop

Goal: choose the next product wedge based on observed demand.

Actions:

- Track activation:
  - visitor to playground proof
  - playground proof to signup
  - signup to first API proof
  - first proof to second proof
  - SDK install to proof creation
  - MCP install to proof creation
- Track workload shape:
  - trace sizes
  - proof latency
  - verification latency
  - template used
  - failed proof causes
  - billing tier
- Track qualitative signals:
  - why users wanted proofs
  - what they currently use instead
  - whether privacy was required
  - whether offline verification mattered
  - whether memory cost was the actual pain
- Run user interviews from free-tier signups, MCP users, and Compute inquiries.

Exit criteria:

- The next major engineering bet is chosen from evidence, not only protocol
  interest.
- The company can decide whether to prioritize Postgres scale, more templates,
  zkML, zkVM, rollup proving, or enterprise custom programs.

## Phase 10: Full production-grade company posture

Goal: serve live users immediately with credible reliability, security, and
commercial support.

Actions:

- Public service commitments:
  - status page
  - support email and response expectations
  - terms and privacy
  - security disclosure channel
  - audit status
- Operational commitments:
  - monitored deploys
  - rollback runbooks
  - backups and restore tests
  - billing reconciliation
  - rate-limit and abuse response
  - incident templates
- Product commitments:
  - stable API versioning
  - stable verifier package
  - documented proof formats
  - deprecation policy
  - template lifecycle labels
- Company commitments:
  - one canonical product repo
  - one research lineage repo
  - one website story
  - one pricing source of truth
  - one security claim vocabulary

Exit criteria:

- A customer can start, pay, prove, verify, and get help without direct founder
  intervention.
- A technical evaluator can audit the trust boundary and reproduce basic tests.
- A business evaluator can understand the wedge, pricing, and roadmap.

## Recommended next 30 days

1. Merge and deploy the reconciliation release in the documented order: API/MCP
   first, then website, then legacy repo positioning. The live canary must pass
   before public launch copy changes are announced.
2. Provision managed Postgres, enable usage dual-write, and record the
   dual-write start timestamp. Run parity checks daily before flipping any
   production read or billing source.
3. Backfill tenant/auth state with `billing/tenant_pg_tools.py`, enable the
   billing-webhook mirror with `HC_TENANT_PG_URL`, compare parity, then set
   `HC_SERVER_AUTH_PG_URL` in both API and MCP so tenant auth no longer depends
   on host-local key files during scale cutovers.
4. Flip shared authenticated quota with `HC_RATE_LIMIT_PG_URL` only after API
   and MCP are both deployed at the same revision and the rollback path is
   rehearsed.
5. Enable `HC_SERVER_JOB_INDEX_SOURCE=postgres` after a proof
   submit/poll/download smoke test confirms completed proofs are readable from
   the shared index.
6. Run five customer interviews and classify them by actual proof need:
   receipt, privacy, long trace, agent workflow, or custom proving.
7. Rehearse the shared-dispatch cutover in staging: `HC_SERVER_PROVE_DISPATCH=shared`
   plus `COMPOSE_PROFILES=shared-workers`, then run
   `scripts/monitoring/shared_dispatch_smoke.sh` in authenticated mode to prove
   submit/poll/download, inspection, verification, cancellation, usage, and
   rollback. Use `hc-job-worker --check-config` before starting the worker
   service and `hc-job-worker --once` for the first controlled staging claim.

## Recommended next 90 days

1. Complete Postgres-backed production state and remove SQLite from the hot
   production path after an observation window.
2. Ship and observe shared worker dispatch so API hosts and worker hosts no
   longer require host affinity for running jobs.
3. Convert docs examples into CI-tested examples across SDKs.
4. Run the external cryptography review for the live STARK receipt path before
   expanding public security claims or ungating more templates.
5. Start one design-partner lane only after measuring user demand:
   custom state-machine receipts, zkML inference, zkVM compute, or rollup
   batches.

## Strategic anti-goals

- Do not merge the old KZG repo into `hc-stark` as production code unless a
  concrete customer need requires a trusted-SRS pairing path.
- Do not make the homepage about repository history.
- Do not market default receipts as input privacy.
- Do not sell broad "ZK for everything" before the self-serve receipt product
  has repeat usage.
- Do not ship future templates into public copy before they are deployed,
  documented, tested, and security-reviewed.
