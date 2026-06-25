# tinyzkp

TypeScript client for the [TinyZKP](https://tinyzkp.com) proving API — generate and verify ZK-STARK proofs.

TinyZKP turns state transitions into receipt-sized STARK proofs that humans,
services, and AI agents can verify later. Get a free API key at
[tinyzkp.com/signup](https://tinyzkp.com/signup?source=npm_tinyzkp&medium=package_registry&platform=npm&intent=api_key)
with 100 proofs/month and no credit card.

## Install

```bash
npm install tinyzkp
```

## Quick Start

ESM (recommended):

```typescript
import { TinyZKP } from "tinyzkp";

const client = new TinyZKP("https://api.tinyzkp.com", { apiKey: "tzk_..." });

// Prove that 1000 + 10 + 20 + 15 = 1045.
const jobId = await client.proveTemplate("accumulator_step", {
  initial: 1000, final: 1045, deltas: [10, 20, 15],
});

// Wait for the proof (polls automatically, typically 1-5 seconds)
const proof = await client.waitForProof(jobId);

// Verify it (always free)
const result = await client.verify(proof);
console.log(result.ok); // true
```

CommonJS (works since v0.1.1):

```javascript
const { TinyZKP } = require("tinyzkp");
const client = new TinyZKP("https://api.tinyzkp.com", { apiKey: "tzk_..." });
```

`HcClient` is the original name; `TinyZKP` is exported as an alias and is preferred in new code.

## What does the live template prove?

The live self-serve template is `accumulator_step`. It proves a transparent state transition: starting from `initial`, applying each value in `deltas` reaches `final`. Use it for balance updates, ledger reconciliation, audit-log checkpoints, and agent state receipts where the verifier needs a compact receipt.

## API

- `new TinyZKP(baseUrl, options?)` — create a client (alias for `HcClient`)
- `proveTemplate(templateId, params, options?)` — submit a proof via template (recommended)
- `prove(request)` — submit via raw program
- `proveStatus(jobId)` — check job status
- `waitForProof(jobId, options?)` — poll until proof is ready
- `verify(proof, allowLegacyV2?)` — verify a proof (always free)
- `templates()` / `template(id)` — list templates / get one template's full schema
- `healthz()` — check server health

`ProofBytes` is exported as a runtime class (`new ProofBytes(version, bytes)`) with a `.toJSON()` helper. Object literals matching `{ version, bytes }` are still accepted everywhere a `ProofBytes` is expected.

## Templates

Production template discovery includes a `lifecycle` field. Public production listings expose live templates by default; audit-gated and preview templates are not part of the self-serve catalog unless a deployment explicitly enables them.

| Template | Lifecycle | Proves | Example |
|----------|-----------|--------|---------|
| `accumulator_step` | `live` | Additive chain is correct | Balance updates, state receipts |

Use [tinyzkp.com/docs](https://tinyzkp.com/docs) for the current template catalog, fit guidance, and security notes. Default receipts are transparent; do not market them as input-private unless the exact flow is documented as supported and audit-cleared.

Uses the Fetch API (Node 18+, Bun, Deno, browsers). Ships both ESM (`dist/esm/`) and CJS (`dist/cjs/`) builds since v0.1.1.

## Distribution Links

- [Get a free API key](https://tinyzkp.com/signup?source=npm_tinyzkp&medium=package_registry&platform=npm&intent=api_key)
- [Verify a receipt in the browser](https://tinyzkp.com/verify?source=npm_tinyzkp&medium=package_registry&platform=npm&intent=verify_receipt)
- [Pricing and limits](https://tinyzkp.com/limits?source=npm_tinyzkp&medium=package_registry&platform=npm&intent=limits)
- [Agent-readable offers](https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=npm_tinyzkp&medium=package_registry&platform=npm&intent=agent_offer)

Default receipts are transparent. Do not put secrets, raw customer data, or
credentials into receipt parameters.
