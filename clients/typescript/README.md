# tinyzkp

TypeScript client for the [TinyZKP](https://tinyzkp.com) proving API — generate and verify ZK-STARK proofs.

## Install

```bash
npm install tinyzkp
```

## Quick Start

```typescript
import { HcClient } from "tinyzkp";

const client = new HcClient("https://api.tinyzkp.com", {
  apiKey: "tzk_...",
});

// Prove a secret is in range [0, 100] — without revealing it
const jobId = await client.proveTemplate("range_proof", {
  min: 0, max: 100, witness_steps: [42, 44],
});

// Wait for the proof (polls automatically, typically 1-5 seconds)
const proof = await client.waitForProof(jobId);

// Verify it (always free)
const result = await client.verify(proof);
console.log(result.ok); // true — verified without learning the secret
```

## What are `witness_steps`?

The `witness_steps` encode your secret value as internal computation steps. They are **never revealed** to the verifier — only the proof (which vouches for them) is shared.

## API

- `new HcClient(baseUrl, options?)` — Create a client
- `proveTemplate(templateId, params)` — Submit a proof via template (recommended)
- `prove(request)` — Submit via raw program
- `proveStatus(jobId)` — Check job status
- `waitForProof(jobId, options?)` — Poll until proof is ready
- `verify(proof)` — Verify a proof (free)
- `healthz()` — Check server health

## Templates

Six built-in templates — no cryptography knowledge needed:

| Template | Proves | Example |
|----------|--------|---------|
| `range_proof` | A secret is in [min, max] | Age verification, credit scores |
| `hash_preimage` | You know a secret matching a hash | Password proofs |
| `computation_attestation` | f(secret) = public output | ML inference proofs |
| `accumulator_step` | Additive chain is correct | Balance updates |
| `policy_compliance` | Actions within a limit | Budget enforcement |
| `data_integrity` | Data sums to checksum | Audit trails |

Uses the Fetch API (Node 18+, Bun, Deno, browsers).
