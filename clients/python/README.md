# tinyzkp

Python client for the [TinyZKP](https://tinyzkp.com) proving API — generate and verify ZK-STARK proofs.

## Install

```bash
pip install tinyzkp
```

## Quick Start

```python
import asyncio
from tinyzkp import TinyZKP

async def main():
    async with TinyZKP("https://api.tinyzkp.com", api_key="tzk_...") as client:
        # Prove that 1000 + 10 + 20 + 15 = 1045.
        job_id = await client.prove_template("accumulator_step", params={
            "initial": 1000, "final": 1045, "deltas": [10, 20, 15],
        })

        # Wait for the proof (polls automatically, typically 1-5 seconds)
        proof = await client.wait_for_proof(job_id)

        # Verify it (always free)
        result = await client.verify(proof)
        assert result.ok  # True

asyncio.run(main())
```

## What does the live template prove?

The live self-serve template is `accumulator_step`. It proves a transparent state transition: starting from `initial`, applying each value in `deltas` reaches `final`. Use it for balance updates, ledger reconciliation, audit-log checkpoints, and agent state receipts where the verifier needs a compact receipt.

## API

- `TinyZKP(base_url, *, api_key=None, timeout=30.0)` — Create a client
- `prove_template(template_id, params={...})` — Submit a proof via template (recommended)
- `prove(program=..., initial_acc=0, final_acc=0, **params)` — Submit via raw program
- `prove_status(job_id)` — Check job status
- `wait_for_proof(job_id, poll_interval=1.0, timeout=300.0)` — Poll until proof is ready
- `verify(proof)` — Verify a proof (free)
- `healthz()` — Check server health

## Templates

Production template discovery includes a `lifecycle` field. Public production listings expose live templates by default; audit-gated and preview templates are not part of the self-serve catalog unless a deployment explicitly enables them.

| Template | Lifecycle | Proves | Example |
|----------|-----------|--------|---------|
| `accumulator_step` | `live` | Additive chain is correct | Balance updates, state receipts |

Use [tinyzkp.com/docs](https://tinyzkp.com/docs) for the current template catalog, fit guidance, and security notes. Default receipts are transparent; do not market them as input-private unless the exact flow is documented as supported and audit-cleared.
