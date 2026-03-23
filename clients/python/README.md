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
        # Prove a secret is in range [0, 100] — without revealing it
        job_id = await client.prove_template("range_proof", params={
            "min": 0, "max": 100, "witness_steps": [42, 44],
        })

        # Wait for the proof (polls automatically, typically 1-5 seconds)
        proof = await client.wait_for_proof(job_id)

        # Verify it (always free)
        result = await client.verify(proof)
        assert result.ok  # True — verified without learning the secret

asyncio.run(main())
```

## What are `witness_steps`?

The `witness_steps` encode your secret value as internal computation steps. They are **never revealed** to the verifier — only the proof (which vouches for them) is shared.

## API

- `TinyZKP(base_url, *, api_key=None, timeout=30.0)` — Create a client
- `prove_template(template_id, params={...})` — Submit a proof via template (recommended)
- `prove(program=..., initial_acc=0, final_acc=0, **params)` — Submit via raw program
- `prove_status(job_id)` — Check job status
- `wait_for_proof(job_id, poll_interval=1.0, timeout=300.0)` — Poll until proof is ready
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

Supports both `aiohttp` (default) and `httpx` backends.
