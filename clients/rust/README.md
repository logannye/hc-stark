# tinyzkp

Rust client for the [TinyZKP](https://tinyzkp.com) proving API. Generate and
verify STARK state-transition receipts from async Rust services, jobs, and
agent backends.

Get a free API key at
[tinyzkp.com/signup](https://tinyzkp.com/signup?source=crates_tinyzkp&medium=package_registry&platform=crates_io&intent=api_key)
with 100 proofs/month and no credit card.

## Install

```bash
cargo add tinyzkp
```

## Quick Start

```rust
use serde_json::json;
use tinyzkp::{TinyZKP, TemplateProveOptions};

#[tokio::main]
async fn main() -> Result<(), tinyzkp::Error> {
    let client = TinyZKP::new("https://api.tinyzkp.com").with_api_key("tzk_...");

    let job_id = client
        .prove_template(
            "accumulator_step",
            json!({ "initial": 1000, "final": 1045, "deltas": [10, 20, 15] }),
            TemplateProveOptions::default(),
        )
        .await?;

    let proof = client.wait_for_proof(&job_id, None).await?;
    let result = client.verify(&proof, true).await?;
    assert!(result.ok);
    Ok(())
}
```

## What does the live template prove?

The live self-serve template is `accumulator_step`. It proves a transparent
state transition: starting from `initial`, applying each value in `deltas`
reaches `final`. Use it for balance updates, ledger reconciliation, audit-log
checkpoints, and agent state receipts where the verifier needs a compact
receipt.

## Distribution Links

- [Get a free API key](https://tinyzkp.com/signup?source=crates_tinyzkp&medium=package_registry&platform=crates_io&intent=api_key)
- [Verify a receipt in the browser](https://tinyzkp.com/verify?source=crates_tinyzkp&medium=package_registry&platform=crates_io&intent=verify_receipt)
- [Pricing and limits](https://tinyzkp.com/limits?source=crates_tinyzkp&medium=package_registry&platform=crates_io&intent=limits)
- [Agent-readable offers](https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=crates_tinyzkp&medium=package_registry&platform=crates_io&intent=agent_offer)

Default receipts are transparent. Do not put secrets, raw customer data, or
credentials into receipt parameters.
