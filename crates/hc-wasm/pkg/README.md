# @tinyzkp/verify

Client-side WASM verifier for TinyZKP STARK receipts. Use it when a browser,
wallet, dashboard, or agent UI needs local verification without calling the
TinyZKP API.

## Install

```bash
npm install @tinyzkp/verify
```

## Quick Start

```javascript
import init, { verify_json } from "@tinyzkp/verify";

await init();

const proofJson = await fetch("/proof.json").then((res) => res.text());
const result = verify_json(proofJson);
console.log(result.ok);
```

## When to use it

Use this package for free local verification. To generate new receipts, get a
free API key at
[tinyzkp.com/signup](https://tinyzkp.com/signup?source=npm_wasm_verifier&medium=package_registry&platform=npm&intent=api_key).

Default receipts are transparent. Do not put secrets, raw customer data, or
credentials into receipt parameters.

## Distribution Links

- [Generate receipts with an API key](https://tinyzkp.com/signup?source=npm_wasm_verifier&medium=package_registry&platform=npm&intent=api_key)
- [Verify a receipt in the browser](https://tinyzkp.com/verify?source=npm_wasm_verifier&medium=package_registry&platform=npm&intent=verify_receipt)
- [Pricing and limits](https://tinyzkp.com/limits?source=npm_wasm_verifier&medium=package_registry&platform=npm&intent=limits)
- [Agent-readable offers](https://tinyzkp.com/.well-known/tinyzkp-offers.json?source=npm_wasm_verifier&medium=package_registry&platform=npm&intent=agent_offer)
