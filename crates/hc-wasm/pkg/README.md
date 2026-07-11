# @tinyzkp/verify

Local WebAssembly verification for official Plonky3 `ProofBundleV1` artifacts.
The package verifies in the caller's browser and does not call a TinyZKP API.
It contains no proving, receipt, account, billing, or hosted-verification API.

Backend v1 proves transparent verifiable computation. It does not claim
zero-knowledge or witness privacy.

## Install

```bash
npm install @tinyzkp/verify
```

## Verify a bundle

```javascript
import init, { verify_bundle, version } from "@tinyzkp/verify";

await init();
const bundleJson = await fetch("/proof-bundle.json").then((response) => response.text());
const result = verify_bundle(bundleJson);

if (!result.ok) throw new Error(result.error);
console.log(version());
```

The verifier rejects unknown schema versions, malformed or oversized proof
encoding, manifest/proof digest mismatches, dependency-profile skew, mutated
public values, and proofs rejected by the unmodified Plonky3 0.6.1 verifier.

See [documentation](https://tinyzkp.com/docs),
[security status](https://tinyzkp.com/security), and
[backend status](https://tinyzkp.com/status). Package publication remains
blocked until the backend release gate passes.
