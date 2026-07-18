# Security policy

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/logannye/hc-stark/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Never send or attach:

- witness or trace data;
- customer proofs containing confidential public inputs;
- license keys or entitlement files;
- credentials, private keys, tokens, or environment files;
- proprietary AIR source.

Use a synthetic or public reproduction and include the exact release identity,
compatibility profile, and official verifier outcome.

## Supported surface

Only the exact profile and platform in the current signed compatibility
manifest are supported. Historical hosted APIs, MCP services, SDKs, beta
workers, billing services, and research protocols are outside the production
security boundary.

TinyZKP does not make a zero-knowledge privacy claim for the current product.
Scratch storage may contain sensitive witness-derived material; customers are
responsible for encrypted storage, access control, retention, and media
sanitization on their infrastructure.

## Release integrity

Production artifacts must have:

- immutable versioned filenames or OCI digests;
- SHA-256 checksums;
- a Sigstore bundle;
- GitHub artifact attestations;
- an SPDX SBOM;
- an exact engine SHA and compatibility profile.

Do not use an artifact whose release identity or signatures cannot be verified.
