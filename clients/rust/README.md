# TinyZKP Rust artifact SDK

Local contracts and helpers for TinyZKP’s resource-bounded Plonky3 0.6.1
backend. This recovery package contains no hosted proving, polling, template,
legacy receipt, or remote-verification client.

It provides:

- typed `WorkloadManifestV1`, `ProofBundleV1`, and `BenchmarkReportV1`;
- canonical manifest hashing and local official verification;
- Fibonacci/Poseidon2 manifest builders;
- the public `ResourceBoundedWorkload` integration API; and
- safe `hc-cli` prove/resume/verify subprocess helpers.

Package publication remains blocked by `backend_release_ready.py` until fixed-
host reports, independent reviews, signed artifacts, identity parity, and a
real design-partner acceptance record pass.
