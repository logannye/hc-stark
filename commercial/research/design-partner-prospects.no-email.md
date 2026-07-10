# No-email design-partner prospect research

> Status: `research_only_blocked_until_live_no_email_canary`
>
> Evidence checked: `2026-07-10`

This is organization-level research, not an outreach list or pipeline. No personal names or addresses were collected and no messages were sent. Every route remains blocked until the live no-email canary passes; repository issues must never be used for unsolicited sales.

## Candidates

### 1. [Plonky3 / Polygon Labs](https://github.com/Plonky3/Plonky3)

- Evidence: [Plonky3 README: STARK zkVM toolkit and production virtual-memory tuning](https://github.com/Plonky3/Plonky3/blob/6b6a3b4d40fca2187d368c9dc1fca417c84ae8c3/README.md) — The upstream project says Plonky3 mainly powers STARK-based zkVMs and documents production virtual-memory tradeoffs for repeated proofs.
- Fit hypothesis: Upstream alignment on fallible block-readable matrices and caller-supplied storage could make TinyZKP's bounded backend useful across the Plonky3 ecosystem; this is primarily an integration and standards relationship, not an assumed customer sale.
- Qualification gaps: Whether upstream maintainers want a storage-interface RFC for the pinned compatibility line; Which reference workload and memory ceiling would be considered representative; Whether exact proof-byte equivalence is required by upstream consumers; Whether any organization has budget for sponsored integration or independent reproduction.
- Public route after canary: [GitHub Discussions](https://github.com/Plonky3/Plonky3/discussions). Use only after the live no-email canary for an organization-level technical discussion; no unsolicited sales pitch.

### 2. [SP1 / Succinct](https://github.com/succinctlabs/sp1)

- Evidence: [SP1 README: prover powered by Plonky3](https://github.com/succinctlabs/sp1/blob/46ea61f0a72cde58bc7fb77ff911fb2db5fb5920/README.md#acknowledgements) — The project README states that the SP1 prover is powered by the Plonky3 toolkit.
- Fit hypothesis: A deterministic bounded-RAM CPU path could be evaluated for SP1 workloads that exceed conventional host memory, while preserving the project's existing proof and verifier contracts.
- Qualification gaps: The active Plonky3 fork and dependency versions in the target release; Whether the relevant constraint is CPU RAM, accelerator memory, or distributed capacity; A reproducible non-sensitive workload with current peak RSS or OOM evidence; Whether a bounded CPU backend fits the current prover architecture and commercial roadmap.
- Public route after canary: [GitHub Discussions](https://github.com/succinctlabs/sp1/discussions). Use only after the live no-email canary for an organization-level technical discussion; no unsolicited sales pitch.

### 3. [OpenVM](https://github.com/openvm-org/openvm)

- Evidence: [OpenVM README: STARK backend and circuit interfaces built on Plonky3](https://github.com/openvm-org/openvm/blob/a34a90b54839e247fdf305feec4ec9e78383fb9a/README.md#acknowledgements) — The project README states that its STARK backend and circuit-writing interfaces are built on Plonky3.
- Fit hypothesis: OpenVM's modular STARK backend is a strong technical match for measuring scratch-backed matrices, DFTs, commitments, and recovery against a real customizable zkVM workload.
- Qualification gaps: The exact backend and Plonky3 revisions required for a partner build; Current whole-process RSS and the phase that determines peak memory; A workload that can be shared as a deterministic non-sensitive generator; Whether official verification and proof-byte equality are sufficient acceptance criteria.
- Public route after canary: [GitHub Issues](https://github.com/openvm-org/openvm/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 4. [Valida](https://github.com/valida-xyz/valida)

- Evidence: [Valida README: Plonky3 STARK backend and explicit prover-performance goals](https://github.com/valida-xyz/valida/blob/5058de8573e239eb1985c8ee8a1cf1b0d0f873c2/README.md#backend) — Valida states that it uses Plonky3 for the STARK IOP and cryptographic operations, and that prover performance and reduced trace overhead are design goals.
- Fit hypothesis: Valida's direct Plonky3 backend and explicit trace-efficiency goals make it a plausible reference integration for comparing conventional and bounded-memory proving.
- Qualification gaps: The supported Plonky3 fork and compatibility expectations; Current maximum practical trace size and measured peak RSS; Whether continuations already address the same operational bottleneck; A representative workload, host profile, target RAM ceiling, and purchasing path.
- Public route after canary: [GitHub Discussions](https://github.com/valida-xyz/valida/discussions). Use only after the live no-email canary for an organization-level technical discussion; no unsolicited sales pitch.

### 5. [Powdr](https://github.com/powdr-labs/powdr)

- Evidence: [Official Plonky3 ecosystem list: Powdr supports a Plonky3 proving backend](https://github.com/Plonky3/awesome-plonky3/blob/14303793c7017a9bbcadefbb0706f4fdb5003425/README.md#zkvms) — The Plonky3 organization's ecosystem list identifies Powdr as a zkVM toolkit supporting Plonky3, and the current Powdr tree contains Plonky3 field integration code.
- Fit hypothesis: Powdr's multi-backend architecture could provide a controlled workload for comparing a bounded Plonky3 path against another supported backend without inventing a new proof protocol.
- Qualification gaps: Whether the Plonky3 backend remains active and production-relevant in the current tree; The proving interface where caller-supplied storage could be integrated; Measured memory pressure for a reproducible Powdr workload; Whether backend benchmarking or integration work has an organizational sponsor.
- Public route after canary: [GitHub Issues](https://github.com/powdr-labs/powdr/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 6. [Pico / Brevis](https://github.com/brevis-network/pico)

- Evidence: [Pico README: proving backend based on Plonky3](https://github.com/brevis-network/pico/blob/22b0aae6321c1f63c72aafd0b506b5f45b91ffb1/README.md#acknowledgements) — The project README states that Pico's proving backend is based on Plonky3 and extends its modularity to the zkVM layer.
- Fit hypothesis: Pico's configurable Plonky3-based backend could exercise TinyZKP's resource-policy layer across multiple fields or proving configurations while retaining official verification.
- Qualification gaps: The active Plonky3 dependency and supported proof configurations; Which workloads are constrained by resident memory rather than accelerator capacity; A reproducible generator, conventional baseline, and target storage host; Whether the backend can accept fallible scratch-backed matrix access without protocol changes.
- Public route after canary: [GitHub Issues](https://github.com/brevis-network/pico/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 7. [Ziren / Project ZKM](https://github.com/ProjectZKM/Ziren)

- Evidence: [Ziren README: proving backend based on Plonky3](https://github.com/ProjectZKM/Ziren/blob/88e0521b82d3ed4c28005fbe220066c8ec76b31a/README.md#acknowledgements) — The project README states directly that the Ziren proving backend is based on Plonky3.
- Fit hypothesis: Ziren is a direct Plonky3 zkVM integration where a bounded-memory evaluation could measure whether deterministic SSD scratch expands feasible trace sizes on ordinary CPU hosts.
- Qualification gaps: The current backend version and whether its verifier target is compatible with the frozen profile; Whole-process peak RSS, wall time, and the dominant memory phase; A non-sensitive input generator and required logical row range; Available NVMe capacity and whether CPU ceiling mode is operationally valuable.
- Public route after canary: [GitHub Issues](https://github.com/ProjectZKM/Ziren/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 8. [Scroll zkVM Prover](https://github.com/scroll-tech/zkvm-prover)

- Evidence: [Scroll zkVM Prover README: complete OpenVM-based rollup prover](https://github.com/scroll-tech/zkvm-prover/blob/5de3d673b78880c0c65756845b502b6cadf079a9/README.md#overview) — Scroll documents a complete prover for OpenVM-based rollup circuits; OpenVM documents that its STARK backend and circuit interfaces are built on Plonky3.
- Fit hypothesis: This is a realistic rollup workload for testing whether bounded storage and checkpoint recovery improve deployment capacity without changing OpenVM or Scroll verifier behavior.
- Qualification gaps: The pinned OpenVM and transitive Plonky3 revisions used by the target prover release; Whether peak memory occurs in the Plonky3 STARK layer or surrounding aggregation; A shareable circuit and input generator with a reproducible conventional baseline; Whether private witness handling requires an on-premises evaluation kit.
- Public route after canary: [GitHub Issues](https://github.com/scroll-tech/zkvm-prover/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 9. [Sphinx / Argument Computer](https://github.com/argumentcomputer/sphinx)

- Evidence: [Sphinx README and manifest: Plonky3 powers the STARK system](https://github.com/argumentcomputer/sphinx/blob/8a39b951e3ea520e295b693ad38bff6b43a2630c/README.md#acknowledgements) — The README says Plonky3 powers much of the system, and the pinned workspace manifest directly lists core Plonky3 AIR, DFT, commitment, FRI, matrix, and uni-STARK crates.
- Fit hypothesis: Sphinx's broad direct use of Plonky3 components makes it suitable for identifying the smallest storage abstraction that can support a real zkVM without forking the verifier.
- Qualification gaps: Whether the observed development branch represents an actively supported deployment target; The exact Plonky3 crate revisions and local prover modifications; A reproducible workload showing a memory ceiling or OOM; A technical and budget owner for a bounded-memory evaluation.
- Public route after canary: [GitHub Issues](https://github.com/argumentcomputer/sphinx/issues). Use only after the live no-email canary and only for a repository-relevant technical RFC permitted by project policy; never open an unsolicited sales issue.

### 10. [RISC Zero](https://github.com/risc0/risc0)

- Evidence: [RISC Zero issue 1462: out-of-memory error while proving with CUDA](https://github.com/risc0/risc0/issues/1462) — The active repository has an open public issue reporting an out-of-memory failure during accelerated proving and asking for memory requirements or alternatives.
- Fit hypothesis: The public OOM report validates resource predictability as a zkVM concern, but RISC Zero is a lower-priority fit because TinyZKP's current production target is Plonky3 and the reported failure is accelerator-specific.
- Qualification gaps: Whether the historical OOM remains representative of a current supported release; Whether the bottleneck is accelerator memory, host memory, or a fixed implementation defect; Whether a CPU scratch-backed approach could preserve the official proof and verifier contracts; Whether non-Plonky3 adapter work would be funded and separately scoped.
- Public route after canary: [GitHub Discussions](https://github.com/risc0/risc0/discussions). Use only after the live no-email canary for an organization-level technical discussion; no unsolicited sales pitch.
