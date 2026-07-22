# Scoped engine resource qualification

The production resource matrix is a single resumable controller run on one
ephemeral public-repository GitHub-hosted runner:

```bash
python3 scripts/benchmark/run_fixed_host_release_matrix.py --help
```

It runs exactly these three entries, in order, for one source and CLI identity:

| Entry | Rows | Mode | Required result |
| --- | ---: | --- | --- |
| Fibonacci | 1,048,576 | Throughput | Baseline and bounded candidate; at least 4× lower RSS and at most 3× wall time |
| Poseidon2 | 1,048,576 | Throughput | Baseline and bounded candidate; at least 4× lower RSS and at most 3× wall time |
| Fibonacci | 16,777,216 | Ceiling | Bounded candidate; no more than 2 GiB RSS and scratch within 10% of the exact estimator |

Poseidon2 at 16,777,216 rows has a bounded scratch estimate of
169,114,584,484 bytes (187,905,093,872 bytes with the required headroom). It is
a post-GA capacity expansion, not a supported production workload, and it is
not part of this matrix.

The controller does not provision persistent infrastructure, approve a
release, or sign artifacts. Before proving it requires Linux cgroup v2 with
delegated `cpu`, `io`, `memory`, and `pids` controllers, four effective CPUs,
15--17 GiB effective memory, non-rotational storage, at least 12,000,000,000
scratch bytes available, and runner-owned mode-0700 scratch roots. It also
requires a clean checkout at the exact release commit and a CLI with that
embedded release identity. Every report records the same host facts and the
exact built-in estimator output.

## Owner execution

The normal path is the `Owner engine resource qualification` workflow in
`.github/workflows/benches.yml`. The repository owner dispatches it from
`main` with `expected_main_sha` set to the full lowercase SHA currently at
`origin/main`. The workflow rejects any other actor, triggering actor, ref, or
commit. It uses `ubuntu-24.04`, builds one release-identity-bound CLI, reclaims
the Cargo target storage, creates only the three scratch roots, runs the full
matrix, and uploads the owner-only result as:

```text
plonky3-backend-release-matrix-<expected_main_sha>
```

For local diagnosis on a runner with the same profile, the equivalent command
sequence is:

```bash
export HC_RELEASE_SHA="$(git rev-parse HEAD)"
export HC_RELEASE_REF=main

for workload in fibonacci-1m poseidon2-1m fibonacci-16m; do
  sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" \
    "/var/lib/tinyzkp-bench/scratch/$workload"
done
sudo install -d -m 0755 /sys/fs/cgroup/tinyzkp-bench
install -d -m 0700 raw-reports/fixed-host-release-matrix

python3 -m venv .benchmark-venv
.benchmark-venv/bin/python -m pip install \
  -r scripts/benchmark/requirements.txt
HC_RELEASE_SHA="$HC_RELEASE_SHA" HC_RELEASE_REF="$HC_RELEASE_REF" \
  cargo build --release -p hc-cli --bin hc-cli --locked

sudo --preserve-env=HC_RELEASE_SHA,HC_RELEASE_REF \
  .benchmark-venv/bin/python \
    scripts/benchmark/run_fixed_host_release_matrix.py \
      --release-sha "$HC_RELEASE_SHA" \
      --hc-cli target/release/hc-cli \
      --output-dir raw-reports/fixed-host-release-matrix
```

The controller removes runtime release-environment overrides when it inspects
`hc-cli release`, so a development binary cannot impersonate an embedded
release identity.

## Evidence and resumption

Running the same command again resumes at workload boundaries. A completed
entry is skipped only after its owner, mode, size, SHA-256, normalized manifest,
host identity, estimator values, and resource-gate semantics revalidate. An
interrupted entry reruns from input generation. Resumption on another host, a
changed binary or manifest, a different commit, or a dirty tracked tree fails
closed.

The durable authority-limiting inventory is:

```text
raw-reports/fixed-host-release-matrix/fixed-host-release-matrix-v1.json
```

Candidate report names are `fibonacci-1m.json`, `poseidon2-1m.json`, and
`fibonacci-16m.json`; the two 1M baselines use the `.baseline.json` suffix.
Preflight reports, normalized manifests, and command logs are recorded beside
them. Every inventoried file has mode `0600`, and every path and digest is read
through a held `O_NOFOLLOW` descriptor with before/after identity checks.

After all three entries pass, the inventory deliberately records:

```json
{
  "status": "local_matrix_complete_release_assembly_pending",
  "local_matrix_gates_passed": true,
  "release_eligible": false
}
```

Signed release assembly remains a separate post-build gate. The candidate
evidence builder consumes this same matrix under `matrix_manifest` for both the
one-million gate and the Fibonacci-only 16,777,216-row gate. The backend gate
rehashes the matrix and rejects any report or normalized manifest not bound by
its exact entry inventory. A standalone report set is not admissible evidence.

Optional independent reproduction and review records remain advisory. They do
not need to exist for publication and cannot enlarge the scoped production
workloads recorded in `release/plonky3-compatibility-v1.json`.
