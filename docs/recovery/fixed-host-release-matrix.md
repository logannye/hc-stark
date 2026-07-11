# Fixed-host backend release matrix

The backend release resource evidence is captured by one local, resumable
controller:

```bash
python3 scripts/benchmark/run_fixed_host_release_matrix.py --help
```

It runs exactly these workloads, in order, on one stable host and source
identity:

| Entry | Rows | Mode | Required result |
| --- | ---: | --- | --- |
| Fibonacci | 1,048,576 | Throughput | Baseline and bounded candidate; at least 4× lower RSS and at most 3× wall time |
| Poseidon2 | 1,048,576 | Throughput | Baseline and bounded candidate; at least 4× lower RSS and at most 3× wall time |
| Fibonacci | 16,777,216 | Ceiling | Bounded candidate; no more than 2 GiB RSS and scratch within 10% of preflight |
| Poseidon2 | 16,777,216 | Ceiling | Bounded candidate; no more than 2 GiB RSS and scratch within 10% of preflight |

The controller does **not** provision a host, change remote infrastructure,
upload evidence, sign a release, or satisfy independent reproduction. It exits
before proving unless the local machine is Linux with delegated cgroup v2,
exactly eight logical CPUs, 15–17 GiB physical RAM, and at least 500 GB free on
non-rotational NVMe scratch. The four pinned manifests, the clean Git commit,
and the release identity embedded in `hc-cli` must all agree.

## Operator execution

Provision the reviewed fixed host separately. On that host, check out the exact
40-character commit and prepare the local scratch and cgroup parent. The four
scratch leaves must be owned by the invoking operator and have mode `0700`:

```bash
export HC_RELEASE_SHA="$(git rev-parse HEAD)"

for workload in fibonacci-1m poseidon2-1m fibonacci-16m poseidon2-16m; do
  sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" \
    "/var/lib/tinyzkp-bench/scratch/$workload"
done
sudo install -d -m 0755 /sys/fs/cgroup/tinyzkp-bench
install -d -m 0700 raw-reports/fixed-host-release-matrix

python3 -m venv .benchmark-venv
.benchmark-venv/bin/python -m pip install -r scripts/benchmark/requirements.txt
HC_RELEASE_SHA="$HC_RELEASE_SHA" cargo build --release -p hc-cli --locked

sudo --preserve-env=HC_RELEASE_SHA \
  .benchmark-venv/bin/python scripts/benchmark/run_fixed_host_release_matrix.py \
    --release-sha "$HC_RELEASE_SHA" \
    --hc-cli target/release/hc-cli \
    --output-dir raw-reports/fixed-host-release-matrix
```

The build environment is deliberate: the controller removes runtime release
environment variables when it inspects `hc-cli release`, so a development
binary cannot impersonate an embedded release identity.

Running the same command again resumes the matrix. A completed workload is
skipped only after all of its owner-only files, sizes, SHA-256 digests,
normalized manifests, and resource-gate semantics revalidate. A workload that
was interrupted is rerun from input generation because release measurements
must cover the complete pipeline. Resumption on another host, a changed binary,
a changed source manifest, or a changed commit fails closed.

The durable inventory is:

```text
raw-reports/fixed-host-release-matrix/fixed-host-release-matrix-v1.json
```

Canonical candidate report names are `fibonacci-1m.json`,
`poseidon2-1m.json`, `fibonacci-16m.json`, and `poseidon2-16m.json`; 1M
baseline files use the `.baseline.json` suffix. Preflight reports, normalized
manifests, and command logs are recorded beside them. Every inventoried file
has mode `0600`, and every path and digest is checked through a held
`O_NOFOLLOW` descriptor with before/after identity verification.

Even after all four local gates pass, the inventory deliberately records:

```json
{
  "local_matrix_gates_passed": true,
  "release_eligible": false
}
```

Independent reproduction, both independent reviews, design-partner acceptance,
and signed release assembly remain external gates. This first-party run must
never be relabeled as independent evidence.

The candidate-evidence builder requires the same matrix file under the
`matrix_manifest` role in both the 1M and 16M first-party resource gates. The
backend gate hashes it again and rejects the candidate unless it binds the
exact source manifests, reports, and normalized manifests supplied by those
gates. It also derives the stable-host identity from every report and compares
it with the single identity in the matrix. The review bundle carries the same
bytes under `raw-reports/fixed_host_matrix_manifest`; a standalone report set
without this authority-limiting manifest is not admissible release evidence.

## GitHub Actions

The `Fixed-host Plonky3 reports` workflow exposes a manual `release_matrix`
input. Selecting it runs the single controller job and suppresses the older
fragmented jobs. Scheduled 1M jobs remain useful telemetry, but their separate
artifacts are not the stable-host-bound backend release matrix. The controller
artifact is still first-party evidence; a different authorized reproducer must
run and sign the independent record.
