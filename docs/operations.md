# Operations Guide

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_SERVER_LISTEN` | `0.0.0.0:8080` | Listen address |
| `HC_SERVER_DATA_DIR` | `.hc-server` | Data directory for job artifacts |
| `HC_SERVER_MAX_INFLIGHT` | `4` | Max concurrent prove jobs per tenant |
| `HC_SERVER_MAX_PROVE_SECS` | `300` | Prove job timeout (seconds) |
| `HC_SERVER_ALLOW_CUSTOM_PROGRAMS` | `false` | Allow arbitrary VM programs |
| `HC_SERVER_MAX_BODY_BYTES` | `25MB` | Max request body size |
| `HC_SERVER_MAX_VERIFY_INFLIGHT` | `8` | Max concurrent verify requests |
| `HC_SERVER_VERIFY_TIMEOUT_MS` | `30000` | Verify request timeout |
| `HC_SERVER_RETENTION_SECS` | `86400` | Job artifact retention (24h) |
| `HC_SERVER_JOB_INDEX_SQLITE` | `true` | Enable SQLite job index |
| `HC_SERVER_JOB_INDEX_DISABLED` | `false` | Force-disable job index |
| `HC_SERVER_MAX_PROVE_RPM` | `100` | Prove rate limit (requests/minute, 0=unlimited) |
| `HC_SERVER_MAX_VERIFY_RPM` | `300` | Verify rate limit (requests/minute, 0=unlimited) |
| `HC_SERVER_RATE_LIMIT_DISABLED` | `false` | Disable all rate limits |
| `HC_SERVER_MAX_BLOCK_SIZE` | `1048576` | Max allowed block_size (2^20) |
| `HC_SERVER_MIN_QUERY_COUNT` | `80` | Min allowed query_count for security |
| `HC_SERVER_GC_INTERVAL_SECS` | `300` | Background GC interval |
| `HC_SERVER_API_KEYS` | (none) | Comma-separated `tenant:key` pairs |
| `HC_SERVER_API_KEYS_FILE` | (none) | Path to API keys file |
| `HC_SERVER_AUTH_GRACE_MS` | `300000` | Rotation grace window: rotated-out keys still authenticate for this long after a hot-reload swap (5min default) |
| `HC_SERVER_WORKER_PATH` | (auto-detect) | Path to hc-worker binary; **validated at boot** — refusal to start if missing or non-executable |
| `HC_SERVER_MAX_WORKER_SPAWN` | `32` | Global cap on concurrent worker subprocess spawns (EMFILE / process-table-exhaustion guard); 0 disables |
| `HC_SERVER_PG_URL` | (none) | Postgres connection string for usage_log dual-write (Phase 1 of [migration plan](postgres_migration.md)). When unset, SQLite-only |
| `RUST_LOG` | (none) | Logging level (e.g., `info`, `debug`) |

### MCP server (hc-mcp-http)

| Variable | Default | Description |
|----------|---------|-------------|
| `HC_MCP_HTTP_HOST` | `0.0.0.0` | Bind host |
| `HC_MCP_HTTP_PORT` | `3001` | Bind port |
| `HC_MCP_REQUIRE_AUTH` | `false` | If true, every MCP request must carry `Authorization: Bearer ...`; missing header → 401 |
| `HC_MCP_TENANT_RPM` | `0` | Optional global RPM override for authenticated tenants. 0 (default) = use per-plan ladder (Free 10, Dev 100, Team 300, Scale 500) — same values as hc-server's `prove_rpm` |
| `HC_MCP_MAX_INFLIGHT` | `2` | Concurrency cap on the anonymous (no-Bearer) lane |
| `HC_MCP_ALLOWED_ORIGINS` | (none) | Comma-separated extra CORS origins on top of the default allowlist (`*.claude.ai`, `*.anthropic.com`, `tinyzkp.com`) |

### Billing cron (sync_usage.py)

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIPE_SECRET_KEY` | required | Stripe API key |
| `HC_USAGE_DB_PATH` | `/opt/hc-stark/data/usage.sqlite` | SQLite usage log path |
| `STRIPE_METER_EVENT_NAME` | `proof_usage` | Stripe Meter event name |
| `HC_UNBILLED_ALERT_HOURS` | `12` | Alert if unbilled rows are older than this — must stay below Stripe's ~24h Meter-event dedup window |
| `ALERT_WEBHOOK_URL` | (none) | Slack/Discord webhook for billing alerts |

## Deployment

### Docker Compose (Development)

```bash
GRAFANA_ADMIN_PASSWORD=changeme docker compose up
```

### Docker Compose (Production / Hetzner)

```bash
export HC_SERVER_API_KEYS="tenant1:key1,tenant2:key2"
export GRAFANA_ADMIN_PASSWORD="<strong-password>"
docker compose -f docker-compose.yml -f deploy/hetzner/docker-compose.prod.yml up -d
```

### Bare Metal

```bash
cargo build -p hc-server --release --bins
HC_SERVER_API_KEYS="demo:demo_key" ./target/release/hc-server
```

## Monitoring

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `hc_prove_submitted_total` | Counter | Total prove submissions |
| `hc_verify_requests_total` | Counter | Total verify requests |
| `hc_prove_completed_total` | CounterVec | Completed proofs (by tenant) |
| `hc_prove_failed_total` | CounterVec | Failed proofs (by tenant) |
| `hc_prove_duration_seconds` | Histogram | Prove job duration |
| `hc_jobs_inflight` | Gauge | Currently in-flight jobs |
| `hc_gc_runs_total` | Counter | Background GC cycles |
| `hc_gc_removed_total` | Counter | Jobs removed by GC |
| `hc_rate_limit_rejections_total` | CounterVec | Rate limit rejections (by endpoint) |

### Alerting Rules

Defined in `deploy/prometheus/alerts.yml`:

- **HcHighFailureRate**: >10% failure rate over 5 minutes
- **HcSlowProves**: P99 prove duration >5 minutes over 10 minutes
- **HcNoCompletions**: No completions despite submissions for 30 minutes

### Grafana

Dashboard provisioned at `deploy/grafana/dashboards/`. Credentials configured via `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` environment variables.

## Troubleshooting

### Stale jobs after crash

On startup, the server reconciles any `Pending` or `Running` jobs to `Failed` with error "server restarted — job was in progress". Check logs for `reconciled stale jobs` message.

### Rate limit errors (429)

- Check `hc_rate_limit_rejections_total` metric
- Override with `HC_SERVER_RATE_LIMIT_DISABLED=1` in emergencies
- Adjust `HC_SERVER_MAX_PROVE_RPM` / `HC_SERVER_MAX_VERIFY_RPM`

### Job index disabled (501 on GET /prove)

- Set `HC_SERVER_JOB_INDEX_SQLITE=true` or remove `HC_SERVER_JOB_INDEX_DISABLED`

## Capacity Planning

- **Memory per job**: ~100MB per block_size=2^16, scales linearly
- **CPU per job**: Single-threaded prover, one worker process per job
- **Disk**: Proof artifacts ~50-500KB each, cleaned by GC after retention period
- **Max concurrent**: Controlled by `HC_SERVER_MAX_INFLIGHT` (default: 4)
