## Retired: deploy with Docker Compose (single-host)

This runbook is historical and **must not be executed**.

The stack it starts no longer exists. Repo-root `docker-compose.yml` is now
literally `services: {}` — `docker compose up --build` builds and starts
nothing, and there is no `hc-server`, no Prometheus, and no Grafana to reach at
the ports below. The `HC_SERVER_*` environment contract, the `demo:demo_key`
bearer key, and the `/healthz`, `/readyz`, and `/docs` routes all belonged to
the retired hosted proving API.

The live system is a static Cloudflare Pages site and one Pages worker with no
containers anywhere. See [`production_operations.md`](production_operations.md).

This repo ships a production-shaped stack via `docker-compose.yml`:

- `hc-server` (Proving API + verifier)
- `prometheus` (metrics collection)
- `grafana` (dashboards)

### 1) Start the stack

```bash
docker compose up --build
```

### 2) Verify it’s up

- API health: `GET /healthz`
- API readiness: `GET /readyz`
- Swagger UI: `/docs`
- Prometheus: `localhost:9090`
- Grafana: `localhost:3000` (default `admin` / `admin`)

### 3) Authentication (API keys)

By default the Compose file sets:

- `HC_SERVER_API_KEYS=demo:demo_key`

Clients must send:

```
Authorization: Bearer demo_key
```

### 4) Workload contract (no arbitrary user code)

By default the stack **disables custom programs**:

- `HC_SERVER_ALLOW_CUSTOM_PROGRAMS=false`

Clients must set `workload_id` in `ProveRequest`. Example: `toy_add_1_2`.

### 5) Data persistence

Compose mounts a named volume `hc_data` at `/data` inside `hc-server`.
Local job status artifacts are stored under `/data/jobs/...`. The worker
request/proof handoff streams over stdin/stdout rather than persisted
`request.json` / `proof.json` files.

