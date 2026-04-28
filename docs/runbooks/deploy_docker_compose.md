## Deploy with Docker Compose (single-host)

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
Job requests/status artifacts are stored under `/data/jobs/...`.


