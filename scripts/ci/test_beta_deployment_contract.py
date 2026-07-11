import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BETA = ROOT / "deploy" / "hetzner" / "beta"


def text(name):
    return (BETA / name).read_text(encoding="utf-8")


def test_api_database_and_object_storage_are_fail_closed():
    compose = text("docker-compose.api.yml")
    assert "127.0.0.1:8090:8090" in compose
    assert "10.77.0.1:8091:8091" in compose
    assert "internal: true" in compose
    assert "networks: [database, egress]" in compose
    # The API needs GitHub/Stripe/R2 and PostgreSQL needs R2 for WAL archiving;
    # PgBouncer remains database-only and no database port is published.
    assert compose.count("networks: [database, egress]") == 2
    assert "TINYZKP_BETA_SECRET_DIR" in compose
    assert "@sha256:53d98b3174b0842c475b9842fb0a733b2d9f7ec9da834ec42252aa553f48c628" in compose
    assert "ports:" not in compose.split("postgres:", 1)[1].split("pgbouncer:", 1)[0]


def test_worker_has_exact_release_resource_envelope_and_no_database_secret():
    compose = text("docker-compose.worker.yml")
    service = text("systemd/tinyzkp-beta-worker.service")
    assert 'cpuset: "0-7"' in compose
    assert "mem_limit: 16g" in compose
    assert 'restart: "no"' in compose
    assert "network_mode: host" in compose
    assert "no-new-privileges:true" in compose
    assert "DATABASE" not in compose and "STRIPE" not in compose and "AWS_" not in compose
    assert "StartLimitBurst=5" in service
    assert "Restart=on-failure" in service
    assert "--abort-on-container-exit --exit-code-from worker" in service


def test_backup_and_rollback_contracts_are_tracked():
    postgres = text("postgresql.conf")
    backup = text("pgbackrest.conf.example")
    rollback = text("caddy-route.rollback.caddy")
    assert "archive_mode = on" in postgres and "archive-push" in postgres
    assert "repo1-cipher-type=aes-256-cbc" in backup
    assert "repo1-retention-full=4" in backup and "repo1-retention-diff=30" in backup
    assert "beta_writes_disabled" in rollback
    assert "reverse_proxy 127.0.0.1:8090" in rollback


def test_beta_routing_cannot_break_ordinary_containment_deploys():
    containment = (ROOT / "deploy" / "hetzner" / "Caddyfile").read_text(encoding="utf-8")
    beta = text("Caddyfile.beta")
    switch = text("switch-beta-route.sh")
    assert "tinyzkp-beta-route.caddy" not in containment
    assert "tinyzkp-beta-route.caddy" in beta
    assert "Caddyfile.tinyzkp-containment" in switch


def test_operator_environment_templates_cover_both_hosts_and_oauth_hostname():
    api = text("compose.api.env.example")
    worker = text("compose.worker.env.example")
    api_runtime = text("beta-api.env.example")
    assert "TINYZKP_BETA_API_IMAGE=" in api and "@sha256:" in api
    assert "TINYZKP_POSTGRES_IMAGE=" in api and "@sha256:" in api
    assert "TINYZKP_BETA_WORKER_IMAGE=" in worker and "@sha256:" in worker
    assert "https://api.tinyzkp.com/v1/auth/github/callback" in api_runtime
    assert "https://tinyzkp.com/v1/auth/github/callback" not in api_runtime


def test_release_authorization_is_two_phase_and_never_rebuilds_candidate():
    candidate = (ROOT / ".github/workflows/public-beta-candidate.yml").read_text()
    authorization = (ROOT / ".github/workflows/public-beta-release.yml").read_text()
    assert "docker buildx build --push" in candidate
    assert "build_dark_canary_authorization.py" in candidate
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in candidate
    assert "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c" in candidate
    assert "pip install pytest -r billing/requirements.txt" in candidate
    assert "components: rustfmt, clippy" in candidate
    assert "extract_public_beta_evidence.py" in authorization
    assert "build_public_beta_authorization.py" in authorization
    assert "docker build" not in authorization
    assert "workflow_dispatch" in candidate and "workflow_dispatch" in authorization


def test_container_context_includes_every_cargo_workspace_member():
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "!crates/**" in dockerignore
    assert "!examples/partner-adapter/**" in dockerignore


def test_r2_lifecycle_prefixes_separate_inputs_bundles_and_backups():
    artifacts = json.loads(text("r2-artifacts-lifecycle.json"))
    by_id = {rule["id"]: rule for rule in artifacts["rules"]}
    uploads = by_id["tinyzkp-beta-uploads-24h"]
    assert uploads["conditions"]["prefix"] == "uploads/"
    assert uploads["deleteObjectsTransition"]["condition"] == {
        "type": "Age",
        "maxAge": 86400,
    }
    assert uploads["abortMultipartUploadsTransition"]["condition"] == {
        "type": "Age",
        "maxAge": 86400,
    }
    bundles = by_id["tinyzkp-beta-bundles-90d-maximum"]
    assert bundles["conditions"]["prefix"] == "bundles/"
    assert bundles["deleteObjectsTransition"]["condition"] == {
        "type": "Age",
        "maxAge": 7776000,
    }
    backups = json.loads(text("r2-backups-lifecycle.json"))
    assert all("deleteObjectsTransition" not in rule for rule in backups["rules"])
