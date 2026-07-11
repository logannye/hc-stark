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
    assert "TINYZKP_BETA_SECRET_DIR" in compose
    assert "@sha256:53d98b3174b0842c475b9842fb0a733b2d9f7ec9da834ec42252aa553f48c628" in compose
    assert "ports:" not in compose.split("postgres:", 1)[1].split("pgbouncer:", 1)[0]


def test_worker_has_exact_release_resource_envelope_and_no_database_secret():
    compose = text("docker-compose.worker.yml")
    assert 'cpuset: "0-7"' in compose
    assert "mem_limit: 16g" in compose
    assert "network_mode: host" in compose
    assert "no-new-privileges:true" in compose
    assert "DATABASE" not in compose and "STRIPE" not in compose and "AWS_" not in compose


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
