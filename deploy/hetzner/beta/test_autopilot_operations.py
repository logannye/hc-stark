from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BETA = ROOT / "deploy" / "hetzner" / "beta"


def test_metrics_are_private_and_legacy_beta_alerts_are_retired():
    compose = (BETA / "docker-compose.api.yml").read_text(encoding="utf-8")
    assert "TINYZKP_BETA_METRICS_BIND: 172.31.77.10:9091" in compose
    assert "9091:9091" not in compose
    assert "tinyzkp-observability" in compose
    prometheus = (ROOT / "deploy/prometheus/prometheus.yml").read_text(encoding="utf-8")
    assert 'job_name: "hc-beta-api"' in prometheus
    assert "beta_metrics_token" in prometheus
    assert 'targets: ["beta-api:9091"]' in prometheus
    alerts = (ROOT / "deploy/prometheus/alerts.yml").read_text(encoding="utf-8")
    assert "tinyzkp_beta_ledger_difference_accounts" in alerts
    assert "hc_prove_failed_total" not in alerts


def test_low_touch_timers_and_binaries_are_installed():
    dockerfile = (BETA / "Dockerfile.api").read_text(encoding="utf-8")
    for binary in (
        "hc-beta-watchdog", "hc-beta-health-report", "hc-beta-owner-digest",
        "hc-beta-support-log", "hc-beta-viability",
    ):
        assert f"/usr/local/bin/{binary}" in dockerfile
    digest_timer = (BETA / "systemd/tinyzkp-owner-digest.timer").read_text()
    assert "Mon *-*-* 16:00:00 UTC" in digest_timer
    storage_timer = (BETA / "systemd/tinyzkp-api-storage-health.timer").read_text()
    assert "OnUnitActiveSec=5min" in storage_timer
    viability = (BETA / "systemd/tinyzkp-viability.timer").read_text()
    assert "OnCalendar=*-*-* 16:30:00 UTC" in viability


def test_activation_records_viability_window_only_after_public_smoke_and_probe():
    source = (ROOT / "scripts/release/activate_public_beta.py").read_text(encoding="utf-8")
    smoke = source.index("run([str(smoke)]")
    probe = source.index("AUDIT_MODE:public_beta")
    activation = source.index("record-beta-activation.sh")
    assert smoke < probe < activation


def test_viability_timer_starts_only_after_public_activation_is_recorded():
    installer = (BETA / "install-beta-host.sh").read_text(encoding="utf-8")
    activation = (BETA / "record-beta-activation.sh").read_text(encoding="utf-8")
    assert "tinyzkp-owner-digest.timer tinyzkp-viability.timer" not in installer
    assert "hc-beta-viability beta-ops activate" in activation
    assert "systemctl enable --now tinyzkp-viability.timer" in activation
    assert activation.index("hc-beta-viability beta-ops activate") < activation.index(
        "systemctl enable --now tinyzkp-viability.timer"
    )


def test_day_90_failure_does_not_disable_existing_jobs():
    source = (
        ROOT / "crates/hc-beta-api/src/bin/hc-beta-viability.rs"
    ).read_text(encoding="utf-8")
    update = source[source.index("day_90_viability_failed") - 250 : source.index("day_90_viability_failed") + 200]
    assert "signup_enabled=false" in update
    assert "checkout_enabled=false" in update
    assert "job_submission_enabled=false" not in update
    assert "DELETE" not in update
