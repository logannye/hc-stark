use crate::AppState;
use serde::Serialize;
use serde_json::json;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct InvariantReport {
    pub release_sha: String,
    pub status: &'static str,
    pub violations: Vec<&'static str>,
}

pub async fn evaluate(state: &AppState) -> anyhow::Result<InvariantReport> {
    let row = sqlx::query(
        "SELECT
          (SELECT count(*) FROM beta_credit_accounts a LEFT JOIN (
             SELECT tenant_id,COALESCE(sum(subscription_delta_millicredits),0) s,
                COALESCE(sum(purchased_delta_millicredits),0) p,
                COALESCE(sum(reserved_delta_millicredits),0) r
             FROM beta_credit_events GROUP BY tenant_id) e USING (tenant_id)
           WHERE a.subscription_millicredits<>COALESCE(e.s,0)
              OR a.purchased_millicredits<>COALESCE(e.p,0)
              OR a.reserved_millicredits<>COALESCE(e.r,0))::bigint ledger_differences,
          (SELECT count(*) FROM beta_billing_discrepancies WHERE resolved_at IS NULL)::bigint billing_discrepancies,
          COALESCE((SELECT status='clean' AND completed_at>now()-interval '26 hours'
             FROM beta_reconciliation_runs WHERE completed_at IS NOT NULL
             ORDER BY completed_at DESC LIMIT 1),false) reconciliation_current,
          (SELECT count(*) FROM beta_stripe_events WHERE processing_status<>'processed'
             AND received_at<now()-interval '15 minutes')::bigint stale_stripe_events,
          (SELECT count(*) FROM beta_proof_jobs WHERE verification_succeeded=false
             AND created_at>COALESCE((SELECT acknowledged_at FROM beta_invariant_acknowledgements
                WHERE invariant='official_verifier_rejection'),'-infinity'::timestamptz))::bigint verifier_rejections,
          COALESCE((SELECT max(last_heartbeat_at)>now()-interval '120 seconds'
             FROM beta_workers WHERE enabled),false) worker_current,
          (SELECT count(*) FROM beta_proof_jobs WHERE status IN ('leased','proving','verifying','cancel_requested')
             AND lease_expires_at<now()-interval '300 seconds')::bigint stale_leases,
          COALESCE((SELECT bool_and(release_sha=$1) FROM beta_workers WHERE enabled),false)
             AND NOT EXISTS(SELECT 1 FROM beta_proof_jobs WHERE status IN ('queued','leased','proving','verifying','cancel_requested') AND release_sha<>$1)
             AS release_identity_matches,
          (SELECT count(*) FROM beta_proof_jobs WHERE status IN ('leased','proving','verifying','cancel_requested'))::bigint active_jobs,
          COALESCE((SELECT healthy AND observed_at>now()-interval '26 hours' AND release_sha=$1
             FROM beta_infrastructure_health WHERE component='backup_wal'),false) backup_current,
          COALESCE((SELECT healthy AND observed_at>now()-interval '10 minutes'
                    AND free_percent>=30 AND release_sha=$1
             FROM beta_infrastructure_health WHERE component='api_storage'),false) api_storage_healthy,
          COALESCE((SELECT bool_and(total_scratch_bytes>0 AND free_scratch_bytes*100/total_scratch_bytes>=30)
             FROM beta_workers WHERE enabled),false) scratch_healthy",
    )
    .bind(&state.config.release_sha)
    .fetch_one(&state.pool)
    .await?;
    let mut violations = Vec::new();
    if row.get::<i64, _>("ledger_differences") != 0 {
        violations.push("ledger_reconstruction_difference");
    }
    if row.get::<i64, _>("billing_discrepancies") != 0 {
        violations.push("open_billing_discrepancy");
    }
    if !row.get::<bool, _>("reconciliation_current") {
        violations.push("reconciliation_stale_or_unclean");
    }
    if row.get::<i64, _>("stale_stripe_events") != 0 {
        violations.push("stripe_backlog_stale");
    }
    if row.get::<i64, _>("verifier_rejections") != 0 {
        violations.push("official_verifier_rejection");
    }
    if !row.get::<bool, _>("worker_current") {
        violations.push("worker_heartbeat_stale");
    }
    if row.get::<i64, _>("stale_leases") != 0 {
        violations.push("lease_stale");
    }
    if !row.get::<bool, _>("release_identity_matches") {
        violations.push("release_identity_mismatch");
    }
    if row.get::<i64, _>("active_jobs") > 4 {
        violations.push("worker_slot_envelope_exceeded");
    }
    if !row.get::<bool, _>("backup_current") {
        violations.push("backup_or_wal_stale");
    }
    if !row.get::<bool, _>("api_storage_healthy") {
        violations.push("api_storage_low_or_stale");
    }
    if !row.get::<bool, _>("scratch_healthy") {
        violations.push("scratch_storage_low");
    }
    if state.object_store.health().await.is_err() {
        violations.push("r2_health_failure");
    }
    Ok(InvariantReport {
        release_sha: state.config.release_sha.clone(),
        status: if violations.is_empty() {
            "passed"
        } else {
            "failed"
        },
        violations,
    })
}

pub async fn enforce(state: &AppState) -> anyhow::Result<InvariantReport> {
    let report = evaluate(state).await?;
    let mut tx = state.pool.begin().await?;
    let _ =
        sqlx::query("SELECT singleton FROM beta_operational_flags WHERE singleton=true FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    if report.violations.is_empty() {
        sqlx::query(
            "UPDATE beta_operational_incidents SET recovered_at=COALESCE(recovered_at,now()),
                    last_observed_at=now() WHERE recovered_at IS NULL",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(report);
    }
    sqlx::query(
        "UPDATE beta_operational_flags SET signup_enabled=false,checkout_enabled=false,
                job_submission_enabled=false,containment_reason=$1,
                contained_at=COALESCE(contained_at,now()),updated_at=now()
          WHERE singleton=true",
    )
    .bind(report.violations.join(","))
    .execute(&mut *tx)
    .await?;
    let existing = sqlx::query(
        "SELECT incident_id,alerted_at IS NULL AS needs_alert FROM beta_operational_incidents
          WHERE recovered_at IS NULL FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let (incident_id, needs_alert) = if let Some(row) = existing {
        let incident_id: Uuid = row.get("incident_id");
        sqlx::query(
            "UPDATE beta_operational_incidents SET violations=$2,last_observed_at=now()
              WHERE incident_id=$1",
        )
        .bind(incident_id)
        .bind(json!(report.violations))
        .execute(&mut *tx)
        .await?;
        (incident_id, row.get("needs_alert"))
    } else {
        let incident_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO beta_operational_incidents
                 (incident_id,release_sha,violations) VALUES ($1,$2,$3)",
        )
        .bind(incident_id)
        .bind(&state.config.release_sha)
        .bind(json!(report.violations))
        .execute(&mut *tx)
        .await?;
        (incident_id, true)
    };
    tx.commit().await?;
    if needs_alert && send_alert(state, &report).await.is_ok() {
        sqlx::query(
            "UPDATE beta_operational_incidents SET alerted_at=now() WHERE incident_id=$1 AND alerted_at IS NULL",
        )
        .bind(incident_id)
        .execute(&state.pool)
        .await?;
    }
    Ok(report)
}

pub async fn recover(state: &AppState, operation: &str) -> anyhow::Result<InvariantReport> {
    if operation.len() < 8 || operation.len() > 200 {
        anyhow::bail!("recovery operation must contain 8-200 characters");
    }
    let mut report = evaluate(state).await?;
    if report.violations == ["official_verifier_rejection"] {
        sqlx::query(
            "INSERT INTO beta_invariant_acknowledgements
                 (invariant,acknowledged_at,release_sha,operation_key)
             VALUES ('official_verifier_rejection',now(),$1,$2)
             ON CONFLICT (invariant) DO UPDATE SET acknowledged_at=EXCLUDED.acknowledged_at,
                 release_sha=EXCLUDED.release_sha,operation_key=EXCLUDED.operation_key",
        )
        .bind(&state.config.release_sha)
        .bind(operation)
        .execute(&state.pool)
        .await?;
        report = evaluate(state).await?;
    }
    if !report.violations.is_empty() {
        anyhow::bail!(
            "invariant recovery is blocked: {}",
            report.violations.join(",")
        );
    }
    let day_90_failed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM beta_viability_reports WHERE report_day=90 AND status='failed')",
    )
    .fetch_one(&state.pool)
    .await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE beta_operational_flags SET signup_enabled=NOT $1,checkout_enabled=NOT $1,
                job_submission_enabled=true,
                containment_reason=CASE WHEN $1 THEN 'day_90_viability_failed' ELSE NULL END,
                contained_at=CASE WHEN $1 THEN COALESCE(contained_at,now()) ELSE NULL END,
                updated_at=now()
          WHERE singleton=true",
    )
    .bind(day_90_failed)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE beta_operational_incidents SET recovered_at=COALESCE(recovered_at,now()),
                last_observed_at=now(),recovery_operation=COALESCE(recovery_operation,$1)
          WHERE incident_id=(SELECT incident_id FROM beta_operational_incidents
             ORDER BY opened_at DESC LIMIT 1)",
    )
    .bind(operation)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(report)
}

async fn send_alert(state: &AppState, report: &InvariantReport) -> anyhow::Result<()> {
    reqwest::Client::new()
        .post(&state.config.alert_webhook_url)
        .bearer_auth(&state.config.alert_webhook_token)
        .json(&json!({
            "text": format!(
                "TinyZKP automatically contained signup, Checkout, and new jobs: {}",
                report.violations.join(", ")
            ),
            "release_sha": report.release_sha,
            "incident":"new_obligations_contained"
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub async fn run_watchdog(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.tick().await;
    loop {
        interval.tick().await;
        match enforce(&state).await {
            Ok(report) if report.violations.is_empty() => {
                tracing::info!("beta invariant watchdog passed")
            }
            Ok(report) => {
                tracing::error!(violations=?report.violations, "beta invariant watchdog contained new obligations")
            }
            Err(error) => {
                tracing::error!(%error, "beta invariant watchdog evaluation failed");
                // An inability to evaluate is itself a fail-closed incident.
                let synthetic = InvariantReport {
                    release_sha: state.config.release_sha.clone(),
                    status: "failed",
                    violations: vec!["watchdog_evaluation_failed"],
                };
                let _ = contain_evaluation_failure(&state, &synthetic).await;
            }
        }
    }
}

async fn contain_evaluation_failure(
    state: &AppState,
    report: &InvariantReport,
) -> anyhow::Result<()> {
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE beta_operational_flags SET signup_enabled=false,checkout_enabled=false,
                job_submission_enabled=false,containment_reason='watchdog_evaluation_failed',
                contained_at=COALESCE(contained_at,now()),updated_at=now() WHERE singleton=true",
    )
    .execute(&mut *tx)
    .await?;
    let existing = sqlx::query(
        "SELECT incident_id,alerted_at IS NULL AS needs_alert FROM beta_operational_incidents
          WHERE recovered_at IS NULL FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let (incident_id, needs_alert) = if let Some(row) = existing {
        (
            row.get::<Uuid, _>("incident_id"),
            row.get::<bool, _>("needs_alert"),
        )
    } else {
        let incident_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO beta_operational_incidents (incident_id,release_sha,violations)
             VALUES ($1,$2,$3)",
        )
        .bind(incident_id)
        .bind(&state.config.release_sha)
        .bind(json!(report.violations))
        .execute(&mut *tx)
        .await?;
        (incident_id, true)
    };
    tx.commit().await?;
    if needs_alert && send_alert(state, report).await.is_ok() {
        sqlx::query("UPDATE beta_operational_incidents SET alerted_at=now() WHERE incident_id=$1")
            .bind(incident_id)
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}
