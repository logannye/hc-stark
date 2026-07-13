use hc_beta_api::business;
use serde_json::{json, Value};
use sqlx::Row;
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("activate") => activate().await,
        Some("report") => report().await,
        _ => anyhow::bail!("usage: hc-beta-viability activate|report"),
    }
}

async fn activate() -> anyhow::Result<()> {
    let cost_file = PathBuf::from(business::required("TINYZKP_BETA_COST_FILE")?);
    let _monthly_fixed = monthly_cost(&cost_file)?;
    let pool = business::pool_from_env().await?;
    let release = business::release_sha()?;
    let changed = sqlx::query(
        "INSERT INTO beta_business_activation (singleton,activated_at,release_sha)
         VALUES (true,now(),$1) ON CONFLICT DO NOTHING",
    )
    .bind(&release)
    .execute(&pool)
    .await?
    .rows_affected();
    if changed == 0 {
        let existing: String =
            sqlx::query_scalar("SELECT release_sha FROM beta_business_activation WHERE singleton")
                .fetch_one(&pool)
                .await?;
        if existing != release {
            anyhow::bail!("business activation is already bound to another release");
        }
    }
    println!("{{\"activation_recorded\":true,\"release_sha\":\"{release}\"}}");
    Ok(())
}

async fn report() -> anyhow::Result<()> {
    let pool = business::pool_from_env().await?;
    let activation = sqlx::query(
        "SELECT release_sha,GREATEST(0,floor(extract(epoch from (now()-activated_at))/86400))::bigint elapsed_days
           FROM beta_business_activation WHERE singleton",
    )
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("public activation has not been recorded"))?;
    let release: String = activation.get("release_sha");
    if release != business::release_sha()? {
        anyhow::bail!("viability release identity does not match the active release");
    }
    let elapsed: i64 = activation.get("elapsed_days");
    let cost_file = PathBuf::from(business::required("TINYZKP_BETA_COST_FILE")?);
    let monthly_fixed = monthly_cost(&cost_file)?;
    let report_dir = PathBuf::from(business::required("TINYZKP_OWNER_REPORT_DIR")?);
    let mut generated = 0;
    for day in [30_i32, 60, 90] {
        if elapsed < i64::from(day)
            || sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM beta_viability_reports WHERE report_day=$1)",
            )
            .bind(day)
            .fetch_one(&pool)
            .await?
        {
            continue;
        }
        let row = sqlx::query(
            "WITH bounds AS (
               SELECT activated_at start_at,activated_at+make_interval(days=>$1) cutoff
                 FROM beta_business_activation WHERE singleton
             ), real_paid AS (
               SELECT DISTINCT tenant_id FROM beta_credit_grants,bounds
                WHERE NOT synthetic_canary AND created_at<=cutoff
             ), paid_jobs AS (
               SELECT j.* FROM beta_proof_jobs j,bounds WHERE j.tenant_id IN (SELECT tenant_id FROM real_paid)
                 AND j.status='completed' AND j.verification_succeeded AND j.completed_at<=cutoff
             )
             SELECT
              (SELECT count(*) FROM real_paid)::bigint paying_tenants,
              (SELECT count(DISTINCT tenant_id) FROM paid_jobs)::bigint activated_tenants,
              (SELECT count(*) FROM (SELECT tenant_id FROM paid_jobs GROUP BY tenant_id HAVING count(DISTINCT completed_at::date)>=2) r)::bigint retained_tenants,
              COALESCE((SELECT sum(settled_millicredits) FROM paid_jobs,bounds WHERE completed_at>cutoff-interval '30 days'),0)::bigint trailing_revenue,
              COALESCE((SELECT sum(measured_cost_millicredits) FROM paid_jobs,bounds WHERE completed_at>cutoff-interval '30 days'),0)::bigint trailing_job_cost,
              (SELECT count(*) FROM paid_jobs)::bigint completed_jobs,
              COALESCE((SELECT sum(minutes) FROM beta_support_minutes,bounds WHERE occurred_at>=start_at AND occurred_at<=cutoff),0)::bigint support_minutes,
              (SELECT count(*) FROM beta_billing_discrepancies,bounds WHERE created_at<=cutoff AND (resolved_at IS NULL OR resolved_at>cutoff))::bigint billing_issues,
              (SELECT count(*) FROM beta_operational_incidents,bounds WHERE opened_at<=cutoff AND (recovered_at IS NULL OR recovered_at>cutoff))::bigint security_issues,
              (SELECT count(*) FROM beta_proof_jobs,bounds WHERE verification_succeeded=false
                 AND created_at<=cutoff AND created_at>COALESCE((SELECT max(acknowledged_at)
                    FROM beta_invariant_acknowledgements WHERE invariant='official_verifier_rejection'
                      AND acknowledged_at<=cutoff),'-infinity'::timestamptz))::bigint verifier_issues,
              (SELECT count(*) FROM beta_retention_deletions,bounds WHERE last_error IS NOT NULL AND created_at<=cutoff AND deleted_at IS NULL)::bigint retention_issues,
              (SELECT count(*) FROM beta_credit_accounts a LEFT JOIN (
                 SELECT tenant_id,COALESCE(sum(subscription_delta_millicredits),0) s,
                    COALESCE(sum(purchased_delta_millicredits),0) p,COALESCE(sum(reserved_delta_millicredits),0) r
                   FROM beta_credit_events GROUP BY tenant_id) e USING (tenant_id)
                 WHERE a.subscription_millicredits<>COALESCE(e.s,0)
                    OR a.purchased_millicredits<>COALESCE(e.p,0)
                    OR a.reserved_millicredits<>COALESCE(e.r,0))::bigint ledger_issues,
              COALESCE((SELECT healthy AND observed_at>now()-interval '26 hours' FROM beta_infrastructure_health WHERE component='backup_wal'),false) backup_healthy",
        )
        .bind(day)
        .fetch_one(&pool)
        .await?;
        let paying: i64 = row.get("paying_tenants");
        let activated: i64 = row.get("activated_tenants");
        let retained: i64 = row.get("retained_tenants");
        let revenue: i64 = row.get("trailing_revenue");
        let direct_cost = row
            .get::<i64, _>("trailing_job_cost")
            .saturating_add(monthly_fixed);
        let completed: i64 = row.get("completed_jobs");
        let support: i64 = row.get("support_minutes");
        let margin_bps = if revenue > 0 {
            (revenue - direct_cost) * 10_000 / revenue
        } else {
            0
        };
        let retention_bps = if activated > 0 {
            retained * 10_000 / activated
        } else {
            0
        };
        let support_per_ten = if completed > 0 {
            support * 10 / completed
        } else if support == 0 {
            0
        } else {
            i64::MAX
        };
        let unresolved = row.get::<i64, _>("billing_issues")
            + row.get::<i64, _>("security_issues")
            + row.get::<i64, _>("verifier_issues")
            + row.get::<i64, _>("retention_issues")
            + row.get::<i64, _>("ledger_issues")
            + i64::from(!row.get::<bool, _>("backup_healthy"));
        let passed = paying >= 5
            && revenue >= direct_cost.saturating_mul(3)
            && margin_bps >= 7_000
            && support_per_ten <= 60
            && retention_bps >= 2_500
            && unresolved == 0;
        let status = if day < 90 {
            "informational"
        } else if passed {
            "passed"
        } else {
            "failed"
        };
        let body = json!({
            "schema_version":"tinyzkp-viability-v1","release_sha":release,"report_day":day,"status":status,
            "definitions":{"synthetic_tenants_excluded":true,"credit_unit":"millicredit","fixed_cost_source":"owner-only cost file"},
            "metrics":{"paying_tenants":paying,"activated_paying_tenants":activated,"retained_tenants":retained,"retention_bps":retention_bps,"trailing_30_consumed_revenue_millicredits":revenue,"trailing_30_direct_cost_millicredits":direct_cost,"realized_gross_margin_bps":margin_bps,"support_minutes":support,"completed_jobs":completed,"support_minutes_per_ten_jobs":support_per_ten,"unresolved_invariants":unresolved},
            "criteria":{"five_paying_tenants":paying>=5,"revenue_three_times_cost":revenue>=direct_cost.saturating_mul(3),"gross_margin_70_percent":margin_bps>=7000,"support_limit":support_per_ten<=60,"retention_25_percent":retention_bps>=2500,"no_unresolved_invariants":unresolved==0},
            "automatic_action":if day==90 && !passed {"disable_new_signup_and_checkout"} else {"none"}
        });
        let (digest, hmac) = business::sign(&body)?;
        let stored = json!({"report":body,"report_sha256":digest,"report_hmac_sha256":hmac});
        business::assert_redacted(&stored)?;
        let mut tx = pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO beta_viability_reports
                 (report_day,release_sha,status,report_json,report_sha256,report_hmac_sha256)
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        )
        .bind(day)
        .bind(&release)
        .bind(status)
        .bind(&stored)
        .bind(&digest)
        .bind(&hmac)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if day == 90 && !passed && inserted == 1 {
            sqlx::query(
                "UPDATE beta_operational_flags SET signup_enabled=false,checkout_enabled=false,
                    containment_reason='day_90_viability_failed',contained_at=COALESCE(contained_at,now()),
                    updated_at=now() WHERE singleton=true",
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        business::write_owner_json(
            &report_dir.join(format!("viability-day-{day}.json")),
            &stored,
        )?;
        if day == 90 && !passed && inserted == 1 {
            business::send_summary(json!({
                "text":"TinyZKP day-90 viability gate failed. New signup and Checkout were disabled; existing paid service remains available.",
                "report_sha256":digest,"release_sha":release
            })).await?;
        }
        generated += 1;
    }
    println!("{{\"reports_generated\":{generated},\"elapsed_days\":{elapsed}}}");
    Ok(())
}

fn monthly_cost(path: &Path) -> anyhow::Result<i64> {
    let value: Value = business::read_owner_json(path)?;
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        anyhow::bail!("cost file schema_version must be 1");
    }
    let cost = value
        .get("monthly_fixed_infrastructure_millicredits")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("cost file lacks monthly fixed millicredits"))?;
    if cost < 0 {
        anyhow::bail!("monthly fixed cost cannot be negative");
    }
    Ok(cost)
}

#[cfg(test)]
mod tests {
    use super::monthly_cost;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn owner_cost_file_is_exact_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cost.json");
        fs::write(
            &path,
            r#"{"schema_version":1,"monthly_fixed_infrastructure_millicredits":75900}"#,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(monthly_cost(&path).unwrap(), 75_900);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(monthly_cost(&path).is_err());
    }
}
