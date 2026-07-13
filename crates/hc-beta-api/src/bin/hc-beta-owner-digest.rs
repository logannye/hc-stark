use hc_beta_api::business;
use serde_json::json;
use sqlx::Row;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = business::pool_from_env().await?;
    let row = sqlx::query(
        "WITH real_tenants AS (
           SELECT DISTINCT tenant_id FROM beta_credit_grants WHERE NOT synthetic_canary
         ), non_synthetic AS (
           SELECT tenant_id FROM tenants t WHERE NOT EXISTS (
             SELECT 1 FROM beta_credit_grants g WHERE g.tenant_id=t.tenant_id AND g.synthetic_canary)
         ), first_jobs AS (
           SELECT tenant_id,min(completed_at) first_at FROM beta_proof_jobs
            WHERE status='completed' AND verification_succeeded GROUP BY tenant_id
         ), weekly_jobs AS (
           SELECT * FROM beta_proof_jobs WHERE created_at>=now()-interval '7 days'
             AND tenant_id IN (SELECT tenant_id FROM non_synthetic)
         )
         SELECT
          to_char(date_trunc('week',now()),'YYYY-MM-DD') period_start,
          (SELECT count(*) FROM tenants WHERE to_timestamp(created_at_ms/1000.0)>=now()-interval '7 days'
             AND tenant_id IN (SELECT tenant_id FROM non_synthetic))::bigint signups,
          (SELECT count(*) FROM beta_api_keys WHERE created_at>=now()-interval '7 days'
             AND tenant_id IN (SELECT tenant_id FROM non_synthetic))::bigint api_keys_created,
          (SELECT count(*) FROM first_jobs WHERE first_at>=now()-interval '7 days'
             AND tenant_id IN (SELECT tenant_id FROM non_synthetic))::bigint first_verified_jobs,
          (SELECT count(*) FROM real_tenants)::bigint paid_tenants,
          (SELECT count(*) FROM (SELECT tenant_id FROM beta_proof_jobs WHERE status='completed'
             AND verification_succeeded AND tenant_id IN (SELECT tenant_id FROM non_synthetic)
             GROUP BY tenant_id HAVING count(DISTINCT completed_at::date)>=2
                AND max(completed_at)>=now()-interval '7 days') r)::bigint repeat_users,
          COALESCE((SELECT sum(granted_millicredits) FROM beta_credit_grants
             WHERE NOT synthetic_canary AND created_at>=now()-interval '7 days'),0)::bigint grants,
          COALESCE((SELECT -sum(subscription_delta_millicredits+purchased_delta_millicredits)
             FROM beta_credit_events WHERE event_type='refund_reversal'
               AND created_at>=now()-interval '7 days'
               AND tenant_id IN (SELECT tenant_id FROM real_tenants)),0)::bigint refunds,
          COALESCE((SELECT sum(settled_millicredits) FROM beta_proof_jobs WHERE status='completed'
             AND completed_at>=now()-interval '7 days' AND tenant_id IN (SELECT tenant_id FROM real_tenants)),0)::bigint consumed_revenue,
          COALESCE((SELECT sum(subscription_millicredits+purchased_millicredits)
             FROM beta_credit_accounts WHERE tenant_id IN (SELECT tenant_id FROM real_tenants)),0)::bigint credit_liability,
          COALESCE((SELECT sum(reserved_millicredits) FROM beta_credit_accounts
             WHERE tenant_id IN (SELECT tenant_id FROM real_tenants)),0)::bigint reservations,
          (SELECT count(*) FROM weekly_jobs WHERE status='completed')::bigint completed_jobs,
          (SELECT count(*) FROM weekly_jobs WHERE status IN ('platform_failed','customer_failed'))::bigint failed_jobs,
          (SELECT count(*) FROM weekly_jobs WHERE status='cancelled')::bigint cancelled_jobs,
          (SELECT count(*) FROM beta_credit_events WHERE event_type IN ('platform_refund','reservation_release')
             AND created_at>=now()-interval '7 days' AND tenant_id IN (SELECT tenant_id FROM non_synthetic))::bigint refunded_jobs,
          COALESCE((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM started_at-created_at))
             FROM weekly_jobs WHERE started_at IS NOT NULL),0)::float8 queue_p50,
          COALESCE((SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM started_at-created_at))
             FROM weekly_jobs WHERE started_at IS NOT NULL),0)::float8 queue_p95,
          COALESCE((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM completed_at-started_at))
             FROM weekly_jobs WHERE completed_at IS NOT NULL AND started_at IS NOT NULL),0)::float8 proof_p50,
          COALESCE((SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY extract(epoch FROM completed_at-started_at))
             FROM weekly_jobs WHERE completed_at IS NOT NULL AND started_at IS NOT NULL),0)::float8 proof_p95,
          COALESCE((SELECT sum(measured_cost_millicredits) FROM weekly_jobs WHERE status='completed'),0)::bigint measured_cost,
          COALESCE((SELECT sum(settled_millicredits) FROM weekly_jobs WHERE status='completed'),0)::bigint settled_revenue,
          COALESCE((SELECT sum((resource_report_json->>'wall_time_ms')::bigint) FROM weekly_jobs
             WHERE status='completed' AND resource_report_json ? 'wall_time_ms'),0)::bigint worker_busy_ms,
          COALESCE((SELECT min(free_scratch_bytes*100/NULLIF(total_scratch_bytes,0)) FROM beta_workers WHERE enabled),0)::bigint scratch_free_percent,
          COALESCE((SELECT sum(proof_size_bytes) FROM beta_proof_jobs WHERE proof_object_key IS NOT NULL),0)::bigint retained_proof_bytes,
          COALESCE((SELECT sum(compressed_bytes) FROM beta_upload_chunks c JOIN beta_uploads u USING(upload_id)
             WHERE u.deleted_at IS NULL),0)::bigint retained_upload_bytes,
          COALESCE((SELECT status FROM beta_reconciliation_runs ORDER BY completed_at DESC NULLS LAST LIMIT 1),'missing') reconciliation,
          COALESCE((SELECT healthy FROM beta_infrastructure_health WHERE component='backup_wal'),false) backup_healthy,
          (SELECT count(*) FROM beta_retention_deletions WHERE last_error IS NOT NULL AND deleted_at IS NULL)::bigint retention_failures,
          (SELECT count(*) FROM beta_operational_incidents WHERE recovered_at IS NULL)::bigint security_alerts,
          COALESCE((SELECT sum(minutes) FROM beta_support_minutes WHERE occurred_at>=now()-interval '7 days'),0)::bigint support_minutes",
    )
    .fetch_one(&pool)
    .await?;
    let measured: i64 = row.get("measured_cost");
    let settled: i64 = row.get("settled_revenue");
    let margin_bps = if settled > 0 {
        (settled - measured) * 10_000 / settled
    } else {
        0
    };
    let period_start: String = row.get("period_start");
    let body = json!({
        "schema_version":"tinyzkp-owner-digest-v1",
        "release_sha":business::release_sha()?,
        "period_start":period_start,
        "period_days":7,
        "funnel":{"signups":row.get::<i64,_>("signups"),"api_keys_created":row.get::<i64,_>("api_keys_created"),"first_verified_jobs":row.get::<i64,_>("first_verified_jobs"),"paid_tenants":row.get::<i64,_>("paid_tenants"),"repeat_users":row.get::<i64,_>("repeat_users")},
        "credits":{"granted_millicredits":row.get::<i64,_>("grants"),"refunded_millicredits":row.get::<i64,_>("refunds"),"consumed_revenue_millicredits":row.get::<i64,_>("consumed_revenue"),"outstanding_liability_millicredits":row.get::<i64,_>("credit_liability"),"reserved_millicredits":row.get::<i64,_>("reservations")},
        "jobs":{"completed":row.get::<i64,_>("completed_jobs"),"failed":row.get::<i64,_>("failed_jobs"),"cancelled":row.get::<i64,_>("cancelled_jobs"),"refunded":row.get::<i64,_>("refunded_jobs"),"queue_seconds":{"p50":row.get::<f64,_>("queue_p50"),"p95":row.get::<f64,_>("queue_p95")},"proof_seconds":{"p50":row.get::<f64,_>("proof_p50"),"p95":row.get::<f64,_>("proof_p95")}},
        "economics":{"measured_cost_millicredits":measured,"settled_millicredits":settled,"realized_gross_margin_bps":margin_bps},
        "capacity":{"worker_utilization_bps":row.get::<i64,_>("worker_busy_ms")*10_000/(7*24*60*60*1000*4),"scratch_free_percent":row.get::<i64,_>("scratch_free_percent"),"retained_proof_bytes":row.get::<i64,_>("retained_proof_bytes"),"retained_upload_bytes":row.get::<i64,_>("retained_upload_bytes")},
        "operations":{"reconciliation":row.get::<String,_>("reconciliation"),"backup_healthy":row.get::<bool,_>("backup_healthy"),"retention_failures":row.get::<i64,_>("retention_failures"),"open_security_alerts":row.get::<i64,_>("security_alerts"),"support_minutes":row.get::<i64,_>("support_minutes")}
    });
    let (digest, hmac) = business::sign(&body)?;
    let report = json!({"report":body,"report_sha256":digest,"report_hmac_sha256":hmac});
    business::assert_redacted(&report)?;
    let directory = PathBuf::from(business::required("TINYZKP_OWNER_REPORT_DIR")?);
    business::write_owner_json(
        &directory.join(format!("owner-digest-{period_start}.json")),
        &report,
    )?;
    business::send_summary(json!({
        "text":format!("TinyZKP weekly: {} paid tenants, {} verified jobs, {} bps margin, {} support minutes",row.get::<i64,_>("paid_tenants"),row.get::<i64,_>("completed_jobs"),margin_bps,row.get::<i64,_>("support_minutes")),
        "report_sha256":digest,
        "release_sha":business::release_sha()?
    })).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
