use crate::AppState;
use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use sqlx::Row;
use std::{sync::Arc, time::Instant};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    http_requests: IntCounterVec,
    http_duration: HistogramVec,
    job_states: IntGaugeVec,
    active_leases: IntGauge,
    worker_heartbeat_age: IntGauge,
    verifier_outcomes: IntGaugeVec,
    stripe_backlog: IntGauge,
    reconciliation_clean: IntGauge,
    reconciliation_age: IntGauge,
    ledger_difference_accounts: IntGauge,
    balances: IntGaugeVec,
    grants: IntGauge,
    refunds: IntGauge,
    retention_failures: IntGauge,
    operational_flags: IntGaugeVec,
    open_incidents: IntGauge,
    storage_free_percent: IntGaugeVec,
    backup_healthy: IntGauge,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new_custom(Some("tinyzkp_beta".into()), None)?;
        let http_requests = IntCounterVec::new(
            Opts::new("http_requests_total", "HTTP requests by normalized route"),
            &["method", "route", "status"],
        )?;
        let http_duration = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "HTTP request latency").buckets(
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0],
            ),
            &["method", "route"],
        )?;
        let job_states =
            IntGaugeVec::new(Opts::new("jobs", "Current proof jobs by state"), &["state"])?;
        let active_leases = IntGauge::new("active_leases", "Active worker leases")?;
        let worker_heartbeat_age = IntGauge::new(
            "worker_heartbeat_age_seconds",
            "Age of newest worker heartbeat",
        )?;
        let verifier_outcomes = IntGaugeVec::new(
            Opts::new("verifier_outcomes", "Persisted official verifier outcomes"),
            &["outcome"],
        )?;
        let stripe_backlog = IntGauge::new("stripe_event_backlog", "Unprocessed Stripe events")?;
        let reconciliation_clean =
            IntGauge::new("reconciliation_clean", "Latest reconciliation is clean")?;
        let reconciliation_age = IntGauge::new(
            "reconciliation_age_seconds",
            "Age of latest completed reconciliation",
        )?;
        let ledger_difference_accounts = IntGauge::new(
            "ledger_difference_accounts",
            "Accounts differing from immutable credit events",
        )?;
        let balances = IntGaugeVec::new(
            Opts::new("credit_millicredits", "Materialized aggregate credit state"),
            &["kind"],
        )?;
        let grants = IntGauge::new("credit_grants", "Immutable credit grants")?;
        let refunds = IntGauge::new("refund_reversed_millicredits", "Reversed credits")?;
        let retention_failures =
            IntGauge::new("retention_failures", "Retention deletions with errors")?;
        let operational_flags = IntGaugeVec::new(
            Opts::new(
                "operational_flag",
                "Whether a new-obligation capability is enabled",
            ),
            &["capability"],
        )?;
        let open_incidents = IntGauge::new("open_incidents", "Open invariant incident windows")?;
        let storage_free_percent = IntGaugeVec::new(
            Opts::new("storage_free_percent", "Reported free storage percentage"),
            &["component"],
        )?;
        let backup_healthy =
            IntGauge::new("backup_healthy", "Backup and WAL freshness is healthy")?;
        for collector in [
            Box::new(http_requests.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(http_duration.clone()),
            Box::new(job_states.clone()),
            Box::new(active_leases.clone()),
            Box::new(worker_heartbeat_age.clone()),
            Box::new(verifier_outcomes.clone()),
            Box::new(stripe_backlog.clone()),
            Box::new(reconciliation_clean.clone()),
            Box::new(reconciliation_age.clone()),
            Box::new(ledger_difference_accounts.clone()),
            Box::new(balances.clone()),
            Box::new(grants.clone()),
            Box::new(refunds.clone()),
            Box::new(retention_failures.clone()),
            Box::new(operational_flags.clone()),
            Box::new(open_incidents.clone()),
            Box::new(storage_free_percent.clone()),
            Box::new(backup_healthy.clone()),
        ] {
            registry.register(collector)?;
        }
        Ok(Self {
            registry: Arc::new(registry),
            http_requests,
            http_duration,
            job_states,
            active_leases,
            worker_heartbeat_age,
            verifier_outcomes,
            stripe_backlog,
            reconciliation_clean,
            reconciliation_age,
            ledger_difference_accounts,
            balances,
            grants,
            refunds,
            retention_failures,
            operational_flags,
            open_incidents,
            storage_free_percent,
            backup_healthy,
        })
    }

    async fn refresh(&self, state: &AppState) -> anyhow::Result<()> {
        const STATES: [&str; 9] = [
            "queued",
            "leased",
            "proving",
            "verifying",
            "completed",
            "cancel_requested",
            "cancelled",
            "platform_failed",
            "customer_failed",
        ];
        for status in STATES {
            self.job_states.with_label_values(&[status]).set(0);
        }
        for row in sqlx::query(
            "SELECT status,count(*)::bigint AS count FROM beta_proof_jobs GROUP BY status",
        )
        .fetch_all(&state.pool)
        .await?
        {
            self.job_states
                .with_label_values(&[row.get::<String, _>("status").as_str()])
                .set(row.get("count"));
        }
        let row = sqlx::query(
            "SELECT
              (SELECT count(*) FROM beta_proof_jobs WHERE status IN ('leased','proving','verifying','cancel_requested'))::bigint active_leases,
              COALESCE((SELECT extract(epoch from (now()-max(last_heartbeat_at)))::bigint FROM beta_workers WHERE enabled),2147483647) heartbeat_age,
              (SELECT count(*) FROM beta_stripe_events WHERE processing_status<>'processed')::bigint stripe_backlog,
              COALESCE((SELECT (status='clean')::int FROM beta_reconciliation_runs WHERE completed_at IS NOT NULL ORDER BY completed_at DESC LIMIT 1),0)::bigint reconciliation_clean,
              COALESCE((SELECT extract(epoch from (now()-max(completed_at)))::bigint FROM beta_reconciliation_runs),2147483647) reconciliation_age,
              (SELECT count(*) FROM beta_credit_accounts a LEFT JOIN (
                 SELECT tenant_id,COALESCE(sum(subscription_delta_millicredits),0) s,
                    COALESCE(sum(purchased_delta_millicredits),0) p,COALESCE(sum(reserved_delta_millicredits),0) r
                 FROM beta_credit_events GROUP BY tenant_id) e USING (tenant_id)
               WHERE a.subscription_millicredits<>COALESCE(e.s,0)
                  OR a.purchased_millicredits<>COALESCE(e.p,0)
                  OR a.reserved_millicredits<>COALESCE(e.r,0))::bigint ledger_differences,
              COALESCE((SELECT sum(subscription_millicredits) FROM beta_credit_accounts),0)::bigint subscription_balance,
              COALESCE((SELECT sum(purchased_millicredits) FROM beta_credit_accounts),0)::bigint purchased_balance,
              COALESCE((SELECT sum(reserved_millicredits) FROM beta_credit_accounts),0)::bigint reserved_balance,
              (SELECT count(*) FROM beta_credit_grants)::bigint grants,
              COALESCE((SELECT sum(reversed_millicredits) FROM beta_credit_grants),0)::bigint refunds,
              (SELECT count(*) FROM beta_retention_deletions WHERE last_error IS NOT NULL AND deleted_at IS NULL)::bigint retention_failures,
              (SELECT count(*) FROM beta_proof_jobs WHERE verification_succeeded)::bigint verifier_accepted,
              (SELECT count(*) FROM beta_proof_jobs WHERE verification_succeeded=false
                 AND created_at>COALESCE((SELECT acknowledged_at FROM beta_invariant_acknowledgements
                    WHERE invariant='official_verifier_rejection'),'-infinity'::timestamptz))::bigint verifier_rejected,
              (SELECT signup_enabled::int FROM beta_operational_flags WHERE singleton)::bigint signup_enabled,
              (SELECT checkout_enabled::int FROM beta_operational_flags WHERE singleton)::bigint checkout_enabled,
              (SELECT job_submission_enabled::int FROM beta_operational_flags WHERE singleton)::bigint jobs_enabled,
              (SELECT count(*) FROM beta_operational_incidents WHERE recovered_at IS NULL)::bigint open_incidents,
              COALESCE((SELECT free_percent FROM beta_infrastructure_health WHERE component='api_storage'),0)::bigint api_free_percent,
              COALESCE((SELECT min(free_scratch_bytes*100/NULLIF(total_scratch_bytes,0)) FROM beta_workers WHERE enabled),0)::bigint scratch_free_percent,
              COALESCE((SELECT healthy::int FROM beta_infrastructure_health WHERE component='backup_wal'),0)::bigint backup_healthy",
        )
        .fetch_one(&state.pool)
        .await?;
        self.active_leases.set(row.get("active_leases"));
        self.worker_heartbeat_age.set(row.get("heartbeat_age"));
        self.stripe_backlog.set(row.get("stripe_backlog"));
        self.reconciliation_clean
            .set(row.get("reconciliation_clean"));
        self.reconciliation_age.set(row.get("reconciliation_age"));
        self.ledger_difference_accounts
            .set(row.get("ledger_differences"));
        for (label, column) in [
            ("subscription", "subscription_balance"),
            ("purchased", "purchased_balance"),
            ("reserved", "reserved_balance"),
        ] {
            self.balances
                .with_label_values(&[label])
                .set(row.get(column));
        }
        self.grants.set(row.get("grants"));
        self.refunds.set(row.get("refunds"));
        self.retention_failures.set(row.get("retention_failures"));
        self.verifier_outcomes
            .with_label_values(&["accepted"])
            .set(row.get("verifier_accepted"));
        self.verifier_outcomes
            .with_label_values(&["rejected"])
            .set(row.get("verifier_rejected"));
        for (label, column) in [
            ("signup", "signup_enabled"),
            ("checkout", "checkout_enabled"),
            ("job_submission", "jobs_enabled"),
        ] {
            self.operational_flags
                .with_label_values(&[label])
                .set(row.get(column));
        }
        self.open_incidents.set(row.get("open_incidents"));
        self.storage_free_percent
            .with_label_values(&["api"])
            .set(row.get("api_free_percent"));
        self.storage_free_percent
            .with_label_values(&["scratch"])
            .set(row.get("scratch_free_percent"));
        self.backup_healthy.set(row.get("backup_healthy"));
        Ok(())
    }
}

pub async fn track_http(
    State(metrics): State<Metrics>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    metrics
        .http_requests
        .with_label_values(&[&method, &route, response.status().as_str()])
        .inc();
    metrics
        .http_duration
        .with_label_values(&[&method, &route])
        .observe(started.elapsed().as_secs_f64());
    response
}

pub async fn endpoint(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let supplied = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !token_matches(supplied, &state.config.metrics_token) {
        return (StatusCode::UNAUTHORIZED, "metrics authorization required").into_response();
    }
    if let Err(error) = state.metrics.refresh(&state).await {
        tracing::error!(%error, "beta metrics refresh failed");
        return (StatusCode::SERVICE_UNAVAILABLE, "metrics unavailable").into_response();
    }
    let families = state.metrics.registry.gather();
    let mut body = Vec::new();
    if TextEncoder::new().encode(&families, &mut body).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed").into_response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", TextEncoder::new().format_type())
        .body(Body::from(body))
        .expect("static metrics response")
}

fn token_matches(supplied: Option<&str>, expected: &str) -> bool {
    let Some(supplied) = supplied else {
        return false;
    };
    supplied.len() == expected.len() && supplied.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::token_matches;

    #[test]
    fn metrics_token_is_exact_and_required() {
        assert!(token_matches(
            Some("a-long-random-token"),
            "a-long-random-token"
        ));
        assert!(!token_matches(None, "a-long-random-token"));
        assert!(!token_matches(
            Some("a-long-random-toke"),
            "a-long-random-token"
        ));
        assert!(!token_matches(
            Some("A-long-random-token"),
            "a-long-random-token"
        ));
    }
}
