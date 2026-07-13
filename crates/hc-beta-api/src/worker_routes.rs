use crate::{
    auth,
    error::ApiError,
    models::*,
    object_store::bundle_object_key,
    public::{as_u64, release_reservation, to_i64},
    AppState,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use hc_plonky3::contracts::{
    hosted_charge_millicredits, hosted_measured_cost_millicredits, HostedProofBundleV1,
    MAX_AIR_BUNDLE_JSON_BYTES,
};
use serde_json::{json, Value};
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

const LEASE_SECONDS: u64 = 120;
const MAX_ATTEMPTS: i32 = 3;
const LEASE_REAP_BATCH: i64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpiredLeaseAction {
    Requeue,
    Cancel,
    PlatformFail,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpiredLeaseSummary {
    pub requeued: usize,
    pub cancelled: usize,
    pub platform_failed: usize,
}

fn expired_lease_action(
    status: &str,
    attempt: i32,
    checkpoint_identity: Option<&str>,
) -> ExpiredLeaseAction {
    if status == "cancel_requested" {
        ExpiredLeaseAction::Cancel
    } else if attempt < MAX_ATTEMPTS && checkpoint_identity.is_some_and(is_digest) {
        ExpiredLeaseAction::Requeue
    } else {
        ExpiredLeaseAction::PlatformFail
    }
}

pub async fn run_lease_reaper(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match reap_expired_leases(&state).await {
            Ok(summary)
                if summary.requeued != 0
                    || summary.cancelled != 0
                    || summary.platform_failed != 0 =>
            {
                tracing::warn!(
                    requeued = summary.requeued,
                    cancelled = summary.cancelled,
                    platform_failed = summary.platform_failed,
                    "expired worker leases reconciled"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "expired worker lease reconciliation failed"),
        }
    }
}

pub async fn reap_expired_leases(state: &AppState) -> Result<ExpiredLeaseSummary, ApiError> {
    let mut tx = state.pool.begin().await?;
    let rows = sqlx::query(
        "SELECT tenant_id,job_id,status,attempt,lease_epoch,checkpoint_identity,
                reserved_subscription_millicredits,reserved_purchased_millicredits
           FROM beta_proof_jobs
          WHERE status IN ('leased','proving','verifying','cancel_requested')
            AND lease_expires_at <= now()
          ORDER BY lease_expires_at,created_at
          FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(LEASE_REAP_BATCH)
    .fetch_all(&mut *tx)
    .await?;
    let mut summary = ExpiredLeaseSummary::default();
    for row in rows {
        let tenant_id: String = row.get("tenant_id");
        let job_id: Uuid = row.get("job_id");
        let status: String = row.get("status");
        let attempt: i32 = row.get("attempt");
        let lease_epoch: i64 = row.get("lease_epoch");
        let checkpoint_identity: Option<String> = row.get("checkpoint_identity");
        let action = expired_lease_action(&status, attempt, checkpoint_identity.as_deref());
        let attempt_result = match action {
            ExpiredLeaseAction::Requeue => {
                sqlx::query(
                    "UPDATE beta_proof_jobs
                        SET status='queued',lease_owner=NULL,lease_expires_at=NULL,
                            error_code='lease_expired'
                      WHERE job_id=$1",
                )
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
                summary.requeued += 1;
                "lease_expired_requeued"
            }
            ExpiredLeaseAction::Cancel => {
                release_reservation(&mut tx, &tenant_id, job_id, &row, "cancelled").await?;
                sqlx::query(
                    "UPDATE beta_proof_jobs SET error_code='cancel_lease_expired' WHERE job_id=$1",
                )
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
                summary.cancelled += 1;
                "cancelled"
            }
            ExpiredLeaseAction::PlatformFail => {
                release_reservation(&mut tx, &tenant_id, job_id, &row, "platform_failed").await?;
                sqlx::query(
                    "UPDATE beta_proof_jobs SET error_code='lease_expired' WHERE job_id=$1",
                )
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
                summary.platform_failed += 1;
                "platform_failed"
            }
        };
        sqlx::query(
            "UPDATE beta_job_attempts SET ended_at=COALESCE(ended_at,now()),result=$4
              WHERE job_id=$1 AND attempt=$2 AND lease_epoch=$3",
        )
        .bind(job_id)
        .bind(attempt)
        .bind(lease_epoch)
        .bind(attempt_result)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(summary)
}

pub async fn draining(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WorkerDrainingRequest>,
) -> Result<Json<Value>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    if request.release_sha != state.config.release_sha {
        return Err(ApiError::Conflict("worker_release_mismatch"));
    }
    let changed = sqlx::query(
        "UPDATE beta_workers SET draining=$2,
             draining_at=CASE WHEN $2 THEN now() ELSE NULL END,last_heartbeat_at=now()
          WHERE worker_id=$1 AND enabled",
    )
    .bind(&worker_id)
    .bind(request.draining)
    .execute(&state.pool)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(ApiError::Unauthorized);
    }
    Ok(Json(
        json!({"worker_id":worker_id,"draining":request.draining}),
    ))
}

pub async fn claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WorkerClaimRequest>,
) -> Result<Json<Option<WorkerClaimResponse>>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    if request.release_sha != state.config.release_sha {
        return Err(ApiError::Conflict("worker_release_mismatch"));
    }
    if request.total_scratch_bytes == 0 || request.free_scratch_bytes > request.total_scratch_bytes
    {
        return Err(ApiError::Invalid("invalid_worker_storage_report"));
    }
    let mut tx = state.pool.begin().await?;
    let worker = sqlx::query(
        "UPDATE beta_workers SET free_scratch_bytes=$2,total_scratch_bytes=$3,
                release_sha=$4,last_heartbeat_at=now()
          WHERE worker_id=$1 AND enabled AND NOT draining
          RETURNING max_slots",
    )
    .bind(&worker_id)
    .bind(to_i64(request.free_scratch_bytes)?)
    .bind(to_i64(request.total_scratch_bytes)?)
    .bind(&request.release_sha)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let max_slots: i32 = worker.get("max_slots");
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM beta_proof_jobs
          WHERE lease_owner=$1 AND status IN ('leased','proving','verifying','cancel_requested')
            AND lease_expires_at > now()",
    )
    .bind(&worker_id)
    .fetch_one(&mut *tx)
    .await?;
    if active >= i64::from(max_slots) {
        tx.commit().await?;
        return Ok(Json(None));
    }
    let row = sqlx::query(
        "SELECT j.job_id,j.attempt,j.lease_epoch,j.public_inputs_json,
                a.package_json,u.manifest_json,u.tenant_id
           FROM beta_proof_jobs j
           JOIN beta_air_packages a ON a.air_package_id=j.air_package_id
           JOIN beta_uploads u ON u.upload_id=j.upload_id
          WHERE j.status='queued' AND j.attempt < 3 AND j.release_sha=$1
            AND j.estimate_json->'resources'->>'scratch_high_water_bytes' IS NOT NULL
            AND (j.estimate_json->'resources'->>'scratch_high_water_bytes')::bigint <= $2 * 70 / 100
          ORDER BY j.created_at
          FOR UPDATE OF j SKIP LOCKED LIMIT 1",
    )
    .bind(&request.release_sha)
    .bind(to_i64(request.free_scratch_bytes)?)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(Json(None));
    };
    let job_id: Uuid = row.get("job_id");
    let attempt = row.get::<i32, _>("attempt") + 1;
    let lease_epoch = row.get::<i64, _>("lease_epoch") + 1;
    sqlx::query(
        "UPDATE beta_proof_jobs SET status='leased',lease_owner=$2,
                lease_expires_at=now()+interval '120 seconds',attempt=$3,lease_epoch=$4,
                started_at=COALESCE(started_at,now()) WHERE job_id=$1",
    )
    .bind(job_id)
    .bind(&worker_id)
    .bind(attempt)
    .bind(lease_epoch)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE beta_sandbox_grants SET entitlement_state='consumed',consumed_at=now()
          WHERE reserved_job_id=$1 AND entitlement_state='reserved'",
    )
    .bind(job_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_job_attempts
             (job_id,attempt,lease_epoch,worker_id,release_sha)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(job_id)
    .bind(attempt)
    .bind(lease_epoch)
    .bind(&worker_id)
    .bind(&request.release_sha)
    .execute(&mut *tx)
    .await?;
    let chunk_rows = sqlx::query(
        "SELECT c.chunk_index,c.object_key FROM beta_upload_chunks c
         JOIN beta_proof_jobs j ON j.upload_id=c.upload_id WHERE j.job_id=$1 ORDER BY c.chunk_index",
    )
    .bind(job_id).fetch_all(&mut *tx).await?;
    tx.commit().await?;

    let mut input_chunks = Vec::with_capacity(chunk_rows.len());
    for chunk in chunk_rows {
        let index =
            u32::try_from(chunk.get::<i32, _>("chunk_index")).map_err(|_| ApiError::Internal)?;
        let object_key: String = chunk.get("object_key");
        let download = state.object_store.presign_download(&object_key).await?;
        input_chunks.push(UploadChunkUrl {
            index,
            object_key,
            upload: download,
        });
    }
    Ok(Json(Some(WorkerClaimResponse {
        job_id,
        attempt: u32::try_from(attempt).map_err(|_| ApiError::Internal)?,
        lease_epoch: u64::try_from(lease_epoch).map_err(|_| ApiError::Internal)?,
        lease_seconds: LEASE_SECONDS,
        air: serde_json::from_value(row.get("package_json")).map_err(|_| ApiError::Internal)?,
        manifest: serde_json::from_value(row.get("manifest_json"))
            .map_err(|_| ApiError::Internal)?,
        public_inputs: serde_json::from_value(row.get("public_inputs_json"))
            .map_err(|_| ApiError::Internal)?,
        input_chunks,
    })))
}

pub async fn startup_validate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WorkerStartupLeaseRequest>,
) -> Result<Json<Option<WorkerClaimResponse>>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    if request.release_sha != state.config.release_sha || !is_digest(&request.checkpoint_identity) {
        return Err(ApiError::Conflict("worker_release_or_checkpoint_mismatch"));
    }
    let row = sqlx::query(
        "UPDATE beta_proof_jobs j SET lease_expires_at=now()+interval '120 seconds'
          FROM beta_air_packages a,beta_uploads u
         WHERE j.job_id=$1 AND j.lease_owner=$2 AND j.attempt=$3 AND j.lease_epoch=$4
           AND j.release_sha=$5 AND j.checkpoint_identity=$6
           AND j.air_package_id=a.air_package_id AND j.upload_id=u.upload_id
           AND j.lease_expires_at > now()
           AND j.status IN ('leased','proving','verifying','cancel_requested')
         RETURNING j.job_id,j.attempt,j.lease_epoch,j.public_inputs_json,
                   a.package_json,u.manifest_json",
    )
    .bind(request.job_id)
    .bind(&worker_id)
    .bind(i32::try_from(request.attempt).map_err(|_| ApiError::Invalid("invalid_attempt"))?)
    .bind(to_i64(request.lease_epoch)?)
    .bind(&request.release_sha)
    .bind(&request.checkpoint_identity)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        return Ok(Json(None));
    };
    let chunk_rows = sqlx::query(
        "SELECT chunk_index,object_key FROM beta_upload_chunks c
          JOIN beta_proof_jobs j ON j.upload_id=c.upload_id
         WHERE j.job_id=$1 ORDER BY chunk_index",
    )
    .bind(request.job_id)
    .fetch_all(&state.pool)
    .await?;
    let mut input_chunks = Vec::with_capacity(chunk_rows.len());
    for chunk in chunk_rows {
        let index =
            u32::try_from(chunk.get::<i32, _>("chunk_index")).map_err(|_| ApiError::Internal)?;
        let object_key: String = chunk.get("object_key");
        let upload = state.object_store.presign_download(&object_key).await?;
        input_chunks.push(UploadChunkUrl {
            index,
            object_key,
            upload,
        });
    }
    Ok(Json(Some(WorkerClaimResponse {
        job_id: request.job_id,
        attempt: request.attempt,
        lease_epoch: request.lease_epoch,
        lease_seconds: LEASE_SECONDS,
        air: serde_json::from_value(row.get("package_json")).map_err(|_| ApiError::Internal)?,
        manifest: serde_json::from_value(row.get("manifest_json"))
            .map_err(|_| ApiError::Internal)?,
        public_inputs: serde_json::from_value(row.get("public_inputs_json"))
            .map_err(|_| ApiError::Internal)?,
        input_chunks,
    })))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<WorkerHeartbeatRequest>,
) -> Result<Json<WorkerHeartbeatResponse>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    if request.total_scratch_bytes == 0 || request.free_scratch_bytes > request.total_scratch_bytes
    {
        return Err(ApiError::Invalid("invalid_worker_storage_report"));
    }
    let checkpoint_identity = request.checkpoint_identity.clone();
    let row = sqlx::query(
        "UPDATE beta_proof_jobs SET
             lease_expires_at=now()+interval '120 seconds',
             progress_json=COALESCE($5,progress_json),
             checkpoint_identity=COALESCE($6,checkpoint_identity),
             status=CASE WHEN status='leased' THEN 'proving' ELSE status END
          WHERE job_id=$1 AND lease_owner=$2 AND attempt=$3 AND lease_epoch=$4
            AND lease_expires_at > now() AND status IN ('leased','proving','verifying','cancel_requested')
          RETURNING status",
    )
    .bind(job_id).bind(&worker_id)
    .bind(i32::try_from(request.attempt).map_err(|_| ApiError::Invalid("invalid_attempt"))?)
    .bind(to_i64(request.lease_epoch)?)
    .bind(request.progress).bind(checkpoint_identity)
    .fetch_optional(&state.pool).await?
    .ok_or(ApiError::Conflict("stale_lease"))?;
    sqlx::query(
        "UPDATE beta_workers SET free_scratch_bytes=$2,total_scratch_bytes=$3,
                last_heartbeat_at=now() WHERE worker_id=$1",
    )
    .bind(&worker_id)
    .bind(to_i64(request.free_scratch_bytes)?)
    .bind(to_i64(request.total_scratch_bytes)?)
    .execute(&state.pool)
    .await?;
    sqlx::query(
        "UPDATE beta_job_attempts SET last_heartbeat_at=now(),checkpoint_identity=COALESCE($4,checkpoint_identity)
          WHERE job_id=$1 AND attempt=$2 AND lease_epoch=$3",
    )
    .bind(job_id).bind(i32::try_from(request.attempt).map_err(|_| ApiError::Internal)?)
    .bind(to_i64(request.lease_epoch)?).bind(request.checkpoint_identity).execute(&state.pool).await?;
    Ok(Json(WorkerHeartbeatResponse {
        lease_seconds: LEASE_SECONDS,
        cancel_requested: row.get::<String, _>("status") == "cancel_requested",
    }))
}

pub async fn output_url(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<WorkerOutputUrlRequest>,
) -> Result<Json<WorkerOutputUrlResponse>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    validate_active_lease(
        &state,
        job_id,
        &worker_id,
        request.attempt,
        request.lease_epoch,
    )
    .await?;
    if request.content_length == 0
        || request.content_length > MAX_AIR_BUNDLE_JSON_BYTES as u64
        || !is_digest(&request.blake3_hex)
    {
        return Err(ApiError::Invalid("invalid_bundle_metadata"));
    }
    let tenant_id: String =
        sqlx::query_scalar("SELECT tenant_id FROM beta_proof_jobs WHERE job_id=$1")
            .bind(job_id)
            .fetch_one(&state.pool)
            .await?;
    let object_key = bundle_object_key(&tenant_id, job_id);
    let upload = state
        .object_store
        .presign_upload(&object_key, request.content_length, &request.blake3_hex)
        .await?;
    Ok(Json(WorkerOutputUrlResponse { object_key, upload }))
}

pub async fn complete(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<WorkerCompleteRequest>,
) -> Result<Json<Value>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    validate_active_lease(
        &state,
        job_id,
        &worker_id,
        request.attempt,
        request.lease_epoch,
    )
    .await?;
    let tenant_id: String =
        sqlx::query_scalar("SELECT tenant_id FROM beta_proof_jobs WHERE job_id=$1")
            .bind(job_id)
            .fetch_one(&state.pool)
            .await?;
    if request.object_key != bundle_object_key(&tenant_id, job_id)
        || !is_digest(&request.blake3_hex)
        || request.content_length == 0
        || request.content_length > MAX_AIR_BUNDLE_JSON_BYTES as u64
    {
        return Err(ApiError::Invalid("invalid_bundle_metadata"));
    }
    let head = state.object_store.head(&request.object_key).await?;
    if head.content_length != request.content_length
        || head.metadata.get("tinyzkp-blake3") != Some(&request.blake3_hex)
    {
        return Err(ApiError::Invalid("bundle_object_mismatch"));
    }
    let bytes = state
        .object_store
        .get(&request.object_key, MAX_AIR_BUNDLE_JSON_BYTES as u64)
        .await?;
    if hex::encode(blake3::hash(&bytes).as_bytes()) != request.blake3_hex {
        return Err(ApiError::Invalid("bundle_digest_mismatch"));
    }
    let bundle: HostedProofBundleV1 =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::Invalid("invalid_hosted_bundle"))?;
    bundle
        .verify()
        .map_err(|_| ApiError::Invalid("official_verification_failed"))?;
    if bundle.proof.provenance.release_sha != state.config.release_sha {
        return Err(ApiError::Conflict("bundle_release_mismatch"));
    }
    let retail_charge = hosted_charge_millicredits(&bundle.resource_report);
    let measured_cost = hosted_measured_cost_millicredits(&bundle.resource_report);

    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT status,lease_owner,attempt,lease_epoch,reserved_millicredits,
                reserved_subscription_millicredits,reserved_purchased_millicredits,
                public_inputs_digest_hex,sandbox_job
           FROM beta_proof_jobs WHERE job_id=$1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure_lease_row(&row, &worker_id, request.attempt, request.lease_epoch)?;
    let expected_public: String = row.get("public_inputs_digest_hex");
    if bundle.proof.public_inputs_digest_hex != expected_public {
        return Err(ApiError::Invalid("bundle_statement_mismatch"));
    }
    let sandbox_job: bool = row.get("sandbox_job");
    let charge = if sandbox_job { 0 } else { retail_charge };
    let margin_bps = if sandbox_job {
        -100_000
    } else {
        i32::try_from(charge.saturating_sub(measured_cost).saturating_mul(10_000) / charge.max(1))
            .map_err(|_| ApiError::Internal)?
    };
    let reserved = as_u64(row.get("reserved_millicredits"))?;
    if !sandbox_job && charge > reserved {
        release_reservation(&mut tx, &tenant_id, job_id, &row, "platform_failed").await?;
        sqlx::query("UPDATE beta_proof_jobs SET error_code='estimate_overflow' WHERE job_id=$1")
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(ApiError::Unavailable("estimate_overflow"));
    }
    let reserved_sub = as_u64(row.get("reserved_subscription_millicredits"))?;
    let reserved_purchased = as_u64(row.get("reserved_purchased_millicredits"))?;
    let charged_sub = reserved_sub.min(charge);
    let charged_purchased = charge - charged_sub;
    let refund_sub = reserved_sub - charged_sub;
    let refund_purchased = reserved_purchased - charged_purchased;
    sqlx::query(
        "UPDATE beta_credit_accounts SET
             subscription_millicredits=subscription_millicredits+$2,
             purchased_millicredits=purchased_millicredits+$3,
             reserved_millicredits=reserved_millicredits-$4,
             version=version+1,updated_at=now() WHERE tenant_id=$1",
    )
    .bind(&tenant_id)
    .bind(to_i64(refund_sub)?)
    .bind(to_i64(refund_purchased)?)
    .bind(to_i64(reserved)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE beta_proof_jobs SET status='completed',verification_succeeded=true,
             settled_millicredits=$2,measured_cost_millicredits=$3,
             resource_report_json=$4,realized_gross_margin_bps=$5,
             proof_object_key=$6,proof_digest_hex=$7,proof_size_bytes=$8,
             completed_at=now(),lease_expires_at=NULL WHERE job_id=$1",
    )
    .bind(job_id)
    .bind(to_i64(charge)?)
    .bind(to_i64(measured_cost)?)
    .bind(serde_json::to_value(&bundle.resource_report).map_err(|_| ApiError::Internal)?)
    .bind(margin_bps)
    .bind(&request.object_key)
    .bind(&request.blake3_hex)
    .bind(to_i64(request.content_length)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_credit_events
             (event_id,tenant_id,event_type,subscription_delta_millicredits,
              purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key,metadata)
         VALUES ($1,$2,'settlement',$3,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::new_v4()).bind(&tenant_id).bind(to_i64(refund_sub)?).bind(to_i64(refund_purchased)?)
    .bind(-to_i64(reserved)?).bind(job_id).bind(format!("job:{job_id}:settlement"))
    .bind(json!({"charged_millicredits":charge,"retail_value_millicredits":retail_charge,
                 "measured_cost_millicredits":measured_cost,"realized_gross_margin_bps":margin_bps,
                 "sandbox_job":sandbox_job,"verified":true})).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE beta_job_attempts SET ended_at=now(),result='completed'
          WHERE job_id=$1 AND attempt=$2 AND lease_epoch=$3",
    )
    .bind(job_id)
    .bind(i32::try_from(request.attempt).map_err(|_| ApiError::Internal)?)
    .bind(to_i64(request.lease_epoch)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"job_id":job_id,"status":"completed","charge_millicredits":charge}),
    ))
}

pub async fn cancelled(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<WorkerFailureRequest>,
) -> Result<Json<Value>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    terminal_failure(
        &state,
        job_id,
        &worker_id,
        request.attempt,
        request.lease_epoch,
        "cancelled",
        &request.code,
    )
    .await?;
    Ok(Json(json!({"job_id":job_id,"status":"cancelled"})))
}

pub async fn failure(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<WorkerFailureRequest>,
) -> Result<Json<Value>, ApiError> {
    let worker_id = auth::authenticate_worker(&headers, &state).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT tenant_id,status,lease_owner,attempt,lease_epoch,checkpoint_identity,
                reserved_subscription_millicredits,reserved_purchased_millicredits
           FROM beta_proof_jobs WHERE job_id=$1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure_lease_row(&row, &worker_id, request.attempt, request.lease_epoch)?;
    let attempt = row.get::<i32, _>("attempt");
    let checkpoint_identity: Option<String> = row.get("checkpoint_identity");
    let status = if request.retryable
        && attempt < 3
        && request.code == "prover_interrupted"
        && checkpoint_identity.as_deref().is_some_and(is_digest)
    {
        sqlx::query(
            "UPDATE beta_proof_jobs SET status='queued',lease_owner=NULL,lease_expires_at=NULL,
                    progress_json=NULL,error_code=$2 WHERE job_id=$1",
        )
        .bind(job_id)
        .bind(&request.code)
        .execute(&mut *tx)
        .await?;
        "queued"
    } else {
        let tenant_id: String = row.get("tenant_id");
        let terminal = if request.code == "invalid_customer_artifact" {
            "customer_failed"
        } else {
            "platform_failed"
        };
        release_reservation(&mut tx, &tenant_id, job_id, &row, terminal).await?;
        sqlx::query("UPDATE beta_proof_jobs SET error_code=$2 WHERE job_id=$1")
            .bind(job_id)
            .bind(&request.code)
            .execute(&mut *tx)
            .await?;
        terminal
    };
    sqlx::query(
        "UPDATE beta_job_attempts SET ended_at=now(),result=$4
          WHERE job_id=$1 AND attempt=$2 AND lease_epoch=$3",
    )
    .bind(job_id)
    .bind(i32::try_from(request.attempt).map_err(|_| ApiError::Internal)?)
    .bind(to_i64(request.lease_epoch)?)
    .bind(status)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"job_id":job_id,"status":status})))
}

async fn terminal_failure(
    state: &AppState,
    job_id: Uuid,
    worker_id: &str,
    attempt: u32,
    lease_epoch: u64,
    final_status: &str,
    code: &str,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT tenant_id,status,lease_owner,attempt,lease_epoch,
                reserved_subscription_millicredits,reserved_purchased_millicredits
           FROM beta_proof_jobs WHERE job_id=$1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure_lease_row(&row, worker_id, attempt, lease_epoch)?;
    let tenant_id: String = row.get("tenant_id");
    release_reservation(&mut tx, &tenant_id, job_id, &row, final_status).await?;
    sqlx::query("UPDATE beta_proof_jobs SET error_code=$2 WHERE job_id=$1")
        .bind(job_id)
        .bind(code)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE beta_job_attempts SET ended_at=now(),result=$4
          WHERE job_id=$1 AND attempt=$2 AND lease_epoch=$3",
    )
    .bind(job_id)
    .bind(i32::try_from(attempt).map_err(|_| ApiError::Internal)?)
    .bind(to_i64(lease_epoch)?)
    .bind(final_status)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn validate_active_lease(
    state: &AppState,
    job_id: Uuid,
    worker_id: &str,
    attempt: u32,
    lease_epoch: u64,
) -> Result<(), ApiError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM beta_proof_jobs
          WHERE job_id=$1 AND lease_owner=$2 AND attempt=$3 AND lease_epoch=$4
            AND lease_expires_at > now() AND status IN ('leased','proving','verifying'))",
    )
    .bind(job_id)
    .bind(worker_id)
    .bind(i32::try_from(attempt).map_err(|_| ApiError::Invalid("invalid_attempt"))?)
    .bind(to_i64(lease_epoch)?)
    .fetch_one(&state.pool)
    .await?;
    if valid {
        Ok(())
    } else {
        Err(ApiError::Conflict("stale_lease"))
    }
}

fn ensure_lease_row(
    row: &sqlx::postgres::PgRow,
    worker_id: &str,
    attempt: u32,
    lease_epoch: u64,
) -> Result<(), ApiError> {
    let status: String = row.get("status");
    if row.get::<Option<String>, _>("lease_owner").as_deref() != Some(worker_id)
        || row.get::<i32, _>("attempt")
            != i32::try_from(attempt).map_err(|_| ApiError::Invalid("invalid_attempt"))?
        || row.get::<i64, _>("lease_epoch") != to_i64(lease_epoch)?
        || !matches!(
            status.as_str(),
            "leased" | "proving" | "verifying" | "cancel_requested"
        )
    {
        return Err(ApiError::Conflict("stale_lease"));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_canonical_lower_hex() {
        assert!(is_digest(&"a".repeat(64)));
        assert!(!is_digest(&"A".repeat(64)));
        assert!(!is_digest("../bundle"));
    }

    #[test]
    fn expired_leases_requeue_only_valid_retryable_checkpoints() {
        let digest = "a".repeat(64);
        assert_eq!(
            expired_lease_action("proving", 1, Some(&digest)),
            ExpiredLeaseAction::Requeue
        );
        assert_eq!(
            expired_lease_action("proving", MAX_ATTEMPTS, Some(&digest)),
            ExpiredLeaseAction::PlatformFail
        );
        assert_eq!(
            expired_lease_action("proving", 1, Some("not-a-digest")),
            ExpiredLeaseAction::PlatformFail
        );
        assert_eq!(
            expired_lease_action("cancel_requested", 1, Some(&digest)),
            ExpiredLeaseAction::Cancel
        );
    }
}
