use crate::{
    auth,
    config::ExposureMode,
    error::ApiError,
    idempotency::{self, IdempotencyOutcome},
    models::*,
    object_store::upload_object_key,
    AppState, Tenant,
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::Engine;
use hc_plonky3::{
    contracts::{AirPackageV1, PublicInputsV1, TraceManifestV1},
    estimate_declarative_statement,
};
use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const MAX_PREDICTED_RSS: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PREDICTED_WALL_MS: u64 = 60 * 60 * 1000;

#[derive(Deserialize)]
pub struct GithubStartQuery {
    #[serde(default = "default_return_path")]
    return_path: String,
}

fn default_return_path() -> String {
    "/dashboard".to_owned()
}

#[derive(Deserialize)]
pub struct GithubCallbackQuery {
    code: String,
    state: String,
}

pub async fn github_start(
    State(state): State<AppState>,
    Query(query): Query<GithubStartQuery>,
) -> Result<Redirect, ApiError> {
    ensure_writes(&state)?;
    if !query.return_path.starts_with('/') || query.return_path.starts_with("//") {
        return Err(ApiError::Invalid("invalid_return_path"));
    }
    let oauth_state = auth::random_token(32);
    let verifier = auth::random_token(64);
    let challenge = auth::pkce_challenge(&verifier);
    let encrypted = auth::encrypt_verifier(&state.config.oauth_cipher_key, &verifier)?;
    sqlx::query(
        "INSERT INTO beta_oauth_states
             (state_hash, pkce_verifier_ciphertext, return_path, expires_at)
         VALUES ($1,$2,$3,now() + interval '10 minutes')",
    )
    .bind(auth::plain_sha256(&oauth_state))
    .bind(encrypted)
    .bind(&query.return_path)
    .execute(&state.pool)
    .await?;
    let url = state.github.authorization_url(&oauth_state, &challenge)?;
    Ok(Redirect::temporary(&url))
}

pub async fn github_callback(
    State(state): State<AppState>,
    Query(query): Query<GithubCallbackQuery>,
) -> Result<Response, ApiError> {
    ensure_writes(&state)?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "UPDATE beta_oauth_states SET consumed_at=now()
          WHERE state_hash=$1 AND consumed_at IS NULL AND expires_at > now()
          RETURNING pkce_verifier_ciphertext, return_path",
    )
    .bind(auth::plain_sha256(&query.state))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    let encrypted: Vec<u8> = row.get("pkce_verifier_ciphertext");
    let return_path: String = row.get("return_path");
    tx.commit().await?;

    let verifier = auth::decrypt_verifier(&state.config.oauth_cipher_key, &encrypted)?;
    let access_token = state.github.exchange(&query.code, &verifier).await?;
    let (user, verified_email) = state.github.identity(&access_token).await?;
    let github_id = user.id.to_string();
    if state.config.exposure == ExposureMode::DarkCanary
        && !state
            .config
            .operator_allowlist
            .iter()
            .any(|id| id == &github_id)
    {
        return Err(ApiError::Unavailable("operator_canary_only"));
    }

    let mut tx = state.pool.begin().await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM beta_auth_identities
          WHERE provider='github' AND provider_user_id=$1 FOR UPDATE",
    )
    .bind(&github_id)
    .fetch_optional(&mut *tx)
    .await?;
    let tenant_id = existing.unwrap_or_else(|| format!("tenant_{}", Uuid::new_v4().simple()));
    let now_ms = now_millis();
    sqlx::query(
        "INSERT INTO tenants
             (tenant_id,email,status,plan,created_at_ms,updated_at_ms)
         VALUES ($1,$2,'active','sandbox',$3,$3)
         ON CONFLICT (tenant_id) DO UPDATE
             SET email=EXCLUDED.email,status='active',updated_at_ms=EXCLUDED.updated_at_ms",
    )
    .bind(&tenant_id)
    .bind(&verified_email)
    .bind(now_ms)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_auth_identities
             (provider,provider_user_id,tenant_id,provider_login,verified_email)
         VALUES ('github',$1,$2,$3,$4)
         ON CONFLICT (provider,provider_user_id) DO UPDATE SET
             provider_login=EXCLUDED.provider_login,
             verified_email=EXCLUDED.verified_email,
             updated_at=now()",
    )
    .bind(&github_id)
    .bind(&tenant_id)
    .bind(&user.login)
    .bind(&verified_email)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO beta_credit_accounts (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await?;
    let granted = sqlx::query(
        "INSERT INTO beta_sandbox_grants (provider,provider_user_id,original_tenant_id)
         VALUES ('github',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(&github_id)
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if granted {
        sqlx::query(
            "UPDATE beta_credit_accounts SET purchased_millicredits=purchased_millicredits+1000,
                    version=version+1,updated_at=now() WHERE tenant_id=$1",
        )
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO beta_credit_events
                 (event_id,tenant_id,event_type,purchased_delta_millicredits,operation_key,metadata)
             VALUES ($1,$2,'sandbox_grant',1000,$3,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant_id)
        .bind(format!("sandbox:github:{github_id}"))
        .bind(json!({"provider":"github","provider_user_id":github_id}))
        .execute(&mut *tx)
        .await?;
    }
    let session = auth::random_token(32);
    sqlx::query(
        "INSERT INTO beta_sessions (session_hash,tenant_id,expires_at)
         VALUES ($1,$2,now() + interval '30 days')",
    )
    .bind(auth::secret_hash(&state.config.secret_pepper, &session))
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let location = format!(
        "{}{}",
        state.config.dashboard_url.trim_end_matches('/'),
        return_path
    );
    let cookie = format!(
        "__Host-tinyzkp_beta={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000"
    );
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Internal)?,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError::Internal)?,
    );
    Ok(response)
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let row = sqlx::query(
        "SELECT subscription_millicredits,purchased_millicredits,reserved_millicredits,paid_work_frozen
           FROM beta_credit_accounts WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(MeResponse {
        tenant_id: tenant.tenant_id,
        plan: tenant.plan,
        subscription_millicredits: as_u64(row.get::<i64, _>("subscription_millicredits"))?,
        purchased_millicredits: as_u64(row.get::<i64, _>("purchased_millicredits"))?,
        reserved_millicredits: as_u64(row.get::<i64, _>("reserved_millicredits"))?,
        paid_work_frozen: row.get("paid_work_frozen"),
    }))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Response, ApiError> {
    ensure_writes(&state)?;
    let tenant = auth::authenticate(&headers, &state).await?;
    let key = idempotency_key(&headers)?;
    if request.label.trim().is_empty() || request.label.len() > 80 {
        return Err(ApiError::Invalid("invalid_api_key_label"));
    }
    let hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    match idempotency::begin(&mut tx, &tenant.tenant_id, "create_api_key", key, &hash).await? {
        IdempotencyOutcome::Replay { status, mut body } => {
            tx.commit().await?;
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "key".into(),
                    Value::String(derive_api_key(&state, &tenant, key)),
                );
            }
            return idempotency::replay(status, body);
        }
        IdempotencyOutcome::New => {}
    }
    let raw = derive_api_key(&state, &tenant, key);
    let id = Uuid::new_v4();
    let prefix = raw.chars().take(14).collect::<String>();
    sqlx::query(
        "INSERT INTO beta_api_keys (api_key_id,tenant_id,key_hash,key_prefix,label)
         VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .bind(auth::secret_hash(&state.config.secret_pepper, &raw))
    .bind(&prefix)
    .bind(request.label.trim())
    .execute(&mut *tx)
    .await?;
    let response = ApiKeyResponse {
        id,
        prefix,
        key: raw,
    };
    let stored = json!({"id":id,"prefix":response.prefix});
    sqlx::query(
        "UPDATE beta_idempotency_keys SET response_status=201,response_json=$4,resource_id=$5
          WHERE tenant_id=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(&tenant.tenant_id)
    .bind("create_api_key")
    .bind(key)
    .bind(stored)
    .bind(id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let changed = sqlx::query(
        "UPDATE beta_api_keys SET revoked_at=COALESCE(revoked_at,now())
          WHERE api_key_id=$1 AND tenant_id=$2",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if changed == 0 {
        Err(ApiError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let mut tx = state.pool.begin().await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM beta_proof_jobs WHERE tenant_id=$1
          AND status IN ('queued','leased','proving','verifying','cancel_requested')",
    )
    .bind(&tenant.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    if active != 0 {
        return Err(ApiError::Conflict("active_jobs_exist"));
    }
    sqlx::query(
        "UPDATE beta_api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE beta_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_retention_deletions
             (deletion_id,tenant_id,object_key,resource_kind,resource_id,not_before)
         SELECT md5(c.object_key)::uuid,u.tenant_id,c.object_key,'trace',u.upload_id,now()
           FROM beta_uploads u JOIN beta_upload_chunks c ON c.upload_id=u.upload_id
          WHERE u.tenant_id=$1 AND u.deleted_at IS NULL
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(&tenant.tenant_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM beta_auth_identities WHERE tenant_id=$1")
        .bind(&tenant.tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE tenants SET status='deleted',email=NULL,deleted_at=now(),updated_at_ms=$2
          WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .bind(now_millis())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn register_air(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterAirRequest>,
) -> Result<Response, ApiError> {
    ensure_writes(&state)?;
    let tenant = auth::authenticate(&headers, &state).await?;
    let key = idempotency_key(&headers)?;
    if request.local_proof.air != request.air
        || request
            .local_proof
            .verify_local_registration_proof()
            .is_err()
        || request.local_proof.provenance.release_sha != state.config.release_sha
    {
        return Err(ApiError::Invalid("invalid_local_registration_proof"));
    }
    let air_digest_hex = hex::encode(
        request
            .air
            .digest()
            .map_err(|_| ApiError::Invalid("invalid_air"))?,
    );
    let hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } =
        idempotency::begin(&mut tx, &tenant.tenant_id, "register_air", key, &hash).await?
    {
        tx.commit().await?;
        return idempotency::replay(status, body);
    }
    let id = Uuid::new_v4();
    let package_json = serde_json::to_value(&request.air).map_err(|_| ApiError::Internal)?;
    let row = sqlx::query(
        "INSERT INTO beta_air_packages
             (air_package_id,tenant_id,air_digest_hex,package_json,release_sha)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id,air_digest_hex) DO UPDATE SET package_json=EXCLUDED.package_json
         RETURNING air_package_id",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .bind(&air_digest_hex)
    .bind(package_json)
    .bind(&state.config.release_sha)
    .fetch_one(&mut *tx)
    .await?;
    let actual_id: Uuid = row.get("air_package_id");
    let response = RegisterAirResponse {
        air_package_id: actual_id,
        air_digest_hex,
        release_sha: state.config.release_sha.clone(),
    };
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "register_air",
        key,
        StatusCode::CREATED,
        &response,
        Some(&actual_id.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn create_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUploadRequest>,
) -> Result<Response, ApiError> {
    ensure_writes(&state)?;
    let tenant = auth::authenticate(&headers, &state).await?;
    let key = idempotency_key(&headers)?;
    let row = sqlx::query(
        "SELECT package_json FROM beta_air_packages
          WHERE air_package_id=$1 AND tenant_id=$2",
    )
    .bind(request.air_package_id)
    .bind(&tenant.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let air: AirPackageV1 =
        serde_json::from_value(row.get("package_json")).map_err(|_| ApiError::Internal)?;
    request
        .manifest
        .validate_for_air(&air)
        .map_err(|_| ApiError::Invalid("invalid_trace_manifest"))?;
    let hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } =
        idempotency::begin(&mut tx, &tenant.tenant_id, "create_upload", key, &hash).await?
    {
        tx.commit().await?;
        return idempotency::replay(status, body);
    }
    let upload_id = Uuid::new_v4();
    let prefix = format!("tenants/{}/uploads/{upload_id}", tenant.tenant_id);
    sqlx::query(
        "INSERT INTO beta_uploads
             (upload_id,tenant_id,air_package_id,trace_digest_hex,manifest_json,object_prefix,status,expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,'pending',now()+interval '24 hours')",
    )
    .bind(upload_id)
    .bind(&tenant.tenant_id)
    .bind(request.air_package_id)
    .bind(&request.manifest.trace_digest_hex)
    .bind(serde_json::to_value(&request.manifest).map_err(|_| ApiError::Internal)?)
    .bind(&prefix)
    .execute(&mut *tx)
    .await?;
    let mut urls = Vec::with_capacity(request.manifest.chunks.len());
    for chunk in &request.manifest.chunks {
        let object_key = upload_object_key(&tenant.tenant_id, upload_id, chunk.index);
        sqlx::query(
            "INSERT INTO beta_upload_chunks
                 (upload_id,chunk_index,object_key,compressed_bytes,uncompressed_bytes,blake3_hex)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(upload_id)
        .bind(i32::try_from(chunk.index).map_err(|_| ApiError::Invalid("invalid_chunk_index"))?)
        .bind(&object_key)
        .bind(
            i64::try_from(chunk.compressed_bytes)
                .map_err(|_| ApiError::Invalid("upload_too_large"))?,
        )
        .bind(
            i64::try_from(chunk.uncompressed_bytes)
                .map_err(|_| ApiError::Invalid("upload_too_large"))?,
        )
        .bind(&chunk.blake3_hex)
        .execute(&mut *tx)
        .await?;
        let upload = state
            .object_store
            .presign_upload(&object_key, chunk.compressed_bytes, &chunk.blake3_hex)
            .await?;
        urls.push(UploadChunkUrl {
            index: chunk.index,
            object_key,
            upload,
        });
    }
    let response = CreateUploadResponse {
        upload_id,
        expires_in_seconds: 900,
        chunks: urls,
    };
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "create_upload",
        key,
        StatusCode::CREATED,
        &response,
        Some(&upload_id.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn create_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateJobRequest>,
) -> Result<Response, ApiError> {
    ensure_writes(&state)?;
    let tenant = auth::authenticate(&headers, &state).await?;
    if tenant.plan == "sandbox" {
        return Err(ApiError::PaymentRequired);
    }
    let key = idempotency_key(&headers)?;
    let row = sqlx::query(
        "SELECT a.package_json,u.manifest_json,u.status,u.expires_at
           FROM beta_air_packages a JOIN beta_uploads u ON u.air_package_id=a.air_package_id
          WHERE a.air_package_id=$1 AND u.upload_id=$2
            AND a.tenant_id=$3 AND u.tenant_id=$3
            AND u.status IN ('pending','complete') AND u.expires_at > now()",
    )
    .bind(request.air_package_id)
    .bind(request.upload_id)
    .bind(&tenant.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let air: AirPackageV1 =
        serde_json::from_value(row.get("package_json")).map_err(|_| ApiError::Internal)?;
    let manifest: TraceManifestV1 =
        serde_json::from_value(row.get("manifest_json")).map_err(|_| ApiError::Internal)?;
    request
        .public_inputs
        .validate_for_air(&air)
        .map_err(|_| ApiError::Invalid("invalid_public_inputs"))?;
    verify_uploaded_chunks(&state, request.upload_id).await?;

    let worker_free: Option<i64> = sqlx::query_scalar(
        "SELECT max(free_scratch_bytes) FROM beta_workers
          WHERE enabled AND release_sha=$1 AND last_heartbeat_at > now()-interval '90 seconds'",
    )
    .bind(&state.config.release_sha)
    .fetch_one(&state.pool)
    .await?;
    let worker_free = worker_free
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(ApiError::Unavailable("no_healthy_worker"))?;
    let estimate = admission_estimate(&air, &manifest, &request.public_inputs)?;
    if estimate.resources.peak_resident_bytes > MAX_PREDICTED_RSS
        || estimate.predicted_wall_time_ms > MAX_PREDICTED_WALL_MS
        || estimate.resources.scratch_high_water_bytes > worker_free.saturating_mul(70) / 100
    {
        return Err(ApiError::Invalid("job_exceeds_beta_limits"));
    }
    let hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } =
        idempotency::begin(&mut tx, &tenant.tenant_id, "create_job", key, &hash).await?
    {
        tx.commit().await?;
        return idempotency::replay(status, body);
    }
    let account = sqlx::query(
        "SELECT subscription_millicredits,purchased_millicredits,paid_work_frozen
           FROM beta_credit_accounts WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(&tenant.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    if account.get::<bool, _>("paid_work_frozen") {
        return Err(ApiError::Unavailable("paid_work_frozen"));
    }
    let concurrency_limit = plan_concurrency(&tenant.plan);
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM beta_proof_jobs WHERE tenant_id=$1
          AND status IN ('queued','leased','proving','verifying','cancel_requested')",
    )
    .bind(&tenant.tenant_id)
    .fetch_one(&mut *tx)
    .await?;
    if active >= i64::from(concurrency_limit) {
        return Err(ApiError::Conflict("plan_concurrency_exceeded"));
    }
    let subscription = as_u64(account.get("subscription_millicredits"))?;
    let purchased = as_u64(account.get("purchased_millicredits"))?;
    if subscription.saturating_add(purchased) < estimate.reservation_millicredits {
        return Err(ApiError::PaymentRequired);
    }
    let reserved_subscription = subscription.min(estimate.reservation_millicredits);
    let reserved_purchased = estimate.reservation_millicredits - reserved_subscription;
    let job_id = Uuid::new_v4();
    let retention_days = plan_retention_days(&tenant.plan);
    let public_inputs_digest_hex = hex::encode(
        request
            .public_inputs
            .digest(&air)
            .map_err(|_| ApiError::Invalid("invalid_public_inputs"))?,
    );
    sqlx::query(
        "UPDATE beta_credit_accounts SET
             subscription_millicredits=subscription_millicredits-$2,
             purchased_millicredits=purchased_millicredits-$3,
             reserved_millicredits=reserved_millicredits+$4,
             version=version+1,updated_at=now()
          WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .bind(to_i64(reserved_subscription)?)
    .bind(to_i64(reserved_purchased)?)
    .bind(to_i64(estimate.reservation_millicredits)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_proof_jobs
             (job_id,tenant_id,air_package_id,upload_id,status,estimate_json,
              public_inputs_json,public_inputs_digest_hex,reserved_millicredits,
              reserved_subscription_millicredits,reserved_purchased_millicredits,
              release_sha,retention_expires_at)
         VALUES ($1,$2,$3,$4,'queued',$5,$6,$7,$8,$9,$10,$11,
                 now()+make_interval(days=>$12))",
    )
    .bind(job_id)
    .bind(&tenant.tenant_id)
    .bind(request.air_package_id)
    .bind(request.upload_id)
    .bind(serde_json::to_value(&estimate).map_err(|_| ApiError::Internal)?)
    .bind(serde_json::to_value(&request.public_inputs).map_err(|_| ApiError::Internal)?)
    .bind(public_inputs_digest_hex)
    .bind(to_i64(estimate.reservation_millicredits)?)
    .bind(to_i64(reserved_subscription)?)
    .bind(to_i64(reserved_purchased)?)
    .bind(&state.config.release_sha)
    .bind(retention_days)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO beta_credit_events
             (event_id,tenant_id,event_type,subscription_delta_millicredits,
              purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key,metadata)
         VALUES ($1,$2,'reservation',$3,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::new_v4())
    .bind(&tenant.tenant_id)
    .bind(-to_i64(reserved_subscription)?)
    .bind(-to_i64(reserved_purchased)?)
    .bind(to_i64(estimate.reservation_millicredits)?)
    .bind(job_id)
    .bind(format!("job:{job_id}:reservation"))
    .bind(json!({"quote_millicredits":estimate.quoted_charge_millicredits}))
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE beta_uploads SET status='complete',completed_at=COALESCE(completed_at,now()) WHERE upload_id=$1")
        .bind(request.upload_id).execute(&mut *tx).await?;
    let response = CreateJobResponse {
        job_id,
        status: "queued".into(),
        estimate,
    };
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "create_job",
        key,
        StatusCode::CREATED,
        &response,
        Some(&job_id.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn get_job(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<JobResponse>, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let row = sqlx::query(
        "SELECT status,estimate_json,progress_json,settled_millicredits,error_code
           FROM beta_proof_jobs WHERE job_id=$1 AND tenant_id=$2",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(JobResponse {
        job_id: id,
        status: row.get("status"),
        estimate: serde_json::from_value(row.get("estimate_json"))
            .map_err(|_| ApiError::Internal)?,
        progress: row.get("progress_json"),
        settled_millicredits: row
            .get::<Option<i64>, _>("settled_millicredits")
            .map(as_u64)
            .transpose()?,
        error_code: row.get("error_code"),
    }))
}

pub async fn cancel_job(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let key = idempotency_key(&headers)?;
    let mut tx = state.pool.begin().await?;
    let hash = hex::encode(sha2::Sha256::digest(id.as_bytes()));
    if let IdempotencyOutcome::Replay { status: _, body } =
        idempotency::begin(&mut tx, &tenant.tenant_id, "cancel_job", key, &hash).await?
    {
        tx.commit().await?;
        return Ok(Json(body));
    }
    let row = sqlx::query(
        "SELECT status,reserved_subscription_millicredits,reserved_purchased_millicredits
           FROM beta_proof_jobs WHERE job_id=$1 AND tenant_id=$2 FOR UPDATE",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let status: String = row.get("status");
    let new_status = match status.as_str() {
        "queued" => {
            release_reservation(&mut tx, &tenant.tenant_id, id, &row, "cancelled").await?;
            "cancelled"
        }
        "leased" | "proving" | "verifying" => {
            sqlx::query("UPDATE beta_proof_jobs SET status='cancel_requested' WHERE job_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            "cancel_requested"
        }
        "cancel_requested" | "cancelled" => status.as_str(),
        "completed" | "platform_failed" | "customer_failed" => {
            return Err(ApiError::Conflict("job_already_terminal"));
        }
        _ => return Err(ApiError::Internal),
    };
    let response = json!({"job_id":id,"status":new_status});
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "cancel_job",
        key,
        StatusCode::OK,
        &response,
        Some(&id.to_string()),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(response))
}

pub async fn get_bundle(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<BundleResponse>, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    let row = sqlx::query(
        "SELECT proof_object_key,proof_digest_hex,proof_size_bytes
           FROM beta_proof_jobs WHERE job_id=$1 AND tenant_id=$2 AND status='completed'",
    )
    .bind(id)
    .bind(&tenant.tenant_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.get("proof_object_key");
    let download = state.object_store.presign_download(&object_key).await?;
    Ok(Json(BundleResponse {
        download,
        size_bytes: as_u64(row.get::<i64, _>("proof_size_bytes"))?,
        blake3_hex: row.get("proof_digest_hex"),
    }))
}

pub async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let _permit = state
        .verify_slots
        .try_acquire()
        .map_err(|_| ApiError::RateLimited)?;
    request
        .bundle
        .verify()
        .map_err(|_| ApiError::Invalid("verification_failed"))?;
    Ok(Json(VerifyResponse {
        valid: true,
        proof_digest_hex: request.bundle.proof.proof_digest_hex,
    }))
}

async fn verify_uploaded_chunks(state: &AppState, upload_id: Uuid) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "SELECT chunk_index,object_key,compressed_bytes,blake3_hex
           FROM beta_upload_chunks WHERE upload_id=$1 ORDER BY chunk_index",
    )
    .bind(upload_id)
    .fetch_all(&state.pool)
    .await?;
    if rows.is_empty() {
        return Err(ApiError::Invalid("upload_has_no_chunks"));
    }
    for row in rows {
        let key: String = row.get("object_key");
        let expected_length = as_u64(row.get::<i64, _>("compressed_bytes"))?;
        let expected_digest: String = row.get("blake3_hex");
        let head = state.object_store.head(&key).await?;
        if head.content_length != expected_length
            || head.metadata.get("tinyzkp-blake3") != Some(&expected_digest)
        {
            return Err(ApiError::Invalid("upload_chunk_metadata_mismatch"));
        }
        sqlx::query(
            "UPDATE beta_upload_chunks SET object_etag=$3,verified_at=now()
              WHERE upload_id=$1 AND chunk_index=$2",
        )
        .bind(upload_id)
        .bind(row.get::<i32, _>("chunk_index"))
        .bind(head.etag)
        .execute(&state.pool)
        .await?;
    }
    Ok(())
}

fn admission_estimate(
    air: &AirPackageV1,
    manifest: &TraceManifestV1,
    public_inputs: &PublicInputsV1,
) -> Result<AdmissionEstimate, ApiError> {
    let policy = ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: MAX_PREDICTED_RSS,
        max_scratch_bytes: 1024 * 1024 * 1024 * 1024,
        scratch_dir: PathBuf::from("/scratch"),
        max_threads: 2,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    };
    let resources = estimate_declarative_statement(
        air.clone(),
        manifest.logical_rows,
        &public_inputs.values,
        &policy,
    )
    .map_err(|_| ApiError::Invalid("unsupported_resource_estimate"))?;
    let expression_work =
        u64::try_from(air.expressions.len() + air.constraints.len() + air.trace_width as usize)
            .map_err(|_| ApiError::Invalid("air_too_large"))?;
    let predicted_wall_time_ms = manifest
        .logical_rows
        .saturating_mul(expression_work)
        .div_ceil(50_000)
        .max(1_000);
    let compute_cost_millicredits = predicted_wall_time_ms
        .saturating_mul(250)
        .div_ceil(3_600_000);
    let io_gib = resources
        .total_read_bytes
        .saturating_add(resources.total_write_bytes)
        .div_ceil(1024 * 1024 * 1024);
    let measured_cost = compute_cost_millicredits.saturating_add(io_gib).max(3);
    let with_operations_reserve = measured_cost.saturating_mul(120).div_ceil(100);
    let quoted_charge_millicredits = with_operations_reserve
        .saturating_mul(100)
        .div_ceil(30)
        .max(10);
    let reservation_millicredits = quoted_charge_millicredits.saturating_mul(125).div_ceil(100);
    Ok(AdmissionEstimate {
        resources,
        predicted_wall_time_ms,
        quoted_charge_millicredits,
        reservation_millicredits,
    })
}

pub(crate) async fn release_reservation(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    job_id: Uuid,
    row: &sqlx::postgres::PgRow,
    final_status: &str,
) -> Result<(), ApiError> {
    let subscription = as_u64(row.get::<i64, _>("reserved_subscription_millicredits"))?;
    let purchased = as_u64(row.get::<i64, _>("reserved_purchased_millicredits"))?;
    let total = subscription + purchased;
    sqlx::query(
        "UPDATE beta_credit_accounts SET
             subscription_millicredits=subscription_millicredits+$2,
             purchased_millicredits=purchased_millicredits+$3,
             reserved_millicredits=reserved_millicredits-$4,
             version=version+1,updated_at=now() WHERE tenant_id=$1",
    )
    .bind(tenant_id)
    .bind(to_i64(subscription)?)
    .bind(to_i64(purchased)?)
    .bind(to_i64(total)?)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE beta_proof_jobs SET status=$2,cancelled_at=CASE WHEN $2='cancelled' THEN now() ELSE cancelled_at END,
                completed_at=now() WHERE job_id=$1",
    )
    .bind(job_id).bind(final_status).execute(&mut **tx).await?;
    sqlx::query(
        "INSERT INTO beta_credit_events
             (event_id,tenant_id,event_type,subscription_delta_millicredits,
              purchased_delta_millicredits,reserved_delta_millicredits,job_id,operation_key,metadata)
         VALUES ($1,$2,'reservation_release',$3,$4,$5,$6,$7,$8)
         ON CONFLICT (tenant_id,operation_key) DO NOTHING",
    )
    .bind(Uuid::new_v4()).bind(tenant_id).bind(to_i64(subscription)?).bind(to_i64(purchased)?)
    .bind(-to_i64(total)?).bind(job_id).bind(format!("job:{job_id}:release"))
    .bind(json!({"reason":final_status})).execute(&mut **tx).await?;
    Ok(())
}

fn plan_concurrency(plan: &str) -> u32 {
    match plan {
        "builder" => 1,
        "pro" => 2,
        "scale_beta" => 4,
        _ => 0,
    }
}

fn plan_retention_days(plan: &str) -> i32 {
    match plan {
        "builder" => 7,
        "pro" => 30,
        "scale_beta" => 90,
        _ => 1,
    }
}

fn derive_api_key(state: &AppState, tenant: &Tenant, idempotency_key: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.config.secret_pepper).expect("HMAC key");
    mac.update(b"tinyzkp-beta-api-key-v1\0");
    mac.update(tenant.tenant_id.as_bytes());
    mac.update(b"\0");
    mac.update(idempotency_key.as_bytes());
    format!(
        "tzb_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Invalid("missing_idempotency_key"))
}

pub(crate) fn ensure_writes(state: &AppState) -> Result<(), ApiError> {
    if state.config.writes_enabled {
        Ok(())
    } else {
        Err(ApiError::Unavailable("beta_writes_disabled"))
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(crate) fn as_u64(value: i64) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| ApiError::Internal)
}

pub(crate) fn to_i64(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::Invalid("numeric_overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_limits_are_fail_closed() {
        assert_eq!(plan_concurrency("builder"), 1);
        assert_eq!(plan_concurrency("pro"), 2);
        assert_eq!(plan_concurrency("scale_beta"), 4);
        assert_eq!(plan_concurrency("unknown"), 0);
    }

    #[test]
    fn reservation_is_at_least_quote() {
        let air = hc_plonky3::contracts::AirPackageV1 {
            schema_version: 1,
            backend: "plonky3".into(),
            profile: hc_plonky3::COMPATIBILITY_PROFILE.into(),
            field: "goldilocks".into(),
            expected_verifier: "p3_uni_stark_0.6.1".into(),
            trace_width: 1,
            public_inputs: vec![],
            expressions: vec![hc_plonky3::contracts::AirExpressionV1::Current { column: 0 }],
            constraints: vec![hc_plonky3::contracts::AirConstraintV1 {
                kind: hc_plonky3::contracts::AirConstraintKindV1::Transition,
                expression: 0,
            }],
        };
        let manifest = TraceManifestV1 {
            schema_version: 1,
            air_digest_hex: hex::encode(air.digest().unwrap()),
            trace_digest_hex: "0".repeat(64),
            logical_rows: 1024,
            trace_width: 1,
            field_encoding: "goldilocks_u64_le".into(),
            compression: "zstd".into(),
            chunk_uncompressed_bytes: 8192,
            chunks: vec![hc_plonky3::contracts::TraceChunkV1 {
                index: 0,
                compressed_bytes: 1,
                uncompressed_bytes: 8192,
                blake3_hex: "0".repeat(64),
            }],
        };
        let public = PublicInputsV1 {
            schema_version: 1,
            air_digest_hex: hex::encode(air.digest().unwrap()),
            values: vec![],
        };
        let estimate = admission_estimate(&air, &manifest, &public).unwrap();
        assert!(estimate.reservation_millicredits >= estimate.quoted_charge_millicredits);
    }
}
