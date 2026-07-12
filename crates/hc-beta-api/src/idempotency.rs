use crate::error::ApiError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

pub enum IdempotencyOutcome {
    New,
    Replay { status: u16, body: Value },
}

pub fn request_hash<T: Serialize>(request: &T) -> Result<String, ApiError> {
    let bytes = serde_json::to_vec(request).map_err(|_| ApiError::Internal)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub async fn begin(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    operation: &str,
    key: &str,
    request_sha256: &str,
) -> Result<IdempotencyOutcome, ApiError> {
    begin_inner(tx, tenant_id, operation, key, request_sha256, false).await
}

/// Resume an incomplete local operation only when the downstream API uses the
/// same idempotency key and guarantees an exact replay (Stripe Checkout and
/// Portal). Do not use this for local ledger mutations.
pub async fn begin_retriable(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    operation: &str,
    key: &str,
    request_sha256: &str,
) -> Result<IdempotencyOutcome, ApiError> {
    begin_inner(tx, tenant_id, operation, key, request_sha256, true).await
}

async fn begin_inner(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    operation: &str,
    key: &str,
    request_sha256: &str,
    retry_incomplete: bool,
) -> Result<IdempotencyOutcome, ApiError> {
    if key.len() < 8 || key.len() > 200 || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ApiError::Invalid("invalid_idempotency_key"));
    }
    let inserted = sqlx::query(
        "INSERT INTO beta_idempotency_keys
             (tenant_id, operation, idempotency_key, request_sha256, expires_at)
         VALUES ($1,$2,$3,$4,now() + interval '24 hours')
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(operation)
    .bind(key)
    .bind(request_sha256)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(IdempotencyOutcome::New);
    }
    let row = sqlx::query(
        "SELECT request_sha256, response_status, response_json
           FROM beta_idempotency_keys
          WHERE tenant_id=$1 AND operation=$2 AND idempotency_key=$3
          FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(operation)
    .bind(key)
    .fetch_one(&mut **tx)
    .await?;
    let stored_hash: String = row.get("request_sha256");
    if stored_hash != request_sha256 {
        return Err(ApiError::Conflict("idempotency_conflict"));
    }
    let status: Option<i32> = row.get("response_status");
    let body: Option<Value> = row.get("response_json");
    match (status, body) {
        (Some(status), Some(body)) => Ok(IdempotencyOutcome::Replay {
            status: u16::try_from(status).map_err(|_| ApiError::Internal)?,
            body,
        }),
        _ if retry_incomplete => Ok(IdempotencyOutcome::New),
        _ => Err(ApiError::Conflict("idempotency_in_progress")),
    }
}

pub async fn finish<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    operation: &str,
    key: &str,
    status: StatusCode,
    body: &T,
    resource_id: Option<&str>,
) -> Result<Value, ApiError> {
    let value = serde_json::to_value(body).map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "UPDATE beta_idempotency_keys
            SET response_status=$4, response_json=$5, resource_id=$6
          WHERE tenant_id=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(tenant_id)
    .bind(operation)
    .bind(key)
    .bind(i32::from(status.as_u16()))
    .bind(&value)
    .bind(resource_id)
    .execute(&mut **tx)
    .await?;
    Ok(value)
}

pub fn replay(status: u16, body: Value) -> Result<Response, ApiError> {
    let status = StatusCode::from_u16(status).map_err(|_| ApiError::Internal)?;
    Ok((status, Json(body)).into_response())
}
