use crate::{
    auth,
    error::ApiError,
    idempotency::{self, IdempotencyOutcome},
    models::{CheckoutRequest, PortalRequest, RedirectResponse},
    stripe::{CheckoutSessionParams, ReconciliationReport, StripeEvent, CATALOG_NAMESPACE},
    AppState,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

pub async fn checkout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CheckoutRequest>,
) -> Result<Response, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    crate::public::ensure_writes(&state)?;
    validate_redirect(&request.success_url, &state.config.dashboard_url)?;
    validate_redirect(&request.cancel_url, &state.config.dashboard_url)?;
    let operation = idempotency_key(&headers)?;
    let request_hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } = idempotency::begin(
        &mut tx,
        &tenant.tenant_id,
        "billing_checkout",
        operation,
        &request_hash,
    )
    .await?
    {
        tx.commit().await?;
        return idempotency::replay(status, body);
    }
    if request.sku.ends_with("_monthly") {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM beta_subscriptions WHERE tenant_id=$1
              AND status IN ('active','trialing','past_due','unpaid'))",
        )
        .bind(&tenant.tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if active {
            return Err(ApiError::Conflict("active_subscription_exists"));
        }
    }
    let customer: Option<String> = sqlx::query_scalar(
        "SELECT stripe_customer_id FROM beta_billing_customers WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let customer_id = match customer {
        Some(customer) => customer,
        None => {
            let customer = state
                .stripe
                .create_customer(
                    &tenant.tenant_id,
                    &format!("{CATALOG_NAMESPACE}:customer:{}", tenant.tenant_id),
                )
                .await?;
            sqlx::query(
                "INSERT INTO beta_billing_customers (tenant_id,stripe_customer_id)
                 VALUES ($1,$2) ON CONFLICT (tenant_id) DO UPDATE SET updated_at=now()",
            )
            .bind(&tenant.tenant_id)
            .bind(&customer)
            .execute(&state.pool)
            .await?;
            customer
        }
    };
    let session = state
        .stripe
        .create_checkout(CheckoutSessionParams {
            tenant_id: &tenant.tenant_id,
            customer_id: &customer_id,
            sku: &request.sku,
            operation_id: operation,
            success_url: &request.success_url,
            cancel_url: &request.cancel_url,
            synthetic_canary: request.synthetic_canary,
        })
        .await?;
    let response = RedirectResponse {
        id: session.id,
        url: session
            .url
            .ok_or(ApiError::Unavailable("stripe_checkout_url_missing"))?,
    };
    let mut tx = state.pool.begin().await?;
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "billing_checkout",
        operation,
        StatusCode::CREATED,
        &response,
        Some(&response.id),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn portal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PortalRequest>,
) -> Result<Response, ApiError> {
    let tenant = auth::authenticate(&headers, &state).await?;
    validate_redirect(&request.return_url, &state.config.dashboard_url)?;
    let operation = idempotency_key(&headers)?;
    let request_hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } = idempotency::begin(
        &mut tx,
        &tenant.tenant_id,
        "billing_portal",
        operation,
        &request_hash,
    )
    .await?
    {
        tx.commit().await?;
        return idempotency::replay(status, body);
    }
    let customer: String = sqlx::query_scalar(
        "SELECT stripe_customer_id FROM beta_billing_customers WHERE tenant_id=$1",
    )
    .bind(&tenant.tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    tx.commit().await?;
    let session = state
        .stripe
        .create_portal(&customer, &request.return_url, operation)
        .await?;
    let response = RedirectResponse {
        id: session.id,
        url: session
            .url
            .ok_or(ApiError::Unavailable("stripe_portal_url_missing"))?,
    };
    let mut tx = state.pool.begin().await?;
    idempotency::finish(
        &mut tx,
        &tenant.tenant_id,
        "billing_portal",
        operation,
        StatusCode::CREATED,
        &response,
        Some(&response.id),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let event = state.stripe.verify_webhook(&body, signature)?;
    let payload_hash = hex::encode(Sha256::digest(&body));
    let stored = sqlx::query(
        "INSERT INTO beta_stripe_events
             (stripe_event_id,event_type,payload_sha256,payload_json,stripe_created_at,
              stripe_customer_id,stripe_object_id,processing_status)
         VALUES ($1,$2,$3,$4,to_timestamp($5),$6,$7,'pending')
         ON CONFLICT DO NOTHING",
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .bind(&payload_hash)
    .bind(
        serde_json::from_slice::<Value>(&body)
            .map_err(|_| ApiError::Invalid("invalid_stripe_event"))?,
    )
    .bind(event.created as f64)
    .bind(string_at(&event.data.object, "/customer"))
    .bind(string_at(&event.data.object, "/id"))
    .execute(&state.pool)
    .await?
    .rows_affected();
    if stored == 0 {
        let existing: String = sqlx::query_scalar(
            "SELECT payload_sha256 FROM beta_stripe_events WHERE stripe_event_id=$1",
        )
        .bind(&event.id)
        .fetch_one(&state.pool)
        .await?;
        if existing != payload_hash {
            return Err(ApiError::Conflict("stripe_event_payload_conflict"));
        }
        return Ok(Json(json!({"received":true,"duplicate":true})));
    }
    match process_event(&state, &event).await {
        Ok(result) => {
            sqlx::query(
                "UPDATE beta_stripe_events SET processing_status='processed',processed_at=now(),
                        processing_result=$2 WHERE stripe_event_id=$1",
            )
            .bind(&event.id)
            .bind(&result)
            .execute(&state.pool)
            .await?;
            Ok(Json(json!({"received":true,"result":result})))
        }
        Err(error) => {
            sqlx::query(
                "UPDATE beta_stripe_events SET processing_status='failed',processed_at=now(),
                        processing_error=$2 WHERE stripe_event_id=$1",
            )
            .bind(&event.id)
            .bind(error.to_string())
            .execute(&state.pool)
            .await?;
            Err(error)
        }
    }
}

async fn process_event(state: &AppState, event: &StripeEvent) -> Result<Value, ApiError> {
    let object = &event.data.object;
    if metadata(object, "tinyzkp_catalog").as_deref() != Some(CATALOG_NAMESPACE) {
        return Ok(json!({"ignored":"foreign_catalog"}));
    }
    let tenant_id = metadata(object, "tinyzkp_tenant_id")
        .ok_or(ApiError::Invalid("stripe_tenant_metadata_missing"))?;
    let sku = metadata(object, "tinyzkp_sku");
    let object_id =
        string_at(object, "/id").ok_or(ApiError::Invalid("stripe_object_id_missing"))?;
    let mut tx = state.pool.begin().await?;
    match event.event_type.as_str() {
        "invoice.paid" => {
            let sku = sku.ok_or(ApiError::Invalid("stripe_sku_metadata_missing"))?;
            let credits = subscription_credits(&sku).ok_or(ApiError::Invalid("unknown_sku"))?;
            let grant_key = format!("invoice:{object_id}:grant");
            let already_granted: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM beta_credit_events WHERE tenant_id=$1 AND operation_key=$2)",
            )
            .bind(&tenant_id)
            .bind(&grant_key)
            .fetch_one(&mut *tx)
            .await?;
            if !already_granted {
                let period_end = number_at(object, "/lines/data/0/period/end")
                    .ok_or(ApiError::Invalid("invoice_period_missing"))?;
                expire_subscription_credits(&mut tx, &tenant_id, event, &object_id).await?;
                grant_credits(
                    &mut tx,
                    &tenant_id,
                    "subscription_grant",
                    credits,
                    event,
                    &grant_key,
                )
                .await?;
                sqlx::query(
                    "UPDATE beta_credit_accounts SET subscription_expires_at=to_timestamp($2) WHERE tenant_id=$1",
                )
                .bind(&tenant_id)
                .bind(period_end as f64)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "UPDATE beta_credit_accounts SET paid_work_frozen=false WHERE tenant_id=$1",
            )
            .bind(&tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        "invoice.payment_failed" => {
            sqlx::query("UPDATE beta_credit_accounts SET paid_work_frozen=true,updated_at=now() WHERE tenant_id=$1")
                .bind(&tenant_id).execute(&mut *tx).await?;
        }
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            if string_at(object, "/mode").as_deref() == Some("payment")
                && string_at(object, "/payment_status").as_deref() == Some("paid")
            {
                let sku = sku.ok_or(ApiError::Invalid("stripe_sku_metadata_missing"))?;
                let credits = topup_credits(&sku).ok_or(ApiError::Invalid("unknown_sku"))?;
                grant_credits(
                    &mut tx,
                    &tenant_id,
                    "topup_grant",
                    credits,
                    event,
                    &format!("checkout:{object_id}:grant"),
                )
                .await?;
            }
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            let status = string_at(object, "/status").unwrap_or_else(|| "deleted".into());
            let plan = sku.as_deref().and_then(plan_for_sku).unwrap_or("sandbox");
            let subscription_id = if event.event_type.ends_with("deleted") {
                None
            } else {
                Some(object_id.as_str())
            };
            sqlx::query(
                "INSERT INTO beta_subscriptions
                     (tenant_id,stripe_subscription_id,stripe_price_id,sku,status,
                      current_period_start,current_period_end,cancel_at_period_end)
                 VALUES ($1,$2,$3,$4,$5,to_timestamp($6),to_timestamp($7),$8)
                 ON CONFLICT (tenant_id) DO UPDATE SET
                   stripe_subscription_id=EXCLUDED.stripe_subscription_id,
                   stripe_price_id=EXCLUDED.stripe_price_id,sku=EXCLUDED.sku,status=EXCLUDED.status,
                   current_period_start=EXCLUDED.current_period_start,
                   current_period_end=EXCLUDED.current_period_end,
                   cancel_at_period_end=EXCLUDED.cancel_at_period_end,updated_at=now()",
            )
            .bind(&tenant_id)
            .bind(subscription_id)
            .bind(string_at(object, "/items/data/0/price/id"))
            .bind(&sku)
            .bind(&status)
            .bind(number_at(object, "/current_period_start").unwrap_or(0) as f64)
            .bind(number_at(object, "/current_period_end").unwrap_or(0) as f64)
            .bind(
                object
                    .pointer("/cancel_at_period_end")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE tenants SET plan=$2,updated_at_ms=(extract(epoch from now())*1000)::bigint WHERE tenant_id=$1")
                .bind(&tenant_id).bind(plan).execute(&mut *tx).await?;
        }
        _ => {
            tx.commit().await?;
            return Ok(json!({"ignored":"unsupported_event_type"}));
        }
    }
    tx.commit().await?;
    Ok(json!({"processed":event.event_type,"tenant_id":tenant_id}))
}

async fn grant_credits(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    event_type: &str,
    credits: u64,
    event: &StripeEvent,
    operation_key: &str,
) -> Result<(), ApiError> {
    let millicredits =
        i64::try_from(credits.saturating_mul(1000)).map_err(|_| ApiError::Internal)?;
    let inserted = sqlx::query(
        "INSERT INTO beta_credit_events
             (event_id,tenant_id,event_type,subscription_delta_millicredits,
              purchased_delta_millicredits,stripe_event_id,operation_key,metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (tenant_id,operation_key) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(event_type)
    .bind(if event_type == "subscription_grant" {
        millicredits
    } else {
        0
    })
    .bind(if event_type == "topup_grant" {
        millicredits
    } else {
        0
    })
    .bind(&event.id)
    .bind(operation_key)
    .bind(json!({"stripe_event_id":event.id}))
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if inserted == 1 {
        let column = if event_type == "subscription_grant" {
            "subscription_millicredits"
        } else {
            "purchased_millicredits"
        };
        let query = format!("UPDATE beta_credit_accounts SET {column}={column}+$2,version=version+1,updated_at=now() WHERE tenant_id=$1");
        sqlx::query(&query)
            .bind(tenant_id)
            .bind(millicredits)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn expire_subscription_credits(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    event: &StripeEvent,
    invoice_id: &str,
) -> Result<(), ApiError> {
    let balance: i64 = sqlx::query_scalar(
        "SELECT subscription_millicredits FROM beta_credit_accounts WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await?;
    if balance > 0 {
        sqlx::query(
            "INSERT INTO beta_credit_events
                 (event_id,tenant_id,event_type,subscription_delta_millicredits,
                  stripe_event_id,operation_key,metadata)
             VALUES ($1,$2,'expiry',$3,$4,$5,$6)",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(-balance)
        .bind(&event.id)
        .bind(format!("invoice:{invoice_id}:expiry"))
        .bind(json!({"reason":"billing_cycle_boundary"}))
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "UPDATE beta_credit_accounts SET subscription_millicredits=0,version=version+1,updated_at=now() WHERE tenant_id=$1",
        )
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

pub async fn reconcile(state: &AppState) -> Result<ReconciliationReport, ApiError> {
    let pending = sqlx::query(
        "SELECT stripe_event_id,payload_json FROM beta_stripe_events
          WHERE processing_status IN ('pending','failed') ORDER BY stripe_created_at LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut replayed_events = 0usize;
    let mut discrepancies = Vec::new();
    for row in pending {
        let event_id: String = row.get("stripe_event_id");
        let payload: Value = row.get("payload_json");
        let event: StripeEvent = match serde_json::from_value(payload) {
            Ok(event) => event,
            Err(_) => {
                discrepancies.push(format!("{event_id}: stored Stripe event is malformed"));
                continue;
            }
        };
        match process_event(state, &event).await {
            Ok(result) => {
                sqlx::query(
                    "UPDATE beta_stripe_events SET processing_status='processed',processed_at=now(),processing_result=$2,processing_error=NULL WHERE stripe_event_id=$1",
                )
                .bind(&event_id).bind(result).execute(&state.pool).await?;
                replayed_events += 1;
            }
            Err(error) => discrepancies.push(format!("{event_id}: {error}")),
        }
    }
    let rows = sqlx::query(
        "SELECT s.tenant_id,s.stripe_subscription_id,s.status,t.plan
           FROM beta_subscriptions s JOIN tenants t ON t.tenant_id=s.tenant_id
          WHERE s.stripe_subscription_id IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await?;
    for row in &rows {
        let subscription: String = row.get("stripe_subscription_id");
        match state
            .stripe
            .retrieve(&format!("/v1/subscriptions/{subscription}"))
            .await
        {
            Ok(remote) => {
                let local_status: Option<String> = row.get("status");
                if string_at(&remote, "/status") != local_status {
                    discrepancies.push(format!(
                        "{}: subscription status mismatch",
                        row.get::<String, _>("tenant_id")
                    ));
                }
            }
            Err(_) => discrepancies.push(format!(
                "{}: subscription retrieval failed",
                row.get::<String, _>("tenant_id")
            )),
        }
    }
    Ok(ReconciliationReport {
        checked_tenants: rows.len(),
        replayed_events,
        discrepancies,
    })
}

fn metadata(value: &Value, key: &str) -> Option<String> {
    value
        .pointer(&format!("/metadata/{key}"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            value
                .pointer(&format!("/subscription_details/metadata/{key}"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            value
                .pointer(&format!("/parent/subscription_details/metadata/{key}"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            value
                .pointer(&format!("/lines/data/0/metadata/{key}"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn string_at(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_at(value: &Value, pointer: &str) -> Option<i64> {
    value.pointer(pointer).and_then(Value::as_i64)
}

fn subscription_credits(sku: &str) -> Option<u64> {
    match sku {
        "builder_monthly" => Some(49),
        "pro_monthly" => Some(210),
        "scale_beta_monthly" => Some(550),
        _ => None,
    }
}

fn topup_credits(sku: &str) -> Option<u64> {
    match sku {
        "topup_25" => Some(25),
        "topup_100" => Some(100),
        "topup_500" => Some(500),
        _ => None,
    }
}

fn plan_for_sku(sku: &str) -> Option<&'static str> {
    match sku {
        "builder_monthly" => Some("builder"),
        "pro_monthly" => Some("pro"),
        "scale_beta_monthly" => Some("scale_beta"),
        _ => None,
    }
}

fn validate_redirect(candidate: &str, dashboard: &str) -> Result<(), ApiError> {
    let candidate =
        url::Url::parse(candidate).map_err(|_| ApiError::Invalid("invalid_redirect_url"))?;
    let dashboard = url::Url::parse(dashboard).map_err(|_| ApiError::Internal)?;
    if candidate.scheme() != "https" || candidate.origin() != dashboard.origin() {
        return Err(ApiError::Invalid("invalid_redirect_url"));
    }
    Ok(())
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Invalid("missing_idempotency_key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_maps_only_expected_skus() {
        assert_eq!(subscription_credits("pro_monthly"), Some(210));
        assert_eq!(topup_credits("topup_100"), Some(100));
        assert_eq!(subscription_credits("legacy"), None);
        assert_eq!(plan_for_sku("scale_beta_monthly"), Some("scale_beta"));
    }

    #[test]
    fn metadata_finds_invoice_subscription_details() {
        let value = json!({"parent":{"subscription_details":{"metadata":{"tinyzkp_catalog":CATALOG_NAMESPACE}}}});
        assert_eq!(
            metadata(&value, "tinyzkp_catalog").as_deref(),
            Some(CATALOG_NAMESPACE)
        );
    }
}
