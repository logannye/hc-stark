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
use hmac::{Hmac, Mac};
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
    if request.synthetic_canary && state.config.exposure != crate::config::ExposureMode::DarkCanary
    {
        return Err(ApiError::Invalid("synthetic_canary_requires_dark_mode"));
    }
    validate_redirect(&request.success_url, &state.config.dashboard_url)?;
    validate_redirect(&request.cancel_url, &state.config.dashboard_url)?;
    let operation = idempotency_key(&headers)?;
    let request_hash = idempotency::request_hash(&request)?;
    let mut tx = state.pool.begin().await?;
    if let IdempotencyOutcome::Replay { status, body } = idempotency::begin_retriable(
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
            release_sha: &state.config.release_sha,
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
    if let IdempotencyOutcome::Replay { status, body } = idempotency::begin_retriable(
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
    if event.livemode != state.stripe.livemode() {
        return Err(ApiError::Invalid("stripe_event_mode_mismatch"));
    }
    let payload_hash = hex::encode(Sha256::digest(&body));
    let stored = sqlx::query(
        "INSERT INTO beta_stripe_events
             (stripe_event_id,event_type,payload_sha256,payload_json,stripe_created_at,
              stripe_customer_id,stripe_object_id,stripe_object_type,livemode,processing_status)
         VALUES ($1,$2,$3,$4,to_timestamp($5),$6,$7,$8,$9,'pending')
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
    .bind(string_at(&event.data.object, "/object"))
    .bind(event.livemode)
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
    Ok(Json(json!({"received":true,"queued":true})))
}

pub async fn run_event_processor(state: AppState) {
    loop {
        match process_pending_events(&state, 25).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, "Stripe event processor failed");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

pub async fn process_pending_events(state: &AppState, limit: usize) -> Result<usize, ApiError> {
    let mut processed = 0usize;
    for _ in 0..limit {
        let mut tx = state.pool.begin().await?;
        let row = sqlx::query(
            "SELECT stripe_event_id,payload_json,processing_attempts
               FROM beta_stripe_events
              WHERE ((processing_status IN ('pending','failed')
                       AND (next_attempt_at IS NULL OR next_attempt_at <= now()))
                  OR (processing_status='processing' AND processing_lease_expires_at < now()))
              ORDER BY stripe_created_at,received_at
              FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            break;
        };
        let event_id: String = row.get("stripe_event_id");
        let payload: Value = row.get("payload_json");
        let attempts: i32 = row.get("processing_attempts");
        sqlx::query(
            "UPDATE beta_stripe_events SET processing_status='processing',
                    processing_attempts=processing_attempts+1,processing_started_at=now(),
                    processing_lease_expires_at=now()+interval '2 minutes',last_attempt_at=now(),
                    next_attempt_at=NULL,processing_error=NULL
              WHERE stripe_event_id=$1",
        )
        .bind(&event_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        let result = match serde_json::from_value::<StripeEvent>(payload) {
            Ok(event) => process_event(state, &event).await,
            Err(_) => Err(ApiError::Invalid("stored_stripe_event_malformed")),
        };
        match result {
            Ok(result) => {
                sqlx::query(
                    "UPDATE beta_stripe_events SET processing_status='processed',processed_at=now(),
                            processing_result=$2,processing_error=NULL,
                            processing_lease_expires_at=NULL WHERE stripe_event_id=$1",
                )
                .bind(&event_id)
                .bind(result)
                .execute(&state.pool)
                .await?;
                processed += 1;
            }
            Err(error) => {
                let delay = 1i64 << u32::try_from((attempts + 1).clamp(1, 10)).unwrap_or(10);
                sqlx::query(
                    "UPDATE beta_stripe_events SET processing_status='failed',processed_at=now(),
                            processing_error=$2,processing_lease_expires_at=NULL,
                            next_attempt_at=now()+($3 * interval '1 second')
                      WHERE stripe_event_id=$1",
                )
                .bind(&event_id)
                .bind(error.to_string())
                .bind(delay)
                .execute(&state.pool)
                .await?;
            }
        }
    }
    Ok(processed)
}

async fn process_event(state: &AppState, event: &StripeEvent) -> Result<Value, ApiError> {
    let object = &event.data.object;
    if matches!(
        event.event_type.as_str(),
        "refund.created" | "refund.updated" | "refund.failed"
    ) {
        return process_refund_event(state, event).await;
    }
    if metadata(object, "tinyzkp_catalog").as_deref() != Some(CATALOG_NAMESPACE) {
        return Ok(json!({"ignored":"foreign_catalog"}));
    }
    let tenant_id = metadata(object, "tinyzkp_tenant_id")
        .ok_or(ApiError::Invalid("stripe_tenant_metadata_missing"))?;
    let sku = metadata(object, "tinyzkp_sku");
    let object_id =
        string_at(object, "/id").ok_or(ApiError::Invalid("stripe_object_id_missing"))?;
    let object_type = string_at(object, "/object").unwrap_or_else(|| "unknown".into());
    let (state_type, state_id) = ordering_identity(&object_type, &object_id, object);
    if event_is_stale(state, &state_type, &state_id, event.created).await? {
        retrieve_canonical_object(state, &state_type, &state_id).await?;
        return Ok(json!({"ignored":"stale_event","object_id":object_id}));
    }
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
                    object,
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
                    object,
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
    record_object_state(&mut tx, &state_type, &state_id, event, object).await?;
    tx.commit().await?;
    Ok(json!({"processed":event.event_type,"tenant_id":tenant_id}))
}

fn ordering_identity(object_type: &str, object_id: &str, object: &Value) -> (String, String) {
    if object_type == "invoice" {
        let subscription = string_at(object, "/subscription")
            .or_else(|| string_at(object, "/parent/subscription_details/subscription"));
        if let Some(subscription) = subscription {
            return ("subscription".into(), subscription);
        }
    }
    (object_type.into(), object_id.into())
}

async fn event_is_stale(
    state: &AppState,
    object_type: &str,
    object_id: &str,
    created: i64,
) -> Result<bool, ApiError> {
    let last = sqlx::query_scalar::<_, i64>(
        "SELECT last_applied_event_created FROM beta_stripe_object_state
          WHERE stripe_object_type=$1 AND stripe_object_id=$2",
    )
    .bind(object_type)
    .bind(object_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(last.is_some_and(|last| created < last))
}

async fn retrieve_canonical_object(
    state: &AppState,
    object_type: &str,
    object_id: &str,
) -> Result<Value, ApiError> {
    let path = match object_type {
        "checkout.session" => format!("/v1/checkout/sessions/{object_id}"),
        "invoice" => format!("/v1/invoices/{object_id}"),
        "refund" => format!("/v1/refunds/{object_id}"),
        "subscription" => format!("/v1/subscriptions/{object_id}"),
        _ => return Err(ApiError::Invalid("unsupported_stripe_object_type")),
    };
    state.stripe.retrieve(&path).await
}

async fn record_object_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    object_type: &str,
    object_id: &str,
    event: &StripeEvent,
    canonical: &Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO beta_stripe_object_state
             (stripe_object_type,stripe_object_id,last_applied_event_created,
              last_applied_event_id,canonical_state)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (stripe_object_type,stripe_object_id) DO UPDATE SET
           last_applied_event_created=EXCLUDED.last_applied_event_created,
           last_applied_event_id=EXCLUDED.last_applied_event_id,
           canonical_state=EXCLUDED.canonical_state,updated_at=now()
         WHERE beta_stripe_object_state.last_applied_event_created
               <= EXCLUDED.last_applied_event_created",
    )
    .bind(object_type)
    .bind(object_id)
    .bind(event.created)
    .bind(&event.id)
    .bind(canonical)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn process_refund_event(state: &AppState, event: &StripeEvent) -> Result<Value, ApiError> {
    let object = &event.data.object;
    let refund_id = string_at(object, "/id").ok_or(ApiError::Invalid("refund_id_missing"))?;
    if event_is_stale(state, "refund", &refund_id, event.created).await? {
        retrieve_canonical_object(state, "refund", &refund_id).await?;
        return Ok(json!({"ignored":"stale_refund","refund_id":refund_id}));
    }
    let payment_intent = string_at(object, "/payment_intent");
    let charge = string_at(object, "/charge");
    let grant = sqlx::query(
        "SELECT grant_id,tenant_id,credit_bucket,granted_millicredits,reversed_millicredits
           FROM beta_credit_grants
          WHERE ($1::text IS NOT NULL AND stripe_payment_intent_id=$1)
             OR ($2::text IS NOT NULL AND stripe_charge_id=$2)
          ORDER BY created_at LIMIT 1",
    )
    .bind(&payment_intent)
    .bind(&charge)
    .fetch_optional(&state.pool)
    .await?;
    let Some(grant) = grant else {
        return Ok(json!({"ignored":"unmatched_refund","refund_id":refund_id}));
    };
    let grant_id: Uuid = grant.get("grant_id");
    let tenant_id: String = grant.get("tenant_id");
    let bucket: String = grant.get("credit_bucket");
    let granted: i64 = grant.get("granted_millicredits");
    let grant_reversed: i64 = grant.get("reversed_millicredits");
    let amount_minor = number_at(object, "/amount").unwrap_or(0).max(0);
    let status = string_at(object, "/status").unwrap_or_else(|| "unknown".into());
    let mut tx = state.pool.begin().await?;
    let previous_refund_reversed: i64 = sqlx::query_scalar(
        "SELECT reversed_millicredits FROM beta_refunds WHERE stripe_refund_id=$1 FOR UPDATE",
    )
    .bind(&refund_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(0);
    sqlx::query(
        "INSERT INTO beta_refunds
             (stripe_refund_id,grant_id,tenant_id,stripe_payment_intent_id,stripe_charge_id,
              amount_minor,status,stripe_event_id,stripe_event_created)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (stripe_refund_id) DO UPDATE SET amount_minor=EXCLUDED.amount_minor,
           status=EXCLUDED.status,stripe_event_id=EXCLUDED.stripe_event_id,
           stripe_event_created=EXCLUDED.stripe_event_created,updated_at=now()",
    )
    .bind(&refund_id)
    .bind(grant_id)
    .bind(&tenant_id)
    .bind(&payment_intent)
    .bind(&charge)
    .bind(amount_minor)
    .bind(&status)
    .bind(&event.id)
    .bind(event.created)
    .execute(&mut *tx)
    .await?;

    if status == "failed" || event.event_type == "refund.failed" {
        sqlx::query(
            "INSERT INTO beta_billing_discrepancies
                 (discrepancy_id,tenant_id,discrepancy_type,semantic_key,details)
             VALUES ($1,$2,'refund_failed',$3,$4) ON CONFLICT (semantic_key) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant_id)
        .bind(format!("refund:{refund_id}:failed"))
        .bind(json!({"refund_id":refund_id,"stripe_event_id":event.id}))
        .execute(&mut *tx)
        .await?;
    } else if status == "succeeded" {
        let (desired, delta) = refund_reversal_delta(
            amount_minor,
            granted,
            grant_reversed,
            previous_refund_reversed,
        )?;
        if delta > 0 {
            let account = sqlx::query(
                "SELECT subscription_millicredits,purchased_millicredits
                   FROM beta_credit_accounts WHERE tenant_id=$1 FOR UPDATE",
            )
            .bind(&tenant_id)
            .fetch_one(&mut *tx)
            .await?;
            let available: i64 = if bucket == "subscription" {
                account.get("subscription_millicredits")
            } else {
                account.get("purchased_millicredits")
            };
            if available < delta {
                sqlx::query(
                    "UPDATE beta_credit_accounts SET paid_work_frozen=true,updated_at=now()
                      WHERE tenant_id=$1",
                )
                .bind(&tenant_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO beta_billing_discrepancies
                         (discrepancy_id,tenant_id,discrepancy_type,semantic_key,details)
                     VALUES ($1,$2,'refund_credits_consumed',$3,$4)
                     ON CONFLICT (semantic_key) DO NOTHING",
                )
                .bind(Uuid::new_v4())
                .bind(&tenant_id)
                .bind(format!("refund:{refund_id}:consumed:{desired}"))
                .bind(json!({"refund_id":refund_id,"required":delta,"available":available}))
                .execute(&mut *tx)
                .await?;
            } else {
                let (subscription_delta, purchased_delta) = if bucket == "subscription" {
                    (-delta, 0)
                } else {
                    (0, -delta)
                };
                sqlx::query(
                    "INSERT INTO beta_credit_events
                         (event_id,tenant_id,event_type,subscription_delta_millicredits,
                          purchased_delta_millicredits,stripe_event_id,operation_key,metadata)
                     VALUES ($1,$2,'refund_reversal',$3,$4,$5,$6,$7)",
                )
                .bind(Uuid::new_v4())
                .bind(&tenant_id)
                .bind(subscription_delta)
                .bind(purchased_delta)
                .bind(&event.id)
                .bind(format!("refund:{refund_id}:reversal:{desired}"))
                .bind(json!({"refund_id":refund_id,"grant_id":grant_id,"amount":delta}))
                .execute(&mut *tx)
                .await?;
                let column = if bucket == "subscription" {
                    "subscription_millicredits"
                } else {
                    "purchased_millicredits"
                };
                let query = format!(
                    "UPDATE beta_credit_accounts SET {column}={column}-$2,
                     version=version+1,updated_at=now() WHERE tenant_id=$1"
                );
                sqlx::query(&query)
                    .bind(&tenant_id)
                    .bind(delta)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query(
                    "UPDATE beta_credit_grants SET reversed_millicredits=reversed_millicredits+$2,
                            updated_at=now() WHERE grant_id=$1",
                )
                .bind(grant_id)
                .bind(delta)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE beta_refunds SET reversed_millicredits=$2,applied_at=now(),updated_at=now()
                      WHERE stripe_refund_id=$1",
                )
                .bind(&refund_id)
                .bind(desired)
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    record_object_state(&mut tx, "refund", &refund_id, event, object).await?;
    tx.commit().await?;
    Ok(json!({"processed":event.event_type,"tenant_id":tenant_id,"refund_id":refund_id}))
}

fn refund_reversal_delta(
    amount_minor: i64,
    granted: i64,
    grant_reversed: i64,
    refund_reversed: i64,
) -> Result<(i64, i64), ApiError> {
    let desired = amount_minor.max(0).saturating_mul(10).min(granted);
    let delta = desired.saturating_sub(refund_reversed);
    if delta > granted.saturating_sub(grant_reversed) {
        return Err(ApiError::Conflict("refund_exceeds_grant"));
    }
    Ok((desired, delta))
}

async fn grant_credits(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    event_type: &str,
    credits: u64,
    event: &StripeEvent,
    object: &Value,
    operation_key: &str,
) -> Result<(), ApiError> {
    let millicredits =
        i64::try_from(credits.saturating_mul(1000)).map_err(|_| ApiError::Internal)?;
    let grant_id = Uuid::new_v4();
    let subscription = event_type == "subscription_grant";
    let inserted = sqlx::query(
        "INSERT INTO beta_credit_grants
             (grant_id,tenant_id,grant_kind,credit_bucket,semantic_key,stripe_invoice_id,
              stripe_checkout_session_id,stripe_payment_intent_id,stripe_charge_id,
              stripe_event_id,granted_millicredits,synthetic_canary)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (semantic_key) DO NOTHING",
    )
    .bind(grant_id)
    .bind(tenant_id)
    .bind(if subscription {
        "subscription"
    } else {
        "topup"
    })
    .bind(if subscription {
        "subscription"
    } else {
        "purchased"
    })
    .bind(operation_key)
    .bind(subscription.then(|| string_at(object, "/id")).flatten())
    .bind((!subscription).then(|| string_at(object, "/id")).flatten())
    .bind(
        string_at(object, "/payment_intent")
            .or_else(|| string_at(object, "/payments/data/0/payment/payment_intent")),
    )
    .bind(
        string_at(object, "/charge")
            .or_else(|| string_at(object, "/latest_charge"))
            .or_else(|| string_at(object, "/payments/data/0/payment/charge")),
    )
    .bind(&event.id)
    .bind(millicredits)
    .bind(metadata(object, "tinyzkp_synthetic_canary").as_deref() == Some("true"))
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO beta_credit_events
             (event_id,tenant_id,event_type,subscription_delta_millicredits,
              purchased_delta_millicredits,stripe_event_id,operation_key,metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
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
    .bind(json!({"stripe_event_id":event.id,"grant_id":grant_id}))
    .execute(&mut **tx)
    .await?;
    let column = if subscription {
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
    let reconciliation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO beta_reconciliation_runs (reconciliation_id,status,release_sha)
         VALUES ($1,'running',$2)",
    )
    .bind(reconciliation_id)
    .bind(&state.config.release_sha)
    .execute(&state.pool)
    .await?;
    let replayed_events = process_pending_events(state, 100).await?;
    let mut discrepancies = Vec::new();
    let checked_tenants = usize::try_from(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM beta_credit_accounts")
            .fetch_one(&state.pool)
            .await?,
    )
    .map_err(|_| ApiError::Internal)?;
    let rows = sqlx::query(
        "SELECT s.tenant_id,s.stripe_subscription_id,s.status,t.plan
           FROM beta_subscriptions s JOIN tenants t ON t.tenant_id=s.tenant_id
          WHERE s.stripe_subscription_id IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await?;
    for customer in sqlx::query("SELECT tenant_id,stripe_customer_id FROM beta_billing_customers")
        .fetch_all(&state.pool)
        .await?
    {
        let tenant: String = customer.get("tenant_id");
        let customer_id: String = customer.get("stripe_customer_id");
        match state
            .stripe
            .retrieve(&format!("/v1/customers/{customer_id}"))
            .await
        {
            Ok(remote)
                if string_at(&remote, "/id").as_deref() == Some(customer_id.as_str())
                    && remote.pointer("/deleted").and_then(Value::as_bool) != Some(true) => {}
            Ok(_) => discrepancies.push(format!("{tenant}: Stripe customer state mismatch")),
            Err(_) => discrepancies.push(format!("{tenant}: Stripe customer retrieval failed")),
        }
    }
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
    for row in sqlx::query(
        "SELECT tenant_id,stripe_invoice_id,stripe_checkout_session_id
           FROM beta_credit_grants",
    )
    .fetch_all(&state.pool)
    .await?
    {
        let tenant: String = row.get("tenant_id");
        let invoice: Option<String> = row.get("stripe_invoice_id");
        let checkout: Option<String> = row.get("stripe_checkout_session_id");
        let (path, expected_pointer, expected_value) = if let Some(invoice) = invoice {
            (format!("/v1/invoices/{invoice}"), "/status", "paid")
        } else if let Some(checkout) = checkout {
            (
                format!("/v1/checkout/sessions/{checkout}"),
                "/payment_status",
                "paid",
            )
        } else {
            discrepancies.push(format!(
                "{tenant}: credit grant has no Stripe source object"
            ));
            continue;
        };
        match state.stripe.retrieve(&path).await {
            Ok(remote)
                if string_at(&remote, expected_pointer).as_deref() == Some(expected_value) => {}
            Ok(_) => discrepancies.push(format!("{tenant}: Stripe grant source is not paid")),
            Err(_) => discrepancies.push(format!("{tenant}: Stripe grant source retrieval failed")),
        }
    }
    for row in sqlx::query("SELECT stripe_refund_id,status,amount_minor FROM beta_refunds")
        .fetch_all(&state.pool)
        .await?
    {
        let refund: String = row.get("stripe_refund_id");
        match state
            .stripe
            .retrieve(&format!("/v1/refunds/{refund}"))
            .await
        {
            Ok(remote)
                if string_at(&remote, "/status") == Some(row.get::<String, _>("status"))
                    && number_at(&remote, "/amount") == Some(row.get::<i64, _>("amount_minor")) => {
            }
            Ok(_) => discrepancies.push(format!("{refund}: refund state mismatch")),
            Err(_) => discrepancies.push(format!("{refund}: refund retrieval failed")),
        }
    }
    for row in sqlx::query(
        "SELECT g.semantic_key,g.reversed_millicredits,
                COALESCE(sum(r.reversed_millicredits),0)::bigint AS refund_reversed
           FROM beta_credit_grants g LEFT JOIN beta_refunds r ON r.grant_id=g.grant_id
          GROUP BY g.semantic_key,g.reversed_millicredits",
    )
    .fetch_all(&state.pool)
    .await?
    {
        if row.get::<i64, _>("reversed_millicredits") != row.get::<i64, _>("refund_reversed") {
            discrepancies.push(format!(
                "{}: refund reversal ledger mismatch",
                row.get::<String, _>("semantic_key")
            ));
        }
    }
    for row in sqlx::query(
        "SELECT a.tenant_id,a.subscription_millicredits,a.purchased_millicredits,
                a.reserved_millicredits,
                COALESCE(sum(e.subscription_delta_millicredits),0)::bigint AS event_subscription,
                COALESCE(sum(e.purchased_delta_millicredits),0)::bigint AS event_purchased,
                COALESCE(sum(e.reserved_delta_millicredits),0)::bigint AS event_reserved
           FROM beta_credit_accounts a
           LEFT JOIN beta_credit_events e ON e.tenant_id=a.tenant_id
          GROUP BY a.tenant_id,a.subscription_millicredits,a.purchased_millicredits,
                   a.reserved_millicredits",
    )
    .fetch_all(&state.pool)
    .await?
    {
        let tenant: String = row.get("tenant_id");
        if row.get::<i64, _>("subscription_millicredits") != row.get::<i64, _>("event_subscription")
            || row.get::<i64, _>("purchased_millicredits") != row.get::<i64, _>("event_purchased")
            || row.get::<i64, _>("reserved_millicredits") != row.get::<i64, _>("event_reserved")
        {
            discrepancies.push(format!("{tenant}: immutable credit ledger mismatch"));
        }
    }
    for row in sqlx::query(
        "SELECT stripe_event_id,processing_error FROM beta_stripe_events
          WHERE processing_status='failed'",
    )
    .fetch_all(&state.pool)
    .await?
    {
        discrepancies.push(format!(
            "{}: {}",
            row.get::<String, _>("stripe_event_id"),
            row.get::<Option<String>, _>("processing_error")
                .unwrap_or_else(|| "Stripe event processing failed".into())
        ));
    }
    for row in
        sqlx::query("SELECT semantic_key FROM beta_billing_discrepancies WHERE resolved_at IS NULL")
            .fetch_all(&state.pool)
            .await?
    {
        discrepancies.push(format!(
            "{}: unresolved billing discrepancy",
            row.get::<String, _>("semantic_key")
        ));
    }
    let generated_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::Internal)?
        .as_secs();
    let unsigned = json!({
        "checked_tenants": checked_tenants,
        "replayed_events": replayed_events,
        "discrepancies": &discrepancies,
        "release_sha": &state.config.release_sha,
        "generated_at_unix": generated_at_unix,
    });
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| ApiError::Internal)?;
    let report_sha256 = hex::encode(Sha256::digest(&bytes));
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.config.reconciliation_hmac_key)
        .map_err(|_| ApiError::Internal)?;
    mac.update(&bytes);
    let report_hmac_sha256 = hex::encode(mac.finalize().into_bytes());
    let report = ReconciliationReport {
        checked_tenants,
        replayed_events,
        discrepancies,
        release_sha: state.config.release_sha.clone(),
        generated_at_unix,
        report_sha256: report_sha256.clone(),
        report_hmac_sha256: report_hmac_sha256.clone(),
    };
    let status = if report.discrepancies.is_empty() {
        "clean"
    } else {
        "discrepancy"
    };
    sqlx::query(
        "UPDATE beta_reconciliation_runs SET completed_at=now(),status=$2,report_json=$3,
                report_sha256=$4,report_hmac_sha256=$5 WHERE reconciliation_id=$1",
    )
    .bind(reconciliation_id)
    .bind(status)
    .bind(serde_json::to_value(&report).map_err(|_| ApiError::Internal)?)
    .bind(report_sha256)
    .bind(report_hmac_sha256)
    .execute(&state.pool)
    .await?;
    Ok(report)
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

    #[test]
    fn invoice_ordering_uses_the_immutable_subscription_id() {
        let invoice = json!({
            "object":"invoice",
            "parent":{"subscription_details":{"subscription":"sub_immutable"}}
        });
        assert_eq!(
            ordering_identity("invoice", "in_old", &invoice),
            ("subscription".into(), "sub_immutable".into())
        );
    }

    #[test]
    fn refund_reversal_is_incremental_capped_and_idempotent() {
        assert_eq!(
            refund_reversal_delta(2_500, 25_000, 0, 0).unwrap(),
            (25_000, 25_000)
        );
        assert_eq!(
            refund_reversal_delta(2_500, 25_000, 25_000, 25_000).unwrap(),
            (25_000, 0)
        );
        assert_eq!(
            refund_reversal_delta(500, 25_000, 0, 0).unwrap(),
            (5_000, 5_000)
        );
        assert!(refund_reversal_delta(2_500, 25_000, 20_000, 0).is_err());
    }
}
