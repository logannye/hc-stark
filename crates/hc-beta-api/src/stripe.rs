use crate::error::ApiError;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub const API_VERSION: &str = "2026-02-25.clover";
pub const CATALOG_NAMESPACE: &str = "tinyzkp_public_beta_v1";

#[derive(Clone)]
pub struct StripeClient {
    http: Client,
    secret_key: String,
    webhook_secret: String,
    portal_configuration: String,
    prices: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StripeObject {
    pub id: String,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created: i64,
    pub data: StripeEventData,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StripeEventData {
    pub object: Value,
}

impl StripeClient {
    pub fn new(
        secret_key: String,
        webhook_secret: String,
        portal_configuration: String,
        prices_json: &str,
    ) -> anyhow::Result<Self> {
        let prices: HashMap<String, String> = serde_json::from_str(prices_json)?;
        let required = [
            "builder_monthly",
            "pro_monthly",
            "scale_beta_monthly",
            "topup_25",
            "topup_100",
            "topup_500",
        ];
        if required
            .iter()
            .any(|sku| !prices.get(*sku).is_some_and(|id| id.starts_with("price_")))
        {
            anyhow::bail!("Stripe beta price map is incomplete");
        }
        Ok(Self {
            http: Client::new(),
            secret_key,
            webhook_secret,
            portal_configuration,
            prices,
        })
    }

    pub async fn create_customer(
        &self,
        tenant_id: &str,
        operation_id: &str,
    ) -> Result<String, ApiError> {
        let response = self
            .post_form(
                "/v1/customers",
                &[
                    ("metadata[tinyzkp_catalog]", CATALOG_NAMESPACE),
                    ("metadata[tinyzkp_tenant_id]", tenant_id),
                ],
                operation_id,
            )
            .await?;
        Ok(response.id)
    }

    pub async fn create_checkout(
        &self,
        tenant_id: &str,
        customer_id: &str,
        sku: &str,
        operation_id: &str,
        success_url: &str,
        cancel_url: &str,
        synthetic_canary: bool,
    ) -> Result<StripeObject, ApiError> {
        let price = self
            .prices
            .get(sku)
            .ok_or(ApiError::Invalid("unknown_sku"))?;
        let mode = if sku.ends_with("_monthly") {
            "subscription"
        } else {
            "payment"
        };
        let canary = if synthetic_canary { "true" } else { "false" };
        let mut fields = vec![
            ("mode", mode),
            ("customer", customer_id),
            ("line_items[0][price]", price.as_str()),
            ("line_items[0][quantity]", "1"),
            ("client_reference_id", tenant_id),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
            ("metadata[tinyzkp_catalog]", CATALOG_NAMESPACE),
            ("metadata[tinyzkp_tenant_id]", tenant_id),
            ("metadata[tinyzkp_sku]", sku),
            ("metadata[tinyzkp_operation_id]", operation_id),
            ("metadata[tinyzkp_synthetic_canary]", canary),
        ];
        if mode == "subscription" {
            fields.extend([
                (
                    "subscription_data[metadata][tinyzkp_catalog]",
                    CATALOG_NAMESPACE,
                ),
                ("subscription_data[metadata][tinyzkp_tenant_id]", tenant_id),
                ("subscription_data[metadata][tinyzkp_sku]", sku),
            ]);
        } else {
            fields.extend([
                (
                    "payment_intent_data[metadata][tinyzkp_catalog]",
                    CATALOG_NAMESPACE,
                ),
                (
                    "payment_intent_data[metadata][tinyzkp_tenant_id]",
                    tenant_id,
                ),
                ("payment_intent_data[metadata][tinyzkp_sku]", sku),
            ]);
        }
        self.post_form("/v1/checkout/sessions", &fields, operation_id)
            .await
    }

    pub async fn create_portal(
        &self,
        customer_id: &str,
        return_url: &str,
        operation_id: &str,
    ) -> Result<StripeObject, ApiError> {
        self.post_form(
            "/v1/billing_portal/sessions",
            &[
                ("customer", customer_id),
                ("configuration", self.portal_configuration.as_str()),
                ("return_url", return_url),
            ],
            operation_id,
        )
        .await
    }

    pub async fn retrieve(&self, path: &str) -> Result<Value, ApiError> {
        let response = self
            .http
            .get(format!("https://api.stripe.com{path}"))
            .basic_auth(&self.secret_key, Some(""))
            .header("Stripe-Version", API_VERSION)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(response)
    }

    async fn post_form(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        idempotency_key: &str,
    ) -> Result<StripeObject, ApiError> {
        let response = self
            .http
            .post(format!("https://api.stripe.com{path}"))
            .basic_auth(&self.secret_key, Some(""))
            .header("Stripe-Version", API_VERSION)
            .header("Idempotency-Key", idempotency_key)
            .form(fields)
            .send()
            .await?
            .error_for_status()?
            .json::<StripeObject>()
            .await?;
        Ok(response)
    }

    pub fn verify_webhook(&self, body: &[u8], signature: &str) -> Result<StripeEvent, ApiError> {
        let mut timestamp = None;
        let mut signatures = Vec::new();
        for part in signature.split(',') {
            if let Some(value) = part.strip_prefix("t=") {
                timestamp = value.parse::<u64>().ok();
            } else if let Some(value) = part.strip_prefix("v1=") {
                signatures.push(value);
            }
        }
        let timestamp = timestamp.ok_or(ApiError::Unauthorized)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApiError::Internal)?
            .as_secs();
        if now.abs_diff(timestamp) > 300 {
            return Err(ApiError::Unauthorized);
        }
        let mut signed = timestamp.to_string().into_bytes();
        signed.push(b'.');
        signed.extend(body);
        let valid = signatures.into_iter().any(|candidate| {
            let Ok(bytes) = hex::decode(candidate) else {
                return false;
            };
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes()) else {
                return false;
            };
            mac.update(&signed);
            mac.verify_slice(&bytes).is_ok()
        });
        if !valid {
            return Err(ApiError::Unauthorized);
        }
        serde_json::from_slice(body).map_err(|_| ApiError::Invalid("invalid_stripe_event"))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ReconciliationReport {
    pub checked_tenants: usize,
    pub replayed_events: usize,
    pub discrepancies: Vec<String>,
}
