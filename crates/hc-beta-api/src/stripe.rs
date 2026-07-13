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
    product_tax_code: String,
    webhook_endpoint: String,
    prices: HashMap<String, String>,
    livemode: bool,
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
    #[serde(default)]
    pub livemode: bool,
    pub data: StripeEventData,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StripeEventData {
    pub object: Value,
}

pub struct CheckoutSessionParams<'a> {
    pub tenant_id: &'a str,
    pub customer_id: &'a str,
    pub sku: &'a str,
    pub operation_id: &'a str,
    pub release_sha: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
    pub synthetic_canary: bool,
}

impl StripeClient {
    pub fn new(
        secret_key: String,
        webhook_secret: String,
        portal_configuration: String,
        product_tax_code: String,
        webhook_endpoint: String,
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
        let livemode = if secret_key.starts_with("sk_live_") {
            true
        } else if secret_key.starts_with("sk_test_") {
            false
        } else {
            anyhow::bail!("Stripe key must be an sk_live_ or sk_test_ secret key");
        };
        Ok(Self {
            http: Client::new(),
            secret_key,
            webhook_secret,
            portal_configuration,
            product_tax_code,
            webhook_endpoint,
            prices,
            livemode,
        })
    }

    pub fn livemode(&self) -> bool {
        self.livemode
    }

    /// Fail startup when the isolated beta catalog, Portal, tax code, or
    /// webhook destination is missing or belongs to the wrong Stripe mode.
    pub async fn preflight(&self) -> anyhow::Result<()> {
        let mut paths = vec![
            format!("/v1/tax_codes/{}", self.product_tax_code),
            format!(
                "/v1/billing_portal/configurations/{}",
                self.portal_configuration
            ),
            format!("/v1/webhook_endpoints/{}", self.webhook_endpoint),
        ];
        paths.extend(
            self.prices
                .values()
                .map(|price| format!("/v1/prices/{price}")),
        );
        for path in paths {
            let object = self
                .retrieve(&path)
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
            if object
                .get("livemode")
                .and_then(Value::as_bool)
                .is_some_and(|mode| mode != self.livemode)
            {
                anyhow::bail!("Stripe beta preflight mode mismatch for {path}");
            }
            if path.contains("/prices/")
                && object.get("active").and_then(Value::as_bool) != Some(true)
            {
                anyhow::bail!("Stripe beta price is not active: {path}");
            }
            if path.contains("/prices/") {
                let product_id = object
                    .get("product")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Stripe beta price has no product: {path}"))?;
                let product = self
                    .retrieve(&format!("/v1/products/{product_id}"))
                    .await
                    .map_err(|error| anyhow::anyhow!(error))?;
                if product.get("tax_code").and_then(Value::as_str)
                    != Some(self.product_tax_code.as_str())
                {
                    anyhow::bail!("Stripe beta product tax code is not approved: {product_id}");
                }
            }
        }
        Ok(())
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
        params: CheckoutSessionParams<'_>,
    ) -> Result<StripeObject, ApiError> {
        let price = self
            .prices
            .get(params.sku)
            .ok_or(ApiError::Invalid("unknown_sku"))?;
        let mode = if params.sku.ends_with("_monthly") {
            "subscription"
        } else {
            "payment"
        };
        let canary = if params.synthetic_canary {
            "true"
        } else {
            "false"
        };
        let mut fields = vec![
            ("mode", mode),
            ("customer", params.customer_id),
            ("automatic_tax[enabled]", "true"),
            ("billing_address_collection", "required"),
            ("customer_update[address]", "auto"),
            ("line_items[0][price]", price.as_str()),
            ("line_items[0][quantity]", "1"),
            ("client_reference_id", params.tenant_id),
            ("success_url", params.success_url),
            ("cancel_url", params.cancel_url),
            ("metadata[tinyzkp_catalog]", CATALOG_NAMESPACE),
            ("metadata[tinyzkp_tenant_id]", params.tenant_id),
            ("metadata[tinyzkp_sku]", params.sku),
            ("metadata[tinyzkp_operation_id]", params.operation_id),
            ("metadata[tinyzkp_release_sha]", params.release_sha),
            ("metadata[tinyzkp_synthetic_canary]", canary),
        ];
        if mode == "subscription" {
            fields.extend([
                (
                    "subscription_data[metadata][tinyzkp_catalog]",
                    CATALOG_NAMESPACE,
                ),
                (
                    "subscription_data[metadata][tinyzkp_tenant_id]",
                    params.tenant_id,
                ),
                ("subscription_data[metadata][tinyzkp_sku]", params.sku),
                (
                    "subscription_data[metadata][tinyzkp_operation_id]",
                    params.operation_id,
                ),
                (
                    "subscription_data[metadata][tinyzkp_release_sha]",
                    params.release_sha,
                ),
                (
                    "subscription_data[metadata][tinyzkp_synthetic_canary]",
                    canary,
                ),
            ]);
        } else {
            fields.extend([
                (
                    "payment_intent_data[metadata][tinyzkp_catalog]",
                    CATALOG_NAMESPACE,
                ),
                (
                    "payment_intent_data[metadata][tinyzkp_tenant_id]",
                    params.tenant_id,
                ),
                ("payment_intent_data[metadata][tinyzkp_sku]", params.sku),
                (
                    "payment_intent_data[metadata][tinyzkp_operation_id]",
                    params.operation_id,
                ),
                (
                    "payment_intent_data[metadata][tinyzkp_release_sha]",
                    params.release_sha,
                ),
                (
                    "payment_intent_data[metadata][tinyzkp_synthetic_canary]",
                    canary,
                ),
            ]);
        }
        self.post_form("/v1/checkout/sessions", &fields, params.operation_id)
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

    pub async fn create_refund(
        &self,
        payment_intent: &str,
        amount_minor: Option<u64>,
        operation_id: &str,
    ) -> Result<Value, ApiError> {
        if !payment_intent.starts_with("pi_") || operation_id.is_empty() {
            return Err(ApiError::Invalid("invalid_refund_request"));
        }
        let mut fields = vec![
            ("payment_intent".to_owned(), payment_intent.to_owned()),
            (
                "metadata[tinyzkp_catalog]".to_owned(),
                CATALOG_NAMESPACE.to_owned(),
            ),
            (
                "metadata[tinyzkp_operation_id]".to_owned(),
                operation_id.to_owned(),
            ),
        ];
        if let Some(amount) = amount_minor {
            if amount == 0 {
                return Err(ApiError::Invalid("invalid_refund_amount"));
            }
            fields.push(("amount".into(), amount.to_string()));
        }
        let response = self
            .http
            .post("https://api.stripe.com/v1/refunds")
            .basic_auth(&self.secret_key, Some(""))
            .header("Stripe-Version", API_VERSION)
            .header("Idempotency-Key", operation_id)
            .form(&fields)
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
    pub release_sha: String,
    pub generated_at_unix: u64,
    pub report_sha256: String,
    pub report_hmac_sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> StripeClient {
        StripeClient::new(
            "sk_test_only".into(),
            "whsec_test_only".into(),
            "bpc_test".into(),
            "txcd_test".into(),
            "we_test".into(),
            r#"{"builder_monthly":"price_builder","pro_monthly":"price_pro","scale_beta_monthly":"price_scale","topup_25":"price_25","topup_100":"price_100","topup_500":"price_500"}"#,
        )
        .unwrap()
    }

    #[test]
    fn webhook_signature_binds_the_unmodified_raw_body() {
        let body = br#"{"id":"evt_test","type":"invoice.paid","created":1,"livemode":false,"data":{"object":{"id":"in_test","object":"invoice"}}}"#;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut signed = format!("{timestamp}.").into_bytes();
        signed.extend(body);
        let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_test_only").unwrap();
        mac.update(&signed);
        let signature = format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        );
        let event = client().verify_webhook(body, &signature).unwrap();
        assert_eq!(event.id, "evt_test");
        let mut changed = body.to_vec();
        changed.push(b' ');
        assert!(client().verify_webhook(&changed, &signature).is_err());
    }

    #[test]
    fn stripe_api_version_is_the_reviewed_clover_release() {
        assert_eq!(API_VERSION, "2026-02-25.clover");
    }
}
