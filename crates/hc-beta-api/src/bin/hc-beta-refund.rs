use anyhow::{bail, Context};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    if std::env::var("TINYZKP_ALLOW_REFUND_WRITE").as_deref() != Ok("1") {
        bail!("TINYZKP_ALLOW_REFUND_WRITE=1 is required");
    }
    let payment_intent = required("TINYZKP_REFUND_PAYMENT_INTENT")?;
    if !payment_intent.starts_with("pi_") {
        bail!("TINYZKP_REFUND_PAYMENT_INTENT must be a PaymentIntent ID");
    }
    let operation_id = required("TINYZKP_REFUND_OPERATION_ID")?;
    let amount = std::env::var("TINYZKP_REFUND_AMOUNT_MINOR")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .context("parse TINYZKP_REFUND_AMOUNT_MINOR")
        })
        .transpose()?;
    let state = hc_beta_api::AppState::create(hc_beta_api::config::Config::from_env()?).await?;
    let refund = state
        .stripe
        .create_refund(&payment_intent, amount, &operation_id)
        .await?;
    let output = serde_json::json!({
        "id": refund.pointer("/id").and_then(serde_json::Value::as_str),
        "status": refund.pointer("/status").and_then(serde_json::Value::as_str),
        "livemode": refund.pointer("/livemode").and_then(serde_json::Value::as_bool),
        "payment_intent": refund.pointer("/payment_intent").and_then(serde_json::Value::as_str),
        "amount_minor": refund.pointer("/amount").and_then(serde_json::Value::as_u64),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("{name} is empty");
    }
    Ok(value)
}
