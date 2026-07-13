use hc_beta_api::business;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let category = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("category is required"))?;
    if !matches!(
        category.as_str(),
        "onboarding" | "billing" | "proof" | "security" | "operations" | "other"
    ) {
        anyhow::bail!("unsupported support category");
    }
    let minutes = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("minutes are required"))?
        .parse::<i32>()?;
    if !(1..=240).contains(&minutes) {
        anyhow::bail!("minutes must be between 1 and 240");
    }
    let operation = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("operation ID is required"))?;
    if args.next().is_some() || !(8..=200).contains(&operation.len()) {
        anyhow::bail!("usage: hc-beta-support-log CATEGORY MINUTES OPERATION_ID");
    }
    let pool = business::pool_from_env().await?;
    sqlx::query(
        "INSERT INTO beta_support_minutes
             (support_entry_id,category,minutes,operation_key)
         VALUES ($1,$2,$3,$4) ON CONFLICT (operation_key) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&category)
    .bind(minutes)
    .bind(&operation)
    .execute(&pool)
    .await?;
    println!("{{\"recorded\":true,\"category\":\"{category}\",\"minutes\":{minutes}}}");
    Ok(())
}
