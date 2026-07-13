use hc_beta_api::business;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let component = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("component is required"))?;
    if !matches!(component.as_str(), "backup_wal" | "api_storage") {
        anyhow::bail!("component must be backup_wal or api_storage");
    }
    let healthy = match std::env::args().nth(2).as_deref() {
        Some("healthy") => true,
        Some("unhealthy") => false,
        _ => anyhow::bail!("status must be healthy or unhealthy"),
    };
    let free_percent = std::env::args()
        .nth(3)
        .map(|value| value.parse::<i32>())
        .transpose()?;
    if component == "api_storage" && !matches!(free_percent, Some(0..=100)) {
        anyhow::bail!("api_storage requires a free percentage from 0 through 100");
    }
    if component == "backup_wal" && free_percent.is_some() {
        anyhow::bail!("backup_wal does not accept a free percentage");
    }
    let pool = business::pool_from_env().await?;
    sqlx::query(
        "INSERT INTO beta_infrastructure_health
             (component,healthy,free_percent,observed_at,release_sha)
         VALUES ($1,$2,$3,now(),$4)
         ON CONFLICT (component) DO UPDATE SET healthy=EXCLUDED.healthy,
             free_percent=EXCLUDED.free_percent,observed_at=EXCLUDED.observed_at,
             release_sha=EXCLUDED.release_sha",
    )
    .bind(&component)
    .bind(healthy)
    .bind(free_percent)
    .bind(business::release_sha()?)
    .execute(&pool)
    .await?;
    println!("{{\"component\":\"{component}\",\"recorded\":true}}");
    Ok(())
}
