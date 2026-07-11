#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let state = hc_beta_api::AppState::create(hc_beta_api::config::Config::from_env()?).await?;
    let report = hc_beta_api::retention::sweep(&state).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.failed == 0 {
        Ok(())
    } else {
        anyhow::bail!("retention deletion failures")
    }
}
