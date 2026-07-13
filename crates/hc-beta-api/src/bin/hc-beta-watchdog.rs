use hc_beta_api::{config::Config, operations, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "check".into());
    let state = AppState::create(Config::from_env()?).await?;
    let report = match command.as_str() {
        "check" => operations::evaluate(&state).await?,
        "enforce" => operations::enforce(&state).await?,
        "recover" => {
            let operation = std::env::args()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("recover requires an operation ID"))?;
            operations::recover(&state, &operation).await?
        }
        _ => anyhow::bail!("usage: hc-beta-watchdog check|enforce|recover OPERATION_ID"),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.violations.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("public-beta invariants failed")
    }
}
