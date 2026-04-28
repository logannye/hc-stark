#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hc_server::run().await
}
