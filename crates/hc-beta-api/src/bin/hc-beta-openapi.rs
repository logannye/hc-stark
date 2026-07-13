use anyhow::{bail, Context, Result};
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let release_sha = arguments
        .next()
        .context("release SHA argument is required")?;
    let output = PathBuf::from(
        arguments
            .next()
            .context("output path argument is required")?,
    );
    if arguments.next().is_some()
        || release_sha.len() != 40
        || !release_sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("usage: hc-beta-openapi RELEASE_SHA OUTPUT");
    }
    let mut bytes = serde_json::to_vec_pretty(&hc_beta_api::openapi::contract(&release_sha))?;
    bytes.push(b'\n');
    fs::write(&output, bytes).with_context(|| format!("write {}", output.display()))?;
    Ok(())
}
