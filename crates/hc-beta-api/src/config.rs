use anyhow::{bail, Context};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, net::SocketAddr, path::PathBuf, process::Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureMode {
    DarkCanary,
    PublicBeta,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub public_bind: SocketAddr,
    pub worker_bind: SocketAddr,
    pub database_url: String,
    pub release_sha: String,
    pub exposure: ExposureMode,
    pub writes_enabled: bool,
    pub operator_allowlist: Vec<String>,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_callback_url: String,
    pub dashboard_url: String,
    pub oauth_cipher_key: [u8; 32],
    pub secret_pepper: Vec<u8>,
    pub r2_bucket: String,
    pub r2_endpoint: String,
    pub r2_region: String,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    pub stripe_portal_configuration: String,
    pub stripe_prices_json: String,
}

#[derive(Deserialize)]
struct ReleaseAuthorization {
    schema_version: u32,
    release_channel: String,
    status: String,
    release_sha: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let release_sha = required("HC_RELEASE_SHA")?;
        if release_sha.len() != 40
            || !release_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("HC_RELEASE_SHA must be a full Git SHA");
        }
        let exposure = match required("TINYZKP_BETA_EXPOSURE")?.as_str() {
            "dark_canary" => ExposureMode::DarkCanary,
            "public_beta" => ExposureMode::PublicBeta,
            _ => bail!("TINYZKP_BETA_EXPOSURE must be dark_canary or public_beta"),
        };
        if exposure == ExposureMode::PublicBeta {
            verify_release_authorization(&release_sha)?;
        }
        let cipher = decode_secret_32("TINYZKP_OAUTH_CIPHER_KEY")?;
        let pepper = decode_secret("TINYZKP_SECRET_PEPPER")?;
        if pepper.len() < 32 {
            bail!("TINYZKP_SECRET_PEPPER must contain at least 32 bytes");
        }
        let allowlist = std::env::var("TINYZKP_OPERATOR_GITHUB_IDS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if exposure == ExposureMode::DarkCanary && allowlist.is_empty() {
            bail!("dark canary mode requires TINYZKP_OPERATOR_GITHUB_IDS");
        }
        Ok(Self {
            public_bind: optional("TINYZKP_BETA_PUBLIC_BIND", "127.0.0.1:8090").parse()?,
            worker_bind: optional("TINYZKP_BETA_WORKER_BIND", "10.77.0.1:8091").parse()?,
            database_url: required("TINYZKP_DATABASE_URL")?,
            release_sha,
            exposure,
            writes_enabled: optional("TINYZKP_BETA_WRITES_ENABLED", "0") == "1",
            operator_allowlist: allowlist,
            github_client_id: required("TINYZKP_GITHUB_CLIENT_ID")?,
            github_client_secret: required("TINYZKP_GITHUB_CLIENT_SECRET")?,
            github_callback_url: required("TINYZKP_GITHUB_CALLBACK_URL")?,
            dashboard_url: required("TINYZKP_DASHBOARD_URL")?,
            oauth_cipher_key: cipher,
            secret_pepper: pepper,
            r2_bucket: required("TINYZKP_R2_ARTIFACT_BUCKET")?,
            r2_endpoint: required("TINYZKP_R2_ENDPOINT")?,
            r2_region: optional("TINYZKP_R2_REGION", "auto"),
            stripe_secret_key: required("STRIPE_SECRET_KEY")?,
            stripe_webhook_secret: required("TINYZKP_STRIPE_WEBHOOK_SECRET")?,
            stripe_portal_configuration: required("TINYZKP_STRIPE_PORTAL_CONFIGURATION")?,
            stripe_prices_json: required("TINYZKP_STRIPE_PRICE_MAP_JSON")?,
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("{name} is empty");
    }
    Ok(value)
}

fn optional(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn decode_secret(name: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(required(name)?)
        .with_context(|| format!("{name} must be base64"))
}

fn decode_secret_32(name: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = decode_secret(name)?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
}

fn verify_release_authorization(expected_sha: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(required("TINYZKP_PUBLIC_BETA_RELEASE_AUTHORIZATION")?);
    let bytes = fs::read(&path).context("read public-beta authorization")?;
    let expected_digest = required("TINYZKP_PUBLIC_BETA_RELEASE_AUTHORIZATION_SHA256")?;
    if hex::encode(Sha256::digest(&bytes)) != expected_digest {
        bail!("public-beta authorization digest mismatch");
    }
    let authorization: ReleaseAuthorization =
        serde_json::from_slice(&bytes).context("parse public-beta authorization")?;
    if authorization.schema_version != 1
        || authorization.release_channel != "public_beta"
        || authorization.status != "ready"
        || authorization.release_sha != expected_sha
    {
        bail!("public-beta authorization is not ready for this release");
    }
    let bundle = PathBuf::from(required(
        "TINYZKP_PUBLIC_BETA_RELEASE_AUTHORIZATION_BUNDLE",
    )?);
    if !bundle.is_file() {
        bail!("public-beta authorization signature bundle is missing");
    }
    let identity = required("TINYZKP_PUBLIC_BETA_SIGNING_IDENTITY_REGEXP")?;
    let issuer = required("TINYZKP_PUBLIC_BETA_SIGNING_ISSUER")?;
    let result = Command::new("/usr/local/bin/cosign")
        .args([
            "verify-blob",
            "--bundle",
            bundle.to_str().context("signature bundle path encoding")?,
            "--certificate-identity-regexp",
            &identity,
            "--certificate-oidc-issuer",
            &issuer,
            path.to_str().context("authorization path encoding")?,
        ])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()
        .context("execute cosign authorization verification")?;
    if !result.status.success() {
        bail!("public-beta authorization signature verification failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_values_are_distinct() {
        assert_ne!(ExposureMode::DarkCanary, ExposureMode::PublicBeta);
    }
}
