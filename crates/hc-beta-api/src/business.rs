use anyhow::{bail, Context};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{fs, path::Path, time::Duration};

pub async fn pool_from_env() -> anyhow::Result<PgPool> {
    let database_url = required("TINYZKP_DATABASE_URL")?;
    PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .context("connect to beta PostgreSQL")
}

pub fn release_sha() -> anyhow::Result<String> {
    let value = required("HC_RELEASE_SHA")?;
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("HC_RELEASE_SHA must be a full Git SHA");
    }
    Ok(value)
}

pub fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("{name} is empty");
    }
    Ok(value)
}

pub fn sign(value: &Value) -> anyhow::Result<(String, String)> {
    let bytes = serde_json::to_vec(value)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let key = base64::engine::general_purpose::STANDARD
        .decode(required("TINYZKP_RECONCILIATION_HMAC_KEY")?)
        .context("TINYZKP_RECONCILIATION_HMAC_KEY must be base64")?;
    if key.len() != 32 {
        bail!("TINYZKP_RECONCILIATION_HMAC_KEY must decode to 32 bytes");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
    mac.update(&bytes);
    Ok((digest, hex::encode(mac.finalize().into_bytes())))
}

pub fn read_owner_json(path: &Path) -> anyhow::Result<Value> {
    ensure_owner_file(path)?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn write_owner_json(path: &Path, value: &Value) -> anyhow::Result<()> {
    let parent = path.parent().context("report path has no parent")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let temporary = parent.join(format!(
            ".{}.tmp",
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("report")
        ));
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn ensure_owner_file(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("owner file must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("owner file must be owned by the current user and mode 0600");
        }
    }
    Ok(())
}

pub async fn send_summary(value: Value) -> anyhow::Result<()> {
    assert_redacted(&value)?;
    let url = required("TINYZKP_ALERT_WEBHOOK_URL")?;
    if !url.starts_with("https://") {
        bail!("TINYZKP_ALERT_WEBHOOK_URL must use HTTPS");
    }
    let token = required("TINYZKP_ALERT_WEBHOOK_TOKEN")?;
    if token.len() < 32 || token.len() > 512 {
        bail!("TINYZKP_ALERT_WEBHOOK_TOKEN must contain 32-512 characters");
    }
    reqwest::Client::new()
        .post(url)
        .bearer_auth(token)
        .json(&value)
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub fn assert_redacted(value: &Value) -> anyhow::Result<()> {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.iter().any(|(key, value)| {
                let key = key.to_ascii_lowercase();
                key == "email"
                    || key == "api_key"
                    || key == "cookie"
                    || key == "object_key"
                    || key == "tenant_id"
                    || key == "stripe_id"
                    || key.ends_with("_tenant_id")
                    || key.ends_with("_stripe_id")
                    || key.ends_with("_url")
                    || walk(value)
            }),
            Value::Array(values) => values.iter().any(walk),
            Value::String(value) => {
                [
                    "sk_",
                    "rk_",
                    "whsec_",
                    "tzb_",
                    "Bearer ",
                    "https://checkout.stripe.com/",
                ]
                .iter()
                .any(|prefix| value.starts_with(prefix))
                    || value.contains("X-Amz-Signature=")
            }
            _ => false,
        }
    }
    if walk(value) {
        bail!("owner report contains a secret-like or identifying field");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::assert_redacted;
    use serde_json::json;

    #[test]
    fn aggregate_owner_reports_reject_identifiers_and_secrets() {
        assert_redacted(&json!({"paid_tenants":5,"release_sha":"a".repeat(40)})).unwrap();
        assert!(assert_redacted(&json!({"tenant_id":"tenant-secret"})).is_err());
        assert!(assert_redacted(&json!({"value":"sk_live_secret"})).is_err());
        assert!(assert_redacted(&json!({"portal_url":"https://example.com"})).is_err());
    }
}
