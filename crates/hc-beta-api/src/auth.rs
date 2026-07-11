use crate::{error::ApiError, AppState, Tenant};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::Row;

type HmacSha256 = Hmac<Sha256>;

pub fn random_token(bytes: usize) -> String {
    use base64::Engine;
    let mut value = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

pub fn secret_hash(pepper: &[u8], value: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper).expect("HMAC accepts any key");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn plain_sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn encrypt_verifier(key: &[u8; 32], verifier: &str) -> Result<Vec<u8>, ApiError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ApiError::Internal)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), verifier.as_bytes())
        .map_err(|_| ApiError::Internal)?;
    let mut result = nonce_bytes.to_vec();
    result.extend(encrypted);
    Ok(result)
}

pub fn decrypt_verifier(key: &[u8; 32], encrypted: &[u8]) -> Result<String, ApiError> {
    if encrypted.len() < 13 {
        return Err(ApiError::Unauthorized);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ApiError::Internal)?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| ApiError::Unauthorized)?;
    String::from_utf8(plain).map_err(|_| ApiError::Unauthorized)
}

pub async fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<Tenant, ApiError> {
    if let Some(raw) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        let hash = secret_hash(&state.config.secret_pepper, raw);
        let row = sqlx::query(
            "SELECT t.tenant_id, t.plan, t.status
               FROM beta_api_keys k JOIN tenants t ON t.tenant_id = k.tenant_id
              WHERE k.key_hash = $1 AND k.revoked_at IS NULL AND t.deleted_at IS NULL",
        )
        .bind(hash)
        .fetch_optional(&state.pool)
        .await?;
        if let Some(row) = row {
            let status: String = row.get("status");
            if status == "active" {
                return authorize_tenant(
                    state,
                    Tenant {
                        tenant_id: row.get("tenant_id"),
                        plan: row.get("plan"),
                    },
                )
                .await;
            }
        }
    }
    if let Some(token) = cookie_value(headers, "__Host-tinyzkp_beta") {
        let hash = secret_hash(&state.config.secret_pepper, token);
        let row = sqlx::query(
            "SELECT t.tenant_id, t.plan, t.status
               FROM beta_sessions s JOIN tenants t ON t.tenant_id = s.tenant_id
              WHERE s.session_hash = $1 AND s.revoked_at IS NULL
                AND s.expires_at > now() AND t.deleted_at IS NULL",
        )
        .bind(hash)
        .fetch_optional(&state.pool)
        .await?;
        if let Some(row) = row {
            let status: String = row.get("status");
            if status == "active" {
                return authorize_tenant(
                    state,
                    Tenant {
                        tenant_id: row.get("tenant_id"),
                        plan: row.get("plan"),
                    },
                )
                .await;
            }
        }
    }
    Err(ApiError::Unauthorized)
}

async fn authorize_tenant(state: &AppState, tenant: Tenant) -> Result<Tenant, ApiError> {
    let count: i32 = sqlx::query_scalar(
        "INSERT INTO beta_rate_limits (tenant_id,scope,window_start,request_count)
         VALUES ($1,'authenticated',date_trunc('minute',now()),1)
         ON CONFLICT (tenant_id,scope,window_start) DO UPDATE
             SET request_count=beta_rate_limits.request_count+1
         RETURNING request_count",
    )
    .bind(&tenant.tenant_id)
    .fetch_one(&state.pool)
    .await?;
    if count > 600 {
        Err(ApiError::RateLimited)
    } else {
        Ok(tenant)
    }
}

pub async fn authenticate_worker(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<String, ApiError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let worker_id = headers
        .get("x-tinyzkp-worker-id")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    let hash = secret_hash(&state.config.secret_pepper, raw);
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM beta_workers WHERE worker_id=$1 AND credential_hash=$2 AND enabled)",
    )
    .bind(worker_id)
    .bind(hash)
    .fetch_one(&state.pool)
    .await?;
    if found {
        Ok(worker_id.to_owned())
    } else {
        Err(ApiError::Unauthorized)
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|pair| {
            pair.strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_domain_keyed_and_pkce_is_stable() {
        assert_ne!(secret_hash(b"a", "token"), secret_hash(b"b", "token"));
        assert_eq!(pkce_challenge("verifier"), pkce_challenge("verifier"));
    }

    #[test]
    fn verifier_ciphertext_round_trips() {
        let key = [7u8; 32];
        let encrypted = encrypt_verifier(&key, "secret-verifier").unwrap();
        assert_ne!(encrypted, b"secret-verifier");
        assert_eq!(
            decrypt_verifier(&key, &encrypted).unwrap(),
            "secret-verifier"
        );
    }
}
