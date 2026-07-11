use crate::error::ApiError;
use aws_sdk_s3::{presigning::PresigningConfig, primitives::ByteStream, Client};
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone)]
pub struct ObjectStore {
    client: Client,
    bucket: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignedUrl {
    pub url: String,
    pub expires_in_seconds: u64,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct ObjectHead {
    pub content_length: u64,
    pub etag: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

impl ObjectStore {
    pub async fn new(bucket: String, endpoint: &str, region: &str) -> anyhow::Result<Self> {
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_owned()))
            .endpoint_url(endpoint)
            .load()
            .await;
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .force_path_style(true)
            .build();
        Ok(Self {
            client: Client::from_conf(config),
            bucket,
        })
    }

    pub async fn presign_upload(
        &self,
        key: &str,
        content_length: u64,
        blake3_hex: &str,
    ) -> Result<SignedUrl, ApiError> {
        let expires = Duration::from_secs(15 * 60);
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(
                i64::try_from(content_length).map_err(|_| ApiError::Invalid("upload_too_large"))?,
            )
            .metadata("tinyzkp-blake3", blake3_hex)
            .presigned(PresigningConfig::expires_in(expires).map_err(|_| ApiError::Internal)?)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to presign R2 upload");
                ApiError::Unavailable("object_store_unavailable")
            })?;
        let mut headers = BTreeMap::new();
        for (name, value) in request.headers() {
            headers.insert(name.to_string(), value.to_string());
        }
        Ok(SignedUrl {
            url: request.uri().to_string(),
            expires_in_seconds: expires.as_secs(),
            headers,
        })
    }

    pub async fn presign_download(&self, key: &str) -> Result<SignedUrl, ApiError> {
        let expires = Duration::from_secs(5 * 60);
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(PresigningConfig::expires_in(expires).map_err(|_| ApiError::Internal)?)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to presign R2 download");
                ApiError::Unavailable("object_store_unavailable")
            })?;
        Ok(SignedUrl {
            url: request.uri().to_string(),
            expires_in_seconds: expires.as_secs(),
            headers: BTreeMap::new(),
        })
    }

    pub async fn head(&self, key: &str) -> Result<ObjectHead, ApiError> {
        let result = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(%error, key, "R2 object HEAD failed");
                ApiError::Invalid("upload_chunk_missing")
            })?;
        let content_length = u64::try_from(result.content_length().unwrap_or_default())
            .map_err(|_| ApiError::Invalid("invalid_object_length"))?;
        let metadata = result
            .metadata()
            .map(|metadata| {
                metadata
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(ObjectHead {
            content_length,
            etag: result.e_tag().map(ToOwned::to_owned),
            metadata,
        })
    }

    pub async fn get(&self, key: &str, maximum_bytes: u64) -> Result<Vec<u8>, ApiError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                tracing::error!(%error, key, "R2 object GET failed");
                ApiError::Unavailable("object_store_unavailable")
            })?;
        if output.content_length().unwrap_or_default() < 0
            || output.content_length().unwrap_or_default() as u64 > maximum_bytes
        {
            return Err(ApiError::Invalid("object_too_large"));
        }
        let bytes = output.body.collect().await.map_err(|error| {
            tracing::error!(%error, key, "R2 body read failed");
            ApiError::Unavailable("object_store_unavailable")
        })?;
        Ok(bytes.into_bytes().to_vec())
    }

    pub async fn put_internal(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApiError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|error| {
                tracing::error!(%error, key, "R2 internal PUT failed");
                ApiError::Unavailable("object_store_unavailable")
            })?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), ApiError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                tracing::error!(%error, key, "R2 object DELETE failed");
                ApiError::Unavailable("object_store_unavailable")
            })?;
        Ok(())
    }
}

pub fn upload_object_key(tenant_id: &str, upload_id: uuid::Uuid, index: u32) -> String {
    format!("tenants/{tenant_id}/uploads/{upload_id}/chunks/{index:06}.zst")
}

pub fn bundle_object_key(tenant_id: &str, job_id: uuid::Uuid) -> String {
    format!("tenants/{tenant_id}/jobs/{job_id}/bundle.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_keys_are_server_scoped() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            upload_object_key("tenant", id, 7),
            "tenants/tenant/uploads/00000000-0000-0000-0000-000000000000/chunks/000007.zst"
        );
        assert!(!bundle_object_key("tenant", id).contains(".."));
    }
}
